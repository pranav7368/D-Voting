/**
 * Issuer (Registration Authority) side of RSABSSA: BlindSign.
 *
 * The `BlindSigner` interface is the seam that lets the private key live
 * somewhere other than this process. The in-process implementation below is
 * correct and fine for the academic demo; a production deployment swaps in a
 * KMS/HSM-backed implementation without touching any protocol code.
 */

import { i2osp, os2ip } from "../util/bytes.ts";
import { bitLength, egcd, modInverse, modPow } from "../util/bigint.ts";
import { BlindRsaError, MIN_MODULUS_BITS, type BlindRsaPrivateKey, type BlindRsaPublicKey } from "./types.ts";

export interface BlindSigner {
  readonly publicKey: BlindRsaPublicKey;
  /** Raw RSA private operation over an already-blinded, already-PSS-encoded value. */
  blindSign(blindedMessage: Uint8Array): Promise<Uint8Array>;
}

/**
 * In-process signer. The private key is held in this process's memory.
 *
 * DEPLOYMENT NOTE: JS BigInt is not constant-time (see util/bigint.ts), so the
 * modular exponentiation below is not side-channel hardened. For anything
 * beyond a demo, implement `BlindSigner` against AWS KMS / CloudHSM instead.
 */
export class LocalBlindSigner implements BlindSigner {
  readonly publicKey: BlindRsaPublicKey;
  readonly #privateKey: BlindRsaPrivateKey;

  constructor(privateKey: BlindRsaPrivateKey) {
    const modulusBits = bitLength(privateKey.n);
    if (modulusBits < MIN_MODULUS_BITS) {
      throw new BlindRsaError(
        `LocalBlindSigner: modulus is ${modulusBits} bits, minimum is ${MIN_MODULUS_BITS}`,
      );
    }
    this.#privateKey = privateKey;
    this.publicKey = { n: privateKey.n, e: privateKey.e, suite: privateKey.suite };
  }

  async blindSign(blindedMessage: Uint8Array): Promise<Uint8Array> {
    const { n, e } = this.#privateKey;
    const modulusBytes = Math.ceil(bitLength(n) / 8);

    if (blindedMessage.length !== modulusBytes) {
      throw new BlindRsaError("blindSign: blinded message has the wrong length");
    }
    const m = os2ip(blindedMessage);
    if (m >= n) {
      throw new BlindRsaError("blindSign: blinded message is not less than the modulus");
    }

    const s = this.#privateOperation(m);

    // Fault check, mandated by RFC 9474 section 4.2.
    //
    // CRT-based RSA is vulnerable to the Bellcore fault attack: if a hardware
    // glitch corrupts exactly one of the two half-exponentiations, the emitted
    // signature s satisfies s^e = m mod p but not mod q -- and gcd(s^e - m, n)
    // then reveals a prime factor of n. One faulty signature leaks the issuer's
    // private key, which would let an attacker mint unlimited voting
    // credentials. Verifying our own output before releasing it turns that
    // catastrophic leak into a returned error.
    if (modPow(s, e, n) !== m) {
      throw new BlindRsaError("blindSign: signature failed self-check (possible fault attack)");
    }

    return i2osp(s, modulusBytes);
  }

  /** RSA private op via the Chinese Remainder Theorem. */
  #privateOperation(m: bigint): bigint {
    const { p, q, dp, dq, qInv, n } = this.#privateKey;

    // Exponentiating mod p and mod q separately works on half-size operands,
    // which is roughly 4x faster than a single exponentiation mod n.
    const sp = modPow(m % p, dp, p);
    const sq = modPow(m % q, dq, q);

    // Garner recombination.
    let h = (qInv * (sp - sq)) % p;
    if (h < 0n) h += p;
    return (sq + h * q) % n;
  }
}

/**
 * Stable identifier for an issuer key: base64url(SHA-256(n || e)).
 *
 * WHY A KEY ID MATTERS -- a subtle attack worth raising in the viva:
 *
 * A malicious Registration Authority could hand each voter a *different* public
 * key. Every credential would still verify against "the" issuer key, but the RA
 * would know which key it gave to which voter, so at tally time it could tell
 * whose ballot was whose. This defeats unlinkability completely without breaking
 * any crypto.
 *
 * The defence is key consistency: there must be exactly one issuer key per
 * election, published where every participant sees the same value (the
 * blockchain genesis block / bulletin board), and clients must pin it. The key
 * ID is what makes that comparison cheap and what ballots reference later.
 */
export async function computeKeyId(publicKey: BlindRsaPublicKey): Promise<string> {
  const { digest } = await import("../hash.ts");
  const { concatBytes, toBase64Url } = await import("../util/bytes.ts");
  const nBytes = i2osp(publicKey.n, Math.ceil(bitLength(publicKey.n) / 8));
  const eBytes = i2osp(publicKey.e, Math.ceil(bitLength(publicKey.e) / 8));
  return toBase64Url(await digest("SHA-256", concatBytes(nBytes, eBytes)));
}

/** Re-exported so callers can sanity-check a loaded key pair before serving traffic. */
export function assertKeyPairConsistent(privateKey: BlindRsaPrivateKey): void {
  if (privateKey.p * privateKey.q !== privateKey.n) {
    throw new BlindRsaError("key check: p * q does not equal n");
  }

  // d must invert e modulo the Carmichael function lambda(n) = lcm(p-1, q-1),
  // NOT Euler's phi(n) = (p-1)(q-1). Both yield working keys, but OpenSSL (and
  // therefore Node) generates the smaller lambda-based d, so checking against
  // phi would reject every real key.
  const pMinus1 = privateKey.p - 1n;
  const qMinus1 = privateKey.q - 1n;
  const [gcdPQ] = egcd(pMinus1, qMinus1);
  const lambda = (pMinus1 / gcdPQ) * qMinus1;
  if ((privateKey.d * privateKey.e) % lambda !== 1n) {
    throw new BlindRsaError("key check: d is not the inverse of e");
  }
  if (privateKey.dp !== privateKey.d % (privateKey.p - 1n)) {
    throw new BlindRsaError("key check: dp is inconsistent");
  }
  if (privateKey.dq !== privateKey.d % (privateKey.q - 1n)) {
    throw new BlindRsaError("key check: dq is inconsistent");
  }
  if (privateKey.qInv !== modInverse(privateKey.q, privateKey.p)) {
    throw new BlindRsaError("key check: qInv is inconsistent");
  }
}
