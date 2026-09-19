/**
 * Client (voter) side of RSABSSA: Blind and Finalize.
 *
 * This module runs on the VOTER'S DEVICE. Nothing here may be moved server-side:
 * the whole point is that the blinding factor `r` is generated and destroyed
 * locally, so the issuer never has the information needed to link a credential
 * back to the person it was issued to.
 */

import { emsaPssEncode, emsaPssVerify } from "../pss.ts";
import { i2osp, os2ip, randomBytes } from "../util/bytes.ts";
import { bitLength, modInverse, modPow, randomBigIntBelow } from "../util/bigint.ts";
import {
  BlindRsaError,
  MIN_MODULUS_BITS,
  type BlindResult,
  type BlindRsaPublicKey,
} from "./types.ts";

/** Generate a fresh anonymous credential: 32 bytes of CSPRNG output. */
export function generateCredential(): Uint8Array {
  // 256 bits. This is the value the vote-casting layer will present later, so
  // it must be unguessable: anyone who can predict it can impersonate a voter.
  return randomBytes(32);
}

/**
 * Blind a credential so the issuer can sign it without seeing it.
 *
 * Steps (RFC 9474 section 4.1):
 *   1. encoded = EMSA-PSS-ENCODE(msg, bitLen(n) - 1)
 *   2. m = OS2IP(encoded); reject if m >= n
 *   3. r <- uniform in [1, n), invertible mod n
 *   4. blinded = m * r^e mod n
 */
export async function blind(
  publicKey: BlindRsaPublicKey,
  message: Uint8Array,
  options: { getRandomBytes?: (n: number) => Uint8Array } = {},
): Promise<BlindResult> {
  const getRandomBytes = options.getRandomBytes ?? randomBytes;
  const modulusBits = bitLength(publicKey.n);
  if (modulusBits < MIN_MODULUS_BITS) {
    throw new BlindRsaError(`blind: modulus is ${modulusBits} bits, minimum is ${MIN_MODULUS_BITS}`);
  }
  const modulusBytes = Math.ceil(modulusBits / 8);

  const encoded = await emsaPssEncode(message, modulusBits - 1, {
    hash: publicKey.suite.hash,
    saltLength: publicKey.suite.saltLength,
  });
  const m = os2ip(encoded);
  if (m >= publicKey.n) {
    throw new BlindRsaError("blind: encoded message is not less than the modulus");
  }

  // Draw r until it is invertible. For an RSA modulus a non-invertible r means
  // we stumbled onto a factor of n, which is astronomically unlikely -- but if
  // it did happen, silently continuing would produce a broken unblinding.
  let r: bigint;
  let rInv: bigint;
  for (;;) {
    r = randomBigIntBelow(publicKey.n, getRandomBytes);
    try {
      rInv = modInverse(r, publicKey.n);
      break;
    } catch {
      continue;
    }
  }

  const blinded = (m * modPow(r, publicKey.e, publicKey.n)) % publicKey.n;

  return {
    blindedMessage: i2osp(blinded, modulusBytes),
    inverse: i2osp(rInv, modulusBytes),
  };
}

/**
 * Unblind the issuer's response and check the result is a real signature.
 *
 * sig = blindSig * r^-1 mod n
 *
 * The verification at the end is NOT optional and NOT redundant. It is what
 * protects the voter from a malicious issuer that returns garbage: without it,
 * the voter would walk away holding an invalid credential and only discover it
 * when their ballot is rejected -- by which point they have already spent their
 * one issuance and are silently disenfranchised. Failing loudly here means the
 * voter can retry (see the idempotent-retry path in the registration service).
 */
export async function finalize(
  publicKey: BlindRsaPublicKey,
  message: Uint8Array,
  blindSignature: Uint8Array,
  inverse: Uint8Array,
): Promise<Uint8Array> {
  const modulusBits = bitLength(publicKey.n);
  const modulusBytes = Math.ceil(modulusBits / 8);

  if (blindSignature.length !== modulusBytes) {
    throw new BlindRsaError("finalize: blind signature has the wrong length");
  }

  const z = os2ip(blindSignature);
  if (z >= publicKey.n) {
    throw new BlindRsaError("finalize: blind signature is not less than the modulus");
  }

  const s = (z * os2ip(inverse)) % publicKey.n;
  const signature = i2osp(s, modulusBytes);

  const ok = await verify(publicKey, message, signature);
  if (!ok) {
    throw new BlindRsaError(
      "finalize: issuer returned an invalid signature (wrong key, or a malicious/faulty issuer)",
    );
  }
  return signature;
}

/**
 * RSASSA-PSS-VERIFY. Public operation -- anyone can run it, which is what makes
 * the credential publicly checkable by the ballot box and by external auditors.
 */
export async function verify(
  publicKey: BlindRsaPublicKey,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const modulusBits = bitLength(publicKey.n);
  const modulusBytes = Math.ceil(modulusBits / 8);
  if (signature.length !== modulusBytes) return false;

  const s = os2ip(signature);
  if (s >= publicKey.n) return false;

  const m = modPow(s, publicKey.e, publicKey.n);
  const emBits = modulusBits - 1;
  let encoded: Uint8Array;
  try {
    encoded = i2osp(m, Math.ceil(emBits / 8));
  } catch {
    return false;
  }

  return emsaPssVerify(message, encoded, emBits, {
    hash: publicKey.suite.hash,
    saltLength: publicKey.suite.saltLength,
  });
}
