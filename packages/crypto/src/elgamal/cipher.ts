/**
 * Exponential ElGamal: the additively homomorphic encryption that makes
 * tallying-without-decrypting possible.
 *
 * THE KEY IDEA. Standard ElGamal encrypts a message m directly as
 * (g^r, m * y^r), which is multiplicatively homomorphic. That is the wrong
 * homomorphism for voting -- we want to ADD votes. So we encrypt g^m instead
 * of m:
 *
 *     Enc(m) = (g^r, g^m * y^r)
 *
 * Now multiplying two ciphertexts adds the plaintexts:
 *
 *     Enc(m1) * Enc(m2) = (g^(r1+r2), g^(m1+m2) * y^(r1+r2)) = Enc(m1 + m2)
 *
 * So the entire election can be summed while every individual ballot stays
 * encrypted. Only the final aggregate is ever decrypted, and even that requires
 * a threshold of trustees to cooperate.
 *
 * THE PRICE. Decryption recovers g^m, not m -- so m must be recovered by
 * solving a discrete logarithm. That is only feasible because m is small: it is
 * a vote count, bounded by the electorate size. See dlog.ts.
 */

import {
  assertInSubgroup,
  groupExp,
  groupExpFixed,
  groupInv,
  groupMul,
  randomScalar,
  GroupError,
} from "./group.ts";
import type { PrimeOrderGroup } from "./group.ts";
import { randomBytes } from "../util/bytes.ts";

export interface ElGamalPublicKey {
  readonly group: PrimeOrderGroup;
  /** y = g^x, where x is the (possibly threshold-shared) private key. */
  readonly y: bigint;
}

export interface ElGamalKeyPair {
  readonly publicKey: ElGamalPublicKey;
  /** The private key. In a threshold election no single party ever holds this. */
  readonly x: bigint;
}

export interface Ciphertext {
  /** alpha = g^r */
  readonly alpha: bigint;
  /** beta = g^m * y^r */
  readonly beta: bigint;
}

export class ElGamalError extends Error {
  override name = "ElGamalError";
}

export function generateKeyPair(
  group: PrimeOrderGroup,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): ElGamalKeyPair {
  const x = randomScalar(group, getRandomBytes);
  return { publicKey: { group, y: groupExp(group, group.g, x) }, x };
}

/**
 * Combine trustee public keys into the election's joint public key.
 *
 * y = product of y_i = g^(sum of x_i)
 *
 * The corresponding private key is the SUM of the trustees' private keys, so it
 * exists only notionally -- no party ever computes or holds it. Encrypting to
 * this joint key is what makes the election undecryptable without cooperation.
 */
export function combinePublicKeys(keys: readonly ElGamalPublicKey[]): ElGamalPublicKey {
  if (keys.length === 0) throw new ElGamalError("combinePublicKeys: no keys supplied");
  const group = keys[0]!.group;
  let y = 1n;
  for (const key of keys) {
    if (key.group.p !== group.p) {
      throw new ElGamalError("combinePublicKeys: keys are from different groups");
    }
    assertInSubgroup(group, key.y, "trustee public key");
    y = groupMul(group, y, key.y);
  }
  return { group, y };
}

/**
 * Encrypt a small non-negative integer.
 *
 * The randomness is returned because the caller needs it as the witness for the
 * ballot-validity zero-knowledge proof. It must be discarded immediately after
 * the proof is built: anyone holding r can decrypt the ballot without the
 * private key, since g^m = beta / y^r.
 */
export function encrypt(
  publicKey: ElGamalPublicKey,
  message: bigint,
  options: { randomness?: bigint; getRandomBytes?: (n: number) => Uint8Array } = {},
): { ciphertext: Ciphertext; randomness: bigint } {
  const { group, y } = publicKey;
  if (message < 0n) throw new ElGamalError("encrypt: message must be non-negative");

  const randomness = options.randomness ?? randomScalar(group, options.getRandomBytes ?? randomBytes);
  if (randomness <= 0n || randomness >= group.q) {
    throw new ElGamalError("encrypt: randomness out of range");
  }

  return {
    ciphertext: {
      alpha: groupExpFixed(group, group.g, randomness),
      // g^message uses a tiny exponent (0 or 1 for a ballot), so the generic
      // path is already optimal there; y^randomness is the hot one.
      beta: groupMul(group, groupExp(group, group.g, message), groupExpFixed(group, y, randomness)),
    },
    randomness,
  };
}

/** Homomorphic addition: Enc(a) + Enc(b) = Enc(a + b). */
export function addCiphertexts(
  group: PrimeOrderGroup,
  ciphertexts: readonly Ciphertext[],
): Ciphertext {
  let alpha = 1n;
  let beta = 1n;
  for (const ct of ciphertexts) {
    alpha = groupMul(group, alpha, ct.alpha);
    beta = groupMul(group, beta, ct.beta);
  }
  return { alpha, beta };
}

/** Subtract a known plaintext offset: turns Enc(m) into Enc(m - offset). */
export function subtractPlaintext(
  group: PrimeOrderGroup,
  ciphertext: Ciphertext,
  offset: bigint,
): Ciphertext {
  return {
    alpha: ciphertext.alpha,
    beta: groupMul(group, ciphertext.beta, groupInv(group, groupExp(group, group.g, offset))),
  };
}

/**
 * Single-authority decryption to the group element g^m.
 *
 * Present for testing and for single-trustee demos. A real election uses the
 * threshold path (see threshold/), where this private key never exists.
 */
export function decryptToGroupElement(
  group: PrimeOrderGroup,
  privateKey: bigint,
  ciphertext: Ciphertext,
): bigint {
  assertValidCiphertext(group, ciphertext);
  const shared = groupExp(group, ciphertext.alpha, privateKey);
  return groupMul(group, ciphertext.beta, groupInv(group, shared));
}

/**
 * Re-randomize a ciphertext without changing its plaintext.
 *
 * Enc(m; r) -> Enc(m; r + r'). Used by mixnets, and useful for demonstrating
 * ElGamal's malleability -- which is precisely why ballot proofs must be bound
 * to a context (see zkp/), or an attacker could re-randomize and replay someone
 * else's ballot as their own.
 */
export function reRandomize(
  publicKey: ElGamalPublicKey,
  ciphertext: Ciphertext,
  options: { randomness?: bigint; getRandomBytes?: (n: number) => Uint8Array } = {},
): { ciphertext: Ciphertext; randomness: bigint } {
  const { group, y } = publicKey;
  const randomness =
    options.randomness ?? randomScalar(group, options.getRandomBytes ?? randomBytes);
  return {
    ciphertext: {
      alpha: groupMul(group, ciphertext.alpha, groupExp(group, group.g, randomness)),
      beta: groupMul(group, ciphertext.beta, groupExp(group, y, randomness)),
    },
    randomness,
  };
}

/**
 * Validate a ciphertext arriving from an untrusted source.
 *
 * Both components must lie in the prime-order subgroup. Without this check an
 * attacker can submit a small-order element and use the resulting partial
 * decryptions as an oracle for the trustees' secret key -- a small-subgroup
 * confinement attack.
 */
export function assertValidCiphertext(group: PrimeOrderGroup, ciphertext: Ciphertext): void {
  try {
    assertInSubgroup(group, ciphertext.alpha, "ciphertext.alpha");
    assertInSubgroup(group, ciphertext.beta, "ciphertext.beta");
  } catch (error) {
    throw new ElGamalError(
      error instanceof GroupError ? error.message : "ciphertext failed subgroup validation",
    );
  }
}

export function ciphertextEquals(a: Ciphertext, b: Ciphertext): boolean {
  return a.alpha === b.alpha && a.beta === b.beta;
}
