/**
 * Shamir secret sharing over the scalar field Z_q.
 *
 * Splits the election private key into n shares such that any k of them
 * reconstruct it and any k-1 reveal NOTHING -- not "a little", not "a weakened
 * version", but nothing at all in the information-theoretic sense. With k-1
 * shares, every possible secret remains exactly equally likely, because there
 * is exactly one degree-(k-1) polynomial through those k-1 points for each
 * candidate secret.
 *
 * That is the property that makes "no single party can decrypt the result"
 * a mathematical fact rather than an access-control policy.
 *
 * The sharing lives in Z_q (q = the prime subgroup order), which is a field
 * because q is prime -- Lagrange interpolation needs division, so a prime
 * modulus is essential. Doing this mod a composite would break reconstruction
 * whenever a denominator shared a factor with the modulus.
 */

import { modInverse } from "../util/bigint.ts";
import { randomBytes } from "../util/bytes.ts";
import { randomScalar, scalarAdd, scalarMul, scalarSub } from "../elgamal/group.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";

export interface Share {
  /** Evaluation point, 1-based. Index 0 is never issued: f(0) IS the secret. */
  readonly index: number;
  readonly value: bigint;
}

export class ShamirError extends Error {
  override name = "ShamirError";
}

export interface SplitResult {
  readonly shares: readonly Share[];
  /**
   * Polynomial coefficients a_0..a_{k-1}, with a_0 = the secret.
   *
   * Returned so the dealer can publish Feldman VSS commitments g^{a_j}. They
   * are as sensitive as the secret itself and must be discarded immediately
   * after the commitments are computed.
   */
  readonly coefficients: readonly bigint[];
}

/**
 * Split `secret` into `total` shares, `threshold` of which reconstruct it.
 *
 * Builds a random polynomial f(X) = secret + a_1 X + ... + a_{k-1} X^{k-1} over
 * Z_q and hands out f(1), f(2), ..., f(n).
 */
export function splitSecret(
  group: PrimeOrderGroup,
  secret: bigint,
  threshold: number,
  total: number,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): SplitResult {
  if (!Number.isInteger(threshold) || !Number.isInteger(total)) {
    throw new ShamirError("splitSecret: threshold and total must be integers");
  }
  if (threshold < 1) throw new ShamirError("splitSecret: threshold must be at least 1");
  if (total < threshold) {
    throw new ShamirError("splitSecret: total shares must be at least the threshold");
  }
  if (secret < 0n || secret >= group.q) {
    throw new ShamirError("splitSecret: secret is out of range for this group");
  }

  const coefficients: bigint[] = [secret];
  for (let j = 1; j < threshold; j++) {
    coefficients.push(randomScalar(group, getRandomBytes));
  }

  const shares: Share[] = [];
  for (let index = 1; index <= total; index++) {
    shares.push({ index, value: evaluatePolynomial(group, coefficients, BigInt(index)) });
  }

  return { shares, coefficients };
}

/** Horner evaluation of f(x) mod q. */
export function evaluatePolynomial(
  group: PrimeOrderGroup,
  coefficients: readonly bigint[],
  x: bigint,
): bigint {
  let result = 0n;
  for (let j = coefficients.length - 1; j >= 0; j--) {
    result = scalarAdd(group, scalarMul(group, result, x), coefficients[j]!);
  }
  return result;
}

/**
 * Lagrange basis coefficient at X = 0 for share `index`, given the participating
 * index set.
 *
 *     lambda_i = product over j != i of  x_j / (x_j - x_i)   (mod q)
 *
 * These depend on WHICH shares turn up, which is why they must be recomputed
 * per decryption rather than baked in at setup.
 */
export function lagrangeCoefficient(
  group: PrimeOrderGroup,
  indices: readonly number[],
  index: number,
): bigint {
  if (!indices.includes(index)) {
    throw new ShamirError("lagrangeCoefficient: index is not in the participating set");
  }

  let numerator = 1n;
  let denominator = 1n;
  const xi = BigInt(index);

  for (const other of indices) {
    if (other === index) continue;
    const xj = BigInt(other);
    numerator = scalarMul(group, numerator, xj);
    denominator = scalarMul(group, denominator, scalarSub(group, xj, xi));
  }

  if (denominator === 0n) {
    throw new ShamirError("lagrangeCoefficient: duplicate share indices");
  }
  return scalarMul(group, numerator, modInverse(denominator, group.q));
}

/** Reconstruct the secret from at least `threshold` distinct shares. */
export function reconstructSecret(
  group: PrimeOrderGroup,
  shares: readonly Share[],
): bigint {
  if (shares.length === 0) throw new ShamirError("reconstructSecret: no shares supplied");

  const indices = shares.map((share) => share.index);
  if (new Set(indices).size !== indices.length) {
    throw new ShamirError("reconstructSecret: duplicate share indices");
  }
  if (indices.some((index) => index < 1)) {
    throw new ShamirError("reconstructSecret: share indices must be >= 1");
  }

  let secret = 0n;
  for (const share of shares) {
    const lambda = lagrangeCoefficient(group, indices, share.index);
    secret = scalarAdd(group, secret, scalarMul(group, lambda, share.value));
  }
  return secret;
}
