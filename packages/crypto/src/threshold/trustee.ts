/**
 * Threshold ElGamal decryption by k-of-n trustees.
 *
 * No party ever holds the election private key during the count. Each trustee
 * holds a Shamir share x_i, applies it to the ciphertext to produce a partial
 * decryption alpha^{x_i}, and proves in zero knowledge that they used the same
 * x_i they committed to at setup. Lagrange interpolation IN THE EXPONENT then
 * combines k partials into alpha^x without ever materialising x:
 *
 *     product over i of (alpha^{x_i})^{lambda_i} = alpha^{sum lambda_i x_i} = alpha^x
 *
 * and the plaintext follows as g^m = beta / alpha^x.
 *
 * WHY THE PROOF IS NOT OPTIONAL. A trustee who submits a random group element
 * instead of alpha^{x_i} corrupts the final tally. Because the tally is only
 * decrypted once, at the end, the corruption is indistinguishable from a
 * legitimate result -- there is nothing to compare it against. The
 * Chaum-Pedersen proof binds the partial decryption to the trustee's PUBLISHED
 * public share, so a bad partial is rejected immediately and attributable to
 * the trustee that produced it.
 *
 * ---------------------------------------------------------------------------
 * KNOWN LIMITATION -- state this plainly in the viva.
 *
 * Setup here is DEALER-BASED: one process generates the election key, splits it,
 * and is trusted to erase it. For the window of that setup, a single party knows
 * the private key.
 *
 * Feldman VSS commitments (published below) close half the gap: trustees can
 * verify their shares are mutually consistent, so a dealer cannot distribute
 * *bad* shares undetected. It does not close the other half: the dealer still
 * saw the key.
 *
 * The full fix is Pedersen distributed key generation, where trustees jointly
 * generate the key and no dealer ever exists. That is the Phase 2 upgrade; the
 * interfaces here are shaped so it can be substituted without changing the
 * decryption path.
 * ---------------------------------------------------------------------------
 */

import {
  assertInSubgroup,
  groupExp,
  groupInv,
  groupMul,
  randomScalar,
} from "../elgamal/group.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";
import type { Ciphertext, ElGamalPublicKey } from "../elgamal/cipher.ts";
import { randomBytes } from "../util/bytes.ts";
import { Transcript } from "../zkp/transcript.ts";
import {
  proveDlogEquality,
  verifyDlogEquality,
  type DlogEqualityProof,
} from "../zkp/dlog-equality.ts";
import { lagrangeCoefficient, splitSecret, type Share } from "./shamir.ts";

export class TrusteeError extends Error {
  override name = "TrusteeError";
}

/** A trustee's private key share. Must never leave the trustee's custody. */
export interface TrusteeKeyShare {
  readonly index: number;
  readonly share: bigint;
}

/** A trustee's published commitment to their share: h_i = g^{x_i}. */
export interface TrusteePublicShare {
  readonly index: number;
  readonly publicShare: bigint;
}

export interface TrusteeSetup {
  readonly group: PrimeOrderGroup;
  readonly threshold: number;
  readonly total: number;
  /** The election's joint public key. Ballots are encrypted to this. */
  readonly publicKey: ElGamalPublicKey;
  /** Private shares. In deployment these are delivered to trustees and erased here. */
  readonly keyShares: readonly TrusteeKeyShare[];
  readonly publicShares: readonly TrusteePublicShare[];
  /** Feldman VSS commitments C_j = g^{a_j}. C_0 equals the election public key. */
  readonly commitments: readonly bigint[];
}

/**
 * Generate an election key and split it across `total` trustees.
 *
 * SECURITY: the returned `keyShares` and the transient private key are the most
 * sensitive values in the system. A production ceremony performs this offline,
 * distributes shares to hardware tokens, and destroys the machine state.
 */
export function setupTrustees(
  group: PrimeOrderGroup,
  threshold: number,
  total: number,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): TrusteeSetup {
  if (threshold < 1 || threshold > total) {
    throw new TrusteeError("setupTrustees: require 1 <= threshold <= total");
  }

  const privateKey = randomScalar(group, getRandomBytes);
  const { shares, coefficients } = splitSecret(group, privateKey, threshold, total, getRandomBytes);

  // Feldman commitments. C_0 = g^{a_0} = g^x is exactly the election public key,
  // so publishing the commitments also publishes the key -- consistently.
  const commitments = coefficients.map((coefficient) => groupExp(group, group.g, coefficient));

  return {
    group,
    threshold,
    total,
    publicKey: { group, y: commitments[0]! },
    keyShares: shares.map((share) => ({ index: share.index, share: share.value })),
    publicShares: shares.map((share) => ({
      index: share.index,
      publicShare: groupExp(group, group.g, share.value),
    })),
    commitments,
  };
}

/**
 * Feldman VSS check: does this share lie on the committed polynomial?
 *
 *     g^{f(i)} == product over j of C_j^{i^j}
 *
 * Each trustee runs this on receipt. It detects a dealer handing out
 * inconsistent shares -- which would otherwise only surface at decryption time,
 * when the election is already over and the result already wrong.
 */
export function verifyShare(
  group: PrimeOrderGroup,
  index: number,
  share: bigint,
  commitments: readonly bigint[],
): boolean {
  if (index < 1) return false;
  try {
    for (const commitment of commitments) {
      assertInSubgroup(group, commitment, "commitment");
    }
  } catch {
    return false;
  }

  let expected = 1n;
  let power = 1n; // i^j mod q
  const i = BigInt(index);
  for (const commitment of commitments) {
    expected = groupMul(group, expected, groupExp(group, commitment, power));
    power = (power * i) % group.q;
  }

  return groupExp(group, group.g, share) === expected;
}

export interface PartialDecryption {
  readonly index: number;
  /** alpha^{x_i} */
  readonly factor: bigint;
  readonly proof: DlogEqualityProof;
}

function partialDecryptionTranscript(
  electionId: string,
  ciphertext: Ciphertext,
  group: PrimeOrderGroup,
  index: number,
): Transcript {
  return new Transcript("dvoting/partial-decryption/v1")
    .absorbString("electionId", electionId)
    .absorbNumber("trusteeIndex", index)
    .absorbElement(group, "alpha", ciphertext.alpha)
    .absorbElement(group, "beta", ciphertext.beta);
}

/**
 * Produce a partial decryption plus a proof it was computed with the committed
 * share.
 *
 * The proof is a Chaum-Pedersen equality of discrete logs:
 *     log_g(h_i) == log_alpha(factor)
 * i.e. "the exponent I just used is the same one I published at setup".
 */
export async function partialDecrypt(
  group: PrimeOrderGroup,
  electionId: string,
  keyShare: TrusteeKeyShare,
  ciphertext: Ciphertext,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): Promise<PartialDecryption> {
  assertInSubgroup(group, ciphertext.alpha, "ciphertext.alpha");
  assertInSubgroup(group, ciphertext.beta, "ciphertext.beta");

  const factor = groupExp(group, ciphertext.alpha, keyShare.share);
  const publicShare = groupExp(group, group.g, keyShare.share);

  const proof = await proveDlogEquality(
    { group, base1: group.g, base2: ciphertext.alpha, y1: publicShare, y2: factor },
    keyShare.share,
    partialDecryptionTranscript(electionId, ciphertext, group, keyShare.index),
    getRandomBytes,
  );

  return { index: keyShare.index, factor, proof };
}

export async function verifyPartialDecryption(
  group: PrimeOrderGroup,
  electionId: string,
  publicShare: TrusteePublicShare,
  ciphertext: Ciphertext,
  partial: PartialDecryption,
): Promise<boolean> {
  if (publicShare.index !== partial.index) return false;
  try {
    assertInSubgroup(group, partial.factor, "partial factor");
  } catch {
    return false;
  }

  return verifyDlogEquality(
    {
      group,
      base1: group.g,
      base2: ciphertext.alpha,
      y1: publicShare.publicShare,
      y2: partial.factor,
    },
    partial.proof,
    partialDecryptionTranscript(electionId, ciphertext, group, partial.index),
  );
}

/**
 * Combine k verified partial decryptions into the plaintext group element g^m.
 *
 * Lagrange interpolation is performed in the exponent, so the private key is
 * reconstructed only "inside" the exponentiation and never as a value any
 * process can read, log, or leak.
 */
export function combinePartialDecryptions(
  group: PrimeOrderGroup,
  ciphertext: Ciphertext,
  partials: readonly PartialDecryption[],
  threshold: number,
): bigint {
  if (partials.length < threshold) {
    throw new TrusteeError(
      `combinePartialDecryptions: ${partials.length} partials supplied, threshold is ${threshold}`,
    );
  }

  // Use exactly `threshold` partials: Lagrange coefficients depend on the
  // participating index set, so the set must be fixed before computing them.
  const used = partials.slice(0, threshold);
  const indices = used.map((partial) => partial.index);
  if (new Set(indices).size !== indices.length) {
    throw new TrusteeError("combinePartialDecryptions: duplicate trustee indices");
  }

  let sharedSecret = 1n;
  for (const partial of used) {
    const lambda = lagrangeCoefficient(group, indices, partial.index);
    sharedSecret = groupMul(group, sharedSecret, groupExp(group, partial.factor, lambda));
  }

  return groupMul(group, ciphertext.beta, groupInv(group, sharedSecret));
}

/** Reconstruct the public shares implied by the Feldman commitments. */
export function publicShareFromCommitments(
  group: PrimeOrderGroup,
  index: number,
  commitments: readonly bigint[],
): bigint {
  let expected = 1n;
  let power = 1n;
  const i = BigInt(index);
  for (const commitment of commitments) {
    expected = groupMul(group, expected, groupExp(group, commitment, power));
    power = (power * i) % group.q;
  }
  return expected;
}

export type { Share };
