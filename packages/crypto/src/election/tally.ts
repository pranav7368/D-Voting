/**
 * Homomorphic tallying and threshold decryption of the result.
 *
 * The count never decrypts an individual ballot. Ciphertexts are multiplied
 * together per candidate, which adds the underlying votes, and only the
 * resulting aggregate is handed to the trustees. Even a full compromise of the
 * tally server therefore yields nothing but ciphertexts.
 */

import type { Ciphertext, ElGamalPublicKey } from "../elgamal/cipher.ts";
import { addCiphertexts } from "../elgamal/cipher.ts";
import { createDiscreteLogTable } from "../elgamal/dlog.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";
import {
  combinePartialDecryptions,
  verifyPartialDecryption,
  type PartialDecryption,
  type TrusteePublicShare,
} from "../threshold/trustee.ts";
import type { EncryptedBallot } from "./ballot.ts";

export class TallyError extends Error {
  override name = "TallyError";
}

/**
 * Sum ballots per candidate.
 *
 * Callers MUST verify each ballot (and its credential) before including it:
 * homomorphic addition is blind, so an invalid ballot would be folded into the
 * total just as happily as a valid one.
 */
export function homomorphicTally(
  group: PrimeOrderGroup,
  candidateCount: number,
  ballots: readonly EncryptedBallot[],
): Ciphertext[] {
  const totals: Ciphertext[] = [];
  for (let index = 0; index < candidateCount; index++) {
    const column: Ciphertext[] = [];
    for (const ballot of ballots) {
      const choice = ballot.choices[index];
      if (!choice) {
        throw new TallyError(`ballot ${ballot.ballotId} is missing a ciphertext for candidate ${index}`);
      }
      column.push(choice);
    }
    // Summing an empty column yields (1, 1) = Enc(0), the correct identity.
    totals.push(addCiphertexts(group, column));
  }
  return totals;
}

export interface CandidateResult {
  readonly candidate: string;
  readonly votes: number;
}

export interface TallyResult {
  readonly results: readonly CandidateResult[];
  readonly ballotsCounted: number;
}

/**
 * Decrypt the aggregate using verified partial decryptions.
 *
 * `partialsByCandidate[i]` holds the partial decryptions for candidate i's
 * aggregate ciphertext. Every partial is verified against the trustee's
 * published public share before use -- an unverified partial can silently
 * change the outcome, and there is no later opportunity to catch it.
 */
export async function decryptTally(
  group: PrimeOrderGroup,
  electionId: string,
  candidates: readonly string[],
  encryptedTotals: readonly Ciphertext[],
  partialsByCandidate: readonly (readonly PartialDecryption[])[],
  publicShares: readonly TrusteePublicShare[],
  threshold: number,
  ballotsCounted: number,
): Promise<TallyResult> {
  if (encryptedTotals.length !== candidates.length) {
    throw new TallyError("decryptTally: totals do not match the candidate list");
  }
  if (partialsByCandidate.length !== candidates.length) {
    throw new TallyError("decryptTally: partial decryptions do not match the candidate list");
  }

  const shareByIndex = new Map(publicShares.map((share) => [share.index, share]));

  // One baby-step table, reused across candidates. A vote total can never
  // exceed the number of ballots counted.
  const dlog = createDiscreteLogTable(group, Math.max(ballotsCounted, 1));

  const results: CandidateResult[] = [];
  for (const [index, candidate] of candidates.entries()) {
    const ciphertext = encryptedTotals[index]!;
    const partials = partialsByCandidate[index]!;

    const verified: PartialDecryption[] = [];
    for (const partial of partials) {
      const publicShare = shareByIndex.get(partial.index);
      if (!publicShare) {
        throw new TallyError(
          `decryptTally: partial from unknown trustee ${partial.index} for "${candidate}"`,
        );
      }
      const ok = await verifyPartialDecryption(group, electionId, publicShare, ciphertext, partial);
      if (!ok) {
        throw new TallyError(
          `decryptTally: trustee ${partial.index} submitted an invalid partial decryption ` +
            `for "${candidate}" -- the tally is not trustworthy and this trustee is at fault`,
        );
      }
      verified.push(partial);
    }

    if (verified.length < threshold) {
      throw new TallyError(
        `decryptTally: only ${verified.length} valid partials for "${candidate}", ` +
          `threshold is ${threshold}`,
      );
    }

    const plaintextElement = combinePartialDecryptions(group, ciphertext, verified, threshold);
    results.push({ candidate, votes: dlog.solve(plaintextElement) });
  }

  return { results, ballotsCounted };
}
