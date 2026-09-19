/**
 * Publishing the result — and letting anyone recount it.
 *
 * ===========================================================================
 * THE GAP THIS CLOSES.
 *
 * Until now a voter could prove their ballot was RECORDED, but nobody could
 * check the COUNT. The tally was computed in memory and announced. An announced
 * result is exactly as trustworthy as the people announcing it, which is the
 * thing end-to-end verifiability is supposed to remove.
 *
 * So the result is sealed onto the chain as evidence, not as an assertion:
 * the encrypted per-candidate totals, every trustee's partial decryption WITH
 * its zero-knowledge proof, the trustees' public shares, and the plaintext
 * counts. That is everything needed to redo the count from scratch.
 *
 * `verifyPublishedTally` then does exactly that, from the chain alone:
 *
 *   1. re-reads every ballot and re-verifies its proofs;
 *   2. re-applies the re-voting rule and checks the published counted set;
 *   3. recomputes the homomorphic totals and checks they match;
 *   4. re-verifies each trustee's decryption proof;
 *   5. re-combines the partials and checks the announced numbers.
 *
 * An observer running this needs no secrets and no cooperation. If the numbers
 * were fabricated, step 3 or 5 fails.
 * ===========================================================================
 */

import {
  addCiphertexts,
  combinePartialDecryptions,
  createDiscreteLogTable,
  verifyPartialDecryption,
  type Ciphertext,
  type ElGamalPublicKey,
  type ElectionParameters,
  type PartialDecryption,
  type TrusteePublicShare,
} from "@dvoting/crypto";
import { encodeElement, os2ip, toBase64Url, fromBase64Url } from "@dvoting/crypto";
import type { Ledger } from "@dvoting/ledger";

import { tallyFromChain } from "./chain-tally.ts";
import {
  ciphertextToWire,
  partialDecryptionFromWire,
  partialDecryptionToWire,
  WireError,
  type WireCiphertext,
  type WirePartialDecryption,
} from "./wire.ts";

export { TALLY_ENTRY_KIND } from "./ballot-box.ts";
import { TALLY_ENTRY_KIND } from "./ballot-box.ts";

export class TallyPublicationError extends Error {
  override name = "TallyPublicationError";
}

export interface PublishedTally {
  readonly electionId: string;
  readonly candidates: readonly string[];
  readonly threshold: number;
  /** Ballot ids that were counted, in chain order. */
  readonly countedBallotIds: readonly string[];
  /** Ballot ids superseded by a later ballot from the same credential. */
  readonly supersededBallotIds: readonly string[];
  readonly encryptedTotals: readonly WireCiphertext[];
  /** One array of partial decryptions per candidate. */
  readonly partialDecryptions: readonly (readonly WirePartialDecryption[])[];
  readonly publicShares: readonly { index: number; publicShare: string }[];
  readonly results: readonly { candidate: string; votes: number }[];
}

export function encodeTally(tally: PublishedTally): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(tally));
}

export function buildPublishedTally(input: {
  election: ElectionParameters;
  publicKey: ElGamalPublicKey;
  threshold: number;
  countedBallotIds: readonly string[];
  supersededBallotIds: readonly string[];
  encryptedTotals: readonly Ciphertext[];
  partialsByCandidate: readonly (readonly PartialDecryption[])[];
  publicShares: readonly TrusteePublicShare[];
  results: readonly { candidate: string; votes: number }[];
}): PublishedTally {
  const { group } = input.publicKey;
  return {
    electionId: input.election.electionId,
    candidates: [...input.election.candidates],
    threshold: input.threshold,
    countedBallotIds: [...input.countedBallotIds],
    supersededBallotIds: [...input.supersededBallotIds],
    encryptedTotals: input.encryptedTotals.map((ct) => ciphertextToWire(group, ct)),
    partialDecryptions: input.partialsByCandidate.map((partials) =>
      partials.map((partial) => partialDecryptionToWire(group, partial)),
    ),
    publicShares: input.publicShares.map((share) => ({
      index: share.index,
      publicShare: toBase64Url(encodeElement(group, share.publicShare)),
    })),
    results: input.results.map((entry) => ({ candidate: entry.candidate, votes: entry.votes })),
  };
}

export interface TallyVerificationReport {
  readonly valid: boolean;
  readonly checks: readonly { label: string; ok: boolean; detail?: string }[];
  readonly recomputedResults?: readonly { candidate: string; votes: number }[];
}

/**
 * Independently recount the election from the chain.
 *
 * Takes NOTHING from the published tally on trust — every number in it is
 * recomputed and compared.
 */
export async function verifyPublishedTally(
  ledger: Ledger,
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  published: PublishedTally,
): Promise<TallyVerificationReport> {
  const { group } = publicKey;
  const checks: { label: string; ok: boolean; detail?: string }[] = [];
  const fail = (label: string, detail: string): TallyVerificationReport => {
    checks.push({ label, ok: false, detail });
    return { valid: false, checks };
  };

  if (published.electionId !== election.electionId) {
    return fail("Election identity", "the published tally is for a different election");
  }

  // --- 1 & 2. Re-read and re-verify every ballot, re-apply the re-voting rule.
  const recount = await tallyFromChain(ledger, election, publicKey);
  if (recount.rejected.length > 0) {
    return fail(
      "Every ballot on the chain verifies",
      `${recount.rejected.length} ballot(s) failed re-verification: ${recount.rejected
        .map((r) => r.ballotId)
        .join(", ")}`,
    );
  }
  checks.push({
    label: "Every ballot on the chain verifies",
    ok: true,
    detail: `${recount.counted.length} counted, ${recount.superseded.length} superseded`,
  });

  const recountedIds = recount.counted.map((item) => item.ballot.ballotId).sort();
  const publishedIds = [...published.countedBallotIds].sort();
  if (recountedIds.length !== publishedIds.length ||
      recountedIds.some((id, index) => id !== publishedIds[index])) {
    // Catches ballots dropped from, or smuggled into, the count.
    return fail(
      "Counted ballots match the published set",
      `chain yields ${recountedIds.length} counted ballots, tally claims ${publishedIds.length}`,
    );
  }
  checks.push({
    label: "Counted ballots match the published set",
    ok: true,
    detail: `${recountedIds.length} ballots`,
  });

  // --- 3. Recompute the homomorphic totals.
  let publishedTotals: Ciphertext[];
  try {
    publishedTotals = published.encryptedTotals.map((ct) => ({
      alpha: os2ip(fromBase64Url(ct.alpha)),
      beta: os2ip(fromBase64Url(ct.beta)),
    }));
  } catch {
    return fail("Encrypted totals are well formed", "could not decode the published totals");
  }

  if (publishedTotals.length !== election.candidates.length) {
    return fail("Encrypted totals are well formed", "wrong number of totals");
  }
  for (const [index, expected] of recount.encryptedTotals.entries()) {
    const actual = publishedTotals[index]!;
    if (actual.alpha !== expected.alpha || actual.beta !== expected.beta) {
      return fail(
        "Homomorphic totals recomputed",
        `total for "${election.candidates[index]}" does not match the sum of the counted ballots`,
      );
    }
  }
  checks.push({
    label: "Homomorphic totals recomputed",
    ok: true,
    detail: `${publishedTotals.length} candidate totals match`,
  });

  // --- 4. Re-verify every trustee's decryption proof.
  const publicShares: TrusteePublicShare[] = [];
  try {
    for (const share of published.publicShares) {
      publicShares.push({
        index: share.index,
        publicShare: os2ip(fromBase64Url(share.publicShare)),
      });
    }
  } catch {
    return fail("Trustee public shares are well formed", "could not decode the public shares");
  }
  const shareByIndex = new Map(publicShares.map((share) => [share.index, share]));

  if (published.partialDecryptions.length !== election.candidates.length) {
    return fail("Partial decryptions present", "wrong number of partial decryption sets");
  }

  const decodedPartials: PartialDecryption[][] = [];
  for (const [index, wirePartials] of published.partialDecryptions.entries()) {
    const candidate = election.candidates[index]!;
    const ciphertext = publishedTotals[index]!;

    let partials: PartialDecryption[];
    try {
      partials = wirePartials.map((partial) => partialDecryptionFromWire(group, partial));
    } catch (error) {
      return fail(
        "Trustee decryption proofs verify",
        `malformed partial for "${candidate}": ${
          error instanceof WireError ? error.message : String(error)
        }`,
      );
    }

    if (partials.length < published.threshold) {
      return fail(
        "Trustee decryption proofs verify",
        `only ${partials.length} partials for "${candidate}", threshold is ${published.threshold}`,
      );
    }

    for (const partial of partials) {
      const share = shareByIndex.get(partial.index);
      if (!share) {
        return fail(
          "Trustee decryption proofs verify",
          `partial from unpublished trustee ${partial.index} for "${candidate}"`,
        );
      }
      const ok = await verifyPartialDecryption(
        group,
        election.electionId,
        share,
        ciphertext,
        partial,
      );
      if (!ok) {
        // A trustee corrupting the tally is caught here, and attributably.
        return fail(
          "Trustee decryption proofs verify",
          `trustee ${partial.index} submitted an invalid decryption proof for "${candidate}"`,
        );
      }
    }
    decodedPartials.push(partials);
  }
  checks.push({
    label: "Trustee decryption proofs verify",
    ok: true,
    detail: `${published.threshold}-of-${publicShares.length} threshold satisfied for every candidate`,
  });

  // --- 5. Recombine and check the announced numbers.
  const dlog = createDiscreteLogTable(group, Math.max(recount.counted.length, 1));
  const recomputed: { candidate: string; votes: number }[] = [];

  for (const [index, candidate] of election.candidates.entries()) {
    const element = combinePartialDecryptions(
      group,
      publishedTotals[index]!,
      decodedPartials[index]!,
      published.threshold,
    );
    let votes: number;
    try {
      votes = dlog.solve(element);
    } catch {
      return fail("Announced result recomputed", `total for "${candidate}" does not decrypt`);
    }
    recomputed.push({ candidate, votes });
  }

  for (const [index, entry] of recomputed.entries()) {
    const claimed = published.results[index];
    if (!claimed || claimed.candidate !== entry.candidate || claimed.votes !== entry.votes) {
      // The announced numbers are not what the ballots actually add up to.
      return fail(
        "Announced result recomputed",
        `"${entry.candidate}": announced ${claimed?.votes ?? "nothing"}, recount gives ${entry.votes}`,
      );
    }
  }

  // Sanity: votes cast cannot exceed ballots counted.
  const totalVotes = recomputed.reduce((sum, entry) => sum + entry.votes, 0);
  if (totalVotes > recount.counted.length * election.maxSelections) {
    return fail(
      "Vote totals are plausible",
      `${totalVotes} votes from ${recount.counted.length} ballots exceeds the permitted maximum`,
    );
  }

  checks.push({
    label: "Announced result recomputed",
    ok: true,
    detail: recomputed.map((entry) => `${entry.candidate}: ${entry.votes}`).join(", "),
  });

  return { valid: true, checks, recomputedResults: recomputed };
}

/** Read the published tally back off the chain. */
export async function readPublishedTally(
  ledger: Ledger,
  electionId: string,
): Promise<PublishedTally | null> {
  const located = await ledger.locateEntry(TALLY_ENTRY_KIND, electionId);
  if (!located) return null;
  try {
    return JSON.parse(new TextDecoder().decode(located.entry.data)) as PublishedTally;
  } catch {
    throw new TallyPublicationError("the published tally on the chain is not valid JSON");
  }
}

/** Convenience for callers that already hold the ciphertexts. */
export function sumCiphertexts(
  publicKey: ElGamalPublicKey,
  ciphertexts: readonly Ciphertext[],
): Ciphertext {
  return addCiphertexts(publicKey.group, ciphertexts);
}
