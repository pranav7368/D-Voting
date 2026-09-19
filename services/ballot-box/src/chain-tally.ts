/**
 * Tallying from the ledger.
 *
 * The tally is computed from what is ON THE CHAIN, not from an internal
 * database. That is the point: an observer who downloads the chain and runs
 * this same logic must arrive at the same encrypted totals, which is what makes
 * the result independently checkable rather than merely asserted.
 *
 * -------------------------------------------------------------------------
 * RE-VOTING AND COERCION -- read this before claiming coercion resistance.
 *
 * A voter may cast any number of ballots before the deadline; only the LAST one
 * counts. The intent is that someone under duress can comply, then quietly
 * re-vote in private later.
 *
 * This is coercion MITIGATION, not the coercion RESISTANCE of the academic
 * literature. Because ballots are grouped by credential fingerprint on a public
 * bulletin board, a coercer who watches the board can see that the credential
 * they coerced cast a later ballot -- they cannot see the new vote, but they can
 * see that one happened. Genuine coercion resistance requires fake credentials
 * that are indistinguishable from real ones (Juels-Catalano-Jakobsson, as
 * implemented in Civitas), which is substantially more complex and is not
 * implemented here.
 * -------------------------------------------------------------------------
 */

import {
  homomorphicTally,
  verifyBallot,
  type Ciphertext,
  type ElGamalPublicKey,
  type ElectionParameters,
  type EncryptedBallot,
} from "@dvoting/crypto";
import type { Block, Ledger } from "@dvoting/ledger";

import { BALLOT_ENTRY_KIND } from "./ballot-box.ts";
import { ballotFromWire, type WireBallot } from "./wire.ts";

export interface ChainBallot {
  readonly ballot: EncryptedBallot;
  readonly blockHeight: number;
  readonly positionInChain: number;
}

export interface TallyInput {
  /** Ballots that actually count: the last per credential. */
  readonly counted: readonly ChainBallot[];
  /** Ballots superseded by a later ballot from the same credential. */
  readonly superseded: readonly ChainBallot[];
  /** Ballots that failed re-verification. Should be empty on an honest chain. */
  readonly rejected: readonly { ballotId: string; reason: string }[];
  readonly encryptedTotals: readonly Ciphertext[];
}

/**
 * Read every ballot from the chain, re-verify it, apply the re-voting rule, and
 * produce the encrypted per-candidate totals.
 *
 * Re-verification is not redundant. The tally must not trust that the ballot
 * box verified correctly -- an observer running this has no reason to, and the
 * whole value of the bulletin board is that it can be checked independently.
 */
export async function tallyFromChain(
  ledger: Ledger,
  election: ElectionParameters,
  electionPublicKey: ElGamalPublicKey,
): Promise<TallyInput> {
  const blocks = await ledger.blocks();

  const parsed: ChainBallot[] = [];
  const rejected: { ballotId: string; reason: string }[] = [];
  let position = 0;

  for (const block of blocks as readonly Block[]) {
    for (const entry of block.entries) {
      if (entry.kind !== BALLOT_ENTRY_KIND) continue;

      let ballot: EncryptedBallot;
      try {
        const wire = JSON.parse(new TextDecoder().decode(entry.data)) as WireBallot;
        ballot = ballotFromWire(electionPublicKey.group, wire);
      } catch (error) {
        rejected.push({
          ballotId: entry.id,
          reason: `unparseable: ${error instanceof Error ? error.message : String(error)}`,
        });
        continue;
      }

      if (ballot.ballotId !== entry.id) {
        rejected.push({ ballotId: entry.id, reason: "ballot id does not match its ledger entry" });
        continue;
      }
      if (!(await verifyBallot(election, electionPublicKey, ballot))) {
        rejected.push({ ballotId: entry.id, reason: "failed zero-knowledge verification" });
        continue;
      }

      parsed.push({ ballot, blockHeight: block.header.height, positionInChain: position++ });
    }
  }

  // Only the last ballot per credential counts. Chain order is the canonical
  // ordering -- it is what every observer sees, and it cannot be rewritten.
  const latest = new Map<string, ChainBallot>();
  for (const item of parsed) {
    latest.set(item.ballot.credentialFingerprint, item);
  }

  const countedSet = new Set([...latest.values()].map((item) => item.positionInChain));
  const counted = parsed.filter((item) => countedSet.has(item.positionInChain));
  const superseded = parsed.filter((item) => !countedSet.has(item.positionInChain));

  const encryptedTotals = homomorphicTally(
    electionPublicKey.group,
    election.candidates.length,
    counted.map((item) => item.ballot),
  );

  return { counted, superseded, rejected, encryptedTotals };
}
