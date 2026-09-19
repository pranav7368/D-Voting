/**
 * The decryption ceremony.
 *
 * ===========================================================================
 * WHY THE COUNT IS NOT A BUTTON.
 *
 * This is the moment the election is decided, and it is deliberately the one
 * moment no single party can perform. The ballot box holds no key share and
 * never will; the administrator has no button for it. The result appears only
 * when `threshold` independent trustees each apply their own share, on their
 * own machine, and prove they did it honestly.
 *
 * What this file does is therefore narrow and entirely public:
 *
 *   1. publish the encrypted per-candidate totals computed from the chain;
 *   2. accept partial decryptions and CHECK EACH PROOF against the trustee's
 *      public share, which was sealed into the election record before voting
 *      opened;
 *   3. once enough valid partials exist, combine them and seal the result.
 *
 * Every input is public and every step is recomputable by an observer. Nothing
 * here is secret, which is precisely why it can live on the ballot box.
 *
 * AUTHENTICATION IS THE PROOF. There is no token on the submission endpoint,
 * and that is not an oversight: only the holder of share i can produce a
 * Chaum-Pedersen proof that verifies against public share i. A bearer token
 * would add a secret to steal without adding a guarantee -- forging a share
 * would still require breaking the discrete logarithm, and possessing the token
 * would still not let you submit anything that verifies.
 * ===========================================================================
 */

import {
  combinePartialDecryptions,
  createDiscreteLogTable,
  encodeElement,
  fromBase64Url,
  os2ip,
  toBase64Url,
  verifyPartialDecryption,
  type Ciphertext,
  type PartialDecryption,
  type TrusteePublicShare,
} from "@dvoting/crypto";

import { BallotBox } from "./ballot-box.ts";
import { tallyFromChain, type TallyInput } from "./chain-tally.ts";
import {
  buildPublishedTally,
  encodeTally,
  readPublishedTally,
} from "./tally-publication.ts";
import {
  partialDecryptionFromWire,
  WireError,
  type WireCiphertext,
  type WirePartialDecryption,
} from "./wire.ts";

export class CeremonyError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
  override name = "CeremonyError";
}

export interface CeremonyStatus {
  readonly phase: "not-ready" | "awaiting-trustees" | "published";
  readonly threshold: number;
  readonly total: number;
  /** Trustee indices whose partial decryptions have been accepted. */
  readonly submitted: readonly number[];
  readonly outstanding: number;
  readonly candidates: readonly string[];
  readonly ballotsCounted: number;
  readonly ballotsSuperseded: number;
  /** The ciphertexts each trustee must decrypt. Empty until voting has closed. */
  readonly encryptedTotals: readonly WireCiphertext[];
  readonly message: string;
}

export interface ShareSubmission {
  readonly index: number;
  /** One partial decryption per candidate, in ballot order. */
  readonly partials: readonly WirePartialDecryption[];
}

export interface SubmissionResult {
  readonly accepted: true;
  readonly index: number;
  readonly submitted: readonly number[];
  readonly outstanding: number;
  /** Set when this submission was the one that reached the threshold. */
  readonly published: boolean;
}

/**
 * Collects trustee decryption shares and publishes the result at threshold.
 *
 * Submitted shares are held in memory. If the service restarts mid-ceremony the
 * trustees who had already submitted simply submit again: a partial decryption
 * is deterministic evidence, not a one-shot action, and re-deriving one costs a
 * trustee a few seconds. Persisting them would mean storing, on the ballot box,
 * a growing set of values whose only purpose is to be published in the tally
 * moments later anyway.
 */
export class DecryptionCeremony {
  readonly #ballotBox: BallotBox;
  /** trustee index -> one verified partial decryption per candidate. */
  readonly #shares = new Map<number, PartialDecryption[]>();
  #tally: TallyInput | null = null;
  /** Serialises submissions so two arrivals cannot both trigger publication. */
  #chain: Promise<unknown> = Promise.resolve();

  constructor(ballotBox: BallotBox) {
    this.#ballotBox = ballotBox;
  }

  /** Roster public shares, decoded once, keyed by trustee index. */
  #roster(): Map<number, TrusteePublicShare> {
    const map = new Map<number, TrusteePublicShare>();
    for (const share of this.#ballotBox.trustees.publicShares) {
      map.set(share.index, {
        index: share.index,
        publicShare: os2ip(fromBase64Url(share.publicShare)),
      });
    }
    return map;
  }

  /**
   * The encrypted totals, computed from the chain and then frozen.
   *
   * Cached because every trustee must decrypt exactly the same ciphertexts: if
   * two trustees were served totals computed at different moments, their
   * partials would not combine, and the failure would look like a bad proof
   * rather than a moving target. The election is closed by this point, so the
   * chain cannot change underneath the cache.
   */
  async #totals(): Promise<TallyInput> {
    if (this.#tally) return this.#tally;
    const tally = await tallyFromChain(
      this.#ballotBox.ledger,
      this.#ballotBox.election,
      this.#ballotBox.electionPublicKey,
    );
    if (tally.rejected.length > 0) {
      throw new CeremonyError(
        "chain_invalid",
        `${tally.rejected.length} ballot(s) on the chain fail verification; refusing to tally.`,
      );
    }
    this.#tally = tally;
    return tally;
  }

  async status(): Promise<CeremonyStatus> {
    const { threshold, total } = this.#ballotBox.trustees;
    const candidates = this.#ballotBox.election.candidates;
    const published = await readPublishedTally(
      this.#ballotBox.ledger,
      this.#ballotBox.election.electionId,
    );
    const submitted = [...this.#shares.keys()].sort((a, b) => a - b);

    if (published) {
      return {
        phase: "published",
        threshold,
        total,
        submitted,
        outstanding: 0,
        candidates,
        ballotsCounted: published.countedBallotIds.length,
        ballotsSuperseded: published.supersededBallotIds.length,
        encryptedTotals: published.encryptedTotals,
        message: "The result is on the chain and can be recounted by anyone.",
      };
    }

    if (this.#ballotBox.phase !== "closed") {
      return {
        phase: "not-ready",
        threshold,
        total,
        submitted: [],
        outstanding: threshold,
        candidates,
        ballotsCounted: 0,
        ballotsSuperseded: 0,
        encryptedTotals: [],
        message: "Voting has not closed. No totals exist to decrypt.",
      };
    }

    const tally = await this.#totals();
    const group = this.#ballotBox.electionPublicKey.group;

    return {
      phase: "awaiting-trustees",
      threshold,
      total,
      submitted,
      outstanding: Math.max(threshold - submitted.length, 0),
      candidates,
      ballotsCounted: tally.counted.length,
      ballotsSuperseded: tally.superseded.length,
      encryptedTotals: tally.encryptedTotals.map((ct) => ({
        alpha: toBase64Url(encodeElement(group, ct.alpha)),
        beta: toBase64Url(encodeElement(group, ct.beta)),
      })),
      message: `${submitted.length} of ${threshold} required trustees have submitted.`,
    };
  }

  /** Accept one trustee's partial decryptions, publishing if that reaches the threshold. */
  async submit(submission: ShareSubmission): Promise<SubmissionResult> {
    const run = this.#chain.then(
      () => this.#submit(submission),
      () => this.#submit(submission),
    );
    // Keep the queue alive regardless of this submission's outcome, so one
    // rejected trustee cannot wedge the ceremony for everybody else.
    this.#chain = run.catch(() => undefined);
    return run;
  }

  async #submit(submission: ShareSubmission): Promise<SubmissionResult> {
    if (this.#ballotBox.phase !== "closed") {
      throw new CeremonyError(
        "election_open",
        "Voting has not closed. Decryption cannot begin while ballots are still being accepted.",
      );
    }
    if (
      await readPublishedTally(this.#ballotBox.ledger, this.#ballotBox.election.electionId)
    ) {
      throw new CeremonyError("already_published", "The result has already been published.");
    }

    const roster = this.#roster();
    const publicShare = roster.get(submission.index);
    if (!publicShare) {
      throw new CeremonyError(
        "unknown_trustee",
        `Trustee ${submission.index} is not part of this election's roster.`,
      );
    }
    if (this.#shares.has(submission.index)) {
      throw new CeremonyError(
        "already_submitted",
        `Trustee ${submission.index} has already submitted a decryption share.`,
      );
    }

    const tally = await this.#totals();
    const group = this.#ballotBox.electionPublicKey.group;
    const candidates = this.#ballotBox.election.candidates;

    if (submission.partials.length !== candidates.length) {
      throw new CeremonyError(
        "wrong_shape",
        `Expected one partial decryption per candidate (${candidates.length}), received ${submission.partials.length}.`,
      );
    }

    const verified: PartialDecryption[] = [];
    for (const [index, wire] of submission.partials.entries()) {
      let partial: PartialDecryption;
      try {
        partial = partialDecryptionFromWire(group, wire);
      } catch (error) {
        throw new CeremonyError(
          "malformed_share",
          error instanceof WireError ? error.message : "Malformed partial decryption.",
        );
      }
      if (partial.index !== submission.index) {
        throw new CeremonyError(
          "index_mismatch",
          "A partial decryption is labelled with a different trustee index.",
        );
      }

      const ok = await verifyPartialDecryption(
        group,
        this.#ballotBox.election.electionId,
        publicShare,
        tally.encryptedTotals[index]!,
        partial,
      );
      if (!ok) {
        // Attributable by construction: the proof is bound to this trustee's
        // published share, so a bad submission names its own author.
        throw new CeremonyError(
          "invalid_proof",
          `The decryption proof for "${candidates[index]}" does not verify against trustee ${submission.index}'s published share.`,
        );
      }
      verified.push(partial);
    }

    this.#shares.set(submission.index, verified);

    const submitted = [...this.#shares.keys()].sort((a, b) => a - b);
    const { threshold } = this.#ballotBox.trustees;
    let published = false;
    if (submitted.length >= threshold) {
      await this.#publish(tally, roster);
      published = true;
    }

    return {
      accepted: true,
      index: submission.index,
      submitted,
      outstanding: Math.max(threshold - submitted.length, 0),
      published,
    };
  }

  /** Combine the partials, decrypt each total, and seal the result on the chain. */
  async #publish(tally: TallyInput, roster: Map<number, TrusteePublicShare>): Promise<void> {
    const group = this.#ballotBox.electionPublicKey.group;
    const election = this.#ballotBox.election;
    const { threshold } = this.#ballotBox.trustees;

    // A fixed, ordered set of contributors: Lagrange coefficients depend on
    // which indices participate, so the set has to be decided before combining.
    const contributors = [...this.#shares.keys()].sort((a, b) => a - b).slice(0, threshold);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (let candidate = 0; candidate < election.candidates.length; candidate++) {
      partialsByCandidate.push(
        contributors.map((index) => this.#shares.get(index)![candidate]!),
      );
    }

    const dlog = createDiscreteLogTable(group, Math.max(tally.counted.length, 1));
    const results: { candidate: string; votes: number }[] = [];

    for (const [index, candidate] of election.candidates.entries()) {
      const element = combinePartialDecryptions(
        group,
        tally.encryptedTotals[index] as Ciphertext,
        partialsByCandidate[index]!,
        threshold,
      );
      let votes: number;
      try {
        votes = dlog.solve(element);
      } catch {
        throw new CeremonyError(
          "decryption_failed",
          `The total for "${candidate}" did not decrypt to a valid count.`,
        );
      }
      results.push({ candidate, votes });
    }

    const published = buildPublishedTally({
      election,
      publicKey: this.#ballotBox.electionPublicKey,
      threshold,
      countedBallotIds: tally.counted.map((item) => item.ballot.ballotId),
      supersededBallotIds: tally.superseded.map((item) => item.ballot.ballotId),
      encryptedTotals: tally.encryptedTotals,
      partialsByCandidate,
      // Only the contributing trustees' shares, so a verifier checks exactly the
      // set that produced the result.
      publicShares: contributors.map((index) => roster.get(index)!),
      results,
    });

    await this.#ballotBox.publishTally({ encode: () => encodeTally(published) });
    await this.#ballotBox.recordAdminAction(
      "ceremony.published",
      `trustees ${contributors.join(", ")} decrypted ${tally.counted.length} ballots`,
    );
  }
}
