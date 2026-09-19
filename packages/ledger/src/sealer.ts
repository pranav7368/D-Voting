/**
 * Block sealing strategies.
 *
 * The ballot box needs blocks sealed; it should not care whether the validators
 * are four processes on one laptop or four organisations on three continents.
 * This port keeps that decision out of the application layer.
 */

import { ZERO_HASH, blockHash, proposeBlock, type Block, type LedgerEntry } from "./block.ts";
import type { Ledger } from "./chain.ts";
import {
  ValidatorNodeError,
  collectQuorum,
  tryCollectQuorum,
  type ValidatorPeer,
} from "./node.ts";
import { attest, withAttestations } from "./block.ts";
import { proposerForHeight, type ValidatorKeyPair } from "./validator.ts";

export interface SealRequest {
  readonly height: number;
  readonly electionId: string;
  readonly previousHash: Uint8Array;
  readonly entries: readonly LedgerEntry[];
}

export interface BlockSealer {
  seal(request: SealRequest): Promise<Block>;
  /** Called once the block is durably appended locally, to replicate it. */
  broadcastCommit?(block: Block): Promise<void>;
}

/**
 * Single-process sealer: one process holds every validator key.
 *
 * DEMO AND TEST ONLY, and it is worth being blunt about why. A quorum produced
 * entirely inside one process proves nothing -- compromise that process and you
 * forge all four signatures. It exists so the system can be exercised on one
 * machine without a network; it must never be the production topology.
 */
export class SingleProcessSealer implements BlockSealer {
  readonly #validatorKeys: readonly ValidatorKeyPair[];
  readonly #ledger: Ledger;

  constructor(ledger: Ledger, validatorKeys: readonly ValidatorKeyPair[]) {
    this.#ledger = ledger;
    this.#validatorKeys = validatorKeys;
  }

  async seal(request: SealRequest): Promise<Block> {
    const scheduled = proposerForHeight(this.#ledger.validatorSet, request.height);
    const proposer = this.#validatorKeys.find((k) => k.identity.id === scheduled.id);
    if (!proposer) {
      throw new ValidatorNodeError(
        `no signing key for scheduled proposer "${scheduled.id}"`,
      );
    }

    let block = await proposeBlock({
      height: request.height,
      electionId: request.electionId,
      previousHash: request.previousHash,
      entries: request.entries,
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });

    const quorum = this.#ledger.validatorSet.quorum;
    const attestations = [...block.attestations];
    for (const validator of this.#validatorKeys) {
      if (attestations.length >= quorum) break;
      if (validator.identity.id === proposer.identity.id) continue;
      attestations.push(await attest(block, validator.identity, validator.privateKey));
    }
    block = withAttestations(block, attestations);
    return block;
  }
}

/**
 * Distributed sealer: the real topology.
 *
 * The scheduled proposer -- which may be a remote node -- builds and signs the
 * block; the other validators each independently re-validate it against their
 * own chain replica before attesting. No single party can produce a quorum.
 */
export class DistributedSealer implements BlockSealer {
  readonly #peers: readonly ValidatorPeer[];
  readonly #ledger: Ledger;

  constructor(ledger: Ledger, peers: readonly ValidatorPeer[]) {
    if (peers.length === 0) throw new ValidatorNodeError("DistributedSealer: no peers configured");
    this.#ledger = ledger;
    this.#peers = peers;
  }

  /**
   * Seal a block, advancing the view if the scheduled proposer cannot serve.
   *
   * ---------------------------------------------------------------------
   * WHY ADVANCING THE VIEW IS SAFE.
   *
   * The worry with proposer failover is a fork: two different blocks both
   * reaching quorum at one height, showing different election records to
   * different observers. Two properties rule that out.
   *
   *   1. QUORUM INTERSECTION. The quorum is a >2/3 supermajority, so any two
   *      quorums share more than n/3 validators -- they cannot be disjoint.
   *   2. NO EQUIVOCATION. A validator refuses to attest a second, different
   *      block at a height it has already attested.
   *
   * Together: for two conflicting blocks to reach quorum, at least one
   * validator would have had to sign both, which rule 2 forbids. So the chain
   * cannot fork no matter how the views are advanced.
   *
   * The cost of rule 2 is that a view change only helps when the failed
   * proposer produced NO block -- which is exactly the unreachable-proposer
   * case this solves. If a proposer produced a block but quorum was not
   * gathered, the right move is to retry that same block (validators
   * re-attest it idempotently), not to advance the view.
   * ---------------------------------------------------------------------
   */
  async seal(request: SealRequest): Promise<Block> {
    const validatorCount = this.#ledger.validatorSet.validators.length;
    const failures: string[] = [];

    for (let view = 0; view < validatorCount; view++) {
      const scheduled = proposerForHeight(this.#ledger.validatorSet, request.height, view);
      const proposer = this.#peers.find((peer) => peer.id === scheduled.id);
      if (!proposer) {
        failures.push(`view ${view}: proposer "${scheduled.id}" is not configured`);
        continue;
      }

      // The proposer may itself be lagging; resynchronise before asking.
      try {
        await this.#syncPeer(proposer);
      } catch {
        // Non-fatal: propose below will fail and the view will advance.
      }

      let proposed: Block;
      try {
        proposed = await proposer.propose({
          height: request.height,
          electionId: request.electionId,
          entries: request.entries,
          view,
        });
      } catch (error) {
        // No block was produced, so no validator can have attested one at this
        // view. Advancing is safe.
        failures.push(
          `view ${view}: ${scheduled.id} could not propose ` +
            `(${error instanceof Error ? error.message : String(error)})`,
        );
        continue;
      }

      return this.#gatherQuorum(proposed, proposer);
    }

    throw new ValidatorNodeError(
      `no validator could propose at height ${request.height} after ${validatorCount} view(s): ` +
        failures.join("; "),
    );
  }

  async #gatherQuorum(proposed: Block, proposer: ValidatorPeer): Promise<Block> {
    const others = this.#peers.filter((peer) => peer.id !== proposer.id);
    const quorum = this.#ledger.validatorSet.quorum;

    const attempt = await tryCollectQuorum(proposed, others, quorum);
    if (attempt.reached) return attempt.block;

    // Some validators may have refused simply because they missed earlier
    // blocks. Replay what they are missing and try again, rather than treating a
    // recoverable gap as a failed election.
    const behind = attempt.refusals.filter((refusal) => refusal.behindAt !== undefined);
    if (behind.length === 0) {
      const detail = attempt.refusals.map((r) => `${r.validator}: ${r.reason}`).join("; ");
      throw new ValidatorNodeError(
        `failed to reach quorum: ${attempt.attestations}/${quorum} attestations` +
          (detail ? ` (${detail})` : ""),
      );
    }

    for (const refusal of behind) {
      const peer = this.#peers.find((candidate) => candidate.id === refusal.validator);
      if (peer) await this.#catchUp(peer, refusal.behindAt!);
    }

    const { block } = await collectQuorum(proposed, others, quorum);
    return block;
  }

  /**
   * Bring a peer up to this node's height, discovering where it is first.
   *
   * Called before proposing and after a failed commit. Without it, a validator
   * that misses blocks only recovers if it happens to be polled for an
   * attestation — and since polling stops as soon as quorum is met, the ones
   * beyond the quorum would drift further behind indefinitely, silently
   * shrinking the effective validator set until a single failure stalls the
   * election.
   */
  async #syncPeer(peer: ValidatorPeer): Promise<void> {
    if (!peer.height) return;
    let peerHeight: number;
    try {
      peerHeight = await peer.height();
    } catch {
      return; // unreachable; the quorum rule covers it
    }
    const localHeight = await this.#ledger.height();
    if (peerHeight >= localHeight) return;
    await this.#catchUp(peer, peerHeight);
  }

  /**
   * Replay committed blocks to a lagging validator.
   *
   * Safe to do from an untrusted coordinator: `commit` runs full validation, so
   * a node cannot be fed a bogus chain — it simply rejects anything that does
   * not verify against its own validator set.
   */
  async #catchUp(peer: ValidatorPeer, fromHeight: number): Promise<void> {
    const localHeight = await this.#ledger.height();
    for (let height = fromHeight; height < localHeight; height++) {
      const block = await this.#ledger.getBlock(height);
      if (!block) break;
      try {
        await peer.commit(block);
      } catch {
        // Already has it, or unreachable again. The quorum rule decides the
        // outcome either way.
        break;
      }
    }
  }

  /**
   * Replicate a committed block to every peer.
   *
   * Failures are tolerated: a node that misses a block is behind, not broken,
   * and will refuse to attest until it catches up -- which is the correct,
   * visible behaviour rather than a silent divergence.
   */
  async broadcastCommit(block: Block): Promise<void> {
    for (const peer of this.#peers) {
      try {
        await peer.commit(block);
      } catch {
        // A commit usually fails because the peer is missing earlier blocks, so
        // this one does not link. Resynchronise rather than leaving it stranded:
        // replication is where a lagging node is most cheaply repaired.
        try {
          await this.#syncPeer(peer);
        } catch {
          // Still unreachable. Tolerated by design — that is what the quorum is
          // for — and it will be resynchronised on a later round.
        }
      }
    }
  }
}

/** Convenience: compute the previous hash for the next block on a ledger. */
export async function nextSealRequest(
  ledger: Ledger,
  electionId: string,
  entries: readonly LedgerEntry[],
): Promise<SealRequest> {
  const head = await ledger.head();
  return {
    height: await ledger.height(),
    electionId,
    previousHash: head ? await blockHash(head.header) : ZERO_HASH,
    entries,
  };
}
