/**
 * Validator nodes: independent authorities that each hold ONLY their own key.
 *
 * ===========================================================================
 * WHY THIS MATTERS.
 *
 * A quorum rule is worthless if one process holds every validator's signing
 * key. "3 of 4 authorities attested this block" means nothing when a single
 * machine produced all four signatures -- compromise it and you forge the whole
 * quorum. Independent authorities have to actually be independent.
 *
 * A ValidatorNode therefore:
 *   - holds exactly one signing key, its own;
 *   - keeps its OWN replica of the chain, so it validates against what it has
 *     independently accepted rather than trusting the proposer's view;
 *   - INDEPENDENTLY re-validates every block before signing, including
 *     re-verifying the entries;
 *   - refuses to sign two different blocks at the same height.
 *
 * That last rule is the important one. A validator that signs whatever it is
 * handed adds no security at all -- it is a rubber stamp with extra steps.
 *
 * ===========================================================================
 * EQUIVOCATION.
 *
 * If a validator could be induced to attest two DIFFERENT blocks at the same
 * height, an attacker could assemble two conflicting quorums and fork the
 * chain -- showing one version of the election to some observers and a
 * different one to others. Nothing in the block format prevents this; it has to
 * be enforced by the signer.
 *
 * Each node therefore records what it has attested at each height and refuses
 * anything that conflicts. This is the same safety condition that
 * proof-of-stake systems enforce by slashing; here the validators are named and
 * accountable, so the refusal (and any attempt that provoked it) is
 * attributable evidence of misbehaviour.
 */

import { toBase64Url } from "@dvoting/crypto";

import {
  attest,
  blockHash,
  proposeBlock,
  withAttestations,
  type Attestation,
  type Block,
  type LedgerEntry,
} from "./block.ts";
import { Ledger, validateBlock } from "./chain.ts";
import { proposerForHeight, type CryptoKeyLike, type ValidatorIdentity } from "./validator.ts";

export class ValidatorNodeError extends Error {
  override name = "ValidatorNodeError";
}

export interface AttestationRefusal {
  readonly refused: true;
  readonly validator: string;
  readonly reason: string;
  /**
   * Set when the refusal is purely because this node is behind, and carries the
   * height it has reached.
   *
   * This distinction matters. Without it, a node that misses one commit refuses
   * every subsequent block forever — its height never advances, so it can never
   * agree with anyone again. One dropped packet would permanently remove a
   * validator from the set. Reporting *why* it refused turns an unrecoverable
   * failure into a recoverable one.
   */
  readonly behindAt?: number;
}

export type AttestationResponse =
  | { readonly refused: false; readonly attestation: Attestation }
  | AttestationRefusal;

/**
 * Application-level check on a single ledger entry.
 *
 * The ledger itself only knows about bytes. This hook is where a validator
 * plugs in domain rules -- for D-Voting, re-verifying every ballot's credential
 * and zero-knowledge proofs. Without it a dishonest proposer could stuff
 * invalid ballots into a block and the other validators would sign it happily.
 */
export type EntryValidator = (entry: LedgerEntry) => Promise<{ ok: boolean; reason?: string }>;

export interface ProposeRequest {
  readonly height: number;
  readonly electionId: string;
  readonly entries: readonly LedgerEntry[];
  readonly timestamp?: number;
  /** View (round) number. Non-zero means an earlier proposer failed. */
  readonly view?: number;
}

export interface ValidatorNodeOptions {
  readonly identity: ValidatorIdentity;
  readonly privateKey: CryptoKeyLike;
  /** This node's own replica of the chain. */
  readonly ledger: Ledger;
  readonly validateEntry?: EntryValidator;
}

export class ValidatorNode {
  readonly identity: ValidatorIdentity;
  readonly #privateKey: CryptoKeyLike;
  readonly #ledger: Ledger;
  readonly #validateEntry: EntryValidator | undefined;
  /** height -> hash of the block this node has already attested there. */
  readonly #attested = new Map<number, string>();

  constructor(options: ValidatorNodeOptions) {
    this.identity = options.identity;
    this.#privateKey = options.privateKey;
    this.#ledger = options.ledger;
    this.#validateEntry = options.validateEntry;
  }

  get ledger(): Ledger {
    return this.#ledger;
  }

  height(): Promise<number> {
    return this.#ledger.height();
  }

  /**
   * Build and sign a block. Only valid when this node is the scheduled proposer.
   */
  async propose(request: ProposeRequest): Promise<Block> {
    const view = request.view ?? 0;
    const validatorCount = this.#ledger.validatorSet.validators.length;
    if (!Number.isInteger(view) || view < 0 || view >= validatorCount) {
      throw new ValidatorNodeError(
        `view ${view} is out of range for ${validatorCount} validators`,
      );
    }

    const scheduled = proposerForHeight(this.#ledger.validatorSet, request.height, view);
    if (scheduled.id !== this.identity.id) {
      throw new ValidatorNodeError(
        `${this.identity.id} is not the scheduled proposer for height ${request.height} ` +
          `view ${view} (that is ${scheduled.id})`,
      );
    }

    const localHeight = await this.#ledger.height();
    if (request.height !== localHeight) {
      throw new ValidatorNodeError(
        `${this.identity.id} is at height ${localHeight}, cannot propose height ${request.height}`,
      );
    }

    const head = await this.#ledger.head();
    const previousHash = head
      ? await blockHash(head.header)
      : (await import("./block.ts")).ZERO_HASH;

    const block = await proposeBlock({
      height: request.height,
      electionId: request.electionId,
      previousHash,
      entries: request.entries,
      proposer: this.identity,
      signingKey: this.#privateKey,
      view,
      ...(request.timestamp !== undefined ? { timestamp: request.timestamp } : {}),
    });

    this.#attested.set(request.height, toBase64Url(await blockHash(block.header)));
    return block;
  }

  /**
   * Independently validate a proposed block and, if it holds up, attest to it.
   *
   * Everything here is checked against THIS node's own replica. A proposer
   * cannot talk a validator into signing by asserting a chain state the
   * validator has not itself accepted.
   */
  async attest(block: Block): Promise<AttestationResponse> {
    const refuse = (reason: string): AttestationRefusal => ({
      refused: true,
      validator: this.identity.id,
      reason,
    });

    // --- equivocation guard, before anything else --------------------------
    const hash = toBase64Url(await blockHash(block.header));
    const already = this.#attested.get(block.header.height);
    if (already !== undefined && already !== hash) {
      return refuse(
        `already attested a different block at height ${block.header.height} ` +
          "-- refusing to equivocate",
      );
    }
    if (already === hash) {
      // Idempotent: re-attesting the same block is safe and lets a proposer
      // retry after a dropped response.
      return {
        refused: false,
        attestation: await attest(block, this.identity, this.#privateKey),
      };
    }

    // --- must extend THIS node's chain -------------------------------------
    const localHeight = await this.#ledger.height();
    if (block.header.height > localHeight) {
      // Recoverable: this node has simply missed some blocks. Say so, so the
      // caller can replay them rather than writing this validator off.
      return {
        refused: true,
        validator: this.identity.id,
        reason: `block is at height ${block.header.height} but this node is at ${localHeight}`,
        behindAt: localHeight,
      };
    }
    if (block.header.height < localHeight) {
      return refuse(
        `block is at height ${block.header.height} but this node has already reached ${localHeight}`,
      );
    }

    const previous = await this.#ledger.head();
    const structural = await validateBlock(block, previous, this.#ledger.validatorSet, {
      expectedElectionId: this.#ledger.electionId,
    });
    if (!structural.valid) {
      // Quorum is not yet met at attestation time, so a shortfall is expected
      // and is not grounds for refusal -- every other rule is.
      const fatal = structural.errors.filter((error) => !error.includes("quorum is"));
      if (fatal.length > 0) return refuse(fatal.join("; "));
    }

    // --- entry-level rules --------------------------------------------------
    if (this.#validateEntry) {
      for (const entry of block.entries) {
        const result = await this.#validateEntry(entry);
        if (!result.ok) {
          return refuse(`entry "${entry.kind}/${entry.id}" rejected: ${result.reason ?? "invalid"}`);
        }
      }
    }

    // Chain-wide entry uniqueness, against this node's own view.
    for (const entry of block.entries) {
      if (await this.#ledger.hasEntry(entry.kind, entry.id)) {
        return refuse(`entry "${entry.kind}/${entry.id}" is already on this node's chain`);
      }
    }

    this.#attested.set(block.header.height, hash);
    return { refused: false, attestation: await attest(block, this.identity, this.#privateKey) };
  }

  /** Append a fully-attested block to this node's replica. */
  async commit(block: Block): Promise<void> {
    const localHeight = await this.#ledger.height();
    if (block.header.height < localHeight) return; // already have it
    await this.#ledger.append(block);
  }
}

/** Transport-agnostic handle to a validator, local or remote. */
export interface ValidatorPeer {
  readonly id: string;
  propose(request: ProposeRequest): Promise<Block>;
  requestAttestation(block: Block): Promise<AttestationResponse>;
  commit(block: Block): Promise<void>;
  /**
   * Current chain height, when the transport can report it.
   *
   * Optional because a transport may not expose it, but implementing it lets a
   * lagging peer be resynchronised precisely instead of by replaying the whole
   * chain.
   */
  height?(): Promise<number>;
}

/**
 * In-process peer.
 *
 * Still a genuine separation: each LocalValidatorPeer wraps a ValidatorNode
 * holding exactly one key and its own ledger replica. Useful for tests and for
 * running the whole system on one machine without pretending the keys are
 * shared.
 */
export class LocalValidatorPeer implements ValidatorPeer {
  readonly id: string;
  readonly #node: ValidatorNode;

  constructor(node: ValidatorNode) {
    this.id = node.identity.id;
    this.#node = node;
  }

  get node(): ValidatorNode {
    return this.#node;
  }

  propose(request: ProposeRequest): Promise<Block> {
    return this.#node.propose(request);
  }

  requestAttestation(block: Block): Promise<AttestationResponse> {
    return this.#node.attest(block);
  }

  commit(block: Block): Promise<void> {
    return this.#node.commit(block);
  }

  height(): Promise<number> {
    return this.#node.height();
  }
}

export interface QuorumResult {
  readonly block: Block;
  readonly refusals: readonly AttestationRefusal[];
}

export interface QuorumAttempt extends QuorumResult {
  readonly reached: boolean;
  readonly attestations: number;
}

/**
 * Gather attestations without failing when the quorum is short.
 *
 * Returns what it managed to collect plus every refusal, so a caller can act on
 * the reasons — notably by catching up validators that reported themselves
 * behind — and try again.
 */
export async function tryCollectQuorum(
  block: Block,
  peers: readonly ValidatorPeer[],
  quorum: number,
): Promise<QuorumAttempt> {
  const refusals: AttestationRefusal[] = [];
  const collected: Attestation[] = [...block.attestations];
  const have = new Set(collected.map((a) => a.validator));

  for (const peer of peers) {
    if (have.size >= quorum) break;
    if (have.has(peer.id)) continue;

    let response: AttestationResponse;
    try {
      response = await peer.requestAttestation(block);
    } catch (error) {
      refusals.push({
        refused: true,
        validator: peer.id,
        reason: `unreachable: ${error instanceof Error ? error.message : String(error)}`,
      });
      continue;
    }

    if (response.refused) {
      refusals.push(response);
      continue;
    }
    collected.push(response.attestation);
    have.add(peer.id);
  }

  return {
    reached: have.size >= quorum,
    attestations: have.size,
    block: withAttestations(block, collected),
    refusals,
  };
}

/**
 * Gather attestations from peers until quorum is reached.
 *
 * Peers are polled sequentially and collection stops as soon as the quorum is
 * met, so a healthy network does not pay for unnecessary round trips. A peer
 * that refuses or is unreachable is recorded and skipped -- that is precisely
 * the fault tolerance the quorum exists to provide.
 */
export async function collectQuorum(
  block: Block,
  peers: readonly ValidatorPeer[],
  quorum: number,
): Promise<QuorumResult> {
  const attempt = await tryCollectQuorum(block, peers, quorum);
  if (!attempt.reached) {
    const detail = attempt.refusals.map((r) => `${r.validator}: ${r.reason}`).join("; ");
    throw new ValidatorNodeError(
      `failed to reach quorum: ${attempt.attestations}/${quorum} attestations` +
        (detail ? ` (${detail})` : ""),
    );
  }
  return { block: attempt.block, refusals: attempt.refusals };
}
