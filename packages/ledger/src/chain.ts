/**
 * Chain validation and the append-only ledger.
 *
 * WHAT THE CHAIN ACTUALLY BUYS. It does NOT provide ballot secrecy or ballot
 * integrity -- those come from the cryptographic protocol in @dvoting/crypto.
 * What it provides is TAMPER EVIDENCE: because every header commits to its
 * predecessor's hash, altering or removing any recorded ballot changes every
 * subsequent hash, and the altered chain no longer carries valid validator
 * signatures. An insider with full database access can destroy the ledger, but
 * cannot silently rewrite it -- and "cannot do it silently" is the entire point.
 *
 * This is deliberately NOT open-mining consensus. There is no anonymous
 * hashrate to out-compete, so there is no 51% attack surface; instead a fixed
 * set of named, accountable authorities must attest to each block.
 */

import { constantTimeEqual } from "@dvoting/crypto";

import {
  ZERO_HASH,
  blockHash,
  computeEntriesRoot,
  encodeEntry,
  verifyAttestation,
  type Block,
  type LedgerEntry,
} from "./block.ts";
import { merkleProof, type MerkleProof } from "./merkle.ts";
import { findValidator, proposerForHeight, type ValidatorSet } from "./validator.ts";

export class ChainError extends Error {
  override name = "ChainError";
}

export interface BlockValidationResult {
  readonly valid: boolean;
  readonly errors: readonly string[];
}

/**
 * Validate a block against its predecessor and the validator set.
 *
 * Every rule here is a specific attack being closed, not a formality.
 */
export async function validateBlock(
  block: Block,
  previous: Block | null,
  validatorSet: ValidatorSet,
  options: { expectedElectionId?: string; maxClockSkewMs?: number } = {},
): Promise<BlockValidationResult> {
  const errors: string[] = [];
  const { header } = block;

  // --- Structure -----------------------------------------------------------
  if (!Number.isInteger(header.height) || header.height < 0) {
    errors.push("height must be a non-negative integer");
  }
  if (header.entryCount !== block.entries.length) {
    errors.push(`entryCount ${header.entryCount} does not match ${block.entries.length} entries`);
  }
  if (options.expectedElectionId && header.electionId !== options.expectedElectionId) {
    errors.push(`block belongs to election "${header.electionId}"`);
  }

  // Entry ids must be unique within the block. Duplicates would let the same
  // ballot be counted twice from a single block.
  const ids = block.entries.map((entry) => entry.id);
  if (new Set(ids).size !== ids.length) {
    errors.push("block contains duplicate entry ids");
  }

  // --- Linkage -------------------------------------------------------------
  if (previous === null) {
    if (header.height !== 0) errors.push("first block must be at height 0");
    if (!constantTimeEqual(header.previousHash, ZERO_HASH)) {
      errors.push("genesis block must reference the zero hash");
    }
  } else {
    if (header.height !== previous.header.height + 1) {
      errors.push(`height ${header.height} does not follow ${previous.header.height}`);
    }
    const expectedPrevious = await blockHash(previous.header);
    if (!constantTimeEqual(header.previousHash, expectedPrevious)) {
      // THE tamper-evidence check: any edit to an earlier block breaks this.
      errors.push("previousHash does not match the preceding block");
    }
    if (header.timestamp < previous.header.timestamp) {
      errors.push("timestamp moves backwards");
    }
  }

  const skew = options.maxClockSkewMs ?? 0;
  if (skew > 0 && header.timestamp > Date.now() + skew) {
    errors.push("timestamp is too far in the future");
  }

  // --- Commitment ----------------------------------------------------------
  const expectedRoot = await computeEntriesRoot(block.entries);
  if (!constantTimeEqual(header.merkleRoot, expectedRoot)) {
    // Catches entries being added, removed or reordered after signing.
    errors.push("merkleRoot does not match the block's entries");
  }

  // --- Authority -----------------------------------------------------------
  // The view is bounded by the validator count: after n-1 views every validator
  // has had a turn, so a larger view proves nothing and would let a caller pick
  // any proposer it liked by inflating the number.
  if (!Number.isInteger(header.view) || header.view < 0) {
    errors.push("view must be a non-negative integer");
  } else if (header.view >= validatorSet.validators.length) {
    errors.push(
      `view ${header.view} is out of range for ${validatorSet.validators.length} validators`,
    );
  } else {
    const scheduled = proposerForHeight(validatorSet, header.height, header.view);
    if (header.proposer !== scheduled.id) {
      errors.push(
        `proposer "${header.proposer}" is not scheduled for height ${header.height} ` +
          `view ${header.view} (that is ${scheduled.id})`,
      );
    }
  }

  const attestors = block.attestations.map((a) => a.validator);
  if (new Set(attestors).size !== attestors.length) {
    // Without this, one validator could sign repeatedly to fake a quorum.
    errors.push("duplicate attestations from the same validator");
  }
  if (!attestors.includes(header.proposer)) {
    errors.push("the proposer has not signed its own block");
  }

  let validAttestations = 0;
  for (const attestation of block.attestations) {
    const validator = findValidator(validatorSet, attestation.validator);
    if (!validator) {
      errors.push(`attestation from unknown validator "${attestation.validator}"`);
      continue;
    }
    if (await verifyAttestation(header, attestation, validator)) {
      validAttestations++;
    } else {
      errors.push(`invalid signature from validator "${attestation.validator}"`);
    }
  }

  if (validAttestations < validatorSet.quorum) {
    errors.push(
      `only ${validAttestations} valid attestations, quorum is ${validatorSet.quorum}`,
    );
  }

  return { valid: errors.length === 0, errors };
}

export interface ChainVerificationReport {
  readonly valid: boolean;
  readonly blockCount: number;
  readonly entryCount: number;
  readonly errors: readonly string[];
}

/** Re-verify an entire chain from genesis. Any observer can run this. */
export async function verifyChain(
  blocks: readonly Block[],
  validatorSet: ValidatorSet,
  options: { expectedElectionId?: string } = {},
): Promise<ChainVerificationReport> {
  const errors: string[] = [];
  let entryCount = 0;
  const seenIds = new Set<string>();

  for (const [index, block] of blocks.entries()) {
    const previous = index === 0 ? null : blocks[index - 1]!;
    const result = await validateBlock(block, previous, validatorSet, options);
    for (const error of result.errors) {
      errors.push(`block ${block.header.height}: ${error}`);
    }

    // Entry ids must be unique across the WHOLE chain, not just per block --
    // otherwise a ballot could be replayed into a later block.
    for (const entry of block.entries) {
      const key = `${entry.kind}/${entry.id}`;
      if (seenIds.has(key)) {
        errors.push(`block ${block.header.height}: duplicate entry id "${key}" already in chain`);
      }
      seenIds.add(key);
      entryCount++;
    }
  }

  return { valid: errors.length === 0, blockCount: blocks.length, entryCount, errors };
}

/** Where a given entry lives, plus the proof that it is genuinely there. */
export interface EntryLocation {
  readonly blockHeight: number;
  readonly entryIndex: number;
  readonly entry: LedgerEntry;
  readonly proof: MerkleProof;
  readonly merkleRoot: Uint8Array;
}

export interface BlockStore {
  append(block: Block): Promise<void>;
  height(): Promise<number>;
  head(): Promise<Block | null>;
  getByHeight(height: number): Promise<Block | null>;
  all(): Promise<readonly Block[]>;
  findEntry(kind: string, id: string): Promise<{ block: Block; entryIndex: number } | null>;
  hasEntry(kind: string, id: string): Promise<boolean>;
}

/**
 * The ledger: validated, append-only, never rewritten.
 *
 * There is intentionally no update or delete. The only mutation is `append`,
 * and it refuses anything that does not validate.
 */
export class Ledger {
  readonly #store: BlockStore;
  readonly #validatorSet: ValidatorSet;
  readonly #electionId: string;

  constructor(store: BlockStore, validatorSet: ValidatorSet, electionId: string) {
    this.#store = store;
    this.#validatorSet = validatorSet;
    this.#electionId = electionId;
  }

  get validatorSet(): ValidatorSet {
    return this.#validatorSet;
  }

  get electionId(): string {
    return this.#electionId;
  }

  async append(block: Block): Promise<void> {
    const previous = await this.#store.head();
    const result = await validateBlock(block, previous, this.#validatorSet, {
      expectedElectionId: this.#electionId,
    });
    if (!result.valid) {
      throw new ChainError(`refusing to append invalid block: ${result.errors.join("; ")}`);
    }

    // Chain-wide entry uniqueness. Enforced here as well as in verifyChain so a
    // replayed ballot is rejected at write time, not merely detected later.
    for (const entry of block.entries) {
      if (await this.#store.hasEntry(entry.kind, entry.id)) {
        throw new ChainError(
          `refusing to append block: entry "${entry.kind}/${entry.id}" is already on the chain`,
        );
      }
    }

    await this.#store.append(block);
  }

  head(): Promise<Block | null> {
    return this.#store.head();
  }

  height(): Promise<number> {
    return this.#store.height();
  }

  getBlock(height: number): Promise<Block | null> {
    return this.#store.getByHeight(height);
  }

  blocks(): Promise<readonly Block[]> {
    return this.#store.all();
  }

  hasEntry(kind: string, id: string): Promise<boolean> {
    return this.#store.hasEntry(kind, id);
  }

  /** Locate an entry and build its Merkle inclusion proof. */
  async locateEntry(kind: string, id: string): Promise<EntryLocation | null> {
    const found = await this.#store.findEntry(kind, id);
    if (!found) return null;

    const leaves = found.block.entries.map(encodeEntry);
    return {
      blockHeight: found.block.header.height,
      entryIndex: found.entryIndex,
      entry: found.block.entries[found.entryIndex]!,
      proof: await merkleProof(leaves, found.entryIndex),
      merkleRoot: found.block.header.merkleRoot,
    };
  }

  /** Re-verify everything from genesis. */
  async verify(): Promise<ChainVerificationReport> {
    return verifyChain(await this.#store.all(), this.#validatorSet, {
      expectedElectionId: this.#electionId,
    });
  }

  /** Next height's scheduled proposer. */
  async nextProposer(): Promise<string> {
    const height = await this.#store.height();
    return proposerForHeight(this.#validatorSet, height).id;
  }
}
