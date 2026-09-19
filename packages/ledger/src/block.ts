/**
 * Block structure, canonical encoding and hashing.
 *
 * A block commits to its entries through a Merkle root rather than by including
 * them in the hash directly. That is what lets a voter verify their ballot was
 * recorded using only the signed header plus a logarithmic audit path, without
 * downloading the block -- let alone the chain.
 */

import { digest, toBase64Url } from "@dvoting/crypto";

import { Encoder, encode } from "./canonical.ts";
import { merkleProof, merkleRoot, type MerkleProof } from "./merkle.ts";
import {
  sign,
  verifySignature,
  type CryptoKeyLike,
  type ValidatorIdentity,
} from "./validator.ts";

export const HASH_BYTES = 32;
// Annotated (rather than inferred) so it stays assignable alongside the
// ArrayBufferLike-backed Uint8Arrays that WebCrypto returns.
export const ZERO_HASH: Uint8Array = new Uint8Array(HASH_BYTES);

export class BlockError extends Error {
  override name = "BlockError";
}

/**
 * One record in the ledger.
 *
 * `kind` discriminates record types; `id` must be unique across the whole chain
 * and is what the bulletin board indexes (a ballot tracking code, for instance).
 */
export interface LedgerEntry {
  readonly kind: string;
  readonly id: string;
  readonly data: Uint8Array;
}

export interface BlockHeader {
  readonly height: number;
  readonly electionId: string;
  /** Hash of the previous header. ZERO_HASH at genesis. */
  readonly previousHash: Uint8Array;
  readonly merkleRoot: Uint8Array;
  readonly entryCount: number;
  /** Milliseconds since epoch. */
  readonly timestamp: number;
  readonly proposer: string;
  /**
   * View (round) number for this height. 0 in the normal case.
   *
   * The proposer schedule is (height + view) mod n, so a non-zero view means an
   * earlier proposer failed to produce a block and the round advanced to a
   * replacement. Recording it in the signed header does two things: it lets
   * every validator agree on who was entitled to propose, and it leaves the
   * failover permanently visible on-chain — a chain full of view > 0 blocks is
   * itself evidence that an authority is not doing its job.
   */
  readonly view: number;
}

export interface Attestation {
  readonly validator: string;
  readonly signature: Uint8Array;
}

export interface Block {
  readonly header: BlockHeader;
  readonly entries: readonly LedgerEntry[];
  readonly attestations: readonly Attestation[];
}

/** Canonical encoding of an entry. This is the Merkle leaf payload. */
export function encodeEntry(entry: LedgerEntry): Uint8Array {
  return encode((e: Encoder) => {
    e.string(entry.kind);
    e.string(entry.id);
    e.bytes(entry.data);
  });
}

/** Canonical encoding of a header. This is what gets hashed and signed. */
export function encodeHeader(header: BlockHeader): Uint8Array {
  if (header.previousHash.length !== HASH_BYTES) {
    throw new BlockError("encodeHeader: previousHash must be 32 bytes");
  }
  if (header.merkleRoot.length !== HASH_BYTES) {
    throw new BlockError("encodeHeader: merkleRoot must be 32 bytes");
  }
  return encode((e: Encoder) => {
    // A version tag so a future format change can never be confused with this
    // one, even if every other field happens to match. Bumped to v2 when `view`
    // was added: a v1 header and a v2 header with view 0 must not hash alike.
    e.string("dvoting/block/v2");
    e.u64(header.height);
    e.string(header.electionId);
    e.fixed(header.previousHash, HASH_BYTES);
    e.fixed(header.merkleRoot, HASH_BYTES);
    e.u64(header.entryCount);
    e.u64(header.timestamp);
    e.string(header.proposer);
    e.u64(header.view);
  });
}

export async function blockHash(header: BlockHeader): Promise<Uint8Array> {
  return digest("SHA-256", encodeHeader(header));
}

export function blockHashHex(hash: Uint8Array): string {
  return toBase64Url(hash);
}

/** Recompute the Merkle root over a block's entries. */
export async function computeEntriesRoot(entries: readonly LedgerEntry[]): Promise<Uint8Array> {
  return merkleRoot(entries.map(encodeEntry));
}

/** Build an inclusion proof for one entry within its block. */
export async function buildEntryProof(
  entries: readonly LedgerEntry[],
  entryIndex: number,
): Promise<MerkleProof> {
  return merkleProof(entries.map(encodeEntry), entryIndex);
}

/**
 * Assemble and sign a block.
 *
 * The proposer's own signature is the first attestation; co-validators add
 * theirs via `attest`. A block is not valid until it carries a quorum.
 */
export async function proposeBlock(input: {
  height: number;
  electionId: string;
  previousHash: Uint8Array;
  entries: readonly LedgerEntry[];
  proposer: ValidatorIdentity;
  signingKey: CryptoKeyLike;
  timestamp?: number;
  view?: number;
}): Promise<Block> {
  const entries = [...input.entries];
  const header: BlockHeader = {
    height: input.height,
    electionId: input.electionId,
    previousHash: input.previousHash,
    merkleRoot: await computeEntriesRoot(entries),
    entryCount: entries.length,
    timestamp: input.timestamp ?? Date.now(),
    proposer: input.proposer.id,
    view: input.view ?? 0,
  };

  const signature = await sign(input.signingKey, encodeHeader(header));
  return {
    header,
    entries,
    attestations: [{ validator: input.proposer.id, signature }],
  };
}

/** Produce a co-signature over an existing block header. */
export async function attest(
  block: Block,
  validator: ValidatorIdentity,
  signingKey: CryptoKeyLike,
): Promise<Attestation> {
  return {
    validator: validator.id,
    signature: await sign(signingKey, encodeHeader(block.header)),
  };
}

export function withAttestations(
  block: Block,
  additional: readonly Attestation[],
): Block {
  const seen = new Set(block.attestations.map((a) => a.validator));
  const merged = [...block.attestations];
  for (const attestation of additional) {
    if (!seen.has(attestation.validator)) {
      merged.push(attestation);
      seen.add(attestation.validator);
    }
  }
  return { ...block, attestations: merged };
}

export async function verifyAttestation(
  header: BlockHeader,
  attestation: Attestation,
  validator: ValidatorIdentity,
): Promise<boolean> {
  return verifySignature(validator.publicKey, attestation.signature, encodeHeader(header));
}
