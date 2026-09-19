/**
 * JSON wire format for blocks.
 *
 * Used only for TRANSPORT. It is never hashed — hashing goes through the
 * canonical binary encoder in canonical.ts, precisely because JSON is not a
 * deterministic serialisation. Keeping the two separate means a change to the
 * wire format can never silently change a block hash.
 *
 * Parsing is deliberately strict: every field is length- and type-checked
 * before a Block is constructed. A validator will re-validate everything anyway,
 * but malformed input should be rejected at the boundary rather than becoming a
 * confusing failure three layers in.
 */

import { fromBase64Url, toBase64Url } from "@dvoting/crypto";

import { HASH_BYTES, type Attestation, type Block, type BlockHeader, type LedgerEntry } from "./block.ts";
import { VALIDATOR_SIGNATURE_BYTES } from "./validator.ts";

export class WireFormatError extends Error {
  override name = "WireFormatError";
}

export interface WireBlockHeader {
  height: number;
  electionId: string;
  previousHash: string;
  merkleRoot: string;
  entryCount: number;
  timestamp: number;
  proposer: string;
  view: number;
}

export interface WireLedgerEntry {
  kind: string;
  id: string;
  data: string;
}

export interface WireAttestation {
  validator: string;
  signature: string;
}

export interface WireBlock {
  header: WireBlockHeader;
  entries: WireLedgerEntry[];
  attestations: WireAttestation[];
}

export function blockToWire(block: Block): WireBlock {
  return {
    header: {
      height: block.header.height,
      electionId: block.header.electionId,
      previousHash: toBase64Url(block.header.previousHash),
      merkleRoot: toBase64Url(block.header.merkleRoot),
      entryCount: block.header.entryCount,
      timestamp: block.header.timestamp,
      proposer: block.header.proposer,
      view: block.header.view,
    },
    entries: block.entries.map((entry) => ({
      kind: entry.kind,
      id: entry.id,
      data: toBase64Url(entry.data),
    })),
    attestations: block.attestations.map((attestation) => ({
      validator: attestation.validator,
      signature: toBase64Url(attestation.signature),
    })),
  };
}

export function blockFromWire(wire: unknown): Block {
  const value = expectObject(wire, "block");
  const header = parseHeader(value.header);
  const entries = parseEntries(value.entries);
  const attestations = parseAttestations(value.attestations);

  // Cheap consistency check at the boundary; the full validation happens in
  // validateBlock, which is where security decisions belong.
  if (header.entryCount !== entries.length) {
    throw new WireFormatError("block.header.entryCount does not match block.entries");
  }

  return { header, entries, attestations };
}

export interface WireProposeRequest {
  height: number;
  electionId: string;
  entries: WireLedgerEntry[];
  timestamp?: number;
  view?: number;
}

export function proposeRequestToWire(request: {
  height: number;
  electionId: string;
  entries: readonly LedgerEntry[];
  timestamp?: number;
  view?: number;
}): WireProposeRequest {
  return {
    height: request.height,
    electionId: request.electionId,
    entries: request.entries.map((entry) => ({
      kind: entry.kind,
      id: entry.id,
      data: toBase64Url(entry.data),
    })),
    ...(request.timestamp !== undefined ? { timestamp: request.timestamp } : {}),
    ...(request.view !== undefined ? { view: request.view } : {}),
  };
}

export function proposeRequestFromWire(wire: unknown): {
  height: number;
  electionId: string;
  entries: LedgerEntry[];
  timestamp?: number;
  view?: number;
} {
  const value = expectObject(wire, "proposeRequest");
  const height = expectUint(value.height, "proposeRequest.height");
  const electionId = expectString(value.electionId, "proposeRequest.electionId", 256);
  const entries = parseEntries(value.entries);
  const timestamp =
    value.timestamp === undefined ? undefined : expectUint(value.timestamp, "proposeRequest.timestamp");
  const view = value.view === undefined ? undefined : expectUint(value.view, "proposeRequest.view");

  return {
    height,
    electionId,
    entries,
    ...(timestamp !== undefined ? { timestamp } : {}),
    ...(view !== undefined ? { view } : {}),
  };
}

// --- parsing helpers -------------------------------------------------------

function expectObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new WireFormatError(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function expectString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string") throw new WireFormatError(`${label} must be a string`);
  if (value.length > maxLength) throw new WireFormatError(`${label} exceeds ${maxLength} characters`);
  return value;
}

function expectUint(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new WireFormatError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function expectBytes(value: unknown, label: string, exactLength?: number): Uint8Array {
  if (typeof value !== "string") throw new WireFormatError(`${label} must be a base64url string`);
  let bytes: Uint8Array;
  try {
    bytes = fromBase64Url(value);
  } catch {
    throw new WireFormatError(`${label} is not valid base64url`);
  }
  if (exactLength !== undefined && bytes.length !== exactLength) {
    throw new WireFormatError(`${label} must be exactly ${exactLength} bytes`);
  }
  return bytes;
}

function parseHeader(value: unknown): BlockHeader {
  const header = expectObject(value, "block.header");
  return {
    height: expectUint(header.height, "block.header.height"),
    electionId: expectString(header.electionId, "block.header.electionId", 256),
    previousHash: expectBytes(header.previousHash, "block.header.previousHash", HASH_BYTES),
    merkleRoot: expectBytes(header.merkleRoot, "block.header.merkleRoot", HASH_BYTES),
    entryCount: expectUint(header.entryCount, "block.header.entryCount"),
    timestamp: expectUint(header.timestamp, "block.header.timestamp"),
    proposer: expectString(header.proposer, "block.header.proposer", 128),
    view: expectUint(header.view, "block.header.view"),
  };
}

function parseEntries(value: unknown): LedgerEntry[] {
  if (!Array.isArray(value)) throw new WireFormatError("block.entries must be an array");
  return value.map((raw, index) => {
    const entry = expectObject(raw, `block.entries[${index}]`);
    return {
      kind: expectString(entry.kind, `block.entries[${index}].kind`, 64),
      id: expectString(entry.id, `block.entries[${index}].id`, 256),
      data: expectBytes(entry.data, `block.entries[${index}].data`),
    };
  });
}

function parseAttestations(value: unknown): Attestation[] {
  if (!Array.isArray(value)) throw new WireFormatError("block.attestations must be an array");
  return value.map((raw, index) => {
    const attestation = expectObject(raw, `block.attestations[${index}]`);
    return {
      validator: expectString(attestation.validator, `block.attestations[${index}].validator`, 128),
      signature: expectBytes(
        attestation.signature,
        `block.attestations[${index}].signature`,
        VALIDATOR_SIGNATURE_BYTES,
      ),
    };
  });
}
