/**
 * Witness checkpoints: "at this time, I saw this election's board end here."
 *
 * ===========================================================================
 * THE ATTACK THIS ANSWERS.
 *
 * Validator signatures prove a block was agreed. They do not stop the ballot
 * box from showing DIFFERENT voters DIFFERENT boards: a targeted voter can be
 * served a forged chain signed by keys the box invented, together with those
 * keys, and every check that voter's browser runs will pass. This is the
 * split-view attack, and it is why the bulletin board is called the Achilles
 * heel of e-voting (Hirschi, Schmid and Basin, CSF 2021).
 *
 * A witness is an independent observer (a party's polling agent, a newspaper,
 * a university) that keeps its own copy of the board, refuses to sign anything
 * that rewrites or forks what it has already seen, and periodically signs a
 * checkpoint naming the board's current head. Voters' devices fetch these
 * checkpoints from the witnesses DIRECTLY, never through the ballot box, and
 * accept a receipt only if enough witnesses' heads extend the voter's block.
 * Showing one voter a private board then requires the witnesses to sign it,
 * which honest witnesses will not do.
 *
 * The checkpoint names the genesis block's hash as well as the head: block 0
 * seals the election definition, including the witnesses' own keys, so the
 * genesis hash is the election's fingerprint, the value a commission and its
 * observers publish so anyone can compare it.
 * ===========================================================================
 */

import { fromBase64Url, toBase64Url } from "@dvoting/crypto";

import { encode, type Encoder } from "./canonical.ts";
import { HASH_BYTES } from "./block.ts";
import {
  VALIDATOR_PUBLIC_KEY_BYTES,
  VALIDATOR_SIGNATURE_BYTES,
  sign,
  verifySignature,
  type CryptoKeyLike,
} from "./validator.ts";

export class CheckpointError extends Error {
  override name = "CheckpointError";
}

export interface Checkpoint {
  readonly electionId: string;
  /** Number of blocks seen. The head is the block at height - 1. */
  readonly height: number;
  readonly headHash: Uint8Array;
  /** Hash of block 0, which seals the election definition. */
  readonly genesisHash: Uint8Array;
  /** When the witness saw it, ISO-8601. */
  readonly witnessedAt: string;
}

export interface SignedCheckpoint {
  readonly checkpoint: Checkpoint;
  readonly witness: string;
  readonly signature: Uint8Array;
}

export interface WitnessIdentity {
  readonly id: string;
  readonly publicKey: Uint8Array;
}

/** The exact bytes a witness signs. Versioned, length-prefixed, never JSON. */
export function encodeCheckpoint(checkpoint: Checkpoint, witness: string): Uint8Array {
  if (checkpoint.headHash.length !== HASH_BYTES || checkpoint.genesisHash.length !== HASH_BYTES) {
    throw new CheckpointError("checkpoint hashes must be 32 bytes");
  }
  if (!Number.isInteger(checkpoint.height) || checkpoint.height < 1) {
    throw new CheckpointError("checkpoint height must be at least 1");
  }
  return encode((e: Encoder) => {
    e.string("dvoting/checkpoint/v1");
    // The signer's id is inside the signed bytes, so a signature cannot be
    // re-attributed to a different witness that happens to share a key.
    e.string(witness);
    e.string(checkpoint.electionId);
    e.u32(checkpoint.height);
    e.fixed(checkpoint.headHash, HASH_BYTES);
    e.fixed(checkpoint.genesisHash, HASH_BYTES);
    e.string(checkpoint.witnessedAt);
  });
}

export async function signCheckpoint(
  checkpoint: Checkpoint,
  witness: string,
  key: CryptoKeyLike,
): Promise<SignedCheckpoint> {
  return { checkpoint, witness, signature: await sign(key, encodeCheckpoint(checkpoint, witness)) };
}

/** True only if `signed` was signed by `identity` and names it. */
export async function verifyCheckpoint(
  signed: SignedCheckpoint,
  identity: WitnessIdentity,
): Promise<boolean> {
  if (signed.witness !== identity.id) return false;
  if (identity.publicKey.length !== VALIDATOR_PUBLIC_KEY_BYTES) return false;
  if (signed.signature.length !== VALIDATOR_SIGNATURE_BYTES) return false;
  let message: Uint8Array;
  try {
    message = encodeCheckpoint(signed.checkpoint, signed.witness);
  } catch {
    return false;
  }
  return verifySignature(identity.publicKey, signed.signature, message);
}

export interface WireCheckpoint {
  readonly witness: string;
  readonly electionId: string;
  readonly height: number;
  readonly headHash: string;
  readonly genesisHash: string;
  readonly witnessedAt: string;
  readonly signature: string;
}

export function checkpointToWire(signed: SignedCheckpoint): WireCheckpoint {
  return {
    witness: signed.witness,
    electionId: signed.checkpoint.electionId,
    height: signed.checkpoint.height,
    headHash: toBase64Url(signed.checkpoint.headHash),
    genesisHash: toBase64Url(signed.checkpoint.genesisHash),
    witnessedAt: signed.checkpoint.witnessedAt,
    signature: toBase64Url(signed.signature),
  };
}

export function checkpointFromWire(wire: unknown): SignedCheckpoint {
  const value = wire as Partial<WireCheckpoint> | null;
  if (!value || typeof value !== "object") throw new CheckpointError("checkpoint must be an object");
  const text = (field: keyof WireCheckpoint): string => {
    const v = value[field];
    if (typeof v !== "string" || v.length === 0) throw new CheckpointError(`checkpoint.${field} must be a string`);
    return v;
  };
  if (typeof value.height !== "number" || !Number.isInteger(value.height) || value.height < 1) {
    throw new CheckpointError("checkpoint.height must be a positive integer");
  }
  const headHash = fromBase64Url(text("headHash"));
  const genesisHash = fromBase64Url(text("genesisHash"));
  if (headHash.length !== HASH_BYTES || genesisHash.length !== HASH_BYTES) {
    throw new CheckpointError("checkpoint hashes must be 32 bytes");
  }
  return {
    witness: text("witness"),
    signature: fromBase64Url(text("signature")),
    checkpoint: {
      electionId: text("electionId"),
      height: value.height,
      headHash,
      genesisHash,
      witnessedAt: text("witnessedAt"),
    },
  };
}
