/**
 * Validator identity for Proof-of-Authority consensus.
 *
 * Ed25519 rather than ECDSA, deliberately. ECDSA needs a fresh random nonce per
 * signature, and reusing one -- through a weak RNG, a VM snapshot rollback, or a
 * bad implementation -- leaks the private key outright. That failure has hit
 * real systems (the Sony PS3 and multiple Bitcoin wallets). Ed25519 derives its
 * nonce deterministically from the key and message, so the entire failure mode
 * does not exist. For validator keys that authorise election records, removing a
 * catastrophic-and-silent failure class is worth more than algorithm familiarity.
 *
 * Keys are handled through WebCrypto so verification runs unchanged in a browser
 * -- public verifiability requires that any observer can check the chain without
 * installing anything.
 */

import { toBase64Url } from "@dvoting/crypto";

export const VALIDATOR_PUBLIC_KEY_BYTES = 32;
export const VALIDATOR_SIGNATURE_BYTES = 64;

export class ValidatorError extends Error {
  override name = "ValidatorError";
}

export interface ValidatorIdentity {
  /** Human-meaningful name, e.g. "election-commission". PoA validators are accountable. */
  readonly id: string;
  /** Raw Ed25519 public key, 32 bytes. */
  readonly publicKey: Uint8Array;
}

export interface ValidatorKeyPair {
  readonly identity: ValidatorIdentity;
  readonly privateKey: CryptoKeyLike;
}

/** Structural stand-in for CryptoKey, which is a DOM-lib type. */
export type CryptoKeyLike = Awaited<ReturnType<typeof crypto.subtle.importKey>>;

export async function generateValidatorKeyPair(id: string): Promise<ValidatorKeyPair> {
  const pair = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  // The WebCrypto types model generateKey's return as a union; for Ed25519 it is
  // always a key pair.
  const keyPair = pair as { privateKey: CryptoKeyLike; publicKey: CryptoKeyLike };
  const raw = new Uint8Array(await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey));
  return {
    identity: { id, publicKey: raw },
    privateKey: keyPair.privateKey,
  };
}

export async function importPrivateKey(pkcs8: Uint8Array): Promise<CryptoKeyLike> {
  return globalThis.crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
}

export async function exportPrivateKey(key: CryptoKeyLike): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.exportKey("pkcs8", key));
}

export async function sign(key: CryptoKeyLike, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.sign("Ed25519", key, message));
}

export async function verifySignature(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (publicKey.length !== VALIDATOR_PUBLIC_KEY_BYTES) return false;
  if (signature.length !== VALIDATOR_SIGNATURE_BYTES) return false;
  try {
    const key = await globalThis.crypto.subtle.importKey("raw", publicKey, "Ed25519", false, [
      "verify",
    ]);
    return await globalThis.crypto.subtle.verify("Ed25519", key, signature, message);
  } catch {
    return false;
  }
}

/**
 * The set of authorities permitted to seal blocks.
 *
 * PoA, not open mining, is the correct consensus model for an election: the
 * validators are named, accountable organisations (the Election Commission plus
 * independent observers), and there is no anonymous hashrate to out-compete. It
 * also sidesteps the "51% attack" that open Proof-of-Work invites.
 */
export interface ValidatorSet {
  readonly validators: readonly ValidatorIdentity[];
  /** Minimum attestations (including the proposer) for a block to be valid. */
  readonly quorum: number;
}

export function createValidatorSet(
  validators: readonly ValidatorIdentity[],
  quorum?: number,
): ValidatorSet {
  if (validators.length === 0) throw new ValidatorError("validator set cannot be empty");

  const ids = validators.map((v) => v.id);
  if (new Set(ids).size !== ids.length) {
    throw new ValidatorError("validator ids must be unique");
  }
  for (const validator of validators) {
    if (validator.publicKey.length !== VALIDATOR_PUBLIC_KEY_BYTES) {
      throw new ValidatorError(`validator "${validator.id}" has a malformed public key`);
    }
  }

  // Default to a Byzantine-fault-tolerant supermajority: strictly more than 2/3
  // of validators must attest, so the chain survives up to f faulty validators
  // where n > 3f. A bare majority would let a coalition of half the authorities
  // rewrite records.
  const resolved = quorum ?? Math.floor((2 * validators.length) / 3) + 1;
  if (resolved < 1 || resolved > validators.length) {
    throw new ValidatorError("quorum must be between 1 and the validator count");
  }

  return { validators, quorum: resolved };
}

export function findValidator(set: ValidatorSet, id: string): ValidatorIdentity | undefined {
  return set.validators.find((validator) => validator.id === id);
}

/**
 * Round-robin proposer schedule, with view-based failover.
 *
 * Fixing who may propose each height stops a single validator from racing ahead
 * and monopolising the chain, and makes an absent or misbehaving authority
 * immediately visible: the gap is attributable to a named party.
 *
 * `view` advances the schedule when the previous proposer fails to produce a
 * block, so an offline authority costs one round rather than stalling the
 * election. View v at height h is served by validator (h + v) mod n, so after
 * n-1 views every validator has had a turn.
 */
export function proposerForHeight(
  set: ValidatorSet,
  height: number,
  view = 0,
): ValidatorIdentity {
  if (!Number.isInteger(view) || view < 0) {
    throw new ValidatorError("proposerForHeight: view must be a non-negative integer");
  }
  return set.validators[(height + view) % set.validators.length]!;
}

export function validatorFingerprint(set: ValidatorSet): string {
  const ids = set.validators.map((v) => `${v.id}:${toBase64Url(v.publicKey)}`).sort();
  return `${set.quorum}-of-${set.validators.length}|${ids.join(",")}`;
}
