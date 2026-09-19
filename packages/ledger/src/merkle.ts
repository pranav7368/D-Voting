/**
 * Merkle tree and inclusion proofs, following RFC 6962 (Certificate Transparency).
 *
 * This is what makes the bulletin board usable. Without it, "verify my ballot
 * was included" would mean downloading the entire chain. With it, a voter
 * verifies inclusion from log2(n) hashes -- about 20 hashes for a million
 * ballots -- on a phone, in milliseconds.
 *
 * Two well-known Merkle bugs are avoided here deliberately, and both are worth
 * being able to explain:
 *
 * 1. SECOND-PREIMAGE ATTACK (leaf/node confusion).
 *    If leaves and internal nodes were hashed the same way, an attacker could
 *    present an internal node's hash AS a leaf: the proof would verify, and the
 *    log would appear to contain an entry it never recorded. RFC 6962 prefixes
 *    leaves with 0x00 and internal nodes with 0x01, so the two hash domains can
 *    never collide.
 *
 * 2. DUPLICATE-LAST-LEAF MALLEABILITY (Bitcoin's CVE-2012-2459).
 *    Implementations that pad an odd level by duplicating the final node let two
 *    DIFFERENT leaf lists produce the SAME root -- so a ledger could be
 *    rewritten without changing its published root. RFC 6962 instead splits at
 *    the largest power of two below n and promotes the odd remainder, which is
 *    injective: one leaf list, one root.
 */

import { concatBytes, constantTimeEqual, digest } from "@dvoting/crypto";

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

export class MerkleError extends Error {
  override name = "MerkleError";
}

export interface MerkleProof {
  readonly leafIndex: number;
  readonly treeSize: number;
  /** Sibling hashes, bottom-up. */
  readonly path: readonly Uint8Array[];
}

/** Largest power of two strictly less than n. RFC 6962's split point. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** Hash of a leaf: H(0x00 || data). */
export async function hashLeaf(data: Uint8Array): Promise<Uint8Array> {
  return digest("SHA-256", concatBytes(LEAF_PREFIX, data));
}

/** Hash of an internal node: H(0x01 || left || right). */
export async function hashNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return digest("SHA-256", concatBytes(NODE_PREFIX, left, right));
}

/**
 * Merkle Tree Hash of a list of leaf payloads.
 *
 * The empty tree hashes to SHA-256 of the empty string, per RFC 6962. That
 * matters: an empty block still has a well-defined, verifiable root.
 */
export async function merkleRoot(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) return digest("SHA-256", new Uint8Array(0));
  if (leaves.length === 1) return hashLeaf(leaves[0]!);

  const k = splitPoint(leaves.length);
  const [left, right] = await Promise.all([
    merkleRoot(leaves.slice(0, k)),
    merkleRoot(leaves.slice(k)),
  ]);
  return hashNode(left, right);
}

/** Build the audit path for `leafIndex`. */
export async function merkleProof(
  leaves: readonly Uint8Array[],
  leafIndex: number,
): Promise<MerkleProof> {
  if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= leaves.length) {
    throw new MerkleError("merkleProof: leaf index out of range");
  }
  return {
    leafIndex,
    treeSize: leaves.length,
    path: await buildPath(leaves, leafIndex),
  };
}

async function buildPath(
  leaves: readonly Uint8Array[],
  index: number,
): Promise<Uint8Array[]> {
  if (leaves.length <= 1) return [];

  const k = splitPoint(leaves.length);
  if (index < k) {
    const sub = await buildPath(leaves.slice(0, k), index);
    sub.push(await merkleRoot(leaves.slice(k)));
    return sub;
  }
  const sub = await buildPath(leaves.slice(k), index - k);
  sub.push(await merkleRoot(leaves.slice(0, k)));
  return sub;
}

/**
 * Verify an inclusion proof against a published root.
 *
 * This is the RFC 6962 section 2.1.1 algorithm. A voter runs exactly this,
 * offline, against the root committed in a signed block header.
 */
export async function verifyMerkleProof(
  leafData: Uint8Array,
  proof: MerkleProof,
  root: Uint8Array,
): Promise<boolean> {
  if (proof.leafIndex < 0 || proof.treeSize < 0) return false;
  if (proof.leafIndex >= proof.treeSize) return false;

  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  let r = await hashLeaf(leafData);

  for (const sibling of proof.path) {
    if (sn === 0) return false; // path longer than the tree allows
    if (sibling.length !== 32) return false;

    if ((fn & 1) === 1 || fn === sn) {
      r = await hashNode(sibling, r);
      // Climb past the levels where this node was already a right child.
      while ((fn & 1) === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = await hashNode(r, sibling);
    }
    fn >>= 1;
    sn >>= 1;
  }

  // sn must be exhausted: a short path would otherwise verify against a subtree.
  return sn === 0 && constantTimeEqual(r, root);
}
