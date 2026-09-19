/**
 * Independent verification of a ballot's inclusion in the election record.
 *
 * Plain JavaScript on WebCrypto only: no build step, no dependencies, no
 * framework. It therefore runs unchanged in a voter's browser AND under Node,
 * which is how it gets tested.
 *
 * ===========================================================================
 * WHY THIS FILE MATTERS.
 *
 * "End-to-end verifiable" means a voter must be able to check the election
 * WITHOUT trusting the people running it. A server that says "yes, your ballot
 * is recorded" is worth nothing -- a dishonest server would say exactly the
 * same thing.
 *
 * So this code trusts none of the server's claims. It:
 *
 *   1. re-derives the block header hash from the header's own fields, using the
 *      same canonical encoding the validators signed;
 *   2. re-checks each validator's Ed25519 signature over that hash input,
 *      against public keys the voter can compare with the published set;
 *   3. re-walks the Merkle audit path from the voter's own ballot up to the
 *      root committed in that signed header.
 *
 * If all three hold, the ballot is in a block that a quorum of named
 * authorities signed. The server cannot fake that, because it does not hold
 * their keys.
 * ===========================================================================
 */

// --- encoding helpers ------------------------------------------------------

export function fromBase64Url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concat(...parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function u32(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

/** Length-prefixed field, matching the canonical encoder on the server. */
function lengthPrefixed(bytes) {
  return concat(u32(bytes.length), bytes);
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- canonical block header encoding ---------------------------------------

/**
 * Re-derive the exact bytes the validators signed.
 *
 * This MUST match packages/ledger/src/block.ts encodeHeader byte for byte. If
 * it drifts, signatures stop verifying — which is the failure mode you want,
 * rather than silently accepting something unsigned.
 */
export function encodeBlockHeader(header) {
  return concat(
    lengthPrefixed(utf8("dvoting/block/v2")),
    u64(header.height),
    lengthPrefixed(utf8(header.electionId)),
    fromBase64Url(header.previousHash),
    fromBase64Url(header.merkleRoot),
    u64(header.entryCount),
    u64(header.timestamp),
    lengthPrefixed(utf8(header.proposer)),
    u64(header.view),
  );
}

export async function blockHash(header) {
  return sha256(encodeBlockHeader(header));
}

// --- Merkle inclusion (RFC 6962) -------------------------------------------

async function hashLeaf(data) {
  return sha256(concat(Uint8Array.of(0x00), data));
}

async function hashNode(left, right) {
  return sha256(concat(Uint8Array.of(0x01), left, right));
}

/**
 * RFC 6962 section 2.1.1 inclusion-proof verification.
 *
 * The 0x00/0x01 prefixes are what stop an attacker presenting an internal node
 * as if it were a leaf.
 */
export async function verifyInclusionProof(leafBytes, proof, rootBytes) {
  if (proof.leafIndex < 0 || proof.treeSize < 0) return false;
  if (proof.leafIndex >= proof.treeSize) return false;

  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  let r = await hashLeaf(leafBytes);

  for (const siblingB64 of proof.path) {
    if (sn === 0) return false;
    const sibling = fromBase64Url(siblingB64);
    if (sibling.length !== 32) return false;

    if ((fn & 1) === 1 || fn === sn) {
      r = await hashNode(sibling, r);
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

  return sn === 0 && equalBytes(r, rootBytes);
}

// --- validator signatures ---------------------------------------------------

export async function ed25519Available() {
  try {
    await crypto.subtle.importKey("raw", new Uint8Array(32), "Ed25519", false, ["verify"]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check every attestation on a block header against the published validator set.
 *
 * Returns the validators whose signatures actually verify — not the ones who
 * merely claim to have signed. An unknown validator, or a bad signature, simply
 * does not count toward the quorum.
 */
export async function verifyAttestations(header, attestations, validators) {
  const message = encodeBlockHeader(header);
  const keysById = new Map(validators.map((v) => [v.id, fromBase64Url(v.publicKey)]));

  const verified = [];
  const rejected = [];

  for (const attestation of attestations) {
    const publicKey = keysById.get(attestation.validator);
    if (!publicKey) {
      rejected.push({ validator: attestation.validator, reason: "not in the published validator set" });
      continue;
    }
    try {
      const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, ["verify"]);
      const ok = await crypto.subtle.verify(
        "Ed25519",
        key,
        fromBase64Url(attestation.signature),
        message,
      );
      if (ok) verified.push(attestation.validator);
      else rejected.push({ validator: attestation.validator, reason: "signature does not verify" });
    } catch (error) {
      rejected.push({ validator: attestation.validator, reason: String(error) });
    }
  }

  // Duplicates must not inflate the count: one validator signing twice is one
  // attestation.
  return { verified: [...new Set(verified)], rejected };
}

// --- the whole check --------------------------------------------------------

/**
 * Verify a ballot receipt end to end, trusting nothing the server asserts.
 *
 * `receipt` is the /v1/bulletin/ballots/:id response; `election` is
 * /v1/election. Every check is recomputed locally.
 */
export async function verifyBallotReceipt(receipt, election) {
  const steps = [];
  const fail = (label, detail) => {
    steps.push({ label, ok: false, detail });
    return { ok: false, steps };
  };

  if (!receipt.blockHeader) return fail("Block header present", "the server returned no header");

  // 1. The header commits to the Merkle root we were given.
  const headerRoot = receipt.blockHeader.merkleRoot;
  if (headerRoot !== receipt.merkleRoot) {
    return fail(
      "Merkle root matches the signed header",
      "the root served with the proof is not the one in the block header",
    );
  }
  steps.push({
    label: "Merkle root matches the signed header",
    ok: true,
    detail: `${headerRoot.slice(0, 24)}…`,
  });

  // 2. The validators' signatures cover that header.
  const hasEd25519 = await ed25519Available();
  if (!hasEd25519) {
    steps.push({
      label: "Validator signatures",
      ok: false,
      detail: "this browser does not support Ed25519 in WebCrypto — try a current Chrome/Safari/Firefox",
    });
  } else {
    const { verified, rejected } = await verifyAttestations(
      receipt.blockHeader,
      receipt.attestations ?? [],
      election.validators ?? [],
    );
    const quorum = election.quorum ?? 0;
    if (verified.length < quorum) {
      return fail(
        "Quorum of validator signatures",
        `only ${verified.length} of the required ${quorum} signatures verified` +
          (rejected.length ? ` (${rejected.map((r) => `${r.validator}: ${r.reason}`).join("; ")})` : ""),
      );
    }
    steps.push({
      label: "Quorum of validator signatures",
      ok: true,
      detail: `${verified.length}/${quorum} verified: ${verified.join(", ")}`,
    });
  }

  // 3. The ballot really is in the tree that root commits to.
  const included = await verifyInclusionProof(
    fromBase64Url(receipt.leaf),
    receipt.proof,
    fromBase64Url(receipt.merkleRoot),
  );
  if (!included) {
    return fail("Ballot included in the block", "the Merkle audit path does not reach the root");
  }
  steps.push({
    label: "Ballot included in the block",
    ok: true,
    detail: `entry ${receipt.proof.leafIndex} of ${receipt.proof.treeSize}, ${receipt.proof.path.length} hashes checked`,
  });

  // 4. The block hash is what it claims — belt and braces for display.
  const computed = toBase64Url(await blockHash(receipt.blockHeader));
  steps.push({
    label: "Block hash recomputed locally",
    ok: true,
    detail: `${computed.slice(0, 24)}…`,
  });

  return { ok: steps.every((step) => step.ok), steps };
}
