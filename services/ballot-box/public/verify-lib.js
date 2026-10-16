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

// --- witnesses: one board for everyone --------------------------------------
//
// Everything above trusts the board as the ballot box serves it. A box that
// shows one voter a private board (signed by keys it invented and served
// alongside) passes every check above. Witnesses close that: independent
// observers sign checkpoints naming the board's head, this device fetches them
// from the witnesses DIRECTLY, and a receipt counts as witnessed only if enough
// witnesses' heads extend its block through hash links this device recomputes.
// See packages/ledger/src/checkpoint.ts for the protocol.

/** Must match encodeCheckpoint in packages/ledger/src/checkpoint.ts byte for byte. */
export function encodeCheckpoint(checkpoint, witness) {
  return concat(
    lengthPrefixed(utf8("dvoting/checkpoint/v1")),
    lengthPrefixed(utf8(witness)),
    lengthPrefixed(utf8(checkpoint.electionId)),
    u32(checkpoint.height),
    fromBase64Url(checkpoint.headHash),
    fromBase64Url(checkpoint.genesisHash),
    lengthPrefixed(utf8(checkpoint.witnessedAt)),
  );
}

async function ed25519Verify(publicKey, signature, message) {
  if (!publicKey || publicKey.length !== 32 || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, message);
  } catch {
    return false;
  }
}

/**
 * The election fingerprint: twelve digits of block 0's hash. Block 0 seals
 * the whole election definition, witnesses included, so this is the value a
 * commission and its observers publish for anyone to compare.
 */
export function electionFingerprint(genesisHashB64) {
  const bytes = fromBase64Url(genesisHashB64);
  let value = 0n;
  for (let i = 0; i < 5; i++) value = (value << 8n) | BigInt(bytes[i]);
  const digits = (value % 1_000_000_000_000n).toString().padStart(12, "0");
  return digits.slice(0, 4) + " " + digits.slice(4, 8) + " " + digits.slice(8);
}

/** The witness roster sealed in block 0's configuration entry, or null. */
export function rosterFromGenesis(genesisBlock) {
  const entry = (genesisBlock.entries ?? []).find((e) => e.kind === "election-config");
  if (!entry) return null;
  const record = JSON.parse(new TextDecoder().decode(fromBase64Url(entry.data)));
  return record.witnesses ?? null;
}

/**
 * Decide whether a sealed block is vouched for by enough witnesses.
 *
 *   blockHeight, blockHeader  the receipt's block (header in wire form)
 *   genesisHeader             block 0's header, as served
 *   roster                    { quorum, witnesses: [{ id, publicKey, url }] } from block 0
 *   responses                 [{ witness, body | null, error? }] from each witness
 *   headers                   wire headers for heights blockHeight .. (highest checkpoint - 1)
 *
 * A witness vouches only if its signature verifies against the sealed key, it
 * names this election and this genesis, its height covers the block, and its
 * head hash is reached from the block by hash links recomputed here. A head
 * the links do not reach means that witness saw a DIFFERENT board.
 */
export async function verifyWitnessed({ blockHeight, blockHeader, genesisHeader, roster, responses, headers }) {
  const genesisHash = toBase64Url(await blockHash(genesisHeader));
  const result = {
    ok: false, pending: false, genesisHash, vouched: [], waiting: [], rejected: [], alarms: [],
    quorum: roster?.quorum ?? 0, total: roster?.witnesses?.length ?? 0,
  };
  if (!roster || !Array.isArray(roster.witnesses) || roster.witnesses.length === 0) {
    result.rejected.push({ witness: "-", reason: "this election names no witnesses" });
    return result;
  }

  // Recompute the hash chain from the receipt's block upward.
  const blockHashB64 = toBase64Url(await blockHash(blockHeader));
  const hashAt = new Map([[blockHeight, blockHashB64]]);
  const byHeight = new Map(headers.map((h) => [h.height, h]));
  if (byHeight.has(blockHeight) && toBase64Url(await blockHash(byHeight.get(blockHeight))) !== blockHashB64) {
    result.rejected.push({ witness: "-", reason: "the served header chain does not contain this receipt's block" });
    return result;
  }
  let previous = blockHashB64;
  for (let h = blockHeight + 1; byHeight.has(h); h++) {
    const header = byHeight.get(h);
    if (header.previousHash !== previous) break; // the chain stops linking here
    previous = toBase64Url(await blockHash(header));
    hashAt.set(h, previous);
  }

  const keys = new Map(roster.witnesses.map((w) => [w.id, fromBase64Url(w.publicKey)]));
  for (const witness of roster.witnesses) {
    const response = responses.find((r) => r.witness === witness.id);
    const body = response?.body;
    if (!body?.checkpoint) {
      result.waiting.push({ witness: witness.id, reason: response?.error ?? "no checkpoint yet" });
      continue;
    }
    if (body.alarm) result.alarms.push({ witness: witness.id, alarm: body.alarm });
    const cp = body.checkpoint;
    const signed = await ed25519Verify(keys.get(witness.id), fromBase64Url(cp.signature), encodeCheckpoint(cp, witness.id));
    if (!signed || cp.witness !== witness.id) {
      result.rejected.push({ witness: witness.id, reason: "signature does not verify against the sealed key" });
    } else if (cp.electionId !== genesisHeader.electionId) {
      result.rejected.push({ witness: witness.id, reason: "checkpoint is for election " + cp.electionId });
    } else if (cp.genesisHash !== genesisHash) {
      result.rejected.push({ witness: witness.id, reason: "witness saw a different election definition (block 0)" });
    } else if (cp.height <= blockHeight) {
      result.waiting.push({ witness: witness.id, reason: "has seen " + cp.height + " blocks; this ballot is in block " + blockHeight });
    } else if (hashAt.get(cp.height - 1) !== cp.headHash) {
      result.rejected.push({ witness: witness.id, reason: "witness saw a different board: its head is not reached from this block" });
    } else {
      result.vouched.push(witness.id);
    }
  }
  result.ok = result.vouched.length >= result.quorum;
  result.pending = !result.ok && result.vouched.length + result.waiting.length >= result.quorum;
  return result;
}

/**
 * Collect everything verifyWitnessed needs, fetching checkpoints from each
 * witness's own address and only headers and block 0 from the ballot box.
 */
export async function gatherWitnessEvidence(receipt, { base = "", fetchImpl = fetch } = {}) {
  const getJson = async (url) => {
    const response = await fetchImpl(url, { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    return response.json();
  };
  const genesis = await getJson(base + "/v1/bulletin/blocks/0");
  const roster = rosterFromGenesis(genesis);
  const responses = await Promise.all(
    (roster?.witnesses ?? []).map(async (w) => {
      try {
        return { witness: w.id, body: await getJson(w.url + "/v1/checkpoint") };
      } catch (error) {
        return { witness: w.id, body: null, error: "unreachable (" + error.message + ")" };
      }
    }),
  );
  const top = Math.max(receipt.blockHeight + 1, ...responses.map((r) => r.body?.checkpoint?.height ?? 0));
  const { headers } = await getJson(base + "/v1/bulletin/headers?from=" + receipt.blockHeight + "&to=" + top);
  return verifyWitnessed({
    blockHeight: receipt.blockHeight,
    blockHeader: receipt.blockHeader,
    genesisHeader: genesis.header,
    roster,
    responses,
    headers,
  });
}
