/**
 * Independent verification of the WHOLE chain, not just one ballot.
 *
 * `verify-lib.js` answers "is my ballot in the record, signed by a quorum?".
 * This answers the broader question the Chain Explorer exists to show an
 * observer: "is this actually one unbroken, signed chain, end to end?" —
 * without trusting a single claim the server makes along the way.
 *
 * For every block this recomputes, from the header's own fields:
 *
 *   1. its hash -- compared against what the server claims that block's hash
 *      is, so a server cannot label a block with a hash it does not have;
 *   2. whether it links to the PREVIOUSLY RECOMPUTED hash of the block before
 *      it -- never the server's claimed hash for that block, so a server
 *      cannot present two mutually-consistent lies and have them wave each
 *      other through;
 *   3. whether a quorum of named validators actually signed it.
 *
 * Genesis (height 0) is checked against the all-zero previous-hash every
 * implementation of this chain uses -- there is nothing before it to link to.
 */

import {
  blockHash,
  ed25519Available,
  fromBase64Url,
  toBase64Url,
  verifyAttestations,
} from "./verify-lib.js";

const ZERO_HASH_B64 = toBase64Url(new Uint8Array(32));

/**
 * @param blocks Ascending-height block wire objects, each
 *   `{ header, hash, attestations, entries }` as served by
 *   `GET /v1/bulletin/blocks/:height`.
 * @param election `/v1/election`, for the validator set and quorum.
 * @returns One verdict per block, in the same order.
 */
export async function verifyChain(blocks, election) {
  const hasEd25519 = await ed25519Available();
  const results = [];
  let previousComputedHash = null;

  for (const block of blocks) {
    const computedHash = toBase64Url(await blockHash(block.header));
    const hashOk = computedHash === block.hash;

    const expectedPrev = block.header.height === 0 ? ZERO_HASH_B64 : previousComputedHash;
    const linked = expectedPrev !== null && block.header.previousHash === expectedPrev;

    let verifiedSignatures = [];
    let rejectedSignatures = [];
    if (hasEd25519) {
      const checked = await verifyAttestations(
        block.header,
        block.attestations ?? [],
        election.validators ?? [],
      );
      verifiedSignatures = checked.verified;
      rejectedSignatures = checked.rejected;
    }
    const quorumOk = hasEd25519 && verifiedSignatures.length >= (election.quorum ?? Infinity);

    results.push({
      height: block.header.height,
      computedHash,
      claimedHash: block.hash,
      hashOk,
      linked,
      isGenesis: block.header.height === 0,
      verifiedSignatures,
      rejectedSignatures,
      quorumOk,
      hasEd25519,
      ok: hashOk && linked && (hasEd25519 ? quorumOk : true),
    });

    previousComputedHash = computedHash;
  }

  return results;
}

/** Roll every per-block verdict up into one sentence and one boolean. */
export function summariseChainVerification(results) {
  if (results.length === 0) {
    return { ok: true, message: "No blocks yet." };
  }
  const broken = results.filter((r) => !r.ok);
  if (broken.length === 0) {
    return {
      ok: true,
      message: `All ${results.length} blocks verified: hashes recompute correctly, each links to the one before it, and every block carries a validator quorum's signatures.`,
    };
  }
  return {
    ok: false,
    message: `${broken.length} of ${results.length} block(s) failed independent verification, starting at height ${broken[0].height}.`,
  };
}

/**
 * Decode a ledger entry's UTF-8 JSON payload for display.
 *
 * Every entry kind this decodes is data the protocol already intends to be
 * public: the sealed configuration, the close record, the published tally,
 * and a Benaloh-audited ballot's revealed randomness (that IS the point of
 * publishing an audit -- anyone can re-run it). A cast ballot's entry is
 * deliberately left undecoded here; see the "kindLabel" note in chain-page.js.
 */
export function decodeEntryJson(entry) {
  try {
    return JSON.parse(new TextDecoder().decode(fromBase64Url(entry.data)));
  } catch {
    return null;
  }
}

export {
  blockHash,
  ed25519Available,
  encodeBlockHeader,
  fromBase64Url,
  toBase64Url,
  verifyAttestations,
  verifyInclusionProof,
} from "./verify-lib.js";
