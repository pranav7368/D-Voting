/**
 * The Chain Explorer's independent verifier must actually catch a broken
 * chain, not just render a green tick because nothing threw.
 *
 * These tests build a real, multi-block election (config, ballots, close,
 * published tally) through the real server-side stack, serialise it exactly
 * as `GET /v1/bulletin/blocks/:height` would, and drive the plain-JS browser
 * module against it -- then tamper with specific fields to confirm each kind
 * of lie a dishonest server could tell is actually caught.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createBallot, toBase64Url } from "@dvoting/crypto";
import { blockHash } from "@dvoting/ledger";

// @ts-expect-error -- plain JS module, deliberately untyped (it ships to a browser).
import * as chainLib from "../public/chain-lib.js";

import { ELECTION, createHarness, makeSubmission, makeVoter } from "./helpers.ts";

async function wireBlock(harness: Awaited<ReturnType<typeof createHarness>>, height: number) {
  const block = await harness.ledger.getBlock(height);
  assert.ok(block, `no block at height ${height}`);
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
    hash: toBase64Url(await blockHash(block.header)),
    attestations: block.attestations.map((a) => ({
      validator: a.validator,
      signature: toBase64Url(a.signature),
    })),
    entries: block.entries.map((e) => ({
      kind: e.kind,
      id: e.id,
      data: toBase64Url(e.data),
    })),
  };
}

async function seedChain(ballotCount = 3) {
  const harness = await createHarness();
  // Sealed one at a time, so each ballot lands in its own block -- the tests
  // below need several DISTINCT blocks to splice and reorder.
  for (let i = 0; i < ballotCount; i++) {
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
    await harness.ballotBox.sealBlock();
  }

  const height = await harness.ledger.height();
  const blocks = [];
  for (let h = 0; h < height; h++) blocks.push(await wireBlock(harness, h));

  return { harness, blocks, election: await harness.ballotBox.describe() };
}

describe("verifyChain confirms a genuine chain", () => {
  it("marks every block ok: hash matches, linked, quorum satisfied", async () => {
    const { blocks, election } = await seedChain(4);
    const results = await chainLib.verifyChain(blocks, election);

    assert.equal(results.length, blocks.length);
    for (const result of results) {
      assert.ok(result.ok, `block ${result.height} unexpectedly failed`);
      assert.ok(result.hashOk);
      assert.ok(result.linked);
    }
    assert.equal(results[0].isGenesis, true);
    assert.ok(results[0].quorumOk);

    const summary = chainLib.summariseChainVerification(results);
    assert.equal(summary.ok, true);
  });
});

describe("verifyChain catches every way a server could lie", () => {
  it("REJECTS a block whose claimed hash does not match its own header", async () => {
    const { blocks, election } = await seedChain(2);
    const tampered = blocks.map((b: any, i: number) =>
      i === 1 ? { ...b, hash: b.hash.replace(/^./, b.hash[0] === "A" ? "B" : "A") } : b,
    );

    const results = await chainLib.verifyChain(tampered, election);
    assert.equal(results[1].hashOk, false);
    assert.equal(results[1].ok, false);
  });

  it("REJECTS a block edited AFTER being hashed (proposer swapped)", async () => {
    // Editing a signed field changes the true hash, so it no longer matches
    // the claimed one -- exactly the property that makes tampering detectable.
    const { blocks, election } = await seedChain(2);
    const tampered = blocks.map((b: any, i: number) =>
      i === 1 ? { ...b, header: { ...b.header, proposer: "attacker" } } : b,
    );

    const results = await chainLib.verifyChain(tampered, election);
    assert.equal(results[1].hashOk, false);
  });

  it("REJECTS a chain with a block spliced out (linkage breaks)", async () => {
    // The classic attack: drop an inconvenient block and hope nobody notices.
    // Removing block 1 means block 2's previousHash no longer matches ANY
    // recomputed hash in the sequence presented.
    const { blocks, election } = await seedChain(3);
    const spliced = [blocks[0], blocks[2]];

    const results = await chainLib.verifyChain(spliced, election);
    assert.equal(results[1].linked, false);
    const summary = chainLib.summariseChainVerification(results);
    assert.equal(summary.ok, false);
  });

  it("REJECTS a genesis block that does not link to the all-zero hash", async () => {
    const { blocks, election } = await seedChain(1);
    const first = blocks[0]!;
    const tampered = [{ ...first, header: { ...first.header, previousHash: first.hash } }];

    const results = await chainLib.verifyChain(tampered, election);
    assert.equal(results[0]!.linked, false);
  });

  it("REJECTS forged validator signatures, even with a correct hash and linkage", async () => {
    // A server could get the hashing and linkage right and still not have a
    // real quorum -- this must be checked independently of both.
    const { blocks, election } = await seedChain(1);
    const first = blocks[0]!;
    const forged = [
      {
        ...first,
        attestations: first.attestations.map((a: any) => ({
          ...a,
          signature: chainLib.toBase64Url(new Uint8Array(64).fill(7)),
        })),
      },
    ];

    const results = await chainLib.verifyChain(forged, election);
    assert.equal(results[0]!.hashOk, true);
    assert.equal(results[0]!.linked, true);
    assert.equal(results[0]!.quorumOk, false);
    assert.equal(results[0]!.ok, false);
  });

  it("REJECTS a quorum reached only by inventing an unpublished validator", async () => {
    const { blocks, election } = await seedChain(1);
    const strippedElection = { ...election, validators: election.validators.slice(0, 1) };

    const results = await chainLib.verifyChain(blocks, strippedElection);
    assert.equal(results[0]!.quorumOk, false);
  });
});

describe("decodeEntryJson", () => {
  it("decodes the sealed election configuration for display", async () => {
    const { blocks } = await seedChain(0);
    const configEntry = blocks[0]!.entries.find((e: any) => e.kind === "election-config");
    const decoded = chainLib.decodeEntryJson(configEntry);
    assert.equal(decoded.electionId, ELECTION.electionId);
    assert.deepEqual(decoded.candidates, ELECTION.candidates);
  });

  it("returns null for data that is not valid JSON, rather than throwing", () => {
    const decoded = chainLib.decodeEntryJson({ data: chainLib.toBase64Url(new TextEncoder().encode("not json")) });
    assert.equal(decoded, null);
  });
});
