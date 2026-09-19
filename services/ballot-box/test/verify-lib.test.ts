/**
 * The browser verifier must agree with the server, byte for byte.
 *
 * `public/verify-lib.js` re-implements the canonical header encoding, the
 * Merkle rules and the signature checks in dependency-free JavaScript so a
 * voter's browser can verify without trusting anyone. That independence is only
 * worth something if the reimplementation is exactly right — a single byte of
 * drift and every signature stops verifying.
 *
 * These tests drive the browser code against blocks produced by the real
 * server-side stack.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createBallot, toBase64Url } from "@dvoting/crypto";
import { blockHash, encodeEntry, encodeHeader } from "@dvoting/ledger";

// @ts-expect-error -- plain JS module, deliberately untyped (it ships to a browser).
import * as verifier from "../public/verify-lib.js";

import { ELECTION, createHarness, makeVoter } from "./helpers.ts";

/** Reproduce exactly what GET /v1/bulletin/ballots/:id returns. */
async function buildReceipt(harness: Awaited<ReturnType<typeof createHarness>>, ballotId: string) {
  const located = await harness.ledger.locateEntry("ballot", ballotId);
  assert.ok(located, "ballot not found on the chain");
  const block = await harness.ledger.getBlock(located.blockHeight);
  assert.ok(block);

  return {
    ballotId,
    leaf: toBase64Url(encodeEntry(located.entry)),
    merkleRoot: toBase64Url(located.merkleRoot),
    proof: {
      leafIndex: located.proof.leafIndex,
      treeSize: located.proof.treeSize,
      path: located.proof.path.map((node) => toBase64Url(node)),
    },
    blockHeader: {
      height: block.header.height,
      electionId: block.header.electionId,
      previousHash: toBase64Url(block.header.previousHash),
      merkleRoot: toBase64Url(block.header.merkleRoot),
      entryCount: block.header.entryCount,
      timestamp: block.header.timestamp,
      proposer: block.header.proposer,
      view: block.header.view,
    },
    attestations: block.attestations.map((a) => ({
      validator: a.validator,
      signature: toBase64Url(a.signature),
    })),
  };
}

async function seedElection(ballotCount = 5) {
  const harness = await createHarness();
  const ids: string[] = [];
  for (let i = 0; i < ballotCount; i++) {
    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    const result = await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot,
    });
    ids.push(result.ballotId);
  }
  await harness.ballotBox.sealBlock();
  return { harness, ids, election: await harness.ballotBox.describe() };
}

describe("browser encoder matches the server exactly", () => {
  it("re-derives the identical canonical header bytes", async () => {
    // If this drifts by one byte, every signature check silently fails.
    const { harness } = await seedElection(1);
    const block = await harness.ledger.getBlock(0);
    assert.ok(block);

    const serverBytes = encodeHeader(block.header);
    const browserBytes = verifier.encodeBlockHeader({
      height: block.header.height,
      electionId: block.header.electionId,
      previousHash: toBase64Url(block.header.previousHash),
      merkleRoot: toBase64Url(block.header.merkleRoot),
      entryCount: block.header.entryCount,
      timestamp: block.header.timestamp,
      proposer: block.header.proposer,
      view: block.header.view,
    });

    assert.deepEqual(Array.from(browserBytes), Array.from(serverBytes));
  });

  it("computes the identical block hash", async () => {
    const { harness } = await seedElection(1);
    const block = await harness.ledger.getBlock(0);
    assert.ok(block);

    const serverHash = toBase64Url(await blockHash(block.header));
    const browserHash = verifier.toBase64Url(
      await verifier.blockHash({
        height: block.header.height,
        electionId: block.header.electionId,
        previousHash: toBase64Url(block.header.previousHash),
        merkleRoot: toBase64Url(block.header.merkleRoot),
        entryCount: block.header.entryCount,
        timestamp: block.header.timestamp,
        proposer: block.header.proposer,
        view: block.header.view,
      }),
    );

    assert.equal(browserHash, serverHash);
  });

  it("round-trips base64url identically", () => {
    for (let length = 0; length < 40; length++) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 53 + 7) & 0xff);
      const encoded = toBase64Url(bytes);
      assert.equal(verifier.toBase64Url(bytes), encoded);
      assert.deepEqual(Array.from(verifier.fromBase64Url(encoded)), Array.from(bytes));
    }
  });
});

describe("a voter can verify their receipt independently", () => {
  it("accepts a genuine receipt", async () => {
    const { harness, ids, election } = await seedElection(5);
    const receipt = await buildReceipt(harness, ids[2]!);

    const result = await verifier.verifyBallotReceipt(receipt, election);
    assert.ok(result.ok, JSON.stringify(result.steps, null, 2));

    const labels = result.steps.map((s: { label: string }) => s.label);
    assert.ok(labels.includes("Quorum of validator signatures"));
    assert.ok(labels.includes("Ballot included in the block"));
  });

  it("verifies every ballot in the block", async () => {
    const { harness, ids, election } = await seedElection(7);
    for (const id of ids) {
      const receipt = await buildReceipt(harness, id);
      const result = await verifier.verifyBallotReceipt(receipt, election);
      assert.ok(result.ok, `ballot ${id} failed to verify`);
    }
  });
});

describe("the verifier trusts nothing the server says", () => {
  it("REJECTS a receipt whose ballot was swapped", async () => {
    const { harness, ids, election } = await seedElection(5);
    const receipt = await buildReceipt(harness, ids[1]!);
    const other = await buildReceipt(harness, ids[3]!);

    // Server claims a different ballot sits at this position.
    const forged = { ...receipt, leaf: other.leaf };
    const result = await verifier.verifyBallotReceipt(forged, election);
    assert.ok(!result.ok);
    assert.ok(result.steps.some((s: { ok: boolean }) => !s.ok));
  });

  it("REJECTS a tampered audit path", async () => {
    const { harness, ids, election } = await seedElection(5);
    const receipt = await buildReceipt(harness, ids[1]!);

    const path = [...receipt.proof.path];
    const bytes = verifier.fromBase64Url(path[0]);
    bytes[0] ^= 0xff;
    path[0] = verifier.toBase64Url(bytes);

    const result = await verifier.verifyBallotReceipt(
      { ...receipt, proof: { ...receipt.proof, path } },
      election,
    );
    assert.ok(!result.ok);
  });

  it("REJECTS a forged validator signature", async () => {
    const { harness, ids, election } = await seedElection(3);
    const receipt = await buildReceipt(harness, ids[0]!);

    const attestations = receipt.attestations.map((a) => ({
      ...a,
      signature: verifier.toBase64Url(new Uint8Array(64).fill(9)),
    }));

    const result = await verifier.verifyBallotReceipt({ ...receipt, attestations }, election);
    assert.ok(!result.ok);
    const failure = result.steps.find((s: { ok: boolean }) => !s.ok);
    assert.match(failure.detail, /signatures verified|does not verify/);
  });

  it("REJECTS signatures from validators outside the published set", async () => {
    // A server that invents an authority to reach quorum must be caught.
    const { harness, ids, election } = await seedElection(3);
    const receipt = await buildReceipt(harness, ids[0]!);

    const strippedElection = { ...election, validators: election.validators.slice(0, 1) };
    const result = await verifier.verifyBallotReceipt(receipt, strippedElection);
    assert.ok(!result.ok);
  });

  it("REJECTS a header edited after signing", async () => {
    const { harness, ids, election } = await seedElection(3);
    const receipt = await buildReceipt(harness, ids[0]!);

    // Change the view: the signature no longer covers this header.
    const blockHeader = { ...receipt.blockHeader, view: receipt.blockHeader.view + 1 };
    const result = await verifier.verifyBallotReceipt({ ...receipt, blockHeader }, election);
    assert.ok(!result.ok);
  });

  it("REJECTS a root that disagrees with the signed header", async () => {
    const { harness, ids, election } = await seedElection(5);
    const receipt = await buildReceipt(harness, ids[0]!);
    const other = await buildReceipt(harness, ids[1]!);

    const result = await verifier.verifyBallotReceipt(
      { ...receipt, merkleRoot: other.merkleRoot.replace(/^./, "A") },
      election,
    );
    assert.ok(!result.ok);
    assert.match(result.steps[0].detail, /not the one in the block header/);
  });

  it("REJECTS a proof claiming the wrong position", async () => {
    const { harness, ids, election } = await seedElection(5);
    const receipt = await buildReceipt(harness, ids[2]!);

    const result = await verifier.verifyBallotReceipt(
      { ...receipt, proof: { ...receipt.proof, leafIndex: receipt.proof.leafIndex + 1 } },
      election,
    );
    assert.ok(!result.ok);
  });
});
