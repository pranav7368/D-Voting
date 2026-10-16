import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toBase64Url } from "@dvoting/crypto";
import { blockHash, generateValidatorKeyPair, signCheckpoint, type Block } from "@dvoting/ledger";
import { ELECTION, createHarness, makeSubmission, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";

import { verifyElection } from "../src/index.ts";

async function election() {
  const keys = await Promise.all(["agent-a", "agent-b", "observer"].map((id) => generateValidatorKeyPair(id)));
  const roster = {
    quorum: 2,
    witnesses: keys.map((k) => ({ id: k.identity.id, publicKey: toBase64Url(k.identity.publicKey), url: `http://${k.identity.id}.test` })),
  };
  const harness = await createHarness({ witnesses: roster });
  for (let i = 0; i < 2; i++) {
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
    await harness.ballotBox.sealBlock();
  }
  const blocks = [...(await harness.ledger.blocks())] as Block[];

  /** A checkpoint a witness would sign after seeing `seen` blocks. */
  const checkpoint = async (index: number, seen: Block[] = blocks) =>
    signCheckpoint(
      {
        electionId: ELECTION.electionId,
        height: seen.length,
        headHash: await blockHash(seen.at(-1)!.header),
        genesisHash: await blockHash(seen[0]!.header),
        witnessedAt: new Date().toISOString(),
      },
      keys[index]!.identity.id,
      keys[index]!.privateKey,
    );
  return { blocks, keys, checkpoint };
}

describe("standalone verifier: witnesses", () => {
  it("accepts a board every witness vouches for and prints the election fingerprint", async () => {
    const { blocks, checkpoint } = await election();
    const report = await verifyElection(blocks, { checkpoints: [await checkpoint(0), await checkpoint(1), await checkpoint(2)] });
    assert.equal(report.valid, true, JSON.stringify(report.checks));
    assert.ok(report.checks.some((c) => /independent witnesses/.test(c.label) && c.ok));
    assert.match(report.electionFingerprint ?? "", /^\d{4} \d{4} \d{4}$/);
  });

  it("CATCHES a board that omits blocks the witnesses already saw", async () => {
    // e.g. a box that hides the published result, or the last ballots, from
    // the copy an auditor downloads.
    const { blocks, checkpoint } = await election();
    const report = await verifyElection(blocks.slice(0, -1), { checkpoints: [await checkpoint(0), await checkpoint(1)] });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /has only/);
  });

  it("CATCHES a board whose head differs from what a witness saw", async () => {
    const { blocks, keys } = await election();
    const forged = await signCheckpoint(
      {
        electionId: ELECTION.electionId,
        height: blocks.length,
        headHash: new Uint8Array(32).fill(5),
        genesisHash: await blockHash(blocks[0]!.header),
        witnessedAt: new Date().toISOString(),
      },
      "agent-a",
      keys[0]!.privateKey,
    );
    const report = await verifyElection(blocks, { checkpoints: [forged] });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /differs from the one agent-a saw/);
  });

  it("requires the sealed quorum of witnesses", async () => {
    const { blocks, checkpoint } = await election();
    const report = await verifyElection(blocks, { checkpoints: [await checkpoint(0)] });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /only 1 of the required 2/);
  });

  it("ignores, and reports, a checkpoint from someone outside the sealed roster", async () => {
    const { blocks, checkpoint } = await election();
    const outsider = await generateValidatorKeyPair("stranger");
    const extra = await signCheckpoint(
      (await checkpoint(0)).checkpoint,
      "stranger",
      outsider.privateKey,
    );
    const report = await verifyElection(blocks, { checkpoints: [await checkpoint(0), await checkpoint(1), extra] });
    assert.equal(report.valid, true);
    assert.ok(report.warnings.some((w) => /stranger/.test(w)));
  });

  it("warns when the newest blocks are not yet witnessed", async () => {
    const { blocks, checkpoint } = await election();
    const older = blocks.slice(0, -1);
    const report = await verifyElection(blocks, { checkpoints: [await checkpoint(0, older), await checkpoint(1, older)] });
    assert.equal(report.valid, true);
    assert.ok(report.warnings.some((w) => /not yet covered/.test(w)));
  });
});
