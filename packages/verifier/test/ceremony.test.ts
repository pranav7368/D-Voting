/**
 * The verifier against a result produced by the REAL decryption ceremony.
 *
 * Found by auditing the hosted demo: the ceremony publishes only the shares of
 * the trustees who contributed (any k of n), and the verifier rejected that
 * correct result because it expected all n shares. Earlier tests built the
 * result by hand with every share and so never exercised the real path.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { attest, computeEntriesRoot, type Block } from "@dvoting/ledger";
import { createApp } from "@dvoting/ballot-box/src/app.ts";
import { ELECTION, GROUP, createHarness, makeSubmission, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";
import { Trustee } from "@dvoting/trustee/src/trustee.ts";

import { verifyElection } from "../src/index.ts";

async function electionCountedByCeremony() {
  const harness = await createHarness();
  for (const choice of [[1, 0, 0], [0, 1, 0], [0, 1, 0]]) {
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), choice));
  }
  await harness.ballotBox.sealBlock();
  await harness.ballotBox.closePoll();

  const app = createApp({ ballotBox: harness.ballotBox });
  const toBox = (async (input: string | URL | Request, init?: RequestInit) =>
    app.request(new URL(String(input)).pathname, init)) as typeof fetch;

  // Two of the three trustees (threshold 2) take part; trustee 3 does not.
  for (const keyShare of harness.trustees.keyShares.slice(0, 2)) {
    await new Trustee({
      electionId: ELECTION.electionId, group: GROUP, index: keyShare.index, share: keyShare.share,
      ballotBoxUrl: "http://box.test", fetchImpl: toBox,
    }).participate();
  }
  return { harness, blocks: [...(await harness.ledger.blocks())] as Block[] };
}

describe("standalone verifier: a result from the real ceremony", () => {
  it("verifies a result decrypted by a subset of the trustees", async () => {
    const { blocks } = await electionCountedByCeremony();
    const report = await verifyElection(blocks);
    assert.equal(report.valid, true, JSON.stringify(report.checks.filter((c) => !c.ok)));
    assert.deepEqual(report.results, [
      { candidate: "Alice", votes: 1 },
      { candidate: "Bob", votes: 2 },
      { candidate: "Carol", votes: 0 },
    ]);
    assert.match(report.checks.find((c) => /sealed trustee roster/.test(c.label))!.detail ?? "", /trustees 1, 2 of 3/);
  });

  it("REJECTS a result naming a trustee share that was never sealed", async () => {
    const { harness, blocks } = await electionCountedByCeremony();
    const last = blocks.at(-1)!;
    const index = last.entries.findIndex((e) => e.kind === "tally-result");
    const tally = JSON.parse(new TextDecoder().decode(last.entries[index]!.data));
    // Swap trustee 1's share for trustee 3's: a forged roster, re-signed by
    // every validator so only the roster check can catch it.
    tally.publicShares[0].publicShare = harness.ballotBox.trustees.publicShares.find((s) => s.index === 3)!.publicShare;
    const entries = last.entries.map((e, i) => (i === index ? { ...e, data: new TextEncoder().encode(JSON.stringify(tally)) } : e));
    const header = { ...last.header, merkleRoot: await computeEntriesRoot(entries) };
    const unsigned: Block = { header, entries, attestations: [] };
    const attestations = [];
    for (const key of harness.validatorKeys) attestations.push(await attest(unsigned, key.identity, key.privateKey));
    blocks[blocks.length - 1] = { header, entries, attestations };

    const report = await verifyElection(blocks);
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /trustee 1's share is not the one sealed/);
  });
});
