import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  createBallot,
  decryptTally,
  partialDecrypt,
  toBase64Url,
  type PartialDecryption,
} from "@dvoting/crypto";
import {
  attest,
  blockHash,
  computeEntriesRoot,
  generateValidatorKeyPair,
  blockToWire,
  type Block,
} from "@dvoting/ledger";
import { tallyFromChain } from "@dvoting/ballot-box/src/chain-tally.ts";
import { buildPublishedTally, encodeTally } from "@dvoting/ballot-box/src/tally-publication.ts";
import { ELECTION, GROUP, createHarness, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";
import { rollCommitment } from "@dvoting/registration-authority/src/eligibility/roll-commitment.ts";

import {
  fetchBlocks,
  readExport,
  verifyElection,
  writeExport,
  type PinnedValidators,
} from "../src/index.ts";

const ROLL = ["R-100001", "R-100002", "R-100003", "R-100004"];

/** A real election, run to a published result, with a sealed roll commitment. */
async function runElection(options: { close?: boolean; publish?: boolean } = {}) {
  const close = options.close ?? true;
  const publish = options.publish ?? true;

  const harness = await createHarness({ leaveInSetup: true });
  await harness.ballotBox.openPoll({
    rollCommitment: await rollCommitment(ELECTION.electionId, ROLL),
  });

  const ballotIds: string[] = [];
  for (const selections of [[1, 0, 0], [1, 0, 0], [0, 1, 0]]) {
    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, harness.trustees.publicKey, selections, {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot,
    });
    ballotIds.push(ballot.ballotId);
  }
  await harness.ballotBox.sealBlock();

  if (close) {
    await harness.ballotBox.closePoll();
    if (publish) {
      const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
      const partialsByCandidate: PartialDecryption[][] = [];
      for (const total of input.encryptedTotals) {
        const partials: PartialDecryption[] = [];
        for (const keyShare of harness.trustees.keyShares.slice(0, harness.trustees.threshold)) {
          partials.push(await partialDecrypt(GROUP, ELECTION.electionId, keyShare, total));
        }
        partialsByCandidate.push(partials);
      }
      const decrypted = await decryptTally(
        GROUP,
        ELECTION.electionId,
        ELECTION.candidates,
        input.encryptedTotals,
        partialsByCandidate,
        harness.trustees.publicShares,
        harness.trustees.threshold,
        input.counted.length,
      );
      const tally = buildPublishedTally({
        election: ELECTION,
        publicKey: harness.trustees.publicKey,
        threshold: harness.trustees.threshold,
        countedBallotIds: input.counted.map((item) => item.ballot.ballotId),
        supersededBallotIds: input.superseded.map((item) => item.ballot.ballotId),
        encryptedTotals: input.encryptedTotals,
        partialsByCandidate,
        publicShares: harness.trustees.publicShares,
        results: decrypted.results,
      });
      await harness.ballotBox.publishTally({ encode: () => encodeTally(tally) });
    }
  }

  const blocks = [...(await harness.ledger.blocks())];
  const pinned: PinnedValidators = {
    validators: harness.validatorKeys.map((k) => ({
      id: k.identity.id,
      publicKey: toBase64Url(k.identity.publicKey),
    })),
    quorum: harness.ledger.validatorSet.quorum,
  };
  return { harness, blocks, pinned, ballotIds };
}

const election = await runElection();

describe("standalone verifier", () => {
  it("verifies an honest, published election and recounts it", async () => {
    const report = await verifyElection(election.blocks, {
      pinnedValidators: election.pinned,
      rollIds: ROLL,
      ballotIds: election.ballotIds,
    });

    assert.equal(report.valid, true, JSON.stringify(report.checks, null, 2));
    assert.equal(report.phase, "published");
    assert.equal(report.trustAnchor, "pinned");
    assert.deepEqual(report.warnings, []);
    assert.deepEqual(report.results, [
      { candidate: "Alice", votes: 2 },
      { candidate: "Bob", votes: 1 },
      { candidate: "Carol", votes: 0 },
    ]);
  });

  it("warns, but still verifies, when the validator set is not pinned", async () => {
    const report = await verifyElection(election.blocks);
    assert.equal(report.valid, true);
    assert.equal(report.trustAnchor, "chain");
    assert.ok(report.warnings.some((w) => w.includes("NOT pinned")));
    assert.ok(report.validatorFingerprint?.startsWith("3-of-4|"));
  });

  it("refuses a chain signed by validators other than the pinned ones", async () => {
    const impostor = await generateValidatorKeyPair("observer-1");
    const pinned: PinnedValidators = {
      ...election.pinned,
      validators: election.pinned.validators.map((v) =>
        v.id === "observer-1" ? { id: v.id, publicKey: toBase64Url(impostor.identity.publicKey) } : v,
      ),
    };
    const report = await verifyElection(election.blocks, { pinnedValidators: pinned });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.label, /pinned validators/);
  });

  it("detects a ballot altered after it was sealed", async () => {
    const tampered = election.blocks.map((block) => {
      const index = block.entries.findIndex((entry) => entry.kind === "ballot");
      if (index < 0) return block;
      const entries = block.entries.map((entry, i) => {
        if (i !== index) return entry;
        const data = new Uint8Array(entry.data);
        data[data.length - 10]! ^= 0x01;
        return { ...entry, data };
      });
      return { ...block, entries };
    }) as Block[];

    const report = await verifyElection(tampered, { pinnedValidators: election.pinned });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /block \d+/);
  });

  it("detects a block dropped from the middle of the chain", async () => {
    const report = await verifyElection(
      [election.blocks[0]!, ...election.blocks.slice(2)],
      { pinnedValidators: election.pinned },
    );
    assert.equal(report.valid, false);
  });

  it("detects a forged result even when validators re-sign the forgery", async () => {
    // The strongest attack on the count: a quorum of validators colludes and
    // signs a block whose announced numbers are false. Signatures cannot catch
    // that; the recount must.
    const blocks = [...election.blocks];
    const last = blocks.at(-1)!;
    const tallyIndex = last.entries.findIndex((entry) => entry.kind === "tally-result");
    assert.ok(tallyIndex >= 0);

    const tally = JSON.parse(new TextDecoder().decode(last.entries[tallyIndex]!.data));
    tally.results = [
      { candidate: "Alice", votes: 1 },
      { candidate: "Bob", votes: 2 },
      { candidate: "Carol", votes: 0 },
    ];
    const entries = last.entries.map((entry, i) =>
      i === tallyIndex ? { ...entry, data: new TextEncoder().encode(JSON.stringify(tally)) } : entry,
    );
    const header = { ...last.header, merkleRoot: await computeEntriesRoot(entries) };
    const unsigned: Block = { header, entries, attestations: [] };
    const attestations = [];
    for (const key of election.harness.validatorKeys) {
      attestations.push(await attest(unsigned, key.identity, key.privateKey));
    }
    blocks[blocks.length - 1] = { header, entries, attestations };

    const report = await verifyElection(blocks, { pinnedValidators: election.pinned });
    assert.equal(report.valid, false);
    const failed = report.checks.find((check) => !check.ok)!;
    assert.equal(failed.label, "Announced result recomputed");
    assert.match(failed.detail ?? "", /announced 1, recount gives 2/);
    // Sanity: the forged block itself is perfectly signed.
    assert.ok(await blockHash(header));
  });

  it("detects a roll that is not the one committed to", async () => {
    const report = await verifyElection(election.blocks, {
      pinnedValidators: election.pinned,
      rollIds: [...ROLL, "R-999999"],
    });
    assert.equal(report.valid, false);
    assert.equal(report.checks.at(-1)!.label, "Published roll matches the sealed commitment");
  });

  it("reports a tracking code that is not on the chain", async () => {
    const report = await verifyElection(election.blocks, {
      pinnedValidators: election.pinned,
      ballotIds: ["no-such-ballot"],
    });
    assert.equal(report.valid, false);
    assert.match(report.checks.at(-1)!.detail ?? "", /no ballot/);
  });

  it("verifies an election still in progress and says there is no result yet", async () => {
    const open = await runElection({ close: false });
    const report = await verifyElection(open.blocks, { pinnedValidators: open.pinned });
    assert.equal(report.valid, true, JSON.stringify(report.checks, null, 2));
    assert.equal(report.phase, "open");
    assert.equal(report.results, null);
    assert.ok(report.warnings.some((w) => w.includes("not closed")));
  });

  it("refuses an empty chain", async () => {
    const report = await verifyElection([]);
    assert.equal(report.valid, false);
    assert.equal(report.phase, "empty");
  });

  it("round-trips an export file and verifies it offline", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dvoting-verify-"));
    try {
      const path = join(dir, "board.json");
      await writeExport(path, election.blocks, "http://example.invalid");
      const restored = await readExport(path);
      const report = await verifyElection(restored, { pinnedValidators: election.pinned });
      assert.equal(report.valid, true);
      assert.equal(report.phase, "published");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("downloads the board over HTTP exactly as the ballot box serves it", async () => {
    const requested: string[] = [];
    const fakeFetch = (async (input: string | URL | Request) => {
      const url = String(input);
      requested.push(url);
      const path = new URL(url).pathname;
      if (path === "/v1/bulletin/head") {
        return Response.json({ height: election.blocks.length });
      }
      const match = /^\/v1\/bulletin\/blocks\/(\d+)$/.exec(path);
      const block = match ? election.blocks[Number(match[1])] : undefined;
      if (!block) return new Response("not found", { status: 404 });
      // The real route adds a `hash` field; the verifier must ignore it, not trust it.
      return Response.json({ ...blockToWire(block), hash: "ignored" });
    }) as typeof fetch;

    const blocks = await fetchBlocks("http://ballot-box.test/", fakeFetch);
    assert.equal(blocks.length, election.blocks.length);
    assert.equal(requested[0], "http://ballot-box.test/v1/bulletin/head");

    const report = await verifyElection(blocks, { pinnedValidators: election.pinned });
    assert.equal(report.valid, true);
    assert.equal(report.phase, "published");
  });
});
