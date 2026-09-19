/**
 * The election's life, as recorded on the chain.
 *
 * These tests are about the boundary between what an administrator may do and
 * what the record says was done. Almost all of them are written from the side
 * of someone trying to change an election after it started.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createApp } from "../src/app.ts";
import { BallotBoxError } from "../src/ballot-box.ts";
import {
  assertIdentityMatches,
  ElectionRecordError,
  readElectionRecord,
  validateCandidates,
  type ElectionRecord,
} from "../src/election-record.ts";
import { ELECTION, createHarness, makeSubmission, makeVoter } from "./helpers.ts";

describe("an election is composed before it is sealed", () => {
  it("starts in setup, accepting no ballots", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    assert.equal(harness.ballotBox.phase, "setup");
    assert.equal(harness.ballotBox.isOpen, false);
    assert.equal(await harness.ledger.height(), 0);

    const submission = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);
    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "election_not_open",
    );
  });

  it("lets the ballot be edited while in setup", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    const updated = harness.ballotBox.updateDraft({
      candidates: ["Party A", "Party B", "Party C", "NOTA"],
    });
    assert.deepEqual(updated.candidates, ["Party A", "Party B", "Party C", "NOTA"]);
  });

  it("REFUSES to edit the ballot once the poll has opened", async () => {
    // The single most damaging thing an administrator could do, so the ability
    // stops existing rather than being guarded by a confirmation.
    const harness = await createHarness();
    assert.throws(
      () => harness.ballotBox.updateDraft({ candidates: ["Only Me", "Nobody"] }),
      (error: BallotBoxError) => error.code === "election_sealed",
    );
  });

  it("REFUSES a ballot with duplicate candidate names", () => {
    // Two identical names are indistinguishable to the voter and the result
    // would be unattributable.
    assert.throws(
      () => validateCandidates(["Alice", "Bob", "Alice"]),
      (error: ElectionRecordError) => /distinct/.test(error.message),
    );
  });

  it("REFUSES a ballot with fewer than two candidates", () => {
    assert.throws(() => validateCandidates(["Alice"]), ElectionRecordError);
  });

  it("REFUSES a maximum above the number of candidates", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    assert.throws(
      () => harness.ballotBox.updateDraft({ maxSelections: 9 }),
      (error: BallotBoxError) => error.code === "invalid_selections",
    );
  });

  it("defaults to no display name", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    assert.equal(harness.ballotBox.name, null);
  });

  it("lets the display name be set and cleared while in setup", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    const set = harness.ballotBox.updateDraft({ name: "  General Election 2026  " });
    // Trimmed, and nothing here is bound into any proof -- it is prose, not an
    // identifier. electionId is untouched.
    assert.equal(set.name, "General Election 2026");
    assert.equal(harness.ballotBox.name, "General Election 2026");
    assert.equal(harness.ballotBox.election.electionId, ELECTION.electionId);

    const cleared = harness.ballotBox.updateDraft({ name: null });
    assert.equal(cleared.name, null);
  });

  it("treats a whitespace-only name as no name at all", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    const updated = harness.ballotBox.updateDraft({ name: "   " });
    assert.equal(updated.name, null);
  });

  it("REFUSES to rename the election once the poll has opened", async () => {
    const harness = await createHarness();
    assert.throws(
      () => harness.ballotBox.updateDraft({ name: "Too Late" }),
      (error: BallotBoxError) => error.code === "election_sealed",
    );
  });
});

describe("opening the poll seals the election", () => {
  it("commits the whole configuration to block 0", async () => {
    const harness = await createHarness();

    const record = await readElectionRecord(harness.ledger, ELECTION.electionId);
    assert.ok(record, "no election record on the chain");
    assert.equal(record.electionId, ELECTION.electionId);
    assert.deepEqual(record.candidates, ELECTION.candidates);
    assert.equal(record.quorum, harness.ledger.validatorSet.quorum);
    assert.equal(record.validators.length, 4);
    assert.equal(record.trustees.threshold, 2);
    assert.equal(record.trustees.publicShares.length, 3);
    assert.ok(record.issuerKeyId.length > 0);
    assert.ok(record.electionPublicKey.length > 0);
    assert.equal(record.name, null, "the default harness never sets a name");
  });

  it("seals whatever display name was set before opening", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    harness.ballotBox.updateDraft({ name: "General Election 2026" });
    await harness.ballotBox.openPoll();

    const record = await readElectionRecord(harness.ledger, ELECTION.electionId);
    assert.equal(record?.name, "General Election 2026");

    const described = await harness.ballotBox.describe();
    assert.equal(described.name, "General Election 2026");
    // The identifier every proof and every check is bound to never changes.
    assert.equal(described.electionId, ELECTION.electionId);
  });

  it("carries NO private material", async () => {
    const harness = await createHarness();
    const record = await readElectionRecord(harness.ledger, ELECTION.electionId);
    const text = JSON.stringify(record);
    for (const forbidden of ["privateKey", "keyShare", "share\":", "secret", "pepper"]) {
      assert.ok(!text.includes(forbidden), `the sealed record leaked ${forbidden}`);
    }
  });

  it("REFUSES to open twice", async () => {
    const harness = await createHarness();
    await assert.rejects(
      () => harness.ballotBox.openPoll(),
      (error: BallotBoxError) => error.code === "already_open",
    );
  });

  it("REFUSES a closing time that has already passed", async () => {
    // Sealing an already-expired election would disenfranchise everyone, and
    // could not be undone.
    const harness = await createHarness({ leaveInSetup: true });
    await assert.rejects(
      () => harness.ballotBox.openPoll({ closesAt: new Date(Date.now() - 60_000).toISOString() }),
      (error: BallotBoxError) => error.code === "invalid_schedule",
    );
  });

  it("REFUSES a poll that closes before it opens", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    await assert.rejects(
      () =>
        harness.ballotBox.openPoll({
          opensAt: new Date(Date.now() + 120_000).toISOString(),
          closesAt: new Date(Date.now() + 60_000).toISOString(),
        }),
      (error: BallotBoxError) => error.code === "invalid_schedule",
    );
  });

  it("REFUSES a roll commitment that is not a digest", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    await assert.rejects(
      () => harness.ballotBox.openPoll({ rollCommitment: "not a digest!!" }),
      (error: BallotBoxError) => error.code === "invalid_roll_commitment",
    );
  });
});

describe("the schedule is enforced by the clock", () => {
  it("accepts no ballots before the opening time", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    await harness.ballotBox.openPoll({ opensAt: new Date(Date.now() + 3_600_000).toISOString() });

    assert.equal(harness.ballotBox.phase, "scheduled");
    const submission = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);
    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "election_not_open",
    );
  });

  it("closes itself when the closing time passes, with nobody pressing anything", async () => {
    // A deadline that only takes effect if an operator remembers to act is not
    // a deadline.
    const harness = await createHarness({ leaveInSetup: true });
    await harness.ballotBox.openPoll({ closesAt: new Date(Date.now() + 1_000).toISOString() });
    assert.equal(harness.ballotBox.phase, "voting");
    const submission = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);

    await new Promise((resolve) => setTimeout(resolve, 1_100));

    assert.equal(harness.ballotBox.phase, "closed");
    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "election_closed",
    );
  });
});

describe("closing is one-way and on the record", () => {
  it("writes a close entry to the chain", async () => {
    const harness = await createHarness();
    const record = await harness.ballotBox.closePoll("administrator");

    assert.equal(record.reason, "administrator");
    assert.ok(await harness.ledger.hasEntry("election-closed", ELECTION.electionId));
    assert.equal(harness.ballotBox.phase, "closed");
  });

  it("REFUSES to close twice", async () => {
    const harness = await createHarness();
    await harness.ballotBox.closePoll();
    await assert.rejects(
      () => harness.ballotBox.closePoll(),
      (error: BallotBoxError) => error.code === "already_closed",
    );
  });

  it("REFUSES to close an election that was never opened", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    await assert.rejects(
      () => harness.ballotBox.closePoll(),
      (error: BallotBoxError) => error.code === "not_open",
    );
  });

  it("refuses to audit a ballot after closing", async () => {
    // An audit publishes a ballot's randomness. Accepting one after the close
    // would add a decryptable entry to a sealed record.
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);
    await harness.ballotBox.closePoll();

    await assert.rejects(
      () =>
        harness.ballotBox.spoil({
          ballot: submission.ballot,
          auditSecret: { ballotId: submission.ballot.ballotId, selections: [1, 0, 0], randomness: [] },
        }),
      (error: BallotBoxError) => error.code === "election_closed",
    );
  });
});

describe("a process must agree with the election it is serving", () => {
  const sealed: ElectionRecord = {
    recordVersion: "dvoting/election-config/v1",
    electionId: "e",
    name: null,
    candidates: ["A", "B"],
    minSelections: 1,
    maxSelections: 1,
    group: "modp3072",
    issuerKeyId: "issuer-key-id",
    electionPublicKey: "election-key",
    trustees: { threshold: 2, total: 3, publicShares: [] },
    validators: [{ id: "v1", publicKey: "k1" }],
    quorum: 1,
    rollCommitment: null,
    opensAt: null,
    closesAt: null,
    sealedAt: new Date().toISOString(),
  };
  const running = {
    group: "modp3072",
    issuerKeyId: "issuer-key-id",
    electionPublicKey: "election-key",
    validators: [{ id: "v1", publicKey: "k1" }],
    quorum: 1,
  };

  it("accepts a process configured exactly as the election was sealed", () => {
    assert.doesNotThrow(() => assertIdentityMatches(sealed, running));
  });

  it("REFUSES to serve a swapped issuer key", () => {
    // Substituting the issuer key would let a different authority decide who
    // may vote, without anything else visibly changing.
    assert.throws(
      () => assertIdentityMatches(sealed, { ...running, issuerKeyId: "someone-elses-key" }),
      (error: ElectionRecordError) => /issuer key/.test(error.message),
    );
  });

  it("REFUSES to serve a swapped election key", () => {
    // Ballots encrypted to a key the trustees do not hold can never be counted.
    assert.throws(
      () => assertIdentityMatches(sealed, { ...running, electionPublicKey: "other" }),
      ElectionRecordError,
    );
  });

  it("REFUSES a validator set that differs from the sealed one", () => {
    assert.throws(
      () =>
        assertIdentityMatches(sealed, {
          ...running,
          validators: [{ id: "v1", publicKey: "k1" }, { id: "attacker", publicKey: "k2" }],
        }),
      (error: ElectionRecordError) => /validator set/.test(error.message),
    );
  });

  it("REFUSES a lowered quorum", () => {
    // Dropping the quorum would let fewer authorities sign off on a block.
    assert.throws(() => assertIdentityMatches(sealed, { ...running, quorum: 0 }), ElectionRecordError);
  });
});

describe("the public election descriptor", () => {
  it("reports the phase, the schedule and the roll commitment", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    await harness.ballotBox.openPoll({
      rollCommitment: "bVmNaqurDBS0xuyVOQDY6D8trzsZVWc-8v-I2C6Z6Dw",
    });

    const server = createApp({ ballotBox: harness.ballotBox });
    const body = (await (await server.request("/v1/election")).json()) as Record<string, unknown>;

    assert.equal(body.phase, "voting");
    assert.equal(body.open, true);
    assert.equal(body.rollCommitment, "bVmNaqurDBS0xuyVOQDY6D8trzsZVWc-8v-I2C6Z6Dw");
    assert.deepEqual(body.trustees, { threshold: 2, total: 3 });
  });
});
