import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  auditBallot,
  createBallot,
  prepareBallot,
  verifyBallot,
} from "@dvoting/crypto";

import { BallotBoxError, SPOILED_ENTRY_KIND } from "../src/ballot-box.ts";
import { tallyFromChain } from "../src/chain-tally.ts";
import { ELECTION, createHarness, makeVoter } from "./helpers.ts";

describe("cast-or-audit at the ballot box", () => {
  it("spoils an audited ballot and records it on the chain", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();

    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });

    const result = await harness.ballotBox.spoil({
      ballot: prepared.ballot,
      auditSecret: prepared.secret,
    });
    assert.ok(result.encryptionConsistent, result.reason);
    assert.deepEqual(result.encodedSelections, [1, 0, 0]);

    await harness.ballotBox.sealBlock();
    assert.ok(await harness.ledger.hasEntry(SPOILED_ENTRY_KIND, prepared.ballot.ballotId));
  });

  it("REFUSES to cast a ballot that was audited", async () => {
    // Its randomness is public, so casting it would put a publicly-readable
    // vote into the tally.
    const harness = await createHarness();
    const voter = await makeVoter();

    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });

    await assert.rejects(
      () =>
        harness.ballotBox.cast({
          credential: voter.credential,
          credentialSignature: voter.signature,
          ballot: prepared.ballot,
        }),
      (error: BallotBoxError) => error.code === "ballot_spoiled",
    );
  });

  it("still refuses after the spoiled ballot is sealed on chain", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();

    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    await harness.ballotBox.sealBlock();

    await assert.rejects(
      () =>
        harness.ballotBox.cast({
          credential: voter.credential,
          credentialSignature: voter.signature,
          ballot: prepared.ballot,
        }),
      (error: BallotBoxError) => error.code === "ballot_spoiled",
    );
  });

  it("REFUSES to audit a ballot that was already cast", async () => {
    // Otherwise a coercer could force a voter to "audit" their cast ballot,
    // revealing how they voted.
    const harness = await createHarness();
    const voter = await makeVoter();

    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot: prepared.ballot,
    });

    await assert.rejects(
      () => harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret }),
      (error: BallotBoxError) => error.code === "already_cast",
    );
  });

  it("lets the voter audit, then cast a fresh ballot successfully", async () => {
    // The real flow: audit as many times as you like, then cast a new ballot.
    const harness = await createHarness();
    const voter = await makeVoter();

    for (let i = 0; i < 2; i++) {
      const trial = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
        credentialFingerprint: voter.fingerprint,
      });
      const audit = await auditBallot(
        ELECTION,
        harness.trustees.publicKey,
        trial.ballot,
        trial.secret,
        [1, 0, 0],
      );
      assert.ok(audit.ok, audit.reason);
      await harness.ballotBox.spoil({ ballot: trial.ballot, auditSecret: trial.secret });
    }

    const real = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    const cast = await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot: real,
    });
    assert.equal(cast.ballotId, real.ballotId);
  });

  it("excludes spoiled ballots from the tally", async () => {
    const harness = await createHarness();

    // One voter audits twice then casts; another just casts.
    const auditor = await makeVoter();
    for (let i = 0; i < 2; i++) {
      const trial = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 1, 0], {
        credentialFingerprint: auditor.fingerprint,
      });
      await harness.ballotBox.spoil({ ballot: trial.ballot, auditSecret: trial.secret });
    }
    const real = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: auditor.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: auditor.credential,
      credentialSignature: auditor.signature,
      ballot: real,
    });

    const other = await makeVoter();
    const otherBallot = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: other.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: other.credential,
      credentialSignature: other.signature,
      ballot: otherBallot,
    });

    await harness.ballotBox.sealBlock();

    const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
    // Two counted ballots; the two spoiled ones are not ballots at all.
    assert.equal(input.counted.length, 2);
    assert.equal(input.superseded.length, 0);
    assert.deepEqual(input.rejected, []);
  });

  it("records an INCONSISTENT audit as evidence rather than dropping it", async () => {
    // A client that lies about its own randomness is caught by the ballot box
    // alone, and the failure must land on the public record.
    const harness = await createHarness();
    const voter = await makeVoter();

    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 1, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    // The client claims it encrypted Alice when the ciphertext says Bob.
    const lying = { ...prepared.secret, selections: [1, 0, 0] };

    const result = await harness.ballotBox.spoil({
      ballot: prepared.ballot,
      auditSecret: lying,
    });
    assert.equal(result.encryptionConsistent, false);
    assert.match(result.reason!, /misbehaving/);

    await harness.ballotBox.sealBlock();
    const located = await harness.ledger.locateEntry(SPOILED_ENTRY_KIND, prepared.ballot.ballotId);
    assert.ok(located);
    const record = JSON.parse(new TextDecoder().decode(located.entry.data));
    assert.equal(record.encryptionConsistent, false);
  });

  it("publishes WHAT a ballot encrypted, without learning the voter's intent", async () => {
    // The privacy boundary: the ballot box establishes what the ciphertext
    // contains, but is never told what the voter wanted. A client that swaps
    // the vote is internally consistent, so only the voter can catch it.
    const harness = await createHarness();
    const voter = await makeVoter();

    // Voter picked Alice; the app encrypts Bob and reveals honest randomness.
    const swapped = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 1, 0], {
      credentialFingerprint: voter.fingerprint,
    });

    const result = await harness.ballotBox.spoil({
      ballot: swapped.ballot,
      auditSecret: swapped.secret,
    });

    // Consistent -- the server has no basis to object.
    assert.equal(result.encryptionConsistent, true);
    // ...but it publishes what was actually encrypted, and the voter sees Bob.
    assert.deepEqual(result.encodedSelections, [0, 1, 0]);

    const voterCheck = await auditBallot(
      ELECTION,
      harness.trustees.publicKey,
      swapped.ballot,
      swapped.secret,
      [1, 0, 0], // what the voter actually chose
    );
    assert.ok(!voterCheck.ok);
    assert.match(voterCheck.reason!, /CHEATING/);
  });

  it("rejects audit data for a different ballot", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();

    const a = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    const b = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 1, 0], {
      credentialFingerprint: voter.fingerprint,
    });

    await assert.rejects(
      () => harness.ballotBox.spoil({ ballot: a.ballot, auditSecret: b.secret }),
      (error: BallotBoxError) => error.code === "audit_mismatch",
    );
  });

  it("a prepared ballot is a normal, valid ballot until audited", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 0, 1], {
      credentialFingerprint: voter.fingerprint,
    });
    assert.ok(await verifyBallot(ELECTION, harness.trustees.publicKey, prepared.ballot));
  });
});
