import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MODP_2048 } from "../src/elgamal/group.ts";
import { encrypt } from "../src/elgamal/cipher.ts";
import { setupTrustees } from "../src/threshold/trustee.ts";
import { verifyBallot, type ElectionParameters } from "../src/election/ballot.ts";
import {
  auditAgainstCommitment,
  auditBallot,
  ballotCommitment,
  cheatSurvivalProbability,
  prepareBallot,
} from "../src/election/benaloh.ts";

const GROUP = MODP_2048;

const ELECTION: ElectionParameters = {
  electionId: "benaloh-test",
  candidates: ["Alice", "Bob", "Carol"],
  minSelections: 1,
  maxSelections: 1,
};

describe("cast-or-audit, honest client", () => {
  it("audits successfully when the ballot encodes the voter's choice", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const intended = [1, 0, 0];

    const prepared = await prepareBallot(ELECTION, setup.publicKey, intended);
    const result = await auditBallot(
      ELECTION,
      setup.publicKey,
      prepared.ballot,
      prepared.secret,
      intended,
    );

    assert.ok(result.ok, result.reason);
    assert.deepEqual(result.encodedSelections, intended);
  });

  it("produces a ballot that is still castable if not audited", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [0, 1, 0]);
    assert.ok(await verifyBallot(ELECTION, setup.publicKey, prepared.ballot));
  });

  it("commits to the ballot deterministically", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    assert.equal(
      await ballotCommitment(setup.publicKey, prepared.ballot),
      prepared.commitment,
    );
  });

  it("gives different commitments to different ballots", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const a = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const b = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    // Same selections, but fresh randomness -- so a distinct commitment.
    assert.notEqual(a.commitment, b.commitment);
  });
});

describe("cast-or-audit CATCHES a malicious voting client", () => {
  /**
   * A compromised app: the voter selects Alice, the app encrypts Bob.
   * Every ZK proof still verifies -- they prove well-formedness, not intent.
   */
  async function maliciousClient(
    publicKey: Awaited<ReturnType<typeof setupTrustees>>["publicKey"],
    voterSelected: number[],
    actuallyEncrypt: number[],
  ) {
    // The app builds a perfectly valid ballot for the WRONG candidate...
    const prepared = await prepareBallot(ELECTION, publicKey, actuallyEncrypt);
    // ...and lies to the voter about what it encrypted.
    return {
      prepared,
      lyingSecret: { ...prepared.secret, selections: voterSelected },
    };
  }

  it("the fraudulent ballot passes every other check", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const { prepared } = await maliciousClient(setup.publicKey, [1, 0, 0], [0, 1, 0]);

    // This is the whole problem: nothing else in the system objects.
    assert.ok(
      await verifyBallot(ELECTION, setup.publicKey, prepared.ballot),
      "a vote-swapping ballot is indistinguishable from an honest one without an audit",
    );
  });

  it("catches the client when it lies about what it encrypted", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const voterSelected = [1, 0, 0]; // Alice
    const { prepared, lyingSecret } = await maliciousClient(
      setup.publicKey,
      voterSelected,
      [0, 1, 0], // Bob
    );

    // The app claims it encrypted Alice, but the randomness it must reveal
    // re-encrypts to Bob's ciphertext, not Alice's.
    const result = await auditBallot(
      ELECTION,
      setup.publicKey,
      prepared.ballot,
      lyingSecret,
      voterSelected,
    );

    assert.ok(!result.ok);
    assert.match(result.reason!, /misbehaving/);
  });

  it("catches the client when it reveals the truth (a vote it was not told to cast)", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const voterSelected = [1, 0, 0]; // Alice
    const { prepared } = await maliciousClient(setup.publicKey, voterSelected, [0, 1, 0]);

    // If instead the app reveals honest secrets for the wrong vote, the
    // mismatch against the voter's intent is what exposes it.
    const result = await auditBallot(
      ELECTION,
      setup.publicKey,
      prepared.ballot,
      prepared.secret,
      voterSelected,
    );

    assert.ok(!result.ok);
    assert.match(result.reason!, /CHEATING/);
    assert.deepEqual(result.encodedSelections, [0, 1, 0]);
  });

  it("catches the client substituting a different ballot at audit time", async () => {
    // The app shows commitment C for a dishonest ballot, then at audit reveals
    // an entirely separate honest ballot. Binding to the recorded commitment
    // defeats this.
    const setup = setupTrustees(GROUP, 2, 3);
    const dishonest = await prepareBallot(ELECTION, setup.publicKey, [0, 1, 0]);
    const honestDecoy = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    // Voter recorded the commitment of the ballot they were actually shown.
    const result = await auditAgainstCommitment(
      ELECTION,
      setup.publicKey,
      honestDecoy.ballot,
      honestDecoy.secret,
      dishonest.commitment,
      [1, 0, 0],
    );

    assert.ok(!result.ok);
    assert.match(result.reason!, /substituted a different ballot/);
  });

  it("accepts an honest audit against its own commitment", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [0, 0, 1]);
    const result = await auditAgainstCommitment(
      ELECTION,
      setup.publicKey,
      prepared.ballot,
      prepared.secret,
      prepared.commitment,
      [0, 0, 1],
    );
    assert.ok(result.ok, result.reason);
  });
});

describe("audit input validation", () => {
  it("rejects audit data for a different ballot", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const a = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const b = await prepareBallot(ELECTION, setup.publicKey, [0, 1, 0]);

    const result = await auditBallot(ELECTION, setup.publicKey, a.ballot, b.secret);
    assert.ok(!result.ok);
    assert.match(result.reason!, /different ballot/);
  });

  it("rejects tampered randomness", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const tampered = {
      ...prepared.secret,
      randomness: prepared.secret.randomness.map((r, i) => (i === 0 ? r + 1n : r)),
    };
    const result = await auditBallot(ELECTION, setup.publicKey, prepared.ballot, tampered);
    assert.ok(!result.ok);
  });

  it("rejects a malformed ballot", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const broken = {
      ...prepared.ballot,
      choices: [encrypt(setup.publicKey, 1n).ciphertext, ...prepared.ballot.choices.slice(1)],
    };
    const result = await auditBallot(ELECTION, setup.publicKey, broken, prepared.secret);
    assert.ok(!result.ok);
    assert.match(result.reason!, /zero-knowledge verification/);
  });

  it("rejects mismatched array lengths", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const prepared = await prepareBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const short = { ...prepared.secret, randomness: prepared.secret.randomness.slice(0, 2) };
    assert.ok(!(await auditBallot(ELECTION, setup.publicKey, prepared.ballot, short)).ok);

    const result = await auditBallot(
      ELECTION,
      setup.publicKey,
      prepared.ballot,
      prepared.secret,
      [1, 0],
    );
    assert.ok(!result.ok);
    assert.match(result.reason!, /wrong length/);
  });
});

describe("detection probability", () => {
  it("computes the chance a cheating client survives auditing", () => {
    // A client cheating on every ballot is caught by the first audit.
    assert.equal(cheatSurvivalProbability(1, 1), 0);
    // Cheating on 10% of ballots survives one audit 90% of the time...
    assert.ok(Math.abs(cheatSurvivalProbability(0.1, 1) - 0.9) < 1e-9);
    // ...but only ~35% across 10 audits, and ~0.0027% across 100.
    assert.ok(cheatSurvivalProbability(0.1, 10) < 0.35);
    assert.ok(cheatSurvivalProbability(0.1, 100) < 0.0001);
    // Never auditing means never detecting.
    assert.equal(cheatSurvivalProbability(0.5, 0), 1);
  });

  it("rejects nonsense inputs", () => {
    assert.throws(() => cheatSurvivalProbability(1.5, 1), /cheatRate/);
    assert.throws(() => cheatSurvivalProbability(0.5, -1), /auditCount/);
  });
});
