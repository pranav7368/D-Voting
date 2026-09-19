import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  LocalBlindSigner,
  blind,
  createBallot,
  decryptTally,
  finalize,
  generateCredential,
  partialDecrypt,
  type PartialDecryption,
} from "@dvoting/crypto";
import { generateIssuerKeyPair } from "@dvoting/crypto/keygen";
import { verifyMerkleProof } from "@dvoting/ledger";
import { encodeEntry } from "@dvoting/ledger";

import { BallotBoxError, credentialFingerprint } from "../src/ballot-box.ts";
import { tallyFromChain } from "../src/chain-tally.ts";
import {
  ELECTION,
  GROUP,
  createHarness,
  issuerKeys,
  makeSubmission,
  makeVoter,
} from "./helpers.ts";

describe("casting ballots", () => {
  it("accepts a valid ballot from an eligible voter", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    const result = await harness.ballotBox.cast(submission);
    assert.equal(result.ballotId, submission.ballot.ballotId);
    assert.equal(result.status, "pending");
    assert.equal(result.supersedes, 0);
    assert.equal(harness.ballotBox.pendingCount, 1);
  });

  it("REJECTS a ballot with no valid credential", async () => {
    // The eligibility gate: without the RA's blind signature you cannot vote.
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    const forged = { ...submission, credentialSignature: new Uint8Array(256).fill(3) };
    await assert.rejects(
      () => harness.ballotBox.cast(forged),
      (error: BallotBoxError) => error.code === "invalid_credential",
    );
  });

  it("REJECTS a credential signed by a different Registration Authority", async () => {
    const harness = await createHarness();
    const rogueKeys = generateIssuerKeyPair(2048, issuerKeys.publicKey.suite);
    const rogueSigner = new LocalBlindSigner(rogueKeys.privateKey);

    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(rogueKeys.publicKey, credential);
    const signature = await finalize(
      rogueKeys.publicKey,
      credential,
      await rogueSigner.blindSign(blindedMessage),
      inverse,
    );

    const fingerprint = await credentialFingerprint(credential);
    const ballot = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: fingerprint,
    });

    await assert.rejects(
      () => harness.ballotBox.cast({ credential, credentialSignature: signature, ballot }),
      (error: BallotBoxError) => error.code === "invalid_credential",
    );
  });

  it("REJECTS a ballot not bound to the supplied credential", async () => {
    // Stops an attacker from re-submitting someone else's ballot under their
    // own credential to consume the ballot id and block the real voter.
    const harness = await createHarness();
    const victim = await makeVoter();
    const attacker = await makeVoter();

    const victimSubmission = await makeSubmission(harness, victim, [1, 0, 0]);
    await assert.rejects(
      () =>
        harness.ballotBox.cast({
          credential: attacker.credential,
          credentialSignature: attacker.signature,
          ballot: victimSubmission.ballot,
        }),
      (error: BallotBoxError) => error.code === "credential_mismatch",
    );
  });

  it("REJECTS a ballot with invalid zero-knowledge proofs", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    const tampered = {
      ...submission,
      ballot: {
        ...submission.ballot,
        choices: [
          { alpha: submission.ballot.choices[1]!.alpha, beta: submission.ballot.choices[1]!.beta },
          submission.ballot.choices[1]!,
          submission.ballot.choices[2]!,
        ],
      },
    };

    await assert.rejects(
      () => harness.ballotBox.cast(tampered),
      (error: BallotBoxError) => error.code === "invalid_ballot",
    );
  });

  it("REJECTS an exact replay of a submitted ballot", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    await harness.ballotBox.cast(submission);
    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "duplicate_ballot",
    );
  });

  it("rejects a replay even after the ballot is sealed on chain", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    await harness.ballotBox.cast(submission);
    await harness.ballotBox.sealBlock();

    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "duplicate_ballot",
    );
  });

  it("rejects a ballot for another election", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const other = { ...ELECTION, electionId: "some-other-election" };
    const submission = await makeSubmission(harness, voter, [1, 0, 0], other);

    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "wrong_election",
    );
  });

  it("refuses ballots once the election is closed", async () => {
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    await harness.ballotBox.closePoll();
    await assert.rejects(
      () => harness.ballotBox.cast(submission),
      (error: BallotBoxError) => error.code === "election_closed",
    );
  });

  it("seals automatically once the pending threshold is reached", async () => {
    const harness = await createHarness({ maxPendingBeforeSeal: 2 });

    // Height 1 already: block 0 sealed the election configuration.
    const first = await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
    assert.equal(first.status, "pending");
    assert.equal(await harness.ledger.height(), 1);

    const second = await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [0, 1, 0]));
    assert.equal(second.status, "recorded");
    assert.equal(await harness.ledger.height(), 2);
    assert.equal(harness.ballotBox.pendingCount, 0);
  });
});

describe("the ledger record", () => {
  it("produces a verifiable inclusion proof for a cast ballot", async () => {
    // The voter-facing guarantee: "my ballot is in the log", checkable offline.
    const harness = await createHarness();
    const voter = await makeVoter();
    const submission = await makeSubmission(harness, voter, [1, 0, 0]);

    await harness.ballotBox.cast(submission);
    for (let i = 0; i < 4; i++) {
      await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [0, 1, 0]));
    }
    const block = await harness.ballotBox.sealBlock();
    assert.ok(block);

    const located = await harness.ledger.locateEntry("ballot", submission.ballot.ballotId);
    assert.ok(located);
    assert.ok(
      await verifyMerkleProof(encodeEntry(located.entry), located.proof, located.merkleRoot),
    );
    // The root the proof verifies against is the one in the signed header.
    assert.deepEqual(Array.from(located.merkleRoot), Array.from(block.header.merkleRoot));
  });

  it("produces a chain that verifies from genesis", async () => {
    const harness = await createHarness();
    for (let i = 0; i < 3; i++) {
      await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
      await harness.ballotBox.sealBlock();
    }

    const report = await harness.ledger.verify();
    assert.deepEqual(report.errors, []);
    assert.ok(report.valid);
    // Block 0 seals the election configuration, then one block per ballot.
    assert.equal(report.blockCount, 4);
    assert.equal(report.entryCount, 4);
  });

  it("rotates block proposers round-robin", async () => {
    const harness = await createHarness();
    const proposers: string[] = [];
    for (let i = 0; i < 4; i++) {
      await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
      const block = await harness.ballotBox.sealBlock();
      proposers.push(block!.header.proposer);
    }
    // The configuration block took the commission's turn, so the ballots start
    // at the next validator in the rotation.
    assert.deepEqual(proposers, [
      "observer-1",
      "observer-2",
      "observer-3",
      "election-commission",
    ]);
  });
});

describe("tallying from the chain", () => {
  it("counts ballots read back off the ledger", async () => {
    const harness = await createHarness();
    const votes = [
      [1, 0, 0],
      [1, 0, 0],
      [0, 1, 0],
      [0, 0, 1],
      [1, 0, 0],
    ];
    for (const vote of votes) {
      await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), vote));
    }
    await harness.ballotBox.sealBlock();

    const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
    assert.equal(input.counted.length, 5);
    assert.equal(input.superseded.length, 0);
    assert.deepEqual(input.rejected, []);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of input.encryptedTotals) {
      const partials: PartialDecryption[] = [];
      for (const keyShare of harness.trustees.keyShares.slice(0, 2)) {
        partials.push(await partialDecrypt(GROUP, ELECTION.electionId, keyShare, total));
      }
      partialsByCandidate.push(partials);
    }

    const result = await decryptTally(
      GROUP,
      ELECTION.electionId,
      ELECTION.candidates,
      input.encryptedTotals,
      partialsByCandidate,
      harness.trustees.publicShares,
      harness.trustees.threshold,
      input.counted.length,
    );

    assert.deepEqual(result.results.map((r) => r.votes), [3, 1, 1]);
  });

  it("counts only the LAST ballot per credential (coercion mitigation)", async () => {
    // A coerced voter complies, then quietly re-votes. Only the final ballot
    // counts, and the earlier one is marked superseded.
    const harness = await createHarness();
    const coerced = await makeVoter();

    // Under duress: votes for Bob.
    await harness.ballotBox.cast(await makeSubmission(harness, coerced, [0, 1, 0]));
    await harness.ballotBox.sealBlock();

    // Later, in private: votes for Alice.
    const revote = await harness.ballotBox.cast(await makeSubmission(harness, coerced, [1, 0, 0]));
    assert.equal(revote.supersedes, 1);
    await harness.ballotBox.sealBlock();

    const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
    assert.equal(input.counted.length, 1);
    assert.equal(input.superseded.length, 1);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of input.encryptedTotals) {
      const partials: PartialDecryption[] = [];
      for (const keyShare of harness.trustees.keyShares.slice(0, 2)) {
        partials.push(await partialDecrypt(GROUP, ELECTION.electionId, keyShare, total));
      }
      partialsByCandidate.push(partials);
    }

    const result = await decryptTally(
      GROUP,
      ELECTION.electionId,
      ELECTION.candidates,
      input.encryptedTotals,
      partialsByCandidate,
      harness.trustees.publicShares,
      harness.trustees.threshold,
      input.counted.length,
    );

    // Alice 1, Bob 0 -- the coerced vote was superseded.
    assert.deepEqual(result.results.map((r) => r.votes), [1, 0, 0]);
  });

  it("re-verifies every ballot rather than trusting the ballot box", async () => {
    const harness = await createHarness();
    for (let i = 0; i < 3; i++) {
      await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
    }
    await harness.ballotBox.sealBlock();

    // An observer with only the chain and the public keys reaches the same set.
    const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
    assert.equal(input.counted.length, 3);
    assert.deepEqual(input.rejected, []);
  });

  it("reports an empty chain as an empty tally", async () => {
    const harness = await createHarness();
    const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
    assert.equal(input.counted.length, 0);
    assert.equal(input.encryptedTotals.length, ELECTION.candidates.length);
  });
});
