/**
 * Validators re-verify ballots before attesting.
 *
 * Found while preparing the deployment: the ledger offered validators an
 * entry-check hook, but no service switched it on, so validators attested
 * blocks without looking at the ballots inside, while the documentation said
 * otherwise. These tests pin the behaviour the documentation describes.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createBallot } from "@dvoting/crypto";

import { ballotToWire } from "../src/wire.ts";
import { ELECTION, GROUP, createHarness, makeSubmission, makeVoter } from "./helpers.ts";

describe("validators re-verify every ballot they attest", () => {
  it("seals an honest ballot", async () => {
    const harness = await createHarness({ verifyingValidators: true });
    const submission = await makeSubmission(harness, await makeVoter(), [0, 1, 0]);
    await harness.ballotBox.cast(submission);
    await harness.ballotBox.sealBlock();
    assert.ok(await harness.ledger.hasEntry("ballot", submission.ballot.ballotId));
  });

  it("REFUSES a block carrying a ballot whose proofs do not verify", async () => {
    // A ballot box that skipped its own checks (or was compromised) proposes
    // a ballot stuffed with two votes. Its proofs cannot be valid.
    const harness = await createHarness({ verifyingValidators: true });
    const honest = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0]);
    const stuffed = { ...honest, choices: [honest.choices[0]!, honest.choices[0]!, honest.choices[2]!] };
    const entry = {
      kind: "ballot",
      id: stuffed.ballotId,
      data: new TextEncoder().encode(JSON.stringify(ballotToWire(GROUP, stuffed))),
    };
    await assert.rejects(() => harness.ballotBox.sealBlock([entry]), /quorum|verification/);
    assert.equal(await harness.ledger.hasEntry("ballot", stuffed.ballotId), false);
  });

  it("REFUSES a ballot for a different election", async () => {
    const harness = await createHarness({ verifyingValidators: true });
    const foreign = await createBallot({ ...ELECTION, electionId: "another-election" }, harness.trustees.publicKey, [1, 0, 0]);
    const entry = {
      kind: "ballot",
      id: foreign.ballotId,
      data: new TextEncoder().encode(JSON.stringify(ballotToWire(GROUP, foreign))),
    };
    await assert.rejects(() => harness.ballotBox.sealBlock([entry]));
  });
});
