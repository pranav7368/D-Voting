/**
 * Sealing under concurrency.
 *
 * Found while building the second-device check: the ballot box sealed the
 * whole pending list, awaited the validators, then cleared the list. A ballot
 * accepted during that await was cleared without ever being sealed: accepted,
 * given a tracking code, and silently lost. These tests state the invariants
 * rather than one interleaving, so they hold whichever order the work runs in.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createHarness, makeSubmission, makeVoter } from "./helpers.ts";

async function onChain(harness: Awaited<ReturnType<typeof createHarness>>, kind: string, id: string) {
  return harness.ledger.hasEntry(kind, id);
}

describe("sealing never loses an accepted ballot", () => {
  it("seals every one of many concurrent casts", async () => {
    const harness = await createHarness({ maxPendingBeforeSeal: 1 });
    const submissions = await Promise.all(
      Array.from({ length: 6 }, async () => makeSubmission(harness, await makeVoter(), [1, 0, 0])),
    );

    const results = await Promise.allSettled(submissions.map((s) => harness.ballotBox.cast(s)));
    assert.ok(results.every((r) => r.status === "fulfilled"), JSON.stringify(results.filter((r) => r.status === "rejected")));
    await harness.ballotBox.sealBlock(); // anything still pending

    for (const submission of submissions) {
      assert.ok(await onChain(harness, "ballot", submission.ballot.ballotId), "an accepted ballot is missing from the chain");
    }
    assert.equal(harness.ballotBox.pendingCount, 0);
    assert.equal((await harness.ledger.verify()).valid, true);
  });

  it("keeps a ballot accepted while a seal is in flight", async () => {
    const harness = await createHarness();
    const first = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);
    const second = await makeSubmission(harness, await makeVoter(), [0, 1, 0]);
    await harness.ballotBox.cast(first);

    // Start sealing and cast at the same time.
    const [, cast] = await Promise.all([harness.ballotBox.sealBlock(), harness.ballotBox.cast(second)]);
    assert.ok(cast.trackingCode);
    await harness.ballotBox.sealBlock();

    assert.ok(await onChain(harness, "ballot", first.ballot.ballotId));
    assert.ok(await onChain(harness, "ballot", second.ballot.ballotId), "the ballot cast mid-seal was lost");
    assert.equal(harness.ballotBox.pendingCount, 0);
  });

  it("never seals a ballot after the close record", async () => {
    const harness = await createHarness({ maxPendingBeforeSeal: 1 });
    const submissions = await Promise.all(
      Array.from({ length: 4 }, async () => makeSubmission(harness, await makeVoter(), [0, 0, 1])),
    );

    // Close while ballots are arriving. Each ballot must either be refused or
    // be sealed no later than the close.
    const casts = submissions.map((s) => harness.ballotBox.cast(s));
    const close = harness.ballotBox.closePoll();
    await Promise.allSettled([...casts, close]);
    await harness.ballotBox.sealBlock();

    const blocks = await harness.ledger.blocks();
    const closeHeight = blocks.findIndex((b) => b.entries.some((e) => e.kind === "election-closed"));
    assert.ok(closeHeight >= 0, "the poll did not close");
    const late = blocks.slice(closeHeight + 1).flatMap((b) => b.entries.filter((e) => e.kind === "ballot"));
    assert.deepEqual(late, [], "a ballot was sealed after the close");
    assert.equal(harness.ballotBox.phase, "closed");
  });

  it("accepts only one of two identical ballots submitted at once, and keeps sealing", async () => {
    // Both copies pass the slow checks together. If both were accepted, the
    // ledger would refuse their block and every ballot behind it would stick.
    const harness = await createHarness();
    const submission = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);
    const results = await Promise.allSettled([harness.ballotBox.cast(submission), harness.ballotBox.cast(submission)]);
    assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);

    const next = await makeSubmission(harness, await makeVoter(), [0, 1, 0]);
    await harness.ballotBox.cast(next);
    await harness.ballotBox.sealBlock();
    assert.ok(await onChain(harness, "ballot", submission.ballot.ballotId));
    assert.ok(await onChain(harness, "ballot", next.ballot.ballotId), "sealing jammed after a duplicate");
  });

  it("refuses new ballots from the moment closing starts", async () => {
    const harness = await createHarness();
    const late = await makeSubmission(harness, await makeVoter(), [1, 0, 0]);
    const closing = harness.ballotBox.closePoll();
    await assert.rejects(() => harness.ballotBox.cast(late));
    await closing;
  });

  it("seals a tested ballot without waiting for anyone to cast", async () => {
    // Otherwise the voter's phone waits on a tested ballot that nothing seals.
    const harness = await createHarness({ maxPendingBeforeSeal: 1 });
    const voter = await makeVoter();
    const { prepareBallot } = await import("@dvoting/crypto");
    const { ELECTION } = await import("./helpers.ts");
    const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 1, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    assert.ok(await onChain(harness, "spoiled-ballot", prepared.ballot.ballotId));
  });
});
