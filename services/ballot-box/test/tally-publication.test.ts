import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  createBallot,
  decryptTally,
  encodeElement,
  partialDecrypt,
  toBase64Url,
  type PartialDecryption,
} from "@dvoting/crypto";

import { BallotBoxError } from "../src/ballot-box.ts";
import { tallyFromChain } from "../src/chain-tally.ts";
import {
  buildPublishedTally,
  encodeTally,
  readPublishedTally,
  verifyPublishedTally,
  type PublishedTally,
} from "../src/tally-publication.ts";
import { ELECTION, GROUP, createHarness, makeVoter } from "./helpers.ts";

type Harness = Awaited<ReturnType<typeof createHarness>>;

/** Run a real election and publish the result on the chain. */
async function runElection(votes: number[][] = [[1, 0, 0], [1, 0, 0], [0, 1, 0]]) {
  const harness = await createHarness();

  for (const selections of votes) {
    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, harness.trustees.publicKey, selections, {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot,
    });
  }
  await harness.ballotBox.sealBlock();
  await harness.ballotBox.closePoll();

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
  return { harness, tally };
}

function verify(harness: Harness, tally: PublishedTally) {
  return verifyPublishedTally(harness.ledger, ELECTION, harness.trustees.publicKey, tally);
}

describe("publishing the result", () => {
  it("seals a recountable result onto the chain", async () => {
    const { harness, tally } = await runElection();

    const onChain = await readPublishedTally(harness.ledger, ELECTION.electionId);
    assert.ok(onChain, "no tally found on the chain");
    assert.deepEqual(onChain.results, tally.results);
    assert.deepEqual(onChain.results.map((r) => r.votes), [2, 1, 0]);

    assert.ok((await harness.ledger.verify()).valid);
  });

  it("REFUSES to publish while the election is still open", async () => {
    // A running total lets late voters see the state of the race, and lets an
    // operator decide whether to keep counting based on who is winning.
    const harness = await createHarness();
    await assert.rejects(
      () => harness.ballotBox.publishTally({ encode: () => new Uint8Array([1]) }),
      (error: BallotBoxError) => error.code === "election_open",
    );
  });

  it("REFUSES to publish a second, different result", async () => {
    const { harness, tally } = await runElection();
    await assert.rejects(
      () => harness.ballotBox.publishTally({ encode: () => encodeTally(tally) }),
      (error: BallotBoxError) => error.code === "tally_already_published",
    );
  });

  it("seals a ballot that was still pending when the election closed", async () => {
    // A ballot accepted seconds before the deadline must not be stranded
    // outside the record: closing seals whatever is pending into the same block
    // as the close entry.
    const harness = await createHarness();
    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot,
    });
    assert.equal(harness.ballotBox.pendingCount, 1, "the ballot should still be pending");

    await harness.ballotBox.closePoll();

    assert.equal(harness.ballotBox.pendingCount, 0);
    assert.ok(await harness.ledger.hasEntry("ballot", ballot.ballotId));
    assert.ok(await harness.ledger.hasEntry("election-closed", ELECTION.electionId));
  });
});

describe("anyone can recount from the chain", () => {
  it("accepts an honest result", async () => {
    const { harness, tally } = await runElection();
    const report = await verify(harness, tally);

    assert.ok(report.valid, JSON.stringify(report.checks, null, 2));
    assert.deepEqual(report.recomputedResults?.map((r) => r.votes), [2, 1, 0]);

    const labels = report.checks.map((c) => c.label);
    assert.ok(labels.includes("Homomorphic totals recomputed"));
    assert.ok(labels.includes("Trustee decryption proofs verify"));
    assert.ok(labels.includes("Announced result recomputed"));
  });

  it("recounts a larger election correctly", async () => {
    const votes = [
      [1, 0, 0], [1, 0, 0], [1, 0, 0], [1, 0, 0],
      [0, 1, 0], [0, 1, 0],
      [0, 0, 1],
    ];
    const { harness, tally } = await runElection(votes);
    const report = await verify(harness, tally);
    assert.ok(report.valid);
    assert.deepEqual(report.recomputedResults?.map((r) => r.votes), [4, 2, 1]);
  });
});

describe("a fabricated result is caught", () => {
  it("REJECTS announced numbers that do not match the ballots", async () => {
    // The headline attack: the operator simply announces different numbers.
    const { harness, tally } = await runElection();

    const rigged: PublishedTally = {
      ...tally,
      results: [
        { candidate: "Alice", votes: 0 },
        { candidate: "Bob", votes: 3 },
        { candidate: "Carol", votes: 0 },
      ],
    };

    const report = await verify(harness, rigged);
    assert.ok(!report.valid);
    const failure = report.checks.find((c) => !c.ok);
    assert.match(failure!.detail!, /announced 0, recount gives 2|announced 3, recount gives/);
  });

  it("REJECTS encrypted totals that are not the sum of the ballots", async () => {
    // Swapping in a different ciphertext would let a rigged result decrypt
    // "correctly" from its own proofs.
    const { harness, tally } = await runElection();

    const swapped: PublishedTally = {
      ...tally,
      encryptedTotals: [tally.encryptedTotals[1]!, tally.encryptedTotals[0]!, tally.encryptedTotals[2]!],
    };

    const report = await verify(harness, swapped);
    assert.ok(!report.valid);
    assert.match(report.checks.find((c) => !c.ok)!.detail!, /does not match the sum/);
  });

  it("REJECTS a tally that omits counted ballots", async () => {
    const { harness, tally } = await runElection();
    const shortened: PublishedTally = {
      ...tally,
      countedBallotIds: tally.countedBallotIds.slice(1),
    };

    const report = await verify(harness, shortened);
    assert.ok(!report.valid);
    assert.match(report.checks.find((c) => !c.ok)!.detail!, /counted ballots/);
  });

  it("REJECTS a forged trustee decryption proof", async () => {
    const { harness, tally } = await runElection();

    const tampered: PublishedTally = {
      ...tally,
      partialDecryptions: tally.partialDecryptions.map((partials, index) =>
        index === 0
          ? partials.map((partial, i) =>
              i === 0
                ? {
                    ...partial,
                    factor: toBase64Url(
                      encodeElement(GROUP, harness.trustees.publicKey.y),
                    ),
                  }
                : partial,
            )
          : partials,
      ),
    };

    const report = await verify(harness, tampered);
    assert.ok(!report.valid);
    assert.match(report.checks.find((c) => !c.ok)!.detail!, /invalid decryption proof/);
  });

  it("REJECTS partials from a trustee who is not in the published set", async () => {
    const { harness, tally } = await runElection();
    const stripped: PublishedTally = { ...tally, publicShares: tally.publicShares.slice(0, 1) };

    const report = await verify(harness, stripped);
    assert.ok(!report.valid);
    assert.match(report.checks.find((c) => !c.ok)!.detail!, /unpublished trustee/);
  });

  it("REJECTS a tally below the decryption threshold", async () => {
    const { harness, tally } = await runElection();
    const thin: PublishedTally = {
      ...tally,
      partialDecryptions: tally.partialDecryptions.map((partials) => partials.slice(0, 1)),
    };

    const report = await verify(harness, thin);
    assert.ok(!report.valid);
    assert.match(report.checks.find((c) => !c.ok)!.detail!, /threshold is/);
  });

  it("REJECTS a tally for a different election", async () => {
    const { harness, tally } = await runElection();
    const report = await verify(harness, { ...tally, electionId: "some-other-election" });
    assert.ok(!report.valid);
    assert.match(report.checks[0]!.detail!, /different election/);
  });
});
