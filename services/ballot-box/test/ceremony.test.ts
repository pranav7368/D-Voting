/**
 * The decryption ceremony.
 *
 * The count is the moment an election can be stolen most cheaply: there is one
 * number at the end, and nothing to compare it against. So most of what is
 * tested here is refusal -- a trustee who is not on the roster, a trustee who
 * submits a plausible-looking factor without the matching proof, a second
 * submission from the same trustee, and an attempt to decrypt before voting has
 * closed.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  encodeElement,
  encodeScalar,
  partialDecrypt,
  toBase64Url,
  type PartialDecryption,
} from "@dvoting/crypto";

import { createApp } from "../src/app.ts";
import { CeremonyError, DecryptionCeremony } from "../src/ceremony.ts";
import { tallyFromChain } from "../src/chain-tally.ts";
import { readPublishedTally, verifyPublishedTally } from "../src/tally-publication.ts";
import {
  ELECTION,
  GROUP,
  createHarness,
  makeSubmission,
  makeVoter,
  type Harness,
} from "./helpers.ts";

/** Run a small election and close it, leaving totals waiting to be decrypted. */
async function closedElection(votes: number[][] = [[1, 0, 0], [1, 0, 0], [0, 1, 0]]) {
  const harness = await createHarness();
  for (const selections of votes) {
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), selections));
  }
  await harness.ballotBox.closePoll();
  return harness;
}

/** One trustee's partial decryptions, in the wire shape the endpoint expects. */
async function sharesFor(harness: Harness, trusteeIndex: number) {
  const tally = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
  const keyShare = harness.trustees.keyShares.find((s) => s.index === trusteeIndex)!;

  const partials: PartialDecryption[] = [];
  for (const total of tally.encryptedTotals) {
    partials.push(await partialDecrypt(GROUP, ELECTION.electionId, keyShare, total));
  }
  return partials.map(toWire);
}

function toWire(partial: PartialDecryption) {
  return {
    index: partial.index,
    factor: toBase64Url(encodeElement(GROUP, partial.factor)),
    proof: {
      commitment1: toBase64Url(encodeElement(GROUP, partial.proof.commitment1)),
      commitment2: toBase64Url(encodeElement(GROUP, partial.proof.commitment2)),
      challenge: toBase64Url(encodeScalar(GROUP, partial.proof.challenge)),
      response: toBase64Url(encodeScalar(GROUP, partial.proof.response)),
    },
  };
}

describe("the ceremony publishes what has to be decrypted", () => {
  it("offers nothing while voting is open", async () => {
    // Encrypted totals mid-election are a running total in disguise: they let a
    // trustee decrypt the state of the race before the poll closes.
    const harness = await createHarness();
    const status = await new DecryptionCeremony(harness.ballotBox).status();

    assert.equal(status.phase, "not-ready");
    assert.deepEqual(status.encryptedTotals, []);
  });

  it("offers the totals once voting has closed", async () => {
    const harness = await closedElection();
    const status = await new DecryptionCeremony(harness.ballotBox).status();

    assert.equal(status.phase, "awaiting-trustees");
    assert.equal(status.encryptedTotals.length, ELECTION.candidates.length);
    assert.equal(status.ballotsCounted, 3);
    assert.equal(status.threshold, 2);
    assert.deepEqual(status.submitted, []);
  });

  it("serves the same ciphertexts to every trustee", async () => {
    // Two trustees served totals computed at different moments would produce
    // partials that do not combine, and the failure would look like a bad proof
    // rather than a moving target.
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const first = await ceremony.status();
    const second = await ceremony.status();
    assert.deepEqual(first.encryptedTotals, second.encryptedTotals);
  });
});

describe("a share is accepted only with a proof that verifies", () => {
  it("accepts an honest trustee and reports the progress", async () => {
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const result = await ceremony.submit({ index: 1, partials: await sharesFor(harness, 1) });

    assert.equal(result.accepted, true);
    assert.deepEqual(result.submitted, [1]);
    assert.equal(result.outstanding, 1);
    assert.equal(result.published, false);
  });

  it("publishes the result when the threshold is reached", async () => {
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    // Two different trustees, each applying their own share on their own.
    await ceremony.submit({ index: 1, partials: await sharesFor(harness, 1) });
    const second = await ceremony.submit({ index: 2, partials: await sharesFor(harness, 2) });

    assert.equal(second.published, true);

    const published = await readPublishedTally(harness.ledger, ELECTION.electionId);
    assert.ok(published, "no tally was sealed onto the chain");
    assert.deepEqual(
      published.results.map((r) => r.votes),
      [2, 1, 0],
    );

    // And the sealed result survives an independent recount from the chain.
    const report = await verifyPublishedTally(
      harness.ledger,
      ELECTION,
      harness.trustees.publicKey,
      published,
    );
    assert.ok(report.valid, report.checks.map((c) => `${c.label}: ${c.detail}`).join("; "));
  });

  it("REJECTS a trustee who is not on the sealed roster", async () => {
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    await assert.rejects(
      () => ceremony.submit({ index: 99, partials: [] }),
      (error: CeremonyError) => error.code === "unknown_trustee",
    );
  });

  it("REJECTS a factor submitted without a valid proof", async () => {
    // The attack this stops: a trustee submits a random group element instead
    // of alpha^{x_i}. The tally is decrypted only once, so a corrupted result
    // would be indistinguishable from a legitimate one -- there is nothing to
    // compare it against. The proof is what makes it detectable, and
    // attributable to the trustee that produced it.
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const honest = await sharesFor(harness, 1);
    const forged = honest.map((partial) => ({
      ...partial,
      factor: toBase64Url(encodeElement(GROUP, GROUP.g)),
    }));

    await assert.rejects(
      () => ceremony.submit({ index: 1, partials: forged }),
      (error: CeremonyError) => error.code === "invalid_proof",
    );
  });

  it("REJECTS one trustee's shares submitted under another trustee's index", async () => {
    // Only the holder of share i can produce a proof that verifies against
    // public share i. This is what makes the endpoint safe to leave open.
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const trusteeOne = await sharesFor(harness, 1);
    const relabelled = trusteeOne.map((partial) => ({ ...partial, index: 2 }));

    await assert.rejects(
      () => ceremony.submit({ index: 2, partials: relabelled }),
      (error: CeremonyError) => error.code === "invalid_proof",
    );
  });

  it("REJECTS a submission with the wrong number of partials", async () => {
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const partials = await sharesFor(harness, 1);
    await assert.rejects(
      () => ceremony.submit({ index: 1, partials: partials.slice(0, 1) }),
      (error: CeremonyError) => error.code === "wrong_shape",
    );
  });

  it("REJECTS a second submission from the same trustee", async () => {
    // Otherwise one trustee could reach the threshold alone, which is the whole
    // thing the threshold exists to prevent.
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    const partials = await sharesFor(harness, 1);
    await ceremony.submit({ index: 1, partials });
    await assert.rejects(
      () => ceremony.submit({ index: 1, partials }),
      (error: CeremonyError) => error.code === "already_submitted",
    );
  });

  it("REFUSES to begin while voting is still open", async () => {
    const harness = await createHarness();
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    await assert.rejects(
      () => ceremony.submit({ index: 1, partials: [] }),
      (error: CeremonyError) => error.code === "election_open",
    );
  });

  it("REFUSES a share once the result is published", async () => {
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);
    await ceremony.submit({ index: 1, partials: await sharesFor(harness, 1) });
    await ceremony.submit({ index: 2, partials: await sharesFor(harness, 2) });

    const third = await sharesFor(harness, 3);
    await assert.rejects(
      () => ceremony.submit({ index: 3, partials: third }),
      (error: CeremonyError) => error.code === "already_published",
    );
  });

  it("keeps working for everyone else after one trustee is rejected", async () => {
    // A single bad submission must not be able to wedge the ceremony: the
    // election would then be undecryptable, which is as damaging as a wrong
    // result and far harder to attribute.
    const harness = await closedElection();
    const ceremony = new DecryptionCeremony(harness.ballotBox);

    await assert.rejects(() => ceremony.submit({ index: 99, partials: [] }), CeremonyError);

    const result = await ceremony.submit({ index: 1, partials: await sharesFor(harness, 1) });
    assert.equal(result.accepted, true);
  });
});

describe("the ceremony over HTTP", () => {
  it("is public to read and needs no token to contribute", async () => {
    // The proof inside the submission is the authentication. A bearer token
    // would add a secret to steal without adding a guarantee.
    const harness = await closedElection();
    const server = createApp({ ballotBox: harness.ballotBox });

    const status = (await (await server.request("/v1/ceremony")).json()) as {
      phase: string;
      threshold: number;
    };
    assert.equal(status.phase, "awaiting-trustees");
    assert.equal(status.threshold, 2);

    const response = await server.request("/v1/ceremony/shares", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ index: 1, partials: await sharesFor(harness, 1) }),
    });
    assert.equal(response.status, 201);
  });

  it("never caches the ceremony state", async () => {
    const harness = await closedElection();
    const server = createApp({ ballotBox: harness.ballotBox });
    const response = await server.request("/v1/ceremony");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });

  it("reports a rejected proof as a client error, naming nothing secret", async () => {
    const harness = await closedElection();
    const server = createApp({ ballotBox: harness.ballotBox });

    const partials = (await sharesFor(harness, 1)).map((partial) => ({
      ...partial,
      factor: toBase64Url(encodeElement(GROUP, GROUP.g)),
    }));
    const response = await server.request("/v1/ceremony/shares", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ index: 1, partials }),
    });

    assert.equal(response.status, 400);
    const body = (await response.json()) as { error: string; message: string };
    assert.equal(body.error, "invalid_proof");
    assert.match(body.message, /trustee 1/);
  });
});
