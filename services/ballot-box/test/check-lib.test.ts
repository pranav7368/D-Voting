/**
 * Second-device checks, against a real election.
 *
 * Each attack is a voting device that misbehaves in one specific way. The
 * phone never talks to that device: it reads the bulletin board through the
 * same HTTP routes a real phone uses, and must catch every one.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { prepareBallot } from "@dvoting/crypto";

import { createApp } from "../src/app.ts";
// @ts-expect-error -- plain JS module, deliberately untyped (it ships to a browser).
import * as check from "../public/check-lib.js";
import { ELECTION, createHarness, makeVoter } from "./helpers.ts";

type Harness = Awaited<ReturnType<typeof createHarness>>;

async function setup() {
  const harness = await createHarness();
  const app = createApp({ ballotBox: harness.ballotBox });
  const election = await (await app.request("/v1/election")).json();
  return { harness, app, election };
}

/** What the voting device prepares and shows (as a QR code) before the voter decides. */
async function prepare(harness: Harness, selections: number[]) {
  const voter = await makeVoter();
  const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, selections, {
    credentialFingerprint: voter.fingerprint,
  });
  return { voter, prepared };
}

function linkFor(prepared: { ballot: { ballotId: string }; commitment: string }) {
  return { electionId: ELECTION.electionId, ballotId: prepared.ballot.ballotId, commitment: prepared.commitment };
}

async function receipt(app: ReturnType<typeof createApp>, route: string, ballotId: string) {
  const response = await app.request(`/v1/bulletin/${route}/${ballotId}`);
  assert.equal(response.status, 200, `no ${route} receipt for ${ballotId}`);
  return response.json();
}

describe("second-device check: cast ballots", () => {
  it("confirms an honest ballot was sealed exactly as shown", async () => {
    const { harness, app, election } = await setup();
    const { voter, prepared } = await prepare(harness, [0, 1, 0]);
    await harness.ballotBox.cast({ credential: voter.credential, credentialSignature: voter.signature, ballot: prepared.ballot });
    await harness.ballotBox.sealBlock();

    const result = await check.checkCast(await receipt(app, "ballots", prepared.ballot.ballotId), election, linkFor(prepared));
    assert.equal(result.ok, true, JSON.stringify(result.steps));
    assert.equal(result.steps.at(-1).detail, check.checkCode(prepared.commitment));
  });

  it("CATCHES a device that showed one ballot and cast another", async () => {
    // The device shows the voter an honest ballot's code, then casts a
    // different ballot. Ballot proofs bind the ballot id, so the swapped
    // ballot cannot reuse the honest one's id. Either the QR link names the
    // honest id (and the phone never sees it sealed, which the check page
    // treats as a warning), or, as here, it names the swapped ballot's id with
    // the honest commitment, and the commitments disagree.
    const { harness, app, election } = await setup();
    const { voter, prepared: shown } = await prepare(harness, [1, 0, 0]);
    const swapped = await prepareBallot(ELECTION, harness.trustees.publicKey, [0, 0, 1], {
      credentialFingerprint: voter.fingerprint,
    });
    await harness.ballotBox.cast({ credential: voter.credential, credentialSignature: voter.signature, ballot: swapped.ballot });
    await harness.ballotBox.sealBlock();

    const link = { ...linkFor(shown), ballotId: swapped.ballot.ballotId };
    const result = await check.checkCast(await receipt(app, "ballots", swapped.ballot.ballotId), election, link);
    assert.equal(result.ok, false);
    assert.equal(result.steps.at(-1).id, "matches");
    assert.match(result.steps.at(-1).detail, /sealed .* shown /);
  });

  it("refuses to treat a tested ballot as a cast one", async () => {
    const { harness, app, election } = await setup();
    const { prepared } = await prepare(harness, [1, 0, 0]);
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    await harness.ballotBox.sealBlock();

    const audit = await receipt(app, "audits", prepared.ballot.ballotId);
    const result = await check.checkCast(audit, election, linkFor(prepared));
    assert.equal(result.ok, false);
    assert.match(result.steps.at(-1).detail, /spoiled-ballot/);
  });
});

describe("second-device check: tested ballots", () => {
  it("opens an honest tested ballot and shows what it contained", async () => {
    const { harness, app, election } = await setup();
    const { prepared } = await prepare(harness, [0, 0, 1]);
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    await harness.ballotBox.sealBlock();

    const result = await check.checkTested(await receipt(app, "audits", prepared.ballot.ballotId), election, linkFor(prepared));
    assert.equal(result.ok, true, JSON.stringify(result.steps));
    assert.deepEqual(result.encodedSelections, [0, 0, 1]);
  });

  it("SHOWS the voter the truth when a device encrypted a different choice", async () => {
    // The voter picked Alice; the device encrypted Carol and, when tested,
    // reveals its secrets honestly hoping nobody looks. The math checks out,
    // so the phone's job is to show "Carol" for the voter to reject.
    const { harness, app, election } = await setup();
    const { prepared } = await prepare(harness, [0, 0, 1]);
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    await harness.ballotBox.sealBlock();

    const result = await check.checkTested(await receipt(app, "audits", prepared.ballot.ballotId), election, linkFor(prepared));
    assert.deepEqual(result.encodedSelections, [0, 0, 1], "the phone must report what the ballot really holds");
  });

  it("CATCHES a device that lies about what it encrypted", async () => {
    // Encrypted Carol, but claims Alice when tested.
    const { harness, app, election } = await setup();
    const { prepared } = await prepare(harness, [0, 0, 1]);
    const lie = { ...prepared.secret, selections: [1, 0, 0] };
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: lie });
    await harness.ballotBox.sealBlock();

    const result = await check.checkTested(await receipt(app, "audits", prepared.ballot.ballotId), election, linkFor(prepared));
    assert.equal(result.ok, false);
    assert.equal(result.encodedSelections, null);
  });

  it("CATCHES a device that reveals a different, honest ballot when tested", async () => {
    // Showed the commitment of ballot X, then tested an honest ballot Y.
    const { harness, app, election } = await setup();
    const { prepared: shown } = await prepare(harness, [0, 0, 1]);
    const { prepared: honest } = await prepare(harness, [1, 0, 0]);
    await harness.ballotBox.spoil({ ballot: honest.ballot, auditSecret: honest.secret });
    await harness.ballotBox.sealBlock();

    const link = { ...linkFor(shown), ballotId: honest.ballot.ballotId };
    const result = await check.checkTested(await receipt(app, "audits", honest.ballot.ballotId), election, link);
    assert.equal(result.ok, false);
    assert.match(result.steps.at(-1).detail, /not the one the voter was shown/);
  });

  it("is not found until the tested ballot is sealed", async () => {
    const { harness, app } = await setup();
    const { prepared } = await prepare(harness, [1, 0, 0]);
    await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
    const response = await app.request(`/v1/bulletin/audits/${prepared.ballot.ballotId}`);
    assert.equal(response.status, 404);
  });
});

describe("the lookup the phone polls", () => {
  it("reports only what is sealed, and as what", async () => {
    const { harness, app } = await setup();
    const { voter, prepared: cast } = await prepare(harness, [1, 0, 0]);
    const { prepared: tested } = await prepare(harness, [0, 1, 0]);
    const lookup = async (id: string) =>
      ((await (await app.request(`/v1/bulletin/lookup/${id}`)).json()) as { sealedAs: string | null }).sealedAs;

    await harness.ballotBox.cast({ credential: voter.credential, credentialSignature: voter.signature, ballot: cast.ballot });
    await harness.ballotBox.spoil({ ballot: tested.ballot, auditSecret: tested.secret });
    // Pending entries are not public yet, so they read as unsealed.
    assert.equal(await lookup(cast.ballot.ballotId), null);
    assert.equal(await lookup(tested.ballot.ballotId), null);

    await harness.ballotBox.sealBlock();
    assert.equal(await lookup(cast.ballot.ballotId), "ballot");
    assert.equal(await lookup(tested.ballot.ballotId), "spoiled-ballot");
    assert.equal(await lookup("never-existed-1234"), null);
  });
});

describe("the check link", () => {
  it("round-trips through the URL fragment", () => {
    const link = { electionId: "e-2026", ballotId: "abcDEF123_-xyz", commitment: "A".repeat(43) };
    const url = check.checkLink("https://vote.example", link);
    assert.ok(url.startsWith("https://vote.example/check#"));
    assert.deepEqual(check.parseCheckLink(new URL(url).hash), link);
  });

  it("rejects a malformed link instead of guessing", () => {
    assert.equal(check.parseCheckLink("#e=x&b=short&c=" + "A".repeat(43)), null);
    assert.equal(check.parseCheckLink("#e=x&b=abcdefgh123"), null);
    assert.equal(check.parseCheckLink(""), null);
  });

  it("derives the same 12-digit code the voting page shows", () => {
    assert.match(check.checkCode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), /^0000 0000 0000$/);
    assert.match(check.checkCode("_____________________________________________".slice(0, 43)), /^\d{4} \d{4} \d{4}$/);
  });

  it("decodes a ledger leaf and refuses trailing bytes", () => {
    const enc = new TextEncoder();
    const part = (bytes: Uint8Array) => {
      const out = new Uint8Array(4 + bytes.length);
      new DataView(out.buffer).setUint32(0, bytes.length, false);
      out.set(bytes, 4);
      return out;
    };
    const leaf = new Uint8Array([...part(enc.encode("ballot")), ...part(enc.encode("id-1")), ...part(enc.encode("{}"))]);
    assert.deepEqual(
      { ...check.decodeLeaf(leaf), data: new TextDecoder().decode(check.decodeLeaf(leaf).data) },
      { kind: "ballot", id: "id-1", data: "{}" },
    );
    assert.throws(() => check.decodeLeaf(new Uint8Array([...leaf, 0])), /trailing/);
  });
});
