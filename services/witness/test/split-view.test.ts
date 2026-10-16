/**
 * Split-view attacks, end to end: the device-side check (verify-lib.js, the
 * code a voter's browser runs) against real witnesses watching the real board.
 *
 * The attacker controls the ballot box and what it serves one targeted voter.
 * It does not control the witnesses, which the device reaches directly.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toBase64Url } from "@dvoting/crypto";
import { InMemoryBlockStore, generateValidatorKeyPair } from "@dvoting/ledger";
import { createApp as createBallotBoxApp } from "@dvoting/ballot-box/src/app.ts";
import { ELECTION, createHarness, makeSubmission, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";
// @ts-expect-error -- plain JS module, deliberately untyped (it ships to a browser).
import * as device from "@dvoting/ballot-box/public/verify-lib.js";

import { createApp as createWitnessApp } from "../src/app.ts";
import { Witness } from "../src/witness.ts";

type Harness = Awaited<ReturnType<typeof createHarness>>;

async function setup() {
  const keys = await Promise.all(["agent-a", "agent-b", "observer"].map((id) => generateValidatorKeyPair(id)));
  const roster = {
    quorum: 2,
    witnesses: keys.map((k) => ({
      id: k.identity.id,
      publicKey: toBase64Url(k.identity.publicKey),
      url: `http://${k.identity.id}.test`,
    })),
  };
  const harness = await createHarness({ witnesses: roster });
  const box = createBallotBoxApp({ ballotBox: harness.ballotBox });
  const boxFetch = (async (input: string | URL | Request) => box.request(new URL(String(input), "http://box.test").pathname + new URL(String(input), "http://box.test").search)) as typeof fetch;

  const witnesses = await Promise.all(
    keys.map(async (k) => {
      const store = new InMemoryBlockStore();
      const witness = await Witness.open({
        id: k.identity.id,
        privateKey: k.privateKey,
        electionId: ELECTION.electionId,
        ballotBoxUrl: "http://box.test",
        store,
        fetchImpl: boxFetch,
      });
      return { id: k.identity.id, witness, app: createWitnessApp({ witness, store }) };
    }),
  );
  const syncAll = () => Promise.all(witnesses.map((w) => w.witness.sync()));

  /** What a voter's device can reach: a ballot box (honest or not) and the witnesses. */
  const deviceFetch = (boxApp: ReturnType<typeof createBallotBoxApp>) =>
    (async (input: string | URL | Request) => {
      const url = new URL(String(input), "http://box.test");
      const witness = witnesses.find((w) => url.host === `${w.id}.test`);
      return (witness ? witness.app : boxApp).request(url.pathname + url.search);
    }) as typeof fetch;

  return { harness, box, roster, witnesses, syncAll, deviceFetch };
}

async function castAndSeal(harness: Harness) {
  const submission = await makeSubmission(harness, await makeVoter(), [0, 1, 0]);
  await harness.ballotBox.cast(submission);
  await harness.ballotBox.sealBlock();
  return submission.ballot.ballotId;
}

async function receiptFrom(app: ReturnType<typeof createBallotBoxApp>, ballotId: string) {
  return (await app.request(`/v1/bulletin/ballots/${ballotId}`)).json();
}

describe("witnessed receipts on the voter's device", () => {
  it("vouches for an honest receipt with every witness", async () => {
    const { harness, box, syncAll, deviceFetch } = await setup();
    const ballotId = await castAndSeal(harness);
    await syncAll();

    const result = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(box) });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(result.vouched.sort(), ["agent-a", "agent-b", "observer"]);
    assert.match(device.electionFingerprint(result.genesisHash), /^\d{4} \d{4} \d{4}$/);
  });

  it("waits, rather than failing, until the witnesses have seen the ballot's block", async () => {
    const { harness, box, syncAll, deviceFetch } = await setup();
    await syncAll();
    const ballotId = await castAndSeal(harness);

    const early = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(box) });
    assert.equal(early.ok, false);
    assert.equal(early.pending, true);

    await syncAll();
    const later = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(box) });
    assert.equal(later.ok, true);
  });

  it("CATCHES a private board shown to one voter", async () => {
    // The box runs a second, forged election with the same id, its own
    // validators, and the REAL witness roster copied into its block 0, and
    // shows the targeted voter that board. Every validator signature on it is
    // genuine, so every pre-witness check passes.
    const { harness, roster, syncAll, deviceFetch } = await setup();
    await castAndSeal(harness);
    await syncAll();

    const forged = await createHarness({ witnesses: roster, trustees: harness.trustees });
    const forgedApp = createBallotBoxApp({ ballotBox: forged.ballotBox });
    const ballotId = await castAndSeal(forged);
    const receipt = await receiptFrom(forgedApp, ballotId);

    const election = await (await forgedApp.request("/v1/election")).json();
    assert.equal((await device.verifyBallotReceipt(receipt, election)).ok, true, "the forgery must pass the old checks");

    const result = await device.gatherWitnessEvidence(receipt, { fetchImpl: deviceFetch(forgedApp) });
    assert.equal(result.ok, false);
    assert.equal(result.rejected.length, 3);
    assert.ok(result.rejected.every((r: { reason: string }) => /different election definition/.test(r.reason)));
  });

  it("CATCHES a board whose history was rewritten after the witnesses saw it", async () => {
    const { harness, box, syncAll, deviceFetch } = await setup();
    const ballotId = await castAndSeal(harness);
    await castAndSeal(harness);
    await syncAll();

    // The box serves this voter headers whose links are broken above the
    // voter's block: a rewritten tail the witnesses never signed.
    const lying = createBallotBoxApp({ ballotBox: harness.ballotBox });
    const wrapped = {
      request: async (path: string) => {
        const response = await lying.request(path);
        if (!path.startsWith("/v1/bulletin/headers")) return response;
        const body = (await response.json()) as { headers: { previousHash: string }[] };
        body.headers.at(-1)!.previousHash = "A".repeat(43);
        return Response.json(body);
      },
    } as unknown as ReturnType<typeof createBallotBoxApp>;

    const result = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(wrapped) });
    assert.equal(result.ok, false);
    assert.ok(result.rejected.some((r: { reason: string }) => /different board/.test(r.reason)));
  });

  it("REJECTS a checkpoint not signed by the sealed witness key", async () => {
    const { harness, box, syncAll, deviceFetch, witnesses } = await setup();
    const ballotId = await castAndSeal(harness);
    await syncAll();

    // An impostor answers at agent-a's address with its own key.
    const impostorKeys = await generateValidatorKeyPair("agent-a");
    const store = new InMemoryBlockStore();
    const impostor = await Witness.open({
      id: "agent-a",
      privateKey: impostorKeys.privateKey,
      electionId: ELECTION.electionId,
      ballotBoxUrl: "http://box.test",
      store,
      fetchImpl: (async (input: string | URL | Request) => box.request(new URL(String(input)).pathname)) as typeof fetch,
    });
    await impostor.sync();
    witnesses[0]!.app = createWitnessApp({ witness: impostor, store });

    const result = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(box) });
    assert.ok(result.rejected.some((r: { witness: string; reason: string }) => r.witness === "agent-a" && /signature/.test(r.reason)));
    assert.equal(result.ok, true, "the two honest witnesses still meet the quorum of 2");
  });

  it("shows a witness's alarm to the voter", async () => {
    const { harness, box, syncAll, deviceFetch, witnesses } = await setup();
    const ballotId = await castAndSeal(harness);
    await syncAll();

    // Replace the observer with one that then sees the board shrink.
    const keys = await generateValidatorKeyPair("observer");
    let shrink = false;
    const store = new InMemoryBlockStore();
    const alarmed = await Witness.open({
      id: "observer",
      privateKey: keys.privateKey,
      electionId: ELECTION.electionId,
      ballotBoxUrl: "http://box.test",
      store,
      fetchImpl: (async (input: string | URL | Request) => {
        const path = new URL(String(input)).pathname;
        if (shrink && path === "/v1/bulletin/head") return Response.json({ height: 1, head: null });
        return box.request(path);
      }) as typeof fetch,
    });
    await alarmed.sync();
    shrink = true;
    await alarmed.sync();
    witnesses[2]!.app = createWitnessApp({ witness: alarmed, store });

    const result = await device.gatherWitnessEvidence(await receiptFrom(box, ballotId), { fetchImpl: deviceFetch(box) });
    assert.equal(result.alarms.length, 1);
    assert.equal(result.alarms[0].witness, "observer");
    assert.match(result.alarms[0].alarm, /shrank/);
  });
});
