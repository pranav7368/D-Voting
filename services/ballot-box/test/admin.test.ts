import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createBallot } from "@dvoting/crypto";

import { createApp } from "../src/app.ts";
import { ELECTION, createHarness, makeVoter } from "./helpers.ts";

const TOKEN = "an-admin-token-long-enough-to-be-ok";

describe("admin-page.js only references elements admin.html actually has", () => {
  it("every $(\"id\") lookup resolves to a real element", async () => {
    // Caught for real: renaming an element in admin.html (election-id ->
    // election-title, for the display-name feature) left one $("election-id")
    // lookup behind in the close-poll handler. It returned null and threw
    // inside the click handler -- silently, since nothing here runs the JS --
    // so "Close the poll" stopped working with no server-side signal at all.
    const { app } = await adminApp();
    const html = await (await app.request("/admin")).text();
    const script = await (await app.request("/admin-page.js")).text();

    const declaredIds = new Set([...html.matchAll(/\sid="([\w-]+)"/g)].map((m) => m[1]));
    const referencedIds = [...script.matchAll(/\$\("([\w-]+)"\)/g)].map((m) => m[1]);

    assert.ok(referencedIds.length > 10, "sanity check: expected many $() lookups in admin-page.js");
    for (const id of referencedIds) {
      assert.ok(declaredIds.has(id), `admin-page.js references #${id}, which admin.html does not declare`);
    }
  });
});

async function adminApp(options: { adminToken?: string; leaveInSetup?: boolean } = {}) {
  const harness = await createHarness(
    options.leaveInSetup ? { leaveInSetup: true } : {},
  );
  const app = createApp({
    ballotBox: harness.ballotBox,
    adminToken: options.adminToken ?? TOKEN,
  });
  return { app, harness };
}

function auth(token = TOKEN): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function castOne(harness: Awaited<ReturnType<typeof createHarness>>) {
  const voter = await makeVoter();
  const ballot = await createBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], {
    credentialFingerprint: voter.fingerprint,
  });
  return harness.ballotBox.cast({
    credential: voter.credential,
    credentialSignature: voter.signature,
    ballot,
  });
}

describe("admin authentication", () => {
  it("REJECTS requests with no token", async () => {
    const { app } = await adminApp();
    assert.equal((await app.request("/v1/admin/status")).status, 401);
  });

  it("REJECTS a wrong token", async () => {
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/status", {
      headers: auth("definitely-not-the-admin-token-value"),
    });
    assert.equal(response.status, 401);
  });

  it("REJECTS a token that is a prefix of the real one", async () => {
    // Guards the constant-time comparison against length-based shortcuts.
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/status", {
      headers: auth(TOKEN.slice(0, -1)),
    });
    assert.equal(response.status, 401);
  });

  it("accepts the correct token", async () => {
    const { app } = await adminApp();
    assert.equal((await app.request("/v1/admin/status", { headers: auth() })).status, 200);
  });

  it("refuses to start with a weak admin token", async () => {
    const harness = await createHarness();
    assert.throws(
      () => createApp({ ballotBox: harness.ballotBox, adminToken: "short" }),
      /at least 32/,
    );
  });

  it("does not expose admin routes at all when no token is configured", async () => {
    // A deployment that does not need admin should not have an admin surface.
    const harness = await createHarness();
    const app = createApp({ ballotBox: harness.ballotBox });
    assert.equal((await app.request("/v1/admin/status", { headers: auth() })).status, 404);
    assert.equal((await app.request("/admin")).status, 404);
  });

  it("never caches admin responses", async () => {
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/status", { headers: auth() });
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });
});

describe("admin status", () => {
  it("reports the election phase and counts", async () => {
    const { app, harness } = await adminApp();
    await castOne(harness);
    await castOne(harness);
    await harness.ballotBox.sealBlock();

    const body = (await (await app.request("/v1/admin/status", { headers: auth() })).json()) as
      Record<string, unknown>;

    assert.equal(body.phase, "voting");
    assert.equal(body.ballotsAccepted, 2);
    assert.equal(body.chainValid, true);
    assert.match(String(body.nextStep), /Close the poll/);
  });

  it("NEVER reveals how the ballots lean", async () => {
    // An admin who could see a running total could decide whether to keep
    // counting based on who is winning.
    const { app, harness } = await adminApp();
    for (let i = 0; i < 3; i++) await castOne(harness);
    await harness.ballotBox.sealBlock();

    const text = await (await app.request("/v1/admin/status", { headers: auth() })).text();
    for (const forbidden of ["Alice", "votes", "tally", "result:", "partial"]) {
      assert.ok(
        !text.includes(forbidden) || forbidden === "Alice",
        `admin status leaked "${forbidden}"`,
      );
    }
    // Candidate names are fine (they are public); vote counts are not.
    const body = JSON.parse(text) as Record<string, unknown>;
    assert.equal(body.results, undefined);
    assert.equal(body.encryptedTotals, undefined);
  });

  it("moves to closed, then published", async () => {
    const { app, harness } = await adminApp();
    await castOne(harness);

    await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });

    const closed = (await (await app.request("/v1/admin/status", { headers: auth() })).json()) as
      Record<string, unknown>;
    assert.equal(closed.phase, "closed");
    assert.match(String(closed.nextStep), /trustee decryption ceremony/);
    assert.match(String(closed.nextStep), /holds no key shares/);
  });
});

describe("closing the poll", () => {
  it("requires an explicit confirmation", async () => {
    // Closing ends the franchise for anyone who has not voted; it must not be
    // possible with a stray click or a replayed request.
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({}),
    });
    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, "confirmation_required");
  });

  it("rejects a confirmation naming the wrong election", async () => {
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: "some-other-election" }),
    });
    assert.equal(response.status, 400);
  });

  it("seals pending ballots BEFORE closing", async () => {
    // A ballot accepted moments before the deadline must not be stranded.
    const { app, harness } = await adminApp();
    const cast = await castOne(harness);
    assert.equal(harness.ballotBox.pendingCount, 1);

    await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });

    assert.ok(await harness.ledger.hasEntry("ballot", cast.ballotId));
    assert.equal(harness.ballotBox.pendingCount, 0);
  });

  it("is irreversible", async () => {
    // A reopenable election lets an operator watch the result, then accept more
    // votes. There is deliberately no reopen endpoint.
    const { app, harness } = await adminApp();
    await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });

    const again = await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });
    assert.equal(again.status, 409);

    // And no route reopens it.
    for (const path of ["/v1/admin/open", "/v1/admin/reopen"]) {
      assert.equal((await app.request(path, { method: "POST", headers: auth() })).status, 404);
    }
    assert.equal(harness.ballotBox.isOpen, false);
  });

  it("stops accepting ballots once closed", async () => {
    const { app, harness } = await adminApp();
    await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });
    await assert.rejects(() => castOne(harness), /no longer accepting/);
  });
});

describe("operator audit log", () => {
  it("records every administrative action", async () => {
    const { app, harness } = await adminApp();
    await castOne(harness);

    await app.request("/v1/admin/seal", { method: "POST", headers: auth() });
    await app.request("/v1/admin/close", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: ELECTION.electionId }),
    });

    const body = (await (await app.request("/v1/admin/audit", { headers: auth() })).json()) as {
      entries: { action: string }[];
    };
    const actions = body.entries.map((e) => e.action);
    assert.ok(actions.includes("admin.seal"));
    assert.ok(actions.includes("admin.close"));
  });

  it("requires authentication to read", async () => {
    const { app } = await adminApp();
    assert.equal((await app.request("/v1/admin/audit")).status, 401);
  });
});

describe("the admin console cannot decrypt", () => {
  it("exposes no route that returns plaintext votes", async () => {
    // Structural check of the core boundary: the ballot box holds no trustee
    // key shares, so there is no code path from admin to a plaintext vote.
    const { app, harness } = await adminApp();
    for (let i = 0; i < 3; i++) await castOne(harness);
    await harness.ballotBox.sealBlock();

    for (const path of [
      "/v1/admin/decrypt",
      "/v1/admin/tally",
      "/v1/admin/result",
      "/v1/admin/keys",
    ]) {
      const response = await app.request(path, { method: "POST", headers: auth() });
      assert.equal(response.status, 404, `${path} should not exist`);
    }
  });
});

describe("composing and opening an election over HTTP", () => {
  it("edits the draft ballot while in setup", async () => {
    const { app } = await adminApp({ leaveInSetup: true });

    const response = await app.request("/v1/admin/election/draft", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ candidates: ["Party A", "Party B", "NOTA"], maxSelections: 1 }),
    });

    assert.equal(response.status, 200);
    const body = (await response.json()) as { candidates: string[]; sealed: boolean };
    assert.deepEqual(body.candidates, ["Party A", "Party B", "NOTA"]);
    assert.equal(body.sealed, false);
  });

  it("sets a display name, and seals it when the poll opens", async () => {
    const { app, harness } = await adminApp({ leaveInSetup: true });

    const draft = await app.request("/v1/admin/election/draft", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ name: "General Election 2026" }),
    });
    assert.equal(draft.status, 200);
    assert.equal(((await draft.json()) as { name: string | null }).name, "General Election 2026");

    const open = await app.request("/v1/admin/election/open", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: harness.ballotBox.election.electionId }),
    });
    assert.equal(open.status, 200);

    const status = (await (
      await app.request("/v1/admin/status", { headers: auth() })
    ).json()) as { name: string | null; electionId: string };
    assert.equal(status.name, "General Election 2026");
    // The identifier itself never changes -- only the display name does.
    assert.equal(status.electionId, harness.ballotBox.election.electionId);
  });

  it("REFUSES to edit the ballot after the poll has opened", async () => {
    const { app } = await adminApp();
    const response = await app.request("/v1/admin/election/draft", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ candidates: ["Only Me", "Nobody"] }),
    });

    assert.equal(response.status, 409);
    assert.equal(((await response.json()) as { error: string }).error, "election_sealed");
  });

  it("requires the election id typed back before sealing", async () => {
    // Opening is as irreversible as closing: it fixes the ballot forever.
    const { app } = await adminApp({ leaveInSetup: true });
    const response = await app.request("/v1/admin/election/open", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({ confirmElectionId: "not-this-election" }),
    });

    assert.equal(response.status, 400);
    assert.equal(((await response.json()) as { error: string }).error, "confirmation_required");
  });

  it("seals the election and reports it as voting", async () => {
    const { app, harness } = await adminApp({ leaveInSetup: true });
    const response = await app.request("/v1/admin/election/open", {
      method: "POST",
      headers: auth(),
      body: JSON.stringify({
        confirmElectionId: ELECTION.electionId,
        rollCommitment: "bVmNaqurDBS0xuyVOQDY6D8trzsZVWc-8v-I2C6Z6Dw",
      }),
    });

    assert.equal(response.status, 200);
    const body = (await response.json()) as { phase: string; sealed: boolean };
    assert.equal(body.phase, "voting");
    assert.equal(body.sealed, true);
    assert.ok(await harness.ledger.hasEntry("election-config", ELECTION.electionId));
  });

  it("reports the ceremony progress once closed, and offers no way to hurry it", async () => {
    const { app, harness } = await adminApp();
    await castOne(harness);
    await harness.ballotBox.closePoll();

    const status = (await (
      await app.request("/v1/admin/status", { headers: auth() })
    ).json()) as {
      phase: string;
      ceremony: { threshold: number; submitted: number[]; outstanding: number };
      nextStep: string;
    };

    assert.equal(status.phase, "closed");
    assert.equal(status.ceremony.threshold, 2);
    assert.deepEqual(status.ceremony.submitted, []);
    assert.match(status.nextStep, /it holds no key shares/);

    // There is no admin route that contributes a share on a trustee's behalf.
    for (const path of ["/v1/admin/ceremony", "/v1/admin/decrypt", "/v1/admin/shares"]) {
      const response = await app.request(path, { method: "POST", headers: auth() });
      assert.equal(response.status, 404, `${path} should not exist`);
    }
  });
});
