/**
 * Electoral roll administration.
 *
 * The roll is where an election is most easily stolen, because a fabricated
 * entry produces a cryptographically perfect ballot. The defences are
 * procedural rather than mathematical, so these tests are about whether the
 * procedure actually holds: codes shown once, freezing that cannot be undone, a
 * commitment anyone can recompute, and revocation that does not quietly rewrite
 * what was committed to.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { rollCommitment } from "../src/eligibility/roll-commitment.ts";
import { createHarness, postJson, type TestHarness } from "./helpers.ts";

const ADMIN_TOKEN = "roll-admin-token-long-enough-to-be-accepted";

function adminHarness(): TestHarness {
  return createHarness({ ADMIN_TOKEN });
}

async function admin(
  harness: TestHarness,
  path: string,
  options: { method?: string; body?: unknown; token?: string } = {},
): Promise<Response> {
  return harness.app.request(path, {
    method: options.method ?? "GET",
    headers: {
      Authorization: `Bearer ${options.token ?? ADMIN_TOKEN}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    ...(options.body ? { body: JSON.stringify(options.body) } : {}),
  });
}

describe("roll administration exists only when it is asked for", () => {
  it("is absent without an admin token", async () => {
    // A route that can add voters should not exist unless it was configured.
    const harness = createHarness();
    const response = await harness.app.request("/v1/admin/roll");
    assert.equal(response.status, 404);
  });

  it("REJECTS a wrong token", async () => {
    const harness = adminHarness();
    const response = await admin(harness, "/v1/admin/roll", { token: "not-the-token-but-long-enough" });
    assert.equal(response.status, 401);
  });
});

describe("enrolling voters", () => {
  it("returns each enrolment code exactly once", async () => {
    // The codes exist in that response and nowhere else: the service keeps only
    // an HMAC, so a database compromise yields no usable code and a lost card
    // means a new entry rather than a reprint.
    const harness = adminHarness();

    const created = (await (
      await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 3 } })
    ).json()) as { added: number; cards: { rollId: string; enrolmentCode: string }[] };

    assert.equal(created.added, 3);
    assert.equal(created.cards.length, 3);

    // The summary and the export both refuse to reveal a code again.
    const summary = await (await admin(harness, "/v1/admin/roll")).text();
    const exported = await (await admin(harness, "/v1/admin/roll/export")).text();
    for (const card of created.cards) {
      assert.ok(!summary.includes(card.enrolmentCode), "a code was served a second time");
      assert.ok(!exported.includes(card.enrolmentCode), "a code appeared in the export");
    }
  });

  it("issues codes that actually work for registration", async () => {
    const harness = adminHarness();
    const created = (await (
      await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 1 } })
    ).json()) as { cards: { rollId: string; enrolmentCode: string }[] };

    const response = await postJson(harness.app, "/v1/register", created.cards[0]!);
    assert.equal(response.status, 200);
  });

  it("continues the numbering instead of colliding with the first batch", async () => {
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 2 } });
    const second = await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 2 } });

    assert.equal(second.status, 201);
    const roll = (await (await admin(harness, "/v1/admin/roll")).json()) as { entries: number };
    assert.equal(roll.entries, 4);
  });

  it("accepts explicit roll identifiers from a statutory register", async () => {
    const harness = adminHarness();
    const response = await admin(harness, "/v1/admin/roll", {
      method: "POST",
      body: { rollIds: ["WB-01-0001", "WB-01-0002"] },
    });

    assert.equal(response.status, 201);
    const body = (await response.json()) as { cards: { rollId: string }[] };
    assert.deepEqual(body.cards.map((c) => c.rollId), ["WB-01-0001", "WB-01-0002"]);
  });

  it("REJECTS a list that repeats a roll id", async () => {
    const harness = adminHarness();
    const response = await admin(harness, "/v1/admin/roll", {
      method: "POST",
      body: { rollIds: ["A-1", "A-1"] },
    });
    assert.equal(response.status, 400);
  });

  it("reports how many entries were added before a duplicate stopped it", async () => {
    // Partial success is reported honestly: the earlier entries are already on
    // the roll and their cards still have to be delivered.
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { rollIds: ["A-1"] } });

    const response = await admin(harness, "/v1/admin/roll", {
      method: "POST",
      body: { rollIds: ["A-2", "A-1", "A-3"] },
    });

    assert.equal(response.status, 409);
    const body = (await response.json()) as { cards: { rollId: string }[] };
    assert.deepEqual(body.cards.map((c) => c.rollId), ["A-2"]);
  });
});

describe("freezing the roll", () => {
  it("is one-way: no voter can be added afterwards", async () => {
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 2 } });
    await admin(harness, "/v1/admin/roll/freeze", { method: "POST" });

    const response = await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 1 } });
    assert.equal(response.status, 409);
    assert.equal(((await response.json()) as { error: string }).error, "roll_frozen");
  });

  it("returns the same commitment when called twice", async () => {
    // An operator who loses the response must be able to recover the value
    // without a second, different freeze.
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 3 } });

    const first = (await (await admin(harness, "/v1/admin/roll/freeze", { method: "POST" })).json()) as {
      commitment: string;
    };
    const second = (await (await admin(harness, "/v1/admin/roll/freeze", { method: "POST" })).json()) as {
      commitment: string;
    };
    assert.equal(first.commitment, second.commitment);
  });

  it("produces a commitment anyone can recompute from the published roll", async () => {
    // This is the whole point: publish the roll, and a third party arrives at
    // the digest that was sealed onto the chain.
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 4 } });
    const frozen = (await (await admin(harness, "/v1/admin/roll/freeze", { method: "POST" })).json()) as {
      commitment: string;
    };

    const exported = (await (await admin(harness, "/v1/admin/roll/export")).json()) as {
      rollIds: string[];
    };
    const recomputed = await rollCommitment(harness.config.ELECTION_ID, exported.rollIds);

    assert.equal(recomputed, frozen.commitment);
  });

  it("changes the commitment when a voter is added", async () => {
    // A name added before the freeze is visible in the digest; a name added
    // after it cannot be added at all.
    const harness = adminHarness();
    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 2 } });
    const before = (await (await admin(harness, "/v1/admin/roll")).json()) as { commitment: string };

    await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 1 } });
    const after = (await (await admin(harness, "/v1/admin/roll")).json()) as { commitment: string };

    assert.notEqual(before.commitment, after.commitment);
  });

  it("does not depend on the order voters were added", async () => {
    const first = await rollCommitment("e", ["B", "A", "C"]);
    const second = await rollCommitment("e", ["C", "B", "A"]);
    assert.equal(first, second);
  });

  it("cannot be collided by reshaping the identifiers", async () => {
    // Without length prefixing, ["ab","c"] and ["a","bc"] would hash alike and
    // entries could be reshaped to hide a substitution.
    const first = await rollCommitment("e", ["ab", "c"]);
    const second = await rollCommitment("e", ["a", "bc"]);
    assert.notEqual(first, second);
  });

  it("is bound to the election it was taken for", async () => {
    const first = await rollCommitment("election-a", ["R-1", "R-2"]);
    const second = await rollCommitment("election-b", ["R-1", "R-2"]);
    assert.notEqual(first, second);
  });
});

describe("revoking an entry", () => {
  it("stops the entry authenticating but leaves it in the commitment", async () => {
    // Deleting it would silently change the digest the election was opened
    // with. Revocation is recorded, not erased.
    const harness = adminHarness();
    const created = (await (
      await admin(harness, "/v1/admin/roll", { method: "POST", body: { count: 2 } })
    ).json()) as { cards: { rollId: string; enrolmentCode: string }[] };
    const before = (await (await admin(harness, "/v1/admin/roll")).json()) as { commitment: string };

    const card = created.cards[0]!;
    const revoked = await admin(harness, "/v1/admin/roll/revoke", {
      method: "POST",
      body: { rollId: card.rollId },
    });
    assert.equal(revoked.status, 200);

    const after = (await (await admin(harness, "/v1/admin/roll")).json()) as {
      commitment: string;
      entries: number;
    };
    assert.equal(after.commitment, before.commitment, "revoking changed the roll commitment");
    assert.equal(after.entries, 2);

    // ...and the revoked card no longer authenticates.
    const response = await postJson(harness.app, "/v1/register", card);
    assert.equal(response.status, 403);
  });

  it("reports an unknown roll id without saying whether it exists", async () => {
    const harness = adminHarness();
    const response = await admin(harness, "/v1/admin/roll/revoke", {
      method: "POST",
      body: { rollId: "R-does-not-exist" },
    });
    assert.equal(response.status, 404);
  });
});
