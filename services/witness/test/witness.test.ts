/**
 * The witness, against a real election and a board that lies.
 *
 * The board is the ballot box's real HTTP app, reached through an in-process
 * fetch. Each attack wraps it to serve something the honest box never would.
 */

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { toBase64Url } from "@dvoting/crypto";
import {
  InMemoryBlockStore,
  blockHash,
  generateValidatorKeyPair,
  verifyCheckpoint,
  type BlockStore,
} from "@dvoting/ledger";
import { FileBlockStore } from "@dvoting/ledger/file-store";
import { createApp as createBallotBoxApp } from "@dvoting/ballot-box/src/app.ts";
import { ELECTION, createHarness, makeSubmission, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";

import { createApp } from "../src/app.ts";
import { Witness } from "../src/witness.ts";

type Harness = Awaited<ReturnType<typeof createHarness>>;
type Rewrite = (path: string, body: unknown) => unknown;

/** A fetch that reaches the ballot box in-process, optionally lying. */
function boardFetch(harness: Harness, rewrite?: Rewrite): typeof fetch {
  const app = createBallotBoxApp({ ballotBox: harness.ballotBox });
  return (async (input: string | URL | Request) => {
    const path = new URL(String(input)).pathname;
    const response = await app.request(path);
    if (!rewrite) return response;
    // The lie may be a block the honest board does not have yet, so rewrite
    // missing paths too; an unchanged body keeps the honest status.
    const body = await response.json();
    const out = rewrite(path, body);
    return out === body ? Response.json(body, { status: response.status }) : Response.json(out);
  }) as typeof fetch;
}

async function castAndSeal(harness: Harness, count = 1) {
  for (let i = 0; i < count; i++) {
    await harness.ballotBox.cast(await makeSubmission(harness, await makeVoter(), [1, 0, 0]));
  }
  await harness.ballotBox.sealBlock();
}

async function witnessFor(harness: Harness, options: { rewrite?: Rewrite; store?: BlockStore; pin?: Uint8Array } = {}) {
  const keys = await generateValidatorKeyPair("agent-a");
  const witness = await Witness.open({
    id: "agent-a",
    privateKey: keys.privateKey,
    electionId: ELECTION.electionId,
    ballotBoxUrl: "http://board.test",
    store: options.store ?? new InMemoryBlockStore(),
    fetchImpl: boardFetch(harness, options.rewrite),
    ...(options.pin ? { genesisPin: options.pin } : {}),
  });
  return { witness, keys };
}

describe("a witness vouches for one board", () => {
  it("signs a checkpoint naming the board's real head and genesis", async () => {
    const harness = await createHarness();
    await castAndSeal(harness, 2);
    const { witness, keys } = await witnessFor(harness);
    await witness.sync();

    const signed = witness.latest!;
    assert.ok(signed, "no checkpoint after syncing an open election");
    assert.equal(await verifyCheckpoint(signed, keys.identity), true);
    const blocks = await harness.ledger.blocks();
    assert.equal(signed.checkpoint.height, blocks.length);
    assert.equal(toBase64Url(signed.checkpoint.headHash), toBase64Url(await blockHash(blocks.at(-1)!.header)));
    assert.equal(toBase64Url(signed.checkpoint.genesisHash), toBase64Url(await blockHash(blocks[0]!.header)));
    assert.equal((await witness.status()).state, "ok");
  });

  it("follows the board as it grows", async () => {
    const harness = await createHarness();
    const { witness } = await witnessFor(harness);
    await witness.sync();
    const before = witness.latest!.checkpoint.height;
    await castAndSeal(harness);
    await witness.sync();
    assert.equal(witness.latest!.checkpoint.height, before + 1);
  });

  it("signs nothing before the election opens", async () => {
    const harness = await createHarness({ leaveInSetup: true });
    const { witness } = await witnessFor(harness);
    await witness.sync();
    assert.equal(witness.latest, null);
    assert.equal((await witness.status()).state, "waiting");
  });
});

describe("a witness refuses to vouch for a rewritten board", () => {
  it("ALARMS when the board shrinks", async () => {
    const harness = await createHarness();
    await castAndSeal(harness);
    let lie = false;
    const { witness } = await witnessFor(harness, {
      rewrite: (path, body) => (lie && path === "/v1/bulletin/head" ? { ...(body as object), height: 1 } : body),
    });
    await witness.sync();
    const good = witness.latest!;

    lie = true;
    await castAndSeal(harness);
    await witness.sync();
    const status = await witness.status();
    assert.equal(status.state, "alarm");
    assert.match(status.alarm!, /shrank/);
    assert.equal(witness.latest, good, "a new checkpoint was signed despite the alarm");
  });

  it("ALARMS when the board shows a different head at the same height", async () => {
    const harness = await createHarness();
    await castAndSeal(harness);
    let lie = false;
    const { witness } = await witnessFor(harness, {
      rewrite: (path, body) => {
        if (!lie || path !== "/v1/bulletin/head") return body;
        const b = body as { head: { hash: string } };
        return { ...b, head: { ...b.head, hash: "x".repeat(43) } };
      },
    });
    await witness.sync();
    lie = true;
    await witness.sync();
    assert.match((await witness.status()).alarm ?? "", /fork/);
  });

  it("ALARMS when a new block does not extend the history it saw", async () => {
    // A second, independent election's block 2 is perfectly signed, but it
    // was built on a different block 1.
    const harness = await createHarness();
    const other = await createHarness({ trustees: harness.trustees });
    await castAndSeal(harness);
    await castAndSeal(other);
    await castAndSeal(other);
    const foreign = await (await createBallotBoxApp({ ballotBox: other.ballotBox }).request("/v1/bulletin/blocks/2")).json();

    let lie = false;
    const { witness } = await witnessFor(harness, {
      rewrite: (path, body) => {
        if (!lie) return body;
        if (path === "/v1/bulletin/head") return { ...(body as object), height: 3 };
        if (path === "/v1/bulletin/blocks/2") return foreign;
        return body;
      },
    });
    await witness.sync();
    lie = true;
    await witness.sync();
    assert.match((await witness.status()).alarm ?? "", /does not extend/);
  });

  it("ALARMS when block 0 is not the election it was told to watch", async () => {
    const harness = await createHarness();
    const { witness } = await witnessFor(harness, { pin: new Uint8Array(32).fill(9) });
    await witness.sync();
    assert.match((await witness.status()).alarm ?? "", /genesis/);
    assert.equal(witness.latest, null);
  });

  it("stays alarmed: a fork is a human decision, not one a process talks itself out of", async () => {
    const harness = await createHarness();
    await castAndSeal(harness);
    let lie = false;
    const { witness } = await witnessFor(harness, {
      rewrite: (path, body) => (lie && path === "/v1/bulletin/head" ? { ...(body as object), height: 1 } : body),
    });
    await witness.sync();
    const good = witness.latest!;

    lie = true;
    await witness.sync();
    assert.equal((await witness.status()).state, "alarm");

    lie = false; // the board "recovers"
    await castAndSeal(harness);
    await witness.sync();
    assert.equal((await witness.status()).state, "alarm");
    assert.equal(witness.latest, good, "an alarmed witness signed again");
  });
});

describe("a witness remembers across restarts", () => {
  it("re-verifies its replica and still catches a rollback after restarting", async () => {
    const dir = await mkdtemp(join(tmpdir(), "dvoting-witness-"));
    try {
      const harness = await createHarness();
      await castAndSeal(harness, 2);
      const path = join(dir, "replica.jsonl");

      const first = await FileBlockStore.open(path, { fsync: false });
      const { witness } = await witnessFor(harness, { store: first });
      await witness.sync();
      const seen = (await witness.status()).height;
      await first.close();

      // Restart against a board that has been rolled back by one block.
      const reopened = await FileBlockStore.open(path, { fsync: false });
      const { witness: restarted } = await witnessFor(harness, {
        store: reopened,
        rewrite: (p, body) => (p === "/v1/bulletin/head" ? { ...(body as object), height: seen - 1 } : body),
      });
      assert.equal((await restarted.status()).height, seen);
      await restarted.sync();
      assert.match((await restarted.status()).alarm ?? "", /shrank/);
      await reopened.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe("the witness's public surface", () => {
  it("serves the checkpoint, any alarm, and a mirror of the board", async () => {
    const harness = await createHarness();
    await castAndSeal(harness);
    const store = new InMemoryBlockStore();
    const { witness } = await witnessFor(harness, { store });
    await witness.sync();
    const app = createApp({ witness, store });

    const response = await app.request("/v1/checkpoint");
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), "*");
    const body = (await response.json()) as { checkpoint: { height: number }; alarm: string | null };
    assert.equal(body.alarm, null);
    assert.equal(body.checkpoint.height, await harness.ledger.height());

    const mirrored = (await (await app.request("/v1/bulletin/head")).json()) as { height: number };
    assert.equal(mirrored.height, await harness.ledger.height());
    assert.equal((await app.request("/v1/bulletin/blocks/0")).status, 200);
  });
});
