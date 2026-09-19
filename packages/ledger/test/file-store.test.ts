import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { mkdtemp, readFile, rm, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { utf8 } from "@dvoting/crypto";

import { ZERO_HASH, attest, blockHash, proposeBlock, withAttestations, type Block, type LedgerEntry } from "../src/block.ts";
import { Ledger } from "../src/chain.ts";
import { FileBlockStore, FileStoreError } from "../src/file-store.ts";
import { blockToWire } from "../src/wire.ts";
import {
  createValidatorSet,
  generateValidatorKeyPair,
  proposerForHeight,
  type ValidatorKeyPair,
  type ValidatorSet,
} from "../src/validator.ts";

const ELECTION = "file-store-test";

let dir: string;
let keyPairs: ValidatorKeyPair[];
let validatorSet: ValidatorSet;
let counter = 0;

before(async () => {
  dir = await mkdtemp(join(tmpdir(), "dvoting-ledger-"));
  keyPairs = await Promise.all([
    generateValidatorKeyPair("commission"),
    generateValidatorKeyPair("observer-a"),
    generateValidatorKeyPair("observer-b"),
  ]);
  validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

function nextPath(): string {
  counter += 1;
  return join(dir, `chain-${counter}.jsonl`);
}

function entry(id: string, payload = "x"): LedgerEntry {
  return { kind: "ballot", id, data: utf8(payload) };
}

async function buildBlock(height: number, previousHash: Uint8Array, entries: LedgerEntry[]): Promise<Block> {
  const scheduled = proposerForHeight(validatorSet, height);
  const proposer = keyPairs.find((k) => k.identity.id === scheduled.id)!;

  let block = await proposeBlock({
    height,
    electionId: ELECTION,
    previousHash,
    entries,
    proposer: proposer.identity,
    signingKey: proposer.privateKey,
  });

  const extra = [];
  for (const other of keyPairs.filter((k) => k.identity.id !== proposer.identity.id)) {
    if (extra.length >= validatorSet.quorum - 1) break;
    extra.push(await attest(block, other.identity, other.privateKey));
  }
  return withAttestations(block, extra);
}

/** Write `count` blocks through a Ledger backed by `path`, then close. */
async function seedChain(path: string, count: number): Promise<Block[]> {
  const store = await FileBlockStore.open(path);
  const ledger = new Ledger(store, validatorSet, ELECTION);
  const blocks: Block[] = [];
  let previousHash: Uint8Array = ZERO_HASH;

  for (let height = 0; height < count; height++) {
    const block = await buildBlock(height, previousHash, [
      entry(`b${height}-e0`),
      entry(`b${height}-e1`),
    ]);
    await ledger.append(block);
    blocks.push(block);
    previousHash = await blockHash(block.header);
  }

  await store.close();
  return blocks;
}

describe("durability", () => {
  it("survives a restart with the chain intact", async () => {
    const path = nextPath();
    const written = await seedChain(path, 3);

    // Reopen as a fresh process would.
    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);

    assert.equal(await ledger.height(), 3);
    const report = await ledger.verify();
    assert.deepEqual(report.errors, []);
    assert.ok(report.valid);

    for (const [height, original] of written.entries()) {
      const loaded = await ledger.getBlock(height);
      assert.ok(loaded);
      assert.deepEqual(blockToWire(loaded), blockToWire(original));
    }
    await store.close();
  });

  it("can be appended to after reopening", async () => {
    const path = nextPath();
    await seedChain(path, 2);

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);
    const head = await ledger.head();
    await ledger.append(await buildBlock(2, await blockHash(head!.header), [entry("after-restart")]));
    await store.close();

    const reopened = await FileBlockStore.open(path);
    const finalLedger = new Ledger(reopened, validatorSet, ELECTION);
    assert.equal(await finalLedger.height(), 3);
    assert.ok(await finalLedger.hasEntry("ballot", "after-restart"));
    assert.ok((await finalLedger.verify()).valid);
    await reopened.close();
  });

  it("rebuilds the entry index on load", async () => {
    const path = nextPath();
    await seedChain(path, 3);

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);

    assert.ok(await ledger.hasEntry("ballot", "b1-e1"));
    assert.ok(!(await ledger.hasEntry("ballot", "nope")));

    // Inclusion proofs must still work after a reload.
    const located = await ledger.locateEntry("ballot", "b2-e0");
    assert.ok(located);
    assert.equal(located.blockHeight, 2);
    await store.close();
  });

  it("starts empty on a fresh path", async () => {
    const store = await FileBlockStore.open(nextPath());
    assert.equal(await store.height(), 0);
    assert.equal(await store.head(), null);
    await store.close();
  });

  it("still rejects a replayed entry after a restart", async () => {
    // Chain-wide uniqueness must survive the process, not just live in memory.
    const path = nextPath();
    await seedChain(path, 2);

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);
    const head = await ledger.head();
    const replay = await buildBlock(2, await blockHash(head!.header), [entry("b0-e0")]);

    await assert.rejects(() => ledger.append(replay), /already on the chain/);
    await store.close();
  });
});

describe("crash recovery", () => {
  it("discards a torn final line", async () => {
    // Simulates a power cut mid-append. The block was never acknowledged, so
    // dropping it is correct.
    const path = nextPath();
    await seedChain(path, 3);
    await appendFile(path, '{"header":{"height":3,"elect');

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);

    assert.equal(await ledger.height(), 3);
    assert.ok((await ledger.verify()).valid);
    await store.close();
  });

  it("discards a complete block whose trailing newline never landed", async () => {
    // Subtle case: the JSON is valid but unterminated, so the append was never
    // acknowledged. Treating it as complete would splice the NEXT block onto it.
    const path = nextPath();
    const blocks = await seedChain(path, 2);
    const orphan = await buildBlock(2, await blockHash(blocks[1]!.header), [entry("orphan")]);
    await appendFile(path, JSON.stringify(blockToWire(orphan))); // no "\n"

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);
    assert.equal(await ledger.height(), 2, "an unterminated block was treated as committed");
    assert.ok(!(await ledger.hasEntry("ballot", "orphan")));
    await store.close();
  });

  it("truncates the torn tail so later appends are not spliced onto it", async () => {
    const path = nextPath();
    await seedChain(path, 2);
    await appendFile(path, '{"header":{"heig');

    const store = await FileBlockStore.open(path);
    await store.close();

    // The fragment must be gone from disk, not merely ignored in memory.
    const text = await readFile(path, "utf8");
    assert.ok(!text.includes('{"header":{"heig\n') && text.endsWith("\n"));
    assert.equal(text.split("\n").filter((l) => l.length > 0).length, 2);
  });

  it("can append cleanly after recovering from a torn write", async () => {
    const path = nextPath();
    await seedChain(path, 2);
    await appendFile(path, '{"header":{"heig');

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);
    const head = await ledger.head();
    await ledger.append(await buildBlock(2, await blockHash(head!.header), [entry("recovered")]));
    await store.close();

    const reopened = await FileBlockStore.open(path);
    const finalLedger = new Ledger(reopened, validatorSet, ELECTION);
    assert.equal(await finalLedger.height(), 3);
    assert.ok((await finalLedger.verify()).valid);
    await reopened.close();
  });
});

describe("corruption and tampering are refused at load", () => {
  it("REFUSES a corrupt line in the middle of the file", async () => {
    // Silently skipping it would let an attacker delete a ballot by scribbling
    // on the file.
    const path = nextPath();
    await seedChain(path, 3);

    const lines = (await readFile(path, "utf8")).split("\n");
    lines[1] = "{not json";
    await writeFile(path, lines.join("\n"));

    await assert.rejects(() => FileBlockStore.open(path), FileStoreError);
  });

  it("REFUSES a file with a deleted block", async () => {
    const path = nextPath();
    await seedChain(path, 3);

    const lines = (await readFile(path, "utf8")).split("\n").filter((l) => l.length > 0);
    await writeFile(path, `${[lines[0], lines[2]].join("\n")}\n`);

    // Heights no longer form 0,1,2 -- caught before any signature check.
    await assert.rejects(() => FileBlockStore.open(path), /expected 1/);
  });

  it("REFUSES a file with a duplicated entry", async () => {
    const path = nextPath();
    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);

    const genesis = await buildBlock(0, ZERO_HASH, [entry("dup")]);
    await ledger.append(genesis);
    await store.close();

    // Append a second, well-formed block reusing the same entry id.
    const second = await buildBlock(1, await blockHash(genesis.header), [entry("dup")]);
    await appendFile(path, `${JSON.stringify(blockToWire(second))}\n`);

    await assert.rejects(() => FileBlockStore.open(path), /duplicate entry/);
  });

  it("DETECTS a tampered but structurally valid block via chain verification", async () => {
    // Rewriting a ballot keeps the file parseable, so the store loads it -- and
    // the Ledger's own verification is what catches the tampering.
    const path = nextPath();
    const blocks = await seedChain(path, 3);

    const tampered = {
      ...blockToWire(blocks[1]!),
      entries: blockToWire(blocks[1]!).entries.map((e, i) =>
        i === 0 ? { ...e, data: Buffer.from("REWRITTEN").toString("base64url") } : e,
      ),
    };
    const lines = (await readFile(path, "utf8")).split("\n").filter((l) => l.length > 0);
    lines[1] = JSON.stringify(tampered);
    await writeFile(path, `${lines.join("\n")}\n`);

    const store = await FileBlockStore.open(path);
    const ledger = new Ledger(store, validatorSet, ELECTION);
    const report = await ledger.verify();

    assert.ok(!report.valid);
    assert.ok(report.errors.some((e) => e.includes("merkleRoot")));
    await store.close();
  });

  it("rejects an out-of-order append", async () => {
    const path = nextPath();
    await seedChain(path, 2);
    const store = await FileBlockStore.open(path);
    const stray = await buildBlock(0, ZERO_HASH, [entry("stray")]);
    await assert.rejects(() => store.append(stray), /does not follow/);
    await store.close();
  });

  it("refuses operations after close", async () => {
    const store = await FileBlockStore.open(nextPath());
    await store.close();
    await assert.rejects(
      () => store.append({} as unknown as Block),
      /store is closed/,
    );
  });
});
