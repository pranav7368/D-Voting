import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import { utf8 } from "@dvoting/crypto";

import {
  ZERO_HASH,
  attest,
  blockHash,
  encodeHeader,
  proposeBlock,
  withAttestations,
  type Block,
  type LedgerEntry,
} from "../src/block.ts";
import { Ledger, validateBlock, verifyChain } from "../src/chain.ts";
import { InMemoryBlockStore } from "../src/store.ts";
import { verifyMerkleProof } from "../src/merkle.ts";
import {
  createValidatorSet,
  generateValidatorKeyPair,
  proposerForHeight,
  sign,
  type ValidatorKeyPair,
  type ValidatorSet,
} from "../src/validator.ts";

const ELECTION = "ledger-test-2026";

let keyPairs: ValidatorKeyPair[];
let validatorSet: ValidatorSet;

before(async () => {
  keyPairs = await Promise.all([
    generateValidatorKeyPair("election-commission"),
    generateValidatorKeyPair("observer-alpha"),
    generateValidatorKeyPair("observer-beta"),
    generateValidatorKeyPair("observer-gamma"),
  ]);
  validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));
});

function entry(id: string, payload = "payload"): LedgerEntry {
  return { kind: "ballot", id, data: utf8(payload) };
}

/** Build a fully attested block at the given height. */
async function buildBlock(
  height: number,
  previousHash: Uint8Array,
  entries: LedgerEntry[],
  options: { attestors?: number; timestamp?: number } = {},
): Promise<Block> {
  const proposerIdentity = proposerForHeight(validatorSet, height);
  const proposerPair = keyPairs.find((k) => k.identity.id === proposerIdentity.id)!;

  let block = await proposeBlock({
    height,
    electionId: ELECTION,
    previousHash,
    entries,
    proposer: proposerPair.identity,
    signingKey: proposerPair.privateKey,
    ...(options.timestamp !== undefined ? { timestamp: options.timestamp } : {}),
  });

  const wanted = options.attestors ?? validatorSet.quorum;
  const others = keyPairs.filter((k) => k.identity.id !== proposerIdentity.id);
  const extra = [];
  for (const other of others.slice(0, Math.max(0, wanted - 1))) {
    extra.push(await attest(block, other.identity, other.privateKey));
  }
  block = withAttestations(block, extra);
  return block;
}

async function buildChain(blockCount: number): Promise<Block[]> {
  const blocks: Block[] = [];
  let previousHash = ZERO_HASH;
  for (let height = 0; height < blockCount; height++) {
    const block = await buildBlock(height, previousHash, [
      entry(`b${height}-e0`),
      entry(`b${height}-e1`),
    ]);
    blocks.push(block);
    previousHash = await blockHash(block.header);
  }
  return blocks;
}

describe("validator set", () => {
  it("defaults to a Byzantine supermajority quorum", () => {
    // n > 3f tolerance: 4 validators -> quorum 3.
    assert.equal(createValidatorSet(keyPairs.map((k) => k.identity)).quorum, 3);
    assert.equal(createValidatorSet(keyPairs.slice(0, 3).map((k) => k.identity)).quorum, 3);
    assert.equal(createValidatorSet(keyPairs.slice(0, 1).map((k) => k.identity)).quorum, 1);
  });

  it("rejects duplicate validator ids", async () => {
    const duplicate = await generateValidatorKeyPair("election-commission");
    assert.throws(
      () => createValidatorSet([keyPairs[0]!.identity, duplicate.identity]),
      /unique/,
    );
  });

  it("rejects an empty set", () => {
    assert.throws(() => createValidatorSet([]), /cannot be empty/);
  });

  it("rotates the proposer round-robin", () => {
    assert.equal(proposerForHeight(validatorSet, 0).id, "election-commission");
    assert.equal(proposerForHeight(validatorSet, 1).id, "observer-alpha");
    assert.equal(proposerForHeight(validatorSet, 4).id, "election-commission");
  });
});

describe("block validation", () => {
  it("accepts a well-formed genesis block", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    const result = await validateBlock(block, null, validatorSet);
    assert.deepEqual(result.errors, []);
    assert.ok(result.valid);
  });

  it("rejects a genesis block that does not reference the zero hash", async () => {
    const block = await buildBlock(0, new Uint8Array(32).fill(9), [entry("g0")]);
    const result = await validateBlock(block, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("zero hash")));
  });

  it("rejects a block below quorum", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("g0")], { attestors: 2 });
    const result = await validateBlock(block, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("quorum is 3")));
  });

  it("rejects a block proposed by the wrong validator", async () => {
    // Height 1 is observer-alpha's slot; have the commission propose it instead.
    const genesis = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    const wrongProposer = keyPairs[0]!;
    const block = await proposeBlock({
      height: 1,
      electionId: ELECTION,
      previousHash: await blockHash(genesis.header),
      entries: [entry("b1")],
      proposer: wrongProposer.identity,
      signingKey: wrongProposer.privateKey,
    });

    const result = await validateBlock(block, genesis, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("not scheduled")));
  });

  it("rejects duplicate attestations faking a quorum", async () => {
    // One validator signing three times must not satisfy a 3-of-4 quorum.
    const proposer = keyPairs[0]!;
    let block = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("g0")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });
    const signature = await sign(proposer.privateKey, encodeHeader(block.header));
    block = {
      ...block,
      attestations: [
        { validator: proposer.identity.id, signature },
        { validator: proposer.identity.id, signature },
        { validator: proposer.identity.id, signature },
      ],
    };

    const result = await validateBlock(block, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("duplicate attestations")));
  });

  it("rejects an attestation from an unknown validator", async () => {
    const outsider = await generateValidatorKeyPair("rogue");
    let block = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    block = withAttestations(block, [
      await attest(block, outsider.identity, outsider.privateKey),
    ]);

    const result = await validateBlock(block, null, validatorSet);
    assert.ok(result.errors.some((e) => e.includes("unknown validator")));
  });

  it("rejects a forged signature", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    const forged: Block = {
      ...block,
      attestations: block.attestations.map((a, i) =>
        i === 1 ? { ...a, signature: new Uint8Array(64).fill(7) } : a,
      ),
    };

    const result = await validateBlock(forged, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("invalid signature")));
  });

  it("rejects entries added after signing", async () => {
    // THE core tamper check: the Merkle root in the signed header no longer
    // matches the entry list.
    const block = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    const stuffed: Block = { ...block, entries: [...block.entries, entry("smuggled")] };

    const result = await validateBlock(stuffed, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("merkleRoot")));
  });

  it("rejects reordered entries", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("a"), entry("b"), entry("c")]);
    const reordered: Block = {
      ...block,
      entries: [block.entries[2]!, block.entries[1]!, block.entries[0]!],
    };
    const result = await validateBlock(reordered, null, validatorSet);
    assert.ok(result.errors.some((e) => e.includes("merkleRoot")));
  });

  it("rejects duplicate entry ids within a block", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("same"), entry("same", "different")]);
    const result = await validateBlock(block, null, validatorSet);
    assert.ok(result.errors.some((e) => e.includes("duplicate entry ids")));
  });

  it("rejects a backwards timestamp", async () => {
    const genesis = await buildBlock(0, ZERO_HASH, [entry("g0")], { timestamp: 5_000 });
    const next = await buildBlock(1, await blockHash(genesis.header), [entry("b1")], {
      timestamp: 4_000,
    });
    const result = await validateBlock(next, genesis, validatorSet);
    assert.ok(result.errors.some((e) => e.includes("moves backwards")));
  });

  it("rejects a block from another election", async () => {
    const block = await buildBlock(0, ZERO_HASH, [entry("g0")]);
    const result = await validateBlock(block, null, validatorSet, {
      expectedElectionId: "some-other-election",
    });
    assert.ok(result.errors.some((e) => e.includes("belongs to election")));
  });
});

describe("chain verification", () => {
  it("verifies an honest chain", async () => {
    const blocks = await buildChain(5);
    const report = await verifyChain(blocks, validatorSet, { expectedElectionId: ELECTION });
    assert.deepEqual(report.errors, []);
    assert.ok(report.valid);
    assert.equal(report.blockCount, 5);
    assert.equal(report.entryCount, 10);
  });

  it("DETECTS tampering with a historical block", async () => {
    // The whole point of the chain. Edit block 1's entries and every later
    // previousHash stops matching.
    const blocks = await buildChain(5);
    blocks[1] = { ...blocks[1]!, entries: [entry("b1-e0", "TAMPERED"), blocks[1]!.entries[1]!] };

    const report = await verifyChain(blocks, validatorSet, { expectedElectionId: ELECTION });
    assert.ok(!report.valid);
    assert.ok(report.errors.some((e) => e.includes("merkleRoot")));
  });

  it("DETECTS a removed block", async () => {
    const blocks = await buildChain(5);
    const gapped = [blocks[0]!, blocks[1]!, blocks[3]!, blocks[4]!];
    const report = await verifyChain(gapped, validatorSet, { expectedElectionId: ELECTION });
    assert.ok(!report.valid);
    assert.ok(report.errors.some((e) => e.includes("does not follow") || e.includes("previousHash")));
  });

  it("DETECTS a re-signed replacement block", async () => {
    // Even a validator with signing keys cannot silently substitute a block:
    // its hash changes, so every successor's previousHash breaks.
    const blocks = await buildChain(4);
    blocks[1] = await buildBlock(1, blocks[1]!.header.previousHash, [entry("rewritten")]);

    const report = await verifyChain(blocks, validatorSet, { expectedElectionId: ELECTION });
    assert.ok(!report.valid);
    assert.ok(report.errors.some((e) => e.includes("previousHash")));
  });

  it("DETECTS an entry replayed into a later block", async () => {
    const blocks: Block[] = [];
    let previousHash = ZERO_HASH;
    const genesis = await buildBlock(0, previousHash, [entry("ballot-1")]);
    blocks.push(genesis);
    previousHash = await blockHash(genesis.header);
    // Same entry id again, in a properly-linked, properly-signed block.
    const replay = await buildBlock(1, previousHash, [entry("ballot-1")]);
    blocks.push(replay);

    const report = await verifyChain(blocks, validatorSet, { expectedElectionId: ELECTION });
    assert.ok(!report.valid);
    assert.ok(report.errors.some((e) => e.includes("already in chain")));
  });
});

describe("Ledger", () => {
  it("appends and reads back blocks", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    let previousHash = ZERO_HASH;
    for (let height = 0; height < 3; height++) {
      const block = await buildBlock(height, previousHash, [entry(`e${height}`)]);
      await ledger.append(block);
      previousHash = await blockHash(block.header);
    }

    assert.equal(await ledger.height(), 3);
    assert.equal((await ledger.head())!.header.height, 2);
    assert.ok(await ledger.hasEntry("ballot", "e1"));
    assert.ok(!(await ledger.hasEntry("ballot", "nope")));
    assert.ok((await ledger.verify()).valid);
  });

  it("refuses an invalid block", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    const underAttested = await buildBlock(0, ZERO_HASH, [entry("e0")], { attestors: 1 });
    await assert.rejects(() => ledger.append(underAttested), /refusing to append invalid block/);
  });

  it("refuses a block replaying an existing entry id", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    const genesis = await buildBlock(0, ZERO_HASH, [entry("ballot-x")]);
    await ledger.append(genesis);

    const replay = await buildBlock(1, await blockHash(genesis.header), [entry("ballot-x")]);
    await assert.rejects(() => ledger.append(replay), /already on the chain/);
  });

  it("refuses a block that does not link to the head", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    await ledger.append(await buildBlock(0, ZERO_HASH, [entry("e0")]));
    const orphan = await buildBlock(1, new Uint8Array(32).fill(3), [entry("e1")]);
    await assert.rejects(() => ledger.append(orphan), /previousHash/);
  });

  it("produces a verifiable inclusion proof for a recorded entry", async () => {
    // This is the voter-facing guarantee: "my ballot is in the log", provable
    // from the signed header alone.
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    const entries = Array.from({ length: 7 }, (_, i) => entry(`tracker-${i}`));
    const block = await buildBlock(0, ZERO_HASH, entries);
    await ledger.append(block);

    const located = await ledger.locateEntry("ballot", "tracker-4");
    assert.ok(located);
    assert.equal(located.entryIndex, 4);
    assert.equal(located.blockHeight, 0);

    const { encodeEntry } = await import("../src/block.ts");
    assert.ok(
      await verifyMerkleProof(encodeEntry(located.entry), located.proof, located.merkleRoot),
    );
    // ...and the root came from the signed header.
    assert.deepEqual(Array.from(located.merkleRoot), Array.from(block.header.merkleRoot));
  });

  it("returns null for an unknown entry", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    await ledger.append(await buildBlock(0, ZERO_HASH, [entry("e0")]));
    assert.equal(await ledger.locateEntry("ballot", "missing"), null);
  });

  it("reports the next scheduled proposer", async () => {
    const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
    assert.equal(await ledger.nextProposer(), "election-commission");
    await ledger.append(await buildBlock(0, ZERO_HASH, [entry("e0")]));
    assert.equal(await ledger.nextProposer(), "observer-alpha");
  });
});
