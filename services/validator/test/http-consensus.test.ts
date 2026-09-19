/**
 * End-to-end consensus over real HTTP.
 *
 * Four validator authorities run as separate Hono servers on separate ports,
 * each holding exactly one signing key and its own chain replica. The block
 * assembler reaches them only over the network. This exercises the wire format,
 * the auth boundary, and the refusal paths — none of which the in-process
 * transport touches.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { serve, type ServerType } from "@hono/node-server";

import { utf8 } from "@dvoting/crypto";
import {
  DistributedSealer,
  HttpValidatorPeer,
  InMemoryBlockStore,
  Ledger,
  ValidatorNode,
  blockToWire,
  createValidatorSet,
  generateValidatorKeyPair,
  nextSealRequest,
  proposeRequestToWire,
  type Block,
  type LedgerEntry,
  type ValidatorKeyPair,
  type ValidatorPeer,
  type ValidatorSet,
} from "@dvoting/ledger";

import { createValidatorApp } from "../src/app.ts";

const ELECTION = "http-consensus-test";
const PROPOSE_TOKEN = "a-propose-token-long-enough-for-tests";
const BASE_PORT = 18_090;

const VALIDATOR_NAMES = ["commission", "observer-a", "observer-b", "observer-c"];

let keyPairs: ValidatorKeyPair[];
let validatorSet: ValidatorSet;
let nodes: ValidatorNode[];
let servers: ServerType[];
let peers: HttpValidatorPeer[];
let assemblerLedger: Ledger;
let sealer: DistributedSealer;

before(async () => {
  keyPairs = [];
  for (const name of VALIDATOR_NAMES) {
    keyPairs.push(await generateValidatorKeyPair(name));
  }
  validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));

  nodes = keyPairs.map(
    (keyPair) =>
      new ValidatorNode({
        identity: keyPair.identity,
        privateKey: keyPair.privateKey,
        ledger: new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION),
      }),
  );

  servers = nodes.map((node, index) =>
    serve({
      fetch: createValidatorApp({ node, proposeToken: PROPOSE_TOKEN }).fetch,
      port: BASE_PORT + index,
    }),
  );

  peers = nodes.map(
    (node, index) =>
      new HttpValidatorPeer({
        id: node.identity.id,
        baseUrl: `http://127.0.0.1:${BASE_PORT + index}`,
        proposeToken: PROPOSE_TOKEN,
      }),
  );

  assemblerLedger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
  sealer = new DistributedSealer(assemblerLedger, peers);
});

after(() => {
  for (const server of servers) server.close();
});

function entry(id: string, payload = "x"): LedgerEntry {
  return { kind: "ballot", id, data: utf8(payload) };
}

async function sealAndCommit(entries: LedgerEntry[]): Promise<Block> {
  const block = await sealer.seal(await nextSealRequest(assemblerLedger, ELECTION, entries));
  await assemblerLedger.append(block);
  await sealer.broadcastCommit(block);
  return block;
}

describe("consensus over HTTP", () => {
  it("reports status from every node", async () => {
    for (const peer of peers) {
      const status = await peer.status();
      assert.equal(status.validator, peer.id);
      assert.equal(typeof status.height, "number");
    }
  });

  it("seals a block by talking to four separate servers", async () => {
    const block = await sealAndCommit([entry("e0"), entry("e1")]);

    assert.equal(block.header.proposer, "commission");
    assert.ok(block.attestations.length >= validatorSet.quorum);
    const signers = new Set(block.attestations.map((a) => a.validator));
    assert.equal(signers.size, block.attestations.length);
  });

  it("replicates the chain to every node over the network", async () => {
    await sealAndCommit([entry("e2")]);
    await sealAndCommit([entry("e3")]);

    for (const node of nodes) {
      assert.equal(await node.height(), 3, `${node.identity.id} is out of sync`);
      const report = await node.ledger.verify();
      assert.deepEqual(report.errors, []);
      assert.ok(report.valid);
    }
    assert.ok((await assemblerLedger.verify()).valid);
  });

  it("rotates the proposer across servers", async () => {
    const before = await assemblerLedger.height();
    const proposers: string[] = [];
    for (let i = 0; i < 4; i++) {
      proposers.push((await sealAndCommit([entry(`rot-${before}-${i}`)])).header.proposer);
    }
    // Round-robin from wherever the chain currently is.
    const expected = Array.from(
      { length: 4 },
      (_, i) => VALIDATOR_NAMES[(before + i) % VALIDATOR_NAMES.length]!,
    );
    assert.deepEqual(proposers, expected);
  });

  it("survives a round trip through the wire format unchanged", async () => {
    const block = await sealAndCommit([entry("wire-check", "payload with é unicode")]);
    const stored = await nodes[1]!.ledger.getBlock(block.header.height);
    assert.ok(stored);
    assert.deepEqual(blockToWire(stored), blockToWire(block));
  });
});

describe("the propose endpoint is protected", () => {
  it("REJECTS a propose request with no token", async () => {
    // Unauthenticated propose would let an attacker make a validator commit to
    // a block at height H, after which its own anti-equivocation rule locks it
    // out of the legitimate block -- a liveness attack.
    const response = await fetch(`http://127.0.0.1:${BASE_PORT}/v1/propose`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(
        proposeRequestToWire({
          height: await assemblerLedger.height(),
          electionId: ELECTION,
          entries: [entry("hostile")],
        }),
      ),
    });
    assert.equal(response.status, 401);
  });

  it("REJECTS a propose request with the wrong token", async () => {
    const rogue = new HttpValidatorPeer({
      id: "commission",
      baseUrl: `http://127.0.0.1:${BASE_PORT}`,
      proposeToken: "definitely-not-the-right-token-value",
    });
    await assert.rejects(
      () =>
        rogue.propose({
          height: 99,
          electionId: ELECTION,
          entries: [entry("hostile")],
        }),
      /HTTP 401/,
    );
  });

  it("refuses to propose at the wrong height", async () => {
    await assert.rejects(
      () => peers[0]!.propose({ height: 999, electionId: ELECTION, entries: [entry("x")] }),
      /HTTP 409/,
    );
  });
});

describe("attestation refusals travel correctly over HTTP", () => {
  it("returns a structured refusal, not a transport error", async () => {
    // A validator declining is a normal protocol outcome; the caller must be
    // able to tell it apart from the network being down.
    const height = await assemblerLedger.height();
    const proposed = await peers[height % peers.length]!.propose({
      height,
      electionId: ELECTION,
      entries: [entry(`refusal-${height}`)],
    });

    // Tamper after proposing, keeping entryCount consistent so the block passes
    // the wire-format boundary check and actually reaches validation. The
    // signed Merkle root is what catches it.
    const entries = [...proposed.entries, entry("smuggled")];
    const tampered: Block = {
      ...proposed,
      entries,
      header: { ...proposed.header, entryCount: entries.length },
    };

    const response = await peers[(height + 1) % peers.length]!.requestAttestation(tampered);
    assert.ok(response.refused, "a tampered block was attested");
    assert.match(response.reason, /merkleRoot/);
  });

  it("rejects an entry-count mismatch at the wire boundary, before validation", async () => {
    // Structurally impossible blocks are rejected at parse time rather than
    // becoming a confusing failure deeper in.
    const height = await assemblerLedger.height();
    const proposed = await peers[height % peers.length]!.propose({
      height,
      electionId: ELECTION,
      entries: [entry(`boundary-${height}`)],
    });

    const inconsistent: Block = {
      ...proposed,
      entries: [...proposed.entries, entry("smuggled")],
    };

    await assert.rejects(
      () => peers[(height + 1) % peers.length]!.requestAttestation(inconsistent),
      /HTTP 400/,
    );
  });

  it("rejects a malformed block at the boundary", async () => {
    const response = await fetch(`http://127.0.0.1:${BASE_PORT + 1}/v1/attest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ block: { header: { height: -1 } } }),
    });
    assert.equal(response.status, 400);
    const body = (await response.json()) as { error: string };
    assert.equal(body.error, "invalid_block");
  });

  it("rejects a block whose hashes are the wrong length", async () => {
    const response = await fetch(`http://127.0.0.1:${BASE_PORT + 1}/v1/attest`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        block: {
          header: {
            height: 0,
            electionId: ELECTION,
            previousHash: "AAAA",
            merkleRoot: "AAAA",
            entryCount: 0,
            timestamp: 1,
            proposer: "commission",
          },
          entries: [],
          attestations: [],
        },
      }),
    });
    assert.equal(response.status, 400);
  });
});

describe("a lagging node resynchronises over the network", () => {
  it("catches up a validator that missed commits, and it attests again", async () => {
    // Simulates a node that was unreachable for a few blocks. Without
    // resynchronisation it would refuse everything forever, because its height
    // never advances.
    const laggard = nodes[3]!;
    const partitioned: ValidatorPeer = {
      id: laggard.identity.id,
      propose: (r) => peers[3]!.propose(r),
      requestAttestation: (b) => peers[3]!.requestAttestation(b),
      commit: async () => {
        /* network partition: commit never arrives */
      },
      height: () => peers[3]!.height(),
    };

    // Uses the shared authoritative ledger so the cluster stays coherent for
    // later tests.
    const heightBefore = await laggard.height();
    const partitionedSealer = new DistributedSealer(assemblerLedger, [
      peers[0]!,
      peers[1]!,
      peers[2]!,
      partitioned,
    ]);

    // Advance two blocks while node 3 is partitioned.
    for (let i = 0; i < 2; i++) {
      const height = await assemblerLedger.height();
      const block = await partitionedSealer.seal(
        await nextSealRequest(assemblerLedger, ELECTION, [entry(`partition-${height}`)]),
      );
      await assemblerLedger.append(block);
      await partitionedSealer.broadcastCommit(block);
    }
    assert.equal(await laggard.height(), heightBefore, "node should have missed the blocks");

    // The partition heals: the normal sealer resynchronises it over HTTP.
    const block = await sealer.seal(
      await nextSealRequest(assemblerLedger, ELECTION, [
        entry(`healed-${await assemblerLedger.height()}`),
      ]),
    );
    await assemblerLedger.append(block);
    await sealer.broadcastCommit(block);

    assert.equal(
      await laggard.height(),
      await assemblerLedger.height(),
      "the partitioned node did not resynchronise",
    );
    assert.ok((await laggard.ledger.verify()).valid);
  });

  it("reports behindAt across the wire", async () => {
    const height = await assemblerLedger.height();
    // Propose through whichever node is actually scheduled for this height.
    const proposed = await peers[height % peers.length]!.propose({
      height,
      electionId: ELECTION,
      entries: [entry(`behind-probe-${height}`)],
    });
    // Claim a height far beyond anything any node has reached.
    const bumped: Block = { ...proposed, header: { ...proposed.header, height: height + 5 } };

    const response = await peers[(height + 1) % peers.length]!.requestAttestation(bumped);
    assert.ok(response.refused);
    assert.equal(typeof response.behindAt, "number", "behindAt did not survive the wire");
  });
});

describe("fault tolerance over the network", () => {
  /** A peer pointed at a port nothing is listening on. */
  function unreachablePeer(id: string): HttpValidatorPeer {
    return new HttpValidatorPeer({
      id,
      baseUrl: `http://127.0.0.1:${BASE_PORT + 900}`,
      proposeToken: PROPOSE_TOKEN,
      timeoutMs: 500,
    });
  }

  it("seals despite a NON-PROPOSER validator being unreachable", async () => {
    const height = await assemblerLedger.height();
    const proposerIndex = height % peers.length;
    // Knock out a validator that is not scheduled to propose this round.
    const downIndex = (proposerIndex + 1) % peers.length;

    const degraded = new DistributedSealer(
      assemblerLedger,
      peers.map((peer, index) =>
        index === downIndex ? unreachablePeer(VALIDATOR_NAMES[index]!) : peer,
      ),
    );

    const block = await degraded.seal(
      await nextSealRequest(assemblerLedger, ELECTION, [entry(`degraded-${height}`)]),
    );
    assert.ok(block.attestations.length >= validatorSet.quorum);

    await assemblerLedger.append(block);
    await sealer.broadcastCommit(block);
  });

  it("fails over to the next proposer when the scheduled one is unreachable", async () => {
    // The proposer used to be a single point of failure for liveness. A view
    // change now routes around it, over the real network path.
    const height = await assemblerLedger.height();
    const proposerIndex = height % peers.length;

    const failover = new DistributedSealer(
      assemblerLedger,
      peers.map((peer, index) =>
        index === proposerIndex ? unreachablePeer(VALIDATOR_NAMES[index]!) : peer,
      ),
    );

    const request = await nextSealRequest(assemblerLedger, ELECTION, [entry(`failover-${height}`)]);
    const block = await failover.seal(request);

    assert.equal(block.header.view, 1, "view did not advance over HTTP");
    assert.equal(block.header.proposer, VALIDATOR_NAMES[(proposerIndex + 1) % peers.length]);
    assert.ok(block.attestations.length >= validatorSet.quorum);

    await assemblerLedger.append(block);
    await sealer.broadcastCommit(block);
    assert.ok((await assemblerLedger.verify()).valid);
  });
});
