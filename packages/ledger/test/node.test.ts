import assert from "node:assert/strict";
import { before, describe, it } from "node:test";

import { utf8 } from "@dvoting/crypto";

import { ZERO_HASH, blockHash, proposeBlock, type Block, type LedgerEntry } from "../src/block.ts";
import { Ledger, validateBlock } from "../src/chain.ts";
import { InMemoryBlockStore } from "../src/store.ts";
import {
  LocalValidatorPeer,
  ValidatorNode,
  collectQuorum,
  type ValidatorPeer,
} from "../src/node.ts";
import { DistributedSealer, nextSealRequest } from "../src/sealer.ts";
import {
  createValidatorSet,
  generateValidatorKeyPair,
  type ValidatorKeyPair,
  type ValidatorSet,
} from "../src/validator.ts";

const ELECTION = "node-test";

let keyPairs: ValidatorKeyPair[];
let validatorSet: ValidatorSet;

before(async () => {
  keyPairs = await Promise.all([
    generateValidatorKeyPair("commission"),
    generateValidatorKeyPair("observer-a"),
    generateValidatorKeyPair("observer-b"),
    generateValidatorKeyPair("observer-c"),
  ]);
  validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));
});

function entry(id: string, payload = "x"): LedgerEntry {
  return { kind: "ballot", id, data: utf8(payload) };
}

function freshLedger(): Ledger {
  return new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION);
}

interface Cluster {
  nodes: ValidatorNode[];
  peers: LocalValidatorPeer[];
  ledger: Ledger;
  sealer: DistributedSealer;
}

type EntryCheck = (entry: LedgerEntry) => Promise<{ ok: boolean; reason?: string }>;

function createCluster(validateEntry?: EntryCheck): Cluster {
  const nodes = keyPairs.map((keyPair) => buildNode(keyPair, validateEntry));
  const peers = nodes.map((node) => new LocalValidatorPeer(node));
  const ledger = freshLedger();
  return { nodes, peers, ledger, sealer: new DistributedSealer(ledger, peers) };
}

function buildNode(keyPair: ValidatorKeyPair, validateEntry?: EntryCheck): ValidatorNode {
  return new ValidatorNode({
    identity: keyPair.identity,
    privateKey: keyPair.privateKey,
    ledger: freshLedger(),
    ...(validateEntry ? { validateEntry } : {}),
  });
}

/** Seal a block through the cluster and commit it everywhere. */
async function sealAndCommit(cluster: Cluster, entries: LedgerEntry[]): Promise<Block> {
  const request = await nextSealRequest(cluster.ledger, ELECTION, entries);
  const block = await cluster.sealer.seal(request);
  await cluster.ledger.append(block);
  await cluster.sealer.broadcastCommit(block);
  return block;
}

describe("each validator holds only its own key", () => {
  it("seals a block with attestations from independent nodes", async () => {
    const cluster = createCluster();
    const block = await sealAndCommit(cluster, [entry("e0")]);

    assert.equal(block.header.proposer, "commission");
    assert.ok(block.attestations.length >= validatorSet.quorum);

    // Every attestation comes from a distinct validator.
    const signers = block.attestations.map((a) => a.validator);
    assert.equal(new Set(signers).size, signers.length);
    assert.ok((await cluster.ledger.verify()).valid);
  });

  it("replicates committed blocks to every node", async () => {
    const cluster = createCluster();
    for (let i = 0; i < 3; i++) {
      await sealAndCommit(cluster, [entry(`e${i}`)]);
    }

    for (const node of cluster.nodes) {
      assert.equal(await node.height(), 3, `${node.identity.id} is out of sync`);
      assert.ok((await node.ledger.verify()).valid);
    }
  });

  it("rotates the proposer across nodes", async () => {
    const cluster = createCluster();
    const proposers: string[] = [];
    for (let i = 0; i < 4; i++) {
      proposers.push((await sealAndCommit(cluster, [entry(`e${i}`)])).header.proposer);
    }
    assert.deepEqual(proposers, ["commission", "observer-a", "observer-b", "observer-c"]);
  });

  it("refuses to propose when not the scheduled proposer", async () => {
    const cluster = createCluster();
    await assert.rejects(
      () => cluster.nodes[1]!.propose({ height: 0, electionId: ELECTION, entries: [entry("x")] }),
      /not the scheduled proposer/,
    );
  });
});

describe("validators independently re-validate before signing", () => {
  it("REFUSES a block whose entries do not match its Merkle root", async () => {
    // A rubber-stamp validator would sign this. An independent one must not.
    const cluster = createCluster();
    const proposer = keyPairs[0]!;
    const honest = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("e0")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });
    const stuffed: Block = { ...honest, entries: [...honest.entries, entry("smuggled")] };

    const response = await cluster.nodes[1]!.attest(stuffed);
    assert.ok(response.refused);
    assert.match(response.reason, /merkleRoot/);
  });

  it("REFUSES a block from an unscheduled proposer", async () => {
    const cluster = createCluster();
    const wrong = keyPairs[2]!;
    const block = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("e0")],
      proposer: wrong.identity,
      signingKey: wrong.privateKey,
    });

    const response = await cluster.nodes[1]!.attest(block);
    assert.ok(response.refused);
    assert.match(response.reason, /not scheduled/);
  });

  it("REFUSES a block that does not extend its own chain", async () => {
    // The validator trusts its own replica, not the proposer's claims.
    const cluster = createCluster();
    await sealAndCommit(cluster, [entry("e0")]);

    // Build a competing block at height 0, which every node has moved past.
    const proposer = keyPairs[0]!;
    const stale = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("late")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });

    const response = await cluster.nodes[1]!.attest(stale);
    assert.ok(response.refused);
    assert.match(response.reason, /height/);
  });

  it("REFUSES a block replaying an entry already on its chain", async () => {
    const cluster = createCluster();
    await sealAndCommit(cluster, [entry("ballot-1")]);

    const proposer = keyPairs[1]!; // height 1's proposer
    const replay = await proposeBlock({
      height: 1,
      electionId: ELECTION,
      previousHash: await blockHash((await cluster.ledger.head())!.header),
      entries: [entry("ballot-1")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });

    const response = await cluster.nodes[2]!.attest(replay);
    assert.ok(response.refused);
    assert.match(response.reason, /already on this node's chain/);
  });

  it("applies application-level entry rules", async () => {
    // Validators re-verify ballots, so a proposer cannot stuff invalid ones.
    const rejectBad = async (e: LedgerEntry) =>
      e.id === "bad" ? { ok: false, reason: "invalid ballot proof" } : { ok: true };

    const nodes = keyPairs.map((k) => buildNode(k, rejectBad));
    const peers = nodes.map((n) => new LocalValidatorPeer(n));
    const ledger = freshLedger();
    const sealer = new DistributedSealer(ledger, peers);

    await assert.rejects(
      async () => sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("bad")])),
      /failed to reach quorum/,
    );

    // ...and a clean block still seals.
    const ok = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("good")]));
    assert.ok(ok.attestations.length >= validatorSet.quorum);
  });
});

describe("equivocation is refused", () => {
  it("REFUSES to sign two different blocks at the same height", async () => {
    // Two conflicting quorums would fork the chain, showing different election
    // records to different observers.
    const cluster = createCluster();
    const proposer = keyPairs[0]!;

    const blockA = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("version-a")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });
    const blockB = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("version-b")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });

    const first = await cluster.nodes[1]!.attest(blockA);
    assert.ok(!first.refused);

    const second = await cluster.nodes[1]!.attest(blockB);
    assert.ok(second.refused);
    assert.match(second.reason, /refusing to equivocate/);
  });

  it("re-attests the SAME block idempotently", async () => {
    // A dropped response must not lock a validator out of a block it approves.
    const cluster = createCluster();
    const proposer = keyPairs[0]!;
    const block = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("e0")],
      proposer: proposer.identity,
      signingKey: proposer.privateKey,
    });

    const first = await cluster.nodes[1]!.attest(block);
    const retry = await cluster.nodes[1]!.attest(block);
    assert.ok(!first.refused);
    assert.ok(!retry.refused);
    assert.equal(first.attestation.validator, retry.attestation.validator);
  });

  it("a proposer cannot self-equivocate either", async () => {
    const cluster = createCluster();
    await cluster.nodes[0]!.propose({ height: 0, electionId: ELECTION, entries: [entry("a")] });

    const conflicting = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("b")],
      proposer: keyPairs[0]!.identity,
      signingKey: keyPairs[0]!.privateKey,
    });
    const response = await cluster.nodes[0]!.attest(conflicting);
    assert.ok(response.refused);
    assert.match(response.reason, /equivocate/);
  });
});

describe("a lagging validator recovers automatically", () => {
  /** A peer that silently drops commits, simulating lost replication. */
  function droppingCommits(peer: LocalValidatorPeer): ValidatorPeer {
    let dropping = true;
    const wrapper: ValidatorPeer & { stopDropping: () => void } = {
      id: peer.id,
      propose: (r) => peer.propose(r),
      requestAttestation: (b) => peer.requestAttestation(b),
      commit: async (b) => {
        if (dropping) return; // packet lost
        await peer.commit(b);
      },
      height: () => peer.height(),
      stopDropping: () => {
        dropping = false;
      },
    };
    return wrapper;
  }

  it("reports WHY it refused, so the gap is recoverable", async () => {
    const cluster = createCluster();
    // Advance the cluster while node 3 misses everything.
    const isolated = cluster.nodes[3]!;

    const block = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("e0")],
    });
    await cluster.nodes[1]!.commit(
      (await collectQuorum(block, [cluster.peers[1]!, cluster.peers[2]!], validatorSet.quorum)).block,
    );

    // Now ask the isolated node to attest height 1: it is behind.
    const next = await proposeBlock({
      height: 1,
      electionId: ELECTION,
      previousHash: await blockHash(block.header),
      entries: [entry("e1")],
      proposer: keyPairs[1]!.identity,
      signingKey: keyPairs[1]!.privateKey,
    });

    const response = await isolated.attest(next);
    assert.ok(response.refused);
    assert.equal(response.behindAt, 0, "refusal did not report the node's height");
  });

  it("catches a lagging validator up and still seals the block", async () => {
    // THE failure this fixes: without catch-up, one dropped commit removes a
    // validator from the set permanently.
    const cluster = createCluster();
    const flaky = droppingCommits(cluster.peers[3]!) as ValidatorPeer & {
      stopDropping: () => void;
    };
    const peers = [cluster.peers[0]!, cluster.peers[1]!, cluster.peers[2]!, flaky];
    const ledger = freshLedger();
    const sealer = new DistributedSealer(ledger, peers);

    // Two blocks that the flaky node never receives.
    for (let i = 0; i < 2; i++) {
      const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry(`e${i}`)]));
      await ledger.append(block);
      await sealer.broadcastCommit(block);
    }
    assert.equal(await cluster.nodes[3]!.height(), 0, "node should have missed both blocks");

    // Now the flaky node is the scheduled proposer's peer again and its network
    // recovers. The sealer should notice it is behind and replay the gap.
    flaky.stopDropping();
    const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("e2")]));
    await ledger.append(block);
    await sealer.broadcastCommit(block);

    assert.equal(await cluster.nodes[3]!.height(), 3, "lagging node did not catch up");
    assert.ok((await cluster.nodes[3]!.ledger.verify()).valid);
  });

  it("a caught-up validator attests normally again", async () => {
    const cluster = createCluster();
    const flaky = droppingCommits(cluster.peers[2]!) as ValidatorPeer & {
      stopDropping: () => void;
    };
    // Quorum is 3 of 4; drop one node and rely on the other three.
    const peers = [cluster.peers[0]!, cluster.peers[1]!, flaky, cluster.peers[3]!];
    const ledger = freshLedger();
    const sealer = new DistributedSealer(ledger, peers);

    for (let i = 0; i < 2; i++) {
      const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry(`x${i}`)]));
      await ledger.append(block);
      await sealer.broadcastCommit(block);
    }

    flaky.stopDropping();
    const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("x2")]));
    assert.ok(
      block.attestations.some((a) => a.validator === cluster.nodes[2]!.identity.id),
      "the recovered validator did not attest",
    );
  });

  it("validates catch-up blocks rather than trusting the coordinator", async () => {
    // Catch-up is safe from an untrusted source: commit runs full validation.
    const cluster = createCluster();
    const forged = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("forged")],
      proposer: keyPairs[0]!.identity,
      signingKey: keyPairs[0]!.privateKey,
    });
    // Only one signature: below quorum.
    await assert.rejects(() => cluster.nodes[1]!.commit(forged), /quorum/);
    assert.equal(await cluster.nodes[1]!.height(), 0);
  });

  it("distinguishes being AHEAD from being behind", async () => {
    const cluster = createCluster();
    const block = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("e0")],
    });
    const sealed = (
      await collectQuorum(block, [cluster.peers[1]!, cluster.peers[2]!], validatorSet.quorum)
    ).block;
    await cluster.nodes[1]!.commit(sealed);

    // Node 1 is at height 1; ask it to attest height 0 again with a different block.
    const stale = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("stale")],
      proposer: keyPairs[0]!.identity,
      signingKey: keyPairs[0]!.privateKey,
    });
    const response = await cluster.nodes[1]!.attest(stale);
    assert.ok(response.refused);
    assert.equal(response.behindAt, undefined, "an ahead node must not report itself behind");
    assert.match(response.reason, /already reached|equivocate/);
  });
});

describe("view changes (proposer failover)", () => {
  /** A peer that cannot propose, as if the authority were offline. */
  function deadProposer(id: string): ValidatorPeer {
    return {
      id,
      propose: () => Promise.reject(new Error("connection refused")),
      requestAttestation: () => Promise.reject(new Error("connection refused")),
      commit: () => Promise.reject(new Error("connection refused")),
    };
  }

  it("advances to the next proposer when the scheduled one is offline", async () => {
    const cluster = createCluster();
    // Height 0's proposer is "commission"; take it offline.
    const peers = [deadProposer("commission"), ...cluster.peers.slice(1)];
    const ledger = freshLedger();
    const sealer = new DistributedSealer(ledger, peers);

    const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("e0")]));

    assert.equal(block.header.view, 1, "view did not advance");
    assert.equal(block.header.proposer, "observer-a");
    assert.ok(block.attestations.length >= validatorSet.quorum);

    // And it is a fully valid block that the chain accepts.
    await ledger.append(block);
    assert.ok((await ledger.verify()).valid);
  });

  it("skips multiple offline proposers when the quorum still holds", async () => {
    // Needs a set large enough to tolerate two failures: n > 3f means 7
    // validators (quorum 5) tolerate 2, whereas 4 validators tolerate only 1.
    const bigKeys: ValidatorKeyPair[] = [];
    for (let i = 0; i < 7; i++) {
      bigKeys.push(await generateValidatorKeyPair(`v${i}`));
    }
    const bigSet = createValidatorSet(bigKeys.map((k) => k.identity));
    assert.equal(bigSet.quorum, 5);

    const bigNodes = bigKeys.map(
      (keyPair) =>
        new ValidatorNode({
          identity: keyPair.identity,
          privateKey: keyPair.privateKey,
          ledger: new Ledger(new InMemoryBlockStore(), bigSet, ELECTION),
        }),
    );
    const bigPeers: ValidatorPeer[] = bigNodes.map((n) => new LocalValidatorPeer(n));

    // Take the first two scheduled proposers offline.
    bigPeers[0] = deadProposer("v0");
    bigPeers[1] = deadProposer("v1");

    const ledger = new Ledger(new InMemoryBlockStore(), bigSet, ELECTION);
    const sealer = new DistributedSealer(ledger, bigPeers);

    const block = await sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("e0")]));
    assert.equal(block.header.view, 2, "view did not advance past both dead proposers");
    assert.equal(block.header.proposer, "v2");

    await ledger.append(block);
    assert.ok((await ledger.verify()).valid);
  });

  it("cannot proceed when more than a third of validators are offline", async () => {
    // Documents the fault-tolerance bound honestly: 4 validators with a
    // 3-of-4 quorum survive ONE failure, not two. View changes fix proposer
    // liveness; they cannot manufacture a quorum that does not exist.
    const cluster = createCluster();
    const peers = [
      deadProposer("commission"),
      deadProposer("observer-a"),
      cluster.peers[2]!,
      cluster.peers[3]!,
    ];
    const ledger = freshLedger();
    const sealer = new DistributedSealer(ledger, peers);

    await assert.rejects(
      async () => sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("e0")])),
      /failed to reach quorum/,
    );
  });

  it("records the view in the signed header, making failover auditable", async () => {
    const cluster = createCluster();
    const peers = [deadProposer("commission"), ...cluster.peers.slice(1)];
    const ledger = freshLedger();
    const block = await new DistributedSealer(ledger, peers).seal(
      await nextSealRequest(ledger, ELECTION, [entry("e0")]),
    );

    // The view is inside the hashed header, so it cannot be edited after the
    // fact without invalidating every signature.
    const tampered: Block = { ...block, header: { ...block.header, view: 0 } };
    const result = await validateBlock(tampered, null, validatorSet);
    assert.ok(!result.valid);
  });

  it("REJECTS a proposer that is not scheduled for the claimed view", async () => {
    // Without this, any validator could propose by picking a convenient view.
    const cluster = createCluster();
    const wrong = keyPairs[2]!; // not the height-0 view-1 proposer
    const block = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("e0")],
      proposer: wrong.identity,
      signingKey: wrong.privateKey,
      view: 1,
    });

    const response = await cluster.nodes[1]!.attest(block);
    assert.ok(response.refused);
    assert.match(response.reason, /not scheduled/);
  });

  it("REJECTS an out-of-range view", async () => {
    // Inflating the view would otherwise let a caller select any proposer.
    const cluster = createCluster();
    await assert.rejects(
      () => cluster.nodes[0]!.propose({ height: 0, electionId: ELECTION, entries: [], view: 99 }),
      /out of range/,
    );

    const forged = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("e0")],
      proposer: keyPairs[0]!.identity,
      signingKey: keyPairs[0]!.privateKey,
      view: 99,
    });
    const result = await validateBlock(forged, null, validatorSet);
    assert.ok(!result.valid);
    assert.ok(result.errors.some((e) => e.includes("out of range")));
  });

  it("CANNOT fork: two views at one height cannot both reach quorum", async () => {
    // The safety property that makes failover sound. Quorum intersection plus
    // anti-equivocation means no validator can sign both, so a second quorum is
    // unreachable.
    const cluster = createCluster();

    const viewZero = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("version-a")],
    });
    const sealedA = await collectQuorum(
      viewZero,
      cluster.peers.slice(1),
      validatorSet.quorum,
    );
    assert.ok(sealedA.block.attestations.length >= validatorSet.quorum);

    // Now a competing block at view 1, same height.
    const viewOne = await proposeBlock({
      height: 0,
      electionId: ELECTION,
      previousHash: ZERO_HASH,
      entries: [entry("version-b")],
      proposer: keyPairs[1]!.identity,
      signingKey: keyPairs[1]!.privateKey,
      view: 1,
    });

    await assert.rejects(
      () => collectQuorum(viewOne, cluster.peers, validatorSet.quorum),
      /failed to reach quorum/,
    );
  });

  it("fails clearly when every validator is offline", async () => {
    const ledger = freshLedger();
    const sealer = new DistributedSealer(
      ledger,
      keyPairs.map((k) => deadProposer(k.identity.id)),
    );
    await assert.rejects(
      async () => sealer.seal(await nextSealRequest(ledger, ELECTION, [entry("e0")])),
      /no validator could propose/,
    );
  });

  it("uses view 0 when the scheduled proposer is healthy", async () => {
    const cluster = createCluster();
    const block = await cluster.sealer.seal(
      await nextSealRequest(cluster.ledger, ELECTION, [entry("e0")]),
    );
    assert.equal(block.header.view, 0);
    assert.equal(block.header.proposer, "commission");
  });
});

describe("quorum collection", () => {
  it("tolerates a minority of unreachable validators", async () => {
    const cluster = createCluster();
    const proposed = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("e0")],
    });

    const broken: ValidatorPeer = {
      id: "observer-c",
      propose: () => Promise.reject(new Error("offline")),
      requestAttestation: () => Promise.reject(new Error("connection refused")),
      commit: () => Promise.reject(new Error("offline")),
    };
    const peers = [cluster.peers[1]!, cluster.peers[2]!, broken];

    const result = await collectQuorum(proposed, peers, validatorSet.quorum);
    assert.ok(result.block.attestations.length >= validatorSet.quorum);
  });

  it("FAILS when too many validators refuse", async () => {
    const cluster = createCluster();
    const proposed = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("e0")],
    });

    const refuseAll = (id: string): ValidatorPeer => ({
      id,
      propose: () => Promise.reject(new Error("no")),
      requestAttestation: async () => ({ refused: true, validator: id, reason: "policy" }),
      commit: async () => {},
    });

    await assert.rejects(
      () =>
        collectQuorum(
          proposed,
          [refuseAll("observer-a"), refuseAll("observer-b"), refuseAll("observer-c")],
          validatorSet.quorum,
        ),
      /failed to reach quorum/,
    );
  });

  it("stops polling once the quorum is met", async () => {
    const cluster = createCluster();
    const proposed = await cluster.nodes[0]!.propose({
      height: 0,
      electionId: ELECTION,
      entries: [entry("e0")],
    });

    let polled = 0;
    const counting = cluster.peers.slice(1).map(
      (peer): ValidatorPeer => ({
        id: peer.id,
        propose: (r) => peer.propose(r),
        requestAttestation: (b) => {
          polled++;
          return peer.requestAttestation(b);
        },
        commit: (b) => peer.commit(b),
      }),
    );

    await collectQuorum(proposed, counting, validatorSet.quorum);
    // Proposer already signed, so quorum 3 needs only 2 more.
    assert.equal(polled, 2);
  });
});
