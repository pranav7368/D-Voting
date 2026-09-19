/**
 * Durability across a restart, using the real election path.
 *
 * An election that loses its record when a process restarts is unusable, so
 * this exercises the whole stack against file-backed storage: cast ballots,
 * throw every in-memory object away, reload from disk, and confirm the tally
 * and the inclusion proofs still come out right.
 */

import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createBallot,
  decryptTally,
  encodeElement,
  partialDecrypt,
  setupTrustees,
  toBase64Url,
  type PartialDecryption,
  type TrusteeSetup,
} from "@dvoting/crypto";
import {
  DistributedSealer,
  Ledger,
  LocalValidatorPeer,
  ValidatorNode,
  createValidatorSet,
  encodeEntry,
  generateValidatorKeyPair,
  verifyMerkleProof,
  type ValidatorKeyPair,
  type ValidatorSet,
} from "@dvoting/ledger";
import { FileBlockStore } from "@dvoting/ledger/file-store";

import { BallotBox } from "../src/ballot-box.ts";
import { tallyFromChain } from "../src/chain-tally.ts";
import { ELECTION, GROUP, issuerKeys, makeVoter } from "./helpers.ts";

let dir: string;
let keyPairs: ValidatorKeyPair[];
let validatorSet: ValidatorSet;
let trustees: TrusteeSetup;

before(async () => {
  dir = await mkdtemp(join(tmpdir(), "dvoting-durability-"));
  keyPairs = [];
  for (const name of ["commission", "observer-a", "observer-b"]) {
    keyPairs.push(await generateValidatorKeyPair(name));
  }
  validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));
  trustees = setupTrustees(GROUP, 2, 3);
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

interface Cluster {
  ballotBox: BallotBox;
  ledger: Ledger;
  stores: FileBlockStore[];
  close: () => Promise<void>;
}

/**
 * Build a cluster whose ledgers are all file-backed. Calling this twice with
 * the same `tag` simulates restarting every process.
 */
async function bootCluster(tag: string): Promise<Cluster> {
  const stores: FileBlockStore[] = [];

  const nodes: ValidatorNode[] = [];
  for (const [index, keyPair] of keyPairs.entries()) {
    const store = await FileBlockStore.open(join(dir, `${tag}-validator-${index}.jsonl`));
    stores.push(store);
    nodes.push(
      new ValidatorNode({
        identity: keyPair.identity,
        privateKey: keyPair.privateKey,
        ledger: new Ledger(store, validatorSet, ELECTION.electionId),
      }),
    );
  }

  const assemblerStore = await FileBlockStore.open(join(dir, `${tag}-assembler.jsonl`));
  stores.push(assemblerStore);
  const ledger = new Ledger(assemblerStore, validatorSet, ELECTION.electionId);

  const ballotBox = new BallotBox({
    election: ELECTION,
    issuerPublicKey: issuerKeys.publicKey,
    electionPublicKey: trustees.publicKey,
    trustees: {
      threshold: trustees.threshold,
      total: trustees.total,
      publicShares: trustees.publicShares.map((share) => ({
        index: share.index,
        publicShare: toBase64Url(encodeElement(GROUP, share.publicShare)),
      })),
    },
    ledger,
    sealer: new DistributedSealer(ledger, nodes.map((node) => new LocalValidatorPeer(node))),
  });

  // Reads the election's state back off the chain: on a second boot this is
  // what makes the restarted process agree with the one it replaced.
  await ballotBox.load();
  if (ballotBox.phase === "setup") await ballotBox.openPoll();

  return {
    ballotBox,
    ledger,
    stores,
    close: async () => {
      for (const store of stores) await store.close();
    },
  };
}

async function castFor(cluster: Cluster, selections: number[]): Promise<string> {
  const voter = await makeVoter();
  const ballot = await createBallot(ELECTION, trustees.publicKey, selections, {
    credentialFingerprint: voter.fingerprint,
  });
  const result = await cluster.ballotBox.cast({
    credential: voter.credential,
    credentialSignature: voter.signature,
    ballot,
  });
  return result.ballotId;
}

describe("an election survives a full restart", () => {
  it("reloads the chain and produces the same tally", async () => {
    const tag = "election";

    // --- first run ---------------------------------------------------------
    const first = await bootCluster(tag);
    const trackedId = await castFor(first, [1, 0, 0]);
    await castFor(first, [1, 0, 0]);
    await castFor(first, [0, 1, 0]);
    await first.ballotBox.sealBlock();

    const beforeRestart = await tallyFromChain(first.ledger, ELECTION, trustees.publicKey);
    assert.equal(beforeRestart.counted.length, 3);
    await first.close();

    // --- everything is torn down and rebuilt from disk ----------------------
    const second = await bootCluster(tag);

    // Block 0 is the sealed election configuration; block 1 holds the ballots.
    assert.equal(await second.ledger.height(), 2, "chain did not survive the restart");
    const report = await second.ledger.verify();
    assert.deepEqual(report.errors, []);
    assert.ok(report.valid);

    // The voter's tracking code still resolves, with a valid inclusion proof.
    const located = await second.ledger.locateEntry("ballot", trackedId);
    assert.ok(located, "tracking code did not survive the restart");
    assert.ok(
      await verifyMerkleProof(encodeEntry(located.entry), located.proof, located.merkleRoot),
    );

    // The tally is unchanged.
    const afterRestart = await tallyFromChain(second.ledger, ELECTION, trustees.publicKey);
    assert.equal(afterRestart.counted.length, 3);
    assert.deepEqual(
      afterRestart.counted.map((c) => c.ballot.ballotId).sort(),
      beforeRestart.counted.map((c) => c.ballot.ballotId).sort(),
    );

    // ...and it still decrypts to the right result.
    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of afterRestart.encryptedTotals) {
      const partials: PartialDecryption[] = [];
      for (const keyShare of trustees.keyShares.slice(0, 2)) {
        partials.push(await partialDecrypt(GROUP, ELECTION.electionId, keyShare, total));
      }
      partialsByCandidate.push(partials);
    }
    const result = await decryptTally(
      GROUP,
      ELECTION.electionId,
      ELECTION.candidates,
      afterRestart.encryptedTotals,
      partialsByCandidate,
      trustees.publicShares,
      trustees.threshold,
      afterRestart.counted.length,
    );
    assert.deepEqual(result.results.map((r) => r.votes), [2, 1, 0]);

    await second.close();
  });

  it("keeps accepting ballots after the restart", async () => {
    const tag = "continue";

    const first = await bootCluster(tag);
    await castFor(first, [1, 0, 0]);
    await first.ballotBox.sealBlock();
    await first.close();

    const second = await bootCluster(tag);
    await castFor(second, [0, 1, 0]);
    await second.ballotBox.sealBlock();

    // config + first ballot block + second ballot block
    assert.equal(await second.ledger.height(), 3);
    assert.ok((await second.ledger.verify()).valid);

    const tally = await tallyFromChain(second.ledger, ELECTION, trustees.publicKey);
    assert.equal(tally.counted.length, 2);
    await second.close();
  });

  it("CANNOT be reopened by restarting the service after it was closed", async () => {
    // The close used to be a boolean in memory, which meant a restart -- crash,
    // deploy, or a deliberate one -- silently reopened a closed election. It is
    // an entry on the chain now, so the restarted process reaches the same
    // verdict as the one it replaced.
    const tag = "reopen";

    const first = await bootCluster(tag);
    await castFor(first, [1, 0, 0]);
    await first.ballotBox.closePoll();
    assert.equal(first.ballotBox.phase, "closed");
    await first.close();

    const second = await bootCluster(tag);
    assert.equal(second.ballotBox.phase, "closed", "restarting reopened a closed election");
    assert.equal(second.ballotBox.isOpen, false);

    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, trustees.publicKey, [0, 1, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await assert.rejects(
      () =>
        second.ballotBox.cast({
          credential: voter.credential,
          credentialSignature: voter.signature,
          ballot,
        }),
      (error: Error & { code?: string }) => error.code === "election_closed",
    );

    // And the sealed configuration is still the one the election opened with.
    assert.equal(second.ballotBox.record?.electionId, ELECTION.electionId);
    assert.deepEqual(second.ballotBox.record?.candidates, ELECTION.candidates);
    await second.close();
  });

  it("still refuses a ballot replayed from before the restart", async () => {
    // Double-vote protection must be a property of the chain, not of memory.
    const tag = "replay";

    const first = await bootCluster(tag);
    const voter = await makeVoter();
    const ballot = await createBallot(ELECTION, trustees.publicKey, [1, 0, 0], {
      credentialFingerprint: voter.fingerprint,
    });
    await first.ballotBox.cast({
      credential: voter.credential,
      credentialSignature: voter.signature,
      ballot,
    });
    await first.ballotBox.sealBlock();
    await first.close();

    const second = await bootCluster(tag);
    await assert.rejects(
      () =>
        second.ballotBox.cast({
          credential: voter.credential,
          credentialSignature: voter.signature,
          ballot,
        }),
      /already been recorded/,
    );
    await second.close();
  });
});
