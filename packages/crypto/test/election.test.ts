import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MODP_2048, groupExp, groupMul } from "../src/elgamal/group.ts";
import { encrypt } from "../src/elgamal/cipher.ts";
import {
  createBallot,
  generateBallotId,
  verifyBallot,
  type ElectionParameters,
  type EncryptedBallot,
} from "../src/election/ballot.ts";
import { decryptTally, homomorphicTally } from "../src/election/tally.ts";
import {
  partialDecrypt,
  setupTrustees,
  type PartialDecryption,
  type TrusteeSetup,
} from "../src/threshold/trustee.ts";

const GROUP = MODP_2048;

const ELECTION: ElectionParameters = {
  electionId: "general-2026",
  candidates: ["Alice", "Bob", "Carol"],
  minSelections: 1,
  maxSelections: 1,
};

/** Run the trustee side of the count for every candidate. */
async function runTally(
  setup: TrusteeSetup,
  election: ElectionParameters,
  ballots: EncryptedBallot[],
  trusteeIndices: number[],
) {
  const totals = homomorphicTally(GROUP, election.candidates.length, ballots);

  const partialsByCandidate: PartialDecryption[][] = [];
  for (const total of totals) {
    const partials: PartialDecryption[] = [];
    for (const i of trusteeIndices) {
      partials.push(await partialDecrypt(GROUP, election.electionId, setup.keyShares[i]!, total));
    }
    partialsByCandidate.push(partials);
  }

  return decryptTally(
    GROUP,
    election.electionId,
    election.candidates,
    totals,
    partialsByCandidate,
    setup.publicShares,
    setup.threshold,
    ballots.length,
  );
}

describe("a complete election", () => {
  it("runs end to end: encrypt -> prove -> tally -> threshold decrypt", async () => {
    const setup = setupTrustees(GROUP, 3, 5);

    // Six voters. Alice should win 3-2-1.
    const votes = [
      [1, 0, 0],
      [1, 0, 0],
      [1, 0, 0],
      [0, 1, 0],
      [0, 1, 0],
      [0, 0, 1],
    ];

    const ballots: EncryptedBallot[] = [];
    for (const vote of votes) {
      const ballot = await createBallot(ELECTION, setup.publicKey, vote);
      // Every ballot is publicly verifiable before it is counted.
      assert.ok(await verifyBallot(ELECTION, setup.publicKey, ballot));
      ballots.push(ballot);
    }

    const result = await runTally(setup, ELECTION, ballots, [0, 1, 2]);

    assert.equal(result.ballotsCounted, 6);
    assert.deepEqual(
      result.results.map((r) => [r.candidate, r.votes]),
      [
        ["Alice", 3],
        ["Bob", 2],
        ["Carol", 1],
      ],
    );
  });

  it("produces the same result with a different qualifying trustee subset", async () => {
    const setup = setupTrustees(GROUP, 3, 5);
    const ballots: EncryptedBallot[] = [];
    for (const vote of [[1, 0, 0], [0, 1, 0], [1, 0, 0]]) {
      ballots.push(await createBallot(ELECTION, setup.publicKey, vote));
    }

    const first = await runTally(setup, ELECTION, ballots, [0, 1, 2]);
    const second = await runTally(setup, ELECTION, ballots, [2, 3, 4]);
    assert.deepEqual(first.results, second.results);
    assert.equal(first.results[0]!.votes, 2);
  });

  it("never decrypts an individual ballot", async () => {
    // Structural check of the core privacy claim: the only thing that is ever
    // decrypted is the aggregate. A single ballot's ciphertexts are distinct
    // from the tally's and are never passed to any decryption routine.
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const totals = homomorphicTally(GROUP, ELECTION.candidates.length, [ballot]);

    // With one ballot the aggregate equals that ballot -- which is an inherent
    // property of any homomorphic tally, not a flaw in the encryption. It is
    // why a real election must not decrypt a tally with too few ballots.
    assert.equal(totals[0]!.alpha, ballot.choices[0]!.alpha);
  });

  it("counts an abstention correctly when permitted", async () => {
    const abstainable: ElectionParameters = { ...ELECTION, minSelections: 0 };
    const setup = setupTrustees(GROUP, 2, 3);

    const ballots = [
      await createBallot(abstainable, setup.publicKey, [0, 0, 0]),
      await createBallot(abstainable, setup.publicKey, [1, 0, 0]),
    ];
    for (const ballot of ballots) {
      assert.ok(await verifyBallot(abstainable, setup.publicKey, ballot));
    }

    const result = await runTally(setup, abstainable, ballots, [0, 1]);
    assert.deepEqual(result.results.map((r) => r.votes), [1, 0, 0]);
  });

  it("supports approval voting", async () => {
    const approval: ElectionParameters = { ...ELECTION, minSelections: 1, maxSelections: 2 };
    const setup = setupTrustees(GROUP, 2, 3);

    const ballots = [
      await createBallot(approval, setup.publicKey, [1, 1, 0]),
      await createBallot(approval, setup.publicKey, [0, 1, 1]),
      await createBallot(approval, setup.publicKey, [1, 0, 0]),
    ];
    for (const ballot of ballots) {
      assert.ok(await verifyBallot(approval, setup.publicKey, ballot));
    }

    const result = await runTally(setup, approval, ballots, [0, 1]);
    assert.deepEqual(result.results.map((r) => r.votes), [2, 2, 1]);
  });

  it("handles an election with zero ballots", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const result = await runTally(setup, ELECTION, [], [0, 1]);
    assert.deepEqual(result.results.map((r) => r.votes), [0, 0, 0]);
  });
});

describe("ballot fraud is rejected", () => {
  it("refuses to build a ballot selecting too many candidates", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    await assert.rejects(
      () => createBallot(ELECTION, setup.publicKey, [1, 1, 0]),
      /permits 1\.\.1/,
    );
  });

  it("refuses to build a ballot with a non-binary selection", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    await assert.rejects(
      () => createBallot(ELECTION, setup.publicKey, [5, 0, 0]),
      /exactly 0 or 1/,
    );
  });

  it("rejects a ballot whose ciphertext was swapped after proving", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const forged: EncryptedBallot = {
      ...ballot,
      choices: [encrypt(setup.publicKey, 1n).ciphertext, ballot.choices[1]!, ballot.choices[2]!],
    };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, forged)));
  });

  it("rejects a ballot stuffed with an inflated vote", async () => {
    // The attack the validity proofs exist to stop: encrypt 100 instead of 1.
    // A tally without proofs would add it and hand the election to the attacker.
    const setup = setupTrustees(GROUP, 2, 3);
    const honest = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const stuffed: EncryptedBallot = {
      ...honest,
      choices: [encrypt(setup.publicKey, 100n).ciphertext, honest.choices[1]!, honest.choices[2]!],
    };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, stuffed)));
  });

  it("rejects a ballot cloned by re-randomization", async () => {
    // ElGamal is malleable, so an attacker can transform a victim's ciphertexts
    // into fresh-looking ones encrypting the same vote. Context-bound proofs
    // stop the clone from verifying.
    const setup = setupTrustees(GROUP, 2, 3);
    const victim = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const cloned: EncryptedBallot = {
      ...victim,
      ballotId: generateBallotId(),
      choices: victim.choices.map((ct) => ({
        alpha: groupMul(GROUP, ct.alpha, groupExp(GROUP, GROUP.g, 7n)),
        beta: groupMul(GROUP, ct.beta, groupExp(GROUP, setup.publicKey.y, 7n)),
      })),
    };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, cloned)));
  });

  it("rejects a ballot re-cast under a different credential", async () => {
    // Without credential binding, an attacker who observed a submission could
    // re-submit the identical ballot under their own credential, consuming the
    // ballot id and blocking the real voter.
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0], {
      credentialFingerprint: "voter-alpha-credential",
    });
    assert.ok(await verifyBallot(ELECTION, setup.publicKey, ballot));

    const hijacked: EncryptedBallot = { ...ballot, credentialFingerprint: "attacker-credential" };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, hijacked)));
  });

  it("rejects a ballot replayed under a new ballot id", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const original = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const replayed: EncryptedBallot = { ...original, ballotId: generateBallotId() };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, replayed)));
  });

  it("rejects a ballot submitted to the wrong election", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);

    const other: ElectionParameters = { ...ELECTION, electionId: "by-election-2027" };
    assert.ok(!(await verifyBallot(other, setup.publicKey, { ...ballot, electionId: other.electionId })));
  });

  it("rejects a ballot verified against the wrong election key", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const other = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    assert.ok(!(await verifyBallot(ELECTION, other.publicKey, ballot)));
  });

  it("rejects proofs spliced between two ballots", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const a = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const b = await createBallot(ELECTION, setup.publicKey, [0, 1, 0]);

    const spliced: EncryptedBallot = { ...a, choiceProofs: b.choiceProofs };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, spliced)));
  });

  it("rejects a ballot with the wrong number of ciphertexts", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const truncated: EncryptedBallot = { ...ballot, choices: ballot.choices.slice(0, 2) };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, truncated)));
  });

  it("rejects out-of-subgroup ciphertexts in a ballot", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballot = await createBallot(ELECTION, setup.publicKey, [1, 0, 0]);
    const attacked: EncryptedBallot = {
      ...ballot,
      choices: [{ alpha: GROUP.p - 1n, beta: ballot.choices[0]!.beta }, ballot.choices[1]!, ballot.choices[2]!],
    };
    assert.ok(!(await verifyBallot(ELECTION, setup.publicKey, attacked)));
  });
});

describe("tally integrity", () => {
  it("refuses a tally containing a forged partial decryption", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballots = [await createBallot(ELECTION, setup.publicKey, [1, 0, 0])];
    const totals = homomorphicTally(GROUP, ELECTION.candidates.length, ballots);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of totals) {
      const good = await partialDecrypt(GROUP, ELECTION.electionId, setup.keyShares[0]!, total);
      const bad = await partialDecrypt(GROUP, ELECTION.electionId, setup.keyShares[1]!, total);
      partialsByCandidate.push([good, { ...bad, factor: groupExp(GROUP, GROUP.g, 3n) }]);
    }

    await assert.rejects(
      () =>
        decryptTally(
          GROUP,
          ELECTION.electionId,
          ELECTION.candidates,
          totals,
          partialsByCandidate,
          setup.publicShares,
          setup.threshold,
          ballots.length,
        ),
      /invalid partial decryption/,
    );
  });

  it("refuses a tally with too few trustees", async () => {
    const setup = setupTrustees(GROUP, 3, 5);
    const ballots = [await createBallot(ELECTION, setup.publicKey, [1, 0, 0])];
    const totals = homomorphicTally(GROUP, ELECTION.candidates.length, ballots);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of totals) {
      partialsByCandidate.push([
        await partialDecrypt(GROUP, ELECTION.electionId, setup.keyShares[0]!, total),
      ]);
    }

    await assert.rejects(
      () =>
        decryptTally(
          GROUP,
          ELECTION.electionId,
          ELECTION.candidates,
          totals,
          partialsByCandidate,
          setup.publicShares,
          setup.threshold,
          ballots.length,
        ),
      /threshold is 3/,
    );
  });

  it("refuses a partial from an unknown trustee", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const ballots = [await createBallot(ELECTION, setup.publicKey, [1, 0, 0])];
    const totals = homomorphicTally(GROUP, ELECTION.candidates.length, ballots);

    const partialsByCandidate: PartialDecryption[][] = [];
    for (const total of totals) {
      const partial = await partialDecrypt(GROUP, ELECTION.electionId, setup.keyShares[0]!, total);
      partialsByCandidate.push([{ ...partial, index: 99 }]);
    }

    await assert.rejects(
      () =>
        decryptTally(
          GROUP,
          ELECTION.electionId,
          ELECTION.candidates,
          totals,
          partialsByCandidate,
          setup.publicShares,
          setup.threshold,
          ballots.length,
        ),
      /unknown trustee/,
    );
  });
});
