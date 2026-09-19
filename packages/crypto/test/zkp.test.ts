import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MODP_2048, groupExp, groupMul, randomScalar, scalarAdd } from "../src/elgamal/group.ts";
import { encrypt, generateKeyPair } from "../src/elgamal/cipher.ts";
import { Transcript } from "../src/zkp/transcript.ts";
import {
  encryptionStatement,
  proveDlogEquality,
  verifyDlogEquality,
} from "../src/zkp/dlog-equality.ts";
import { proveOneOf, verifyOneOf } from "../src/zkp/disjunctive.ts";

const GROUP = MODP_2048;
const BINARY = [0n, 1n] as const;

function transcript(): Transcript {
  return new Transcript("test/v1").absorbString("context", "unit-test");
}

describe("Fiat-Shamir transcript", () => {
  it("is deterministic for identical absorption", async () => {
    const a = await transcript().absorbString("x", "hello").challenge(GROUP);
    const b = await transcript().absorbString("x", "hello").challenge(GROUP);
    assert.equal(a, b);
  });

  it("produces challenges in range", async () => {
    for (let i = 0; i < 10; i++) {
      const c = await transcript().absorbNumber("i", i).challenge(GROUP);
      assert.ok(c >= 0n && c < GROUP.q);
    }
  });

  it("separates domains", async () => {
    const a = await new Transcript("domain-a").absorbString("x", "v").challenge(GROUP);
    const b = await new Transcript("domain-b").absorbString("x", "v").challenge(GROUP);
    assert.notEqual(a, b);
  });

  it("is not vulnerable to field-boundary ambiguity", async () => {
    // Without length prefixing, ("ab","c") and ("a","bc") would hash identically
    // -- letting an attacker shift bytes between fields to forge a statement.
    const a = await transcript().absorbString("f", "ab").absorbString("g", "c").challenge(GROUP);
    const b = await transcript().absorbString("f", "a").absorbString("g", "bc").challenge(GROUP);
    assert.notEqual(a, b);
  });

  it("distinguishes labels", async () => {
    const a = await transcript().absorbString("label1", "v").challenge(GROUP);
    const b = await transcript().absorbString("label2", "v").challenge(GROUP);
    assert.notEqual(a, b);
  });
});

describe("Chaum-Pedersen discrete-log equality", () => {
  it("proves and verifies a true statement", async () => {
    const x = randomScalar(GROUP);
    const base2 = groupExp(GROUP, GROUP.g, 12345n);
    const statement = {
      group: GROUP,
      base1: GROUP.g,
      base2,
      y1: groupExp(GROUP, GROUP.g, x),
      y2: groupExp(GROUP, base2, x),
    };

    const proof = await proveDlogEquality(statement, x, transcript());
    assert.ok(await verifyDlogEquality(statement, proof, transcript()));
  });

  it("rejects a statement with mismatched exponents", async () => {
    // y1 = g^x but y2 = base2^x' for x' != x: the discrete logs are NOT equal.
    const x = randomScalar(GROUP);
    const other = randomScalar(GROUP);
    const base2 = groupExp(GROUP, GROUP.g, 999n);
    const statement = {
      group: GROUP,
      base1: GROUP.g,
      base2,
      y1: groupExp(GROUP, GROUP.g, x),
      y2: groupExp(GROUP, base2, other),
    };

    const proof = await proveDlogEquality(statement, x, transcript());
    assert.ok(!(await verifyDlogEquality(statement, proof, transcript())));
  });

  it("rejects a proof replayed under a different transcript", async () => {
    // Strong Fiat-Shamir: the challenge binds the context, so a proof valid in
    // one context is invalid in another.
    const x = randomScalar(GROUP);
    const base2 = groupExp(GROUP, GROUP.g, 7n);
    const statement = {
      group: GROUP,
      base1: GROUP.g,
      base2,
      y1: groupExp(GROUP, GROUP.g, x),
      y2: groupExp(GROUP, base2, x),
    };

    const proof = await proveDlogEquality(statement, x, transcript());
    const otherContext = new Transcript("test/v1").absorbString("context", "different");
    assert.ok(!(await verifyDlogEquality(statement, proof, otherContext)));
  });

  it("rejects tampered responses and challenges", async () => {
    const x = randomScalar(GROUP);
    const statement = {
      group: GROUP,
      base1: GROUP.g,
      base2: groupExp(GROUP, GROUP.g, 3n),
      y1: groupExp(GROUP, GROUP.g, x),
      y2: groupExp(GROUP, groupExp(GROUP, GROUP.g, 3n), x),
    };
    const proof = await proveDlogEquality(statement, x, transcript());

    assert.ok(
      !(await verifyDlogEquality(
        statement,
        { ...proof, response: scalarAdd(GROUP, proof.response, 1n) },
        transcript(),
      )),
    );
    assert.ok(
      !(await verifyDlogEquality(
        statement,
        { ...proof, challenge: scalarAdd(GROUP, proof.challenge, 1n) },
        transcript(),
      )),
    );
  });

  it("rejects out-of-subgroup commitments", async () => {
    const x = randomScalar(GROUP);
    const statement = {
      group: GROUP,
      base1: GROUP.g,
      base2: groupExp(GROUP, GROUP.g, 3n),
      y1: groupExp(GROUP, GROUP.g, x),
      y2: groupExp(GROUP, groupExp(GROUP, GROUP.g, 3n), x),
    };
    const proof = await proveDlogEquality(statement, x, transcript());

    assert.ok(
      !(await verifyDlogEquality(statement, { ...proof, commitment1: GROUP.p - 1n }, transcript())),
    );
  });
});

describe("disjunctive proof of ballot validity", () => {
  it("proves an encryption of 0 without revealing which branch is real", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 0n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 0, BINARY, transcript());
    assert.ok(await verifyOneOf(keys.publicKey, ciphertext, BINARY, proof, transcript()));
  });

  it("proves an encryption of 1", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript());
    assert.ok(await verifyOneOf(keys.publicKey, ciphertext, BINARY, proof, transcript()));
  });

  it("hides the vote: proofs for 0 and 1 are structurally identical", async () => {
    // Zero-knowledge in practice. Both proofs have the same shape and the same
    // value ranges, so an observer cannot tell them apart.
    const keys = generateKeyPair(GROUP);
    const zero = await encrypt(keys.publicKey, 0n);
    const one = await encrypt(keys.publicKey, 1n);

    const p0 = await proveOneOf(keys.publicKey, zero.ciphertext, zero.randomness, 0, BINARY, transcript());
    const p1 = await proveOneOf(keys.publicKey, one.ciphertext, one.randomness, 1, BINARY, transcript());

    assert.equal(p0.branches.length, p1.branches.length);
    for (const proof of [p0, p1]) {
      for (const branch of proof.branches) {
        assert.ok(branch.challenge >= 0n && branch.challenge < GROUP.q);
        assert.ok(branch.response >= 0n && branch.response < GROUP.q);
      }
    }
  });

  it("REJECTS a ballot encrypting an out-of-range value", async () => {
    // The attack the proof exists to stop: encrypting 1000 for your candidate.
    // The homomorphic tally would happily add it, since ciphertexts are opaque.
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1000n);

    // An honest prover cannot even construct the proof...
    await assert.rejects(
      () => proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript()),
      /does not encrypt the claimed value/,
    );

    // ...and a proof lifted from a legitimate ballot does not verify against it.
    const legit = encrypt(keys.publicKey, 1n);
    const stolen = await proveOneOf(
      keys.publicKey,
      legit.ciphertext,
      legit.randomness,
      1,
      BINARY,
      transcript(),
    );
    assert.ok(!(await verifyOneOf(keys.publicKey, ciphertext, BINARY, stolen, transcript())));
  });

  it("rejects a proof whose challenges do not sum to the hash", async () => {
    // Forging by simulating ALL branches requires controlling the challenge sum.
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript());

    const tampered = {
      branches: [
        { ...proof.branches[0]!, challenge: scalarAdd(GROUP, proof.branches[0]!.challenge, 1n) },
        proof.branches[1]!,
      ],
    };
    assert.ok(!(await verifyOneOf(keys.publicKey, ciphertext, BINARY, tampered, transcript())));
  });

  it("rejects a proof bound to a different context", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript());

    const other = new Transcript("test/v1").absorbString("context", "another-ballot");
    assert.ok(!(await verifyOneOf(keys.publicKey, ciphertext, BINARY, proof, other)));
  });

  it("rejects a proof transplanted onto a re-randomized copy of the ballot", async () => {
    // ElGamal malleability in action: an attacker re-randomizes a victim's
    // ciphertext to clone their vote. The proof must not travel with it.
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript());

    const cloned = {
      alpha: groupMul(GROUP, ciphertext.alpha, groupExp(GROUP, GROUP.g, 42n)),
      beta: groupMul(GROUP, ciphertext.beta, groupExp(GROUP, keys.publicKey.y, 42n)),
    };
    assert.ok(!(await verifyOneOf(keys.publicKey, cloned, BINARY, proof, transcript())));
  });

  it("supports multi-value ranges for approval voting", async () => {
    const keys = generateKeyPair(GROUP);
    const options = [0n, 1n, 2n, 3n];
    const { ciphertext, randomness } = encrypt(keys.publicKey, 2n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 2, options, transcript());
    assert.ok(await verifyOneOf(keys.publicKey, ciphertext, options, proof, transcript()));
  });

  it("supports a single-value set (degenerate OR)", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 0, [1n], transcript());
    assert.ok(await verifyOneOf(keys.publicKey, ciphertext, [1n], proof, transcript()));
    assert.ok(!(await verifyOneOf(keys.publicKey, ciphertext, [0n], proof, transcript())));
  });

  it("rejects a branch-count mismatch", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext, randomness } = encrypt(keys.publicKey, 1n);
    const proof = await proveOneOf(keys.publicKey, ciphertext, randomness, 1, BINARY, transcript());
    assert.ok(!(await verifyOneOf(keys.publicKey, ciphertext, [0n, 1n, 2n], proof, transcript())));
  });

  it("refuses to prove with mismatched randomness", async () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext } = encrypt(keys.publicKey, 1n);
    await assert.rejects(
      () => proveOneOf(keys.publicKey, ciphertext, randomScalar(GROUP), 1, BINARY, transcript()),
      /randomness does not match/,
    );
  });
});
