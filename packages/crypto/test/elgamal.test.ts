import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getDiffieHellman } from "node:crypto";

import {
  MODP_2048,
  MODP_3072,
  groupExp,
  groupMul,
  isInSubgroup,
  isProbablePrime,
  randomScalar,
  validateGroup,
} from "../src/elgamal/group.ts";
import {
  addCiphertexts,
  assertValidCiphertext,
  combinePublicKeys,
  decryptToGroupElement,
  encrypt,
  generateKeyPair,
  reRandomize,
} from "../src/elgamal/cipher.ts";
import { createDiscreteLogTable, discreteLogSmall } from "../src/elgamal/dlog.ts";

const GROUP = MODP_2048; // fast; MODP_3072 is exercised separately below

describe("group parameters", () => {
  it("match Node's own RFC 3526 tables", () => {
    // Independent cross-check: if the hard-coded constant were mistyped or
    // maliciously substituted, it would not match OpenSSL's copy.
    for (const [group, modpName] of [
      [MODP_2048, "modp14"],
      [MODP_3072, "modp15"],
    ] as const) {
      const nodeGroup = getDiffieHellman(modpName);
      assert.equal(
        group.p,
        BigInt(`0x${nodeGroup.getPrime("hex")}`),
        `${group.name} prime does not match ${modpName}`,
      );
      assert.equal(group.g, BigInt(`0x${nodeGroup.getGenerator("hex")}`));
    }
  });

  it("are safe primes with a prime-order subgroup", () => {
    // Re-derived, not trusted: p prime, q = (p-1)/2 prime, g in the order-q
    // subgroup. This is the expensive check, so it runs only here.
    validateGroup(MODP_2048, 8);
    validateGroup(MODP_3072, 8);
  });

  it("has a generator that does NOT generate the full group", () => {
    // g^q == 1 means g generates the order-q quadratic-residue subgroup. If g
    // generated all of Z*_p, ElGamal would leak the Legendre symbol of the
    // plaintext -- i.e. leak information about the vote.
    for (const group of [MODP_2048, MODP_3072]) {
      assert.equal(groupExp(group, group.g, group.q), 1n);
      assert.notEqual(group.g, 1n);
    }
  });

  it("detects non-members of the subgroup", () => {
    const group = MODP_2048;
    // A quadratic non-residue must be rejected. p-1 has order 2, so it is the
    // canonical small-order element an attacker would try to inject.
    assert.equal(isInSubgroup(group, group.p - 1n), false);
    assert.equal(isInSubgroup(group, 0n), false);
    assert.equal(isInSubgroup(group, group.p), false);
    assert.equal(isInSubgroup(group, 1n), true);
    assert.equal(isInSubgroup(group, groupExp(group, group.g, 12345n)), true);
  });

  it("screens primality correctly on known values", () => {
    assert.equal(isProbablePrime(2n), true);
    assert.equal(isProbablePrime(97n), true);
    assert.equal(isProbablePrime(561n), false); // Carmichael number
    assert.equal(isProbablePrime(7919n), true);
    assert.equal(isProbablePrime(7917n), false);
  });
});

describe("exponential ElGamal", () => {
  it("encrypts and decrypts a small value", () => {
    const keys = generateKeyPair(GROUP);
    const { ciphertext } = encrypt(keys.publicKey, 7n);
    const element = decryptToGroupElement(GROUP, keys.x, ciphertext);
    assert.equal(discreteLogSmall(GROUP, element, 100), 7);
  });

  it("is additively homomorphic", () => {
    const keys = generateKeyPair(GROUP);
    const values = [3n, 5n, 11n, 0n, 1n];
    const ciphertexts = values.map((v) => encrypt(keys.publicKey, v).ciphertext);

    const sum = addCiphertexts(GROUP, ciphertexts);
    const element = decryptToGroupElement(GROUP, keys.x, sum);

    assert.equal(discreteLogSmall(GROUP, element, 100), 20);
  });

  it("is randomized: the same plaintext gives different ciphertexts", () => {
    const keys = generateKeyPair(GROUP);
    const a = encrypt(keys.publicKey, 1n).ciphertext;
    const b = encrypt(keys.publicKey, 1n).ciphertext;
    assert.notEqual(a.alpha, b.alpha);
    assert.notEqual(a.beta, b.beta);
  });

  it("produces ciphertexts inside the subgroup", () => {
    const keys = generateKeyPair(GROUP);
    for (const value of [0n, 1n, 42n]) {
      const { ciphertext } = encrypt(keys.publicKey, value);
      assert.doesNotThrow(() => assertValidCiphertext(GROUP, ciphertext));
    }
  });

  it("rejects ciphertexts outside the subgroup", () => {
    // The small-subgroup confinement attack: p-1 has order 2, so partial
    // decryptions of it would leak the private key one bit at a time.
    assert.throws(
      () => assertValidCiphertext(GROUP, { alpha: GROUP.p - 1n, beta: 1n }),
      /subgroup/,
    );
    assert.throws(() => assertValidCiphertext(GROUP, { alpha: 1n, beta: 0n }), /subgroup/);
  });

  it("re-randomizes without changing the plaintext (ElGamal is malleable)", () => {
    // This is the malleability that forces ballot proofs to be context-bound.
    const keys = generateKeyPair(GROUP);
    const original = encrypt(keys.publicKey, 1n).ciphertext;
    const { ciphertext: copied } = reRandomize(keys.publicKey, original);

    assert.notEqual(original.alpha, copied.alpha);
    assert.equal(
      discreteLogSmall(GROUP, decryptToGroupElement(GROUP, keys.x, copied), 10),
      discreteLogSmall(GROUP, decryptToGroupElement(GROUP, keys.x, original), 10),
    );
  });

  it("combines trustee public keys into a joint key", () => {
    const a = generateKeyPair(GROUP);
    const b = generateKeyPair(GROUP);
    const joint = combinePublicKeys([a.publicKey, b.publicKey]);

    const { ciphertext } = encrypt(joint, 4n);
    // The joint private key is the sum of the individual keys.
    const combinedPrivate = (a.x + b.x) % GROUP.q;
    const element = decryptToGroupElement(GROUP, combinedPrivate, ciphertext);
    assert.equal(discreteLogSmall(GROUP, element, 50), 4);
  });

  it("works at the 3072-bit production group size", () => {
    const keys = generateKeyPair(MODP_3072);
    const { ciphertext } = encrypt(keys.publicKey, 9n);
    const element = decryptToGroupElement(MODP_3072, keys.x, ciphertext);
    assert.equal(discreteLogSmall(MODP_3072, element, 100), 9);
  });
});

describe("discrete logarithm recovery", () => {
  it("recovers values across a range", () => {
    for (const m of [0, 1, 2, 17, 99, 100]) {
      const target = groupExp(GROUP, GROUP.g, BigInt(m));
      assert.equal(discreteLogSmall(GROUP, target, 100), m);
    }
  });

  it("recovers a large-ish tally", () => {
    const table = createDiscreteLogTable(GROUP, 5000);
    for (const m of [0, 1, 4999, 5000, 2500]) {
      assert.equal(table.solve(groupExp(GROUP, GROUP.g, BigInt(m))), m);
    }
  });

  it("throws rather than silently reporting a wrong count", () => {
    // A tally that does not decrypt to a plausible value means corruption. It
    // must never be reported as zero.
    const target = groupExp(GROUP, GROUP.g, 9999n);
    assert.throws(() => discreteLogSmall(GROUP, target, 100), /corrupt|no exponent/);
  });

  it("rejects a random group element", () => {
    const random = groupExp(GROUP, GROUP.g, randomScalar(GROUP));
    assert.throws(() => discreteLogSmall(GROUP, random, 1000), /corrupt|no exponent/);
  });
});

describe("scalar and group arithmetic", () => {
  it("multiplies within the subgroup", () => {
    const a = groupExp(GROUP, GROUP.g, 5n);
    const b = groupExp(GROUP, GROUP.g, 7n);
    assert.equal(groupMul(GROUP, a, b), groupExp(GROUP, GROUP.g, 12n));
  });

  it("samples scalars in range", () => {
    for (let i = 0; i < 50; i++) {
      const s = randomScalar(GROUP);
      assert.ok(s >= 1n && s < GROUP.q);
    }
  });
});
