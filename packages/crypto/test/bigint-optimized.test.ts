/**
 * Correctness tests for the optimized big-integer routines.
 *
 * These matter more than most: modPow was rewritten from the textbook
 * square-and-multiply into a sliding-window implementation, and it underpins
 * BOTH the RSA blind signatures and the entire ElGamal/ZKP stack. Every routine
 * here is checked against an independent reference implementation rather than
 * against itself.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  FixedBaseExponentiator,
  jacobiSymbol,
  modPow,
  randomBigIntBelow,
} from "../src/util/bigint.ts";
import { randomBytes } from "../src/util/bytes.ts";
import { MODP_2048, MODP_3072 } from "../src/elgamal/group.ts";

/** Deliberately naive square-and-multiply, used only as an oracle. */
function referenceModPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = ((base % modulus) + modulus) % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

describe("sliding-window modPow", () => {
  it("matches the reference on known values", () => {
    assert.equal(modPow(2n, 10n, 1000n), 24n);
    assert.equal(modPow(4n, 13n, 497n), 445n);
    assert.equal(modPow(0n, 0n, 7n), 1n);
    assert.equal(modPow(5n, 0n, 7n), 1n);
    assert.equal(modPow(0n, 5n, 7n), 0n);
    assert.equal(modPow(7n, 1n, 7n), 0n);
  });

  it("matches the reference across every window-size boundary", () => {
    // The implementation switches strategy at 8, 128 and 512 exponent bits.
    const modulus = MODP_2048.p;
    const base = 12345678901234567890n;
    for (const bits of [1, 2, 7, 8, 9, 63, 127, 128, 129, 255, 511, 512, 513, 1024, 2047]) {
      const exponent = (1n << BigInt(bits)) - 1n; // all bits set: worst case
      assert.equal(
        modPow(base, exponent, modulus),
        referenceModPow(base, exponent, modulus),
        `mismatch at ${bits}-bit exponent`,
      );
    }
  });

  it("matches the reference on random inputs", () => {
    const modulus = MODP_2048.p;
    for (let i = 0; i < 25; i++) {
      const base = randomBigIntBelow(modulus, randomBytes);
      const exponent = randomBigIntBelow(MODP_2048.q, randomBytes);
      assert.equal(modPow(base, exponent, modulus), referenceModPow(base, exponent, modulus));
    }
  });

  it("handles sparse and dense exponents identically to the reference", () => {
    const modulus = MODP_2048.p;
    const base = 3n;
    const sparse = 1n << 2000n; // single set bit
    const dense = (1n << 2000n) - 1n; // every bit set
    assert.equal(modPow(base, sparse, modulus), referenceModPow(base, sparse, modulus));
    assert.equal(modPow(base, dense, modulus), referenceModPow(base, dense, modulus));
  });

  it("still satisfies RSA round-tripping (regression guard for blind signatures)", () => {
    // Small but genuine RSA parameters: e*d == 1 mod lcm(p-1,q-1).
    const p = 61n;
    const q = 53n;
    const n = p * q;
    const e = 17n;
    const d = 413n;
    for (let m = 2n; m < 50n; m++) {
      assert.equal(modPow(modPow(m, e, n), d, n), m % n, `RSA round-trip failed for ${m}`);
    }
  });

  it("rejects invalid arguments", () => {
    assert.throws(() => modPow(2n, -1n, 7n), RangeError);
    assert.throws(() => modPow(2n, 3n, 0n), RangeError);
    assert.equal(modPow(2n, 3n, 1n), 0n);
  });
});

describe("Jacobi symbol", () => {
  it("agrees with Euler's criterion for the production groups", () => {
    // For prime p, (a/p) == a^((p-1)/2) mod p. This is the exact equivalence
    // the subgroup check relies on, so it is checked directly.
    for (const group of [MODP_2048, MODP_3072]) {
      for (let i = 0; i < 12; i++) {
        const a = randomBigIntBelow(group.p, randomBytes);
        const euler = referenceModPow(a, group.q, group.p);
        const expected = euler === 1n ? 1 : euler === group.p - 1n ? -1 : 0;
        assert.equal(jacobiSymbol(a, group.p), expected, `mismatch for a=${a} in ${group.name}`);
      }
    }
  });

  it("matches known small values", () => {
    // (a/7): squares mod 7 are {1,2,4}.
    assert.equal(jacobiSymbol(1n, 7n), 1);
    assert.equal(jacobiSymbol(2n, 7n), 1);
    assert.equal(jacobiSymbol(3n, 7n), -1);
    assert.equal(jacobiSymbol(4n, 7n), 1);
    assert.equal(jacobiSymbol(5n, 7n), -1);
    assert.equal(jacobiSymbol(6n, 7n), -1);
    assert.equal(jacobiSymbol(7n, 7n), 0);
  });

  it("identifies the generator as a quadratic residue", () => {
    // g = 2 must be a QR, which holds because p == 7 (mod 8).
    for (const group of [MODP_2048, MODP_3072]) {
      assert.equal(jacobiSymbol(group.g, group.p), 1);
      // p-1 has order 2 and is the canonical non-residue.
      assert.equal(jacobiSymbol(group.p - 1n, group.p), -1);
    }
  });

  it("rejects even or non-positive moduli", () => {
    assert.throws(() => jacobiSymbol(3n, 8n), RangeError);
    assert.throws(() => jacobiSymbol(3n, 0n), RangeError);
  });
});

describe("fixed-base exponentiation", () => {
  it("matches modPow across the exponent range", () => {
    const group = MODP_2048;
    const table = new FixedBaseExponentiator(group.g, group.p, group.q.toString(2).length);

    for (const exponent of [0n, 1n, 15n, 16n, 255n, 256n, 65535n]) {
      assert.equal(table.pow(exponent), modPow(group.g, exponent, group.p), `failed at ${exponent}`);
    }
  });

  it("matches modPow on random full-size exponents", () => {
    const group = MODP_2048;
    const base = modPow(group.g, 987654321n, group.p);
    const table = new FixedBaseExponentiator(base, group.p, group.q.toString(2).length);

    for (let i = 0; i < 10; i++) {
      const exponent = randomBigIntBelow(group.q, randomBytes);
      assert.equal(table.pow(exponent), modPow(base, exponent, group.p));
    }
  });

  it("rejects exponents beyond the precomputed range", () => {
    const group = MODP_2048;
    const table = new FixedBaseExponentiator(group.g, group.p, 64);
    assert.throws(() => table.pow(1n << 200n), /exceeds the precomputed range/);
  });

  it("rejects negative exponents", () => {
    const group = MODP_2048;
    const table = new FixedBaseExponentiator(group.g, group.p, 64);
    assert.throws(() => table.pow(-1n), RangeError);
  });

  it("is actually faster than the generic path", () => {
    // Guards against the optimization silently regressing into a pessimization.
    const group = MODP_3072;
    const bits = group.q.toString(2).length;
    const exponents = Array.from({ length: 12 }, () => randomBigIntBelow(group.q, randomBytes));

    const genericStart = performance.now();
    for (const e of exponents) modPow(group.g, e, group.p);
    const genericMs = performance.now() - genericStart;

    const table = new FixedBaseExponentiator(group.g, group.p, bits);
    const fixedStart = performance.now();
    for (const e of exponents) table.pow(e);
    const fixedMs = performance.now() - fixedStart;

    assert.ok(
      fixedMs < genericMs,
      `fixed-base (${fixedMs.toFixed(1)}ms) was not faster than generic (${genericMs.toFixed(1)}ms)`,
    );
  });
});
