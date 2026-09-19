import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  concatBytes,
  constantTimeEqual,
  fromBase64Url,
  i2osp,
  os2ip,
  toBase64Url,
  xorBytes,
} from "../src/util/bytes.ts";
import { bitLength, modInverse, modPow, randomBigIntBelow } from "../src/util/bigint.ts";

describe("i2osp / os2ip", () => {
  it("round-trips values", () => {
    for (const value of [0n, 1n, 255n, 256n, 65535n, 2n ** 300n + 12345n]) {
      const bytes = i2osp(value, 64);
      assert.equal(bytes.length, 64);
      assert.equal(os2ip(bytes), value);
    }
  });

  it("pads to the exact requested length", () => {
    assert.deepEqual(Array.from(i2osp(1n, 4)), [0, 0, 0, 1]);
  });

  it("rejects values that do not fit", () => {
    assert.throws(() => i2osp(256n, 1), RangeError);
  });

  it("rejects negative values", () => {
    assert.throws(() => i2osp(-1n, 4), RangeError);
  });
});

describe("byte helpers", () => {
  it("concatenates", () => {
    const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array([]));
    assert.deepEqual(Array.from(out), [1, 2, 3]);
  });

  it("xors and rejects length mismatch", () => {
    assert.deepEqual(
      Array.from(xorBytes(new Uint8Array([0b1010]), new Uint8Array([0b0110]))),
      [0b1100],
    );
    assert.throws(() => xorBytes(new Uint8Array(2), new Uint8Array(3)), RangeError);
  });

  it("compares in constant time", () => {
    assert.ok(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
    assert.ok(!constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
    assert.ok(!constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])));
  });
});

describe("base64url", () => {
  it("round-trips arbitrary byte lengths", () => {
    for (let len = 0; len < 40; len++) {
      const bytes = new Uint8Array(len).map((_, i) => (i * 37 + 11) & 0xff);
      assert.deepEqual(Array.from(fromBase64Url(toBase64Url(bytes))), Array.from(bytes));
    }
  });

  it("emits url-safe output with no padding", () => {
    const encoded = toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]));
    assert.ok(!encoded.includes("="));
    assert.ok(!encoded.includes("+"));
    assert.ok(!encoded.includes("/"));
  });

  it("matches Node's own base64url encoder", () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255, 128, 64]);
    assert.equal(toBase64Url(bytes), Buffer.from(bytes).toString("base64url"));
  });

  it("rejects malformed input instead of truncating", () => {
    assert.throws(() => fromBase64Url("abc!def"), SyntaxError);
    assert.throws(() => fromBase64Url("abcde"), SyntaxError);
  });
});

describe("modular arithmetic", () => {
  it("computes bit lengths", () => {
    assert.equal(bitLength(0n), 0);
    assert.equal(bitLength(1n), 1);
    assert.equal(bitLength(255n), 8);
    assert.equal(bitLength(256n), 9);
    assert.equal(bitLength(2n ** 2048n - 1n), 2048);
    assert.equal(bitLength(2n ** 2048n), 2049);
  });

  it("computes modular exponentiation", () => {
    assert.equal(modPow(2n, 10n, 1000n), 24n);
    assert.equal(modPow(4n, 13n, 497n), 445n);
    assert.equal(modPow(0n, 0n, 7n), 1n);
  });

  it("computes modular inverses", () => {
    assert.equal(modInverse(3n, 11n), 4n);
    assert.equal((modInverse(17n, 3120n) * 17n) % 3120n, 1n);
    assert.throws(() => modInverse(4n, 8n), RangeError);
  });

  it("samples uniformly within bounds", () => {
    const upper = 1000n;
    const rng = (n: number) => {
      const out = new Uint8Array(n);
      globalThis.crypto.getRandomValues(out);
      return out;
    };
    for (let i = 0; i < 200; i++) {
      const value = randomBigIntBelow(upper, rng);
      assert.ok(value >= 1n && value < upper, `sample ${value} out of range`);
    }
  });

  it("surfaces a broken RNG rather than looping forever", () => {
    // An RNG stuck at all-ones can never produce a value below the bound.
    const stuck = (n: number) => new Uint8Array(n).fill(0xff);
    assert.throws(() => randomBigIntBelow(3n, stuck), /RNG fault/);
  });
});
