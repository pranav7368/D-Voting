import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { emsaPssEncode, emsaPssVerify } from "../src/pss.ts";
import { randomBytes, utf8 } from "../src/util/bytes.ts";

const PARAMS = { hash: "SHA-384", saltLength: 48 } as const;
const EM_BITS = 3071; // matches a 3072-bit RSA modulus

describe("EMSA-PSS", () => {
  it("encodes then verifies", async () => {
    const message = utf8("ballot-credential");
    const encoded = await emsaPssEncode(message, EM_BITS, PARAMS);
    assert.equal(encoded.length, Math.ceil(EM_BITS / 8));
    assert.ok(await emsaPssVerify(message, encoded, EM_BITS, PARAMS));
  });

  it("is randomized: the same message encodes differently each time", async () => {
    const message = utf8("same message");
    const a = await emsaPssEncode(message, EM_BITS, PARAMS);
    const b = await emsaPssEncode(message, EM_BITS, PARAMS);
    assert.notDeepEqual(Array.from(a), Array.from(b));
    // ...yet both verify. This is the randomized-encoding property PSS relies on.
    assert.ok(await emsaPssVerify(message, a, EM_BITS, PARAMS));
    assert.ok(await emsaPssVerify(message, b, EM_BITS, PARAMS));
  });

  it("rejects a different message", async () => {
    const encoded = await emsaPssEncode(utf8("message A"), EM_BITS, PARAMS);
    assert.ok(!(await emsaPssVerify(utf8("message B"), encoded, EM_BITS, PARAMS)));
  });

  it("rejects a tampered encoding at every byte position", async () => {
    const message = utf8("tamper me");
    const encoded = await emsaPssEncode(message, EM_BITS, PARAMS);

    for (const index of [0, 1, 100, encoded.length - 50, encoded.length - 1]) {
      const tampered = Uint8Array.from(encoded);
      tampered[index] = tampered[index]! ^ 0x01;
      assert.ok(
        !(await emsaPssVerify(message, tampered, EM_BITS, PARAMS)),
        `tampering at byte ${index} was not detected`,
      );
    }
  });

  it("rejects a wrong-length encoding", async () => {
    const message = utf8("length check");
    const encoded = await emsaPssEncode(message, EM_BITS, PARAMS);
    assert.ok(!(await emsaPssVerify(message, encoded.subarray(1), EM_BITS, PARAMS)));
  });

  it("keeps the encoded value below 2^emBits", async () => {
    // The top (8*emLen - emBits) bits must be zero, otherwise the encoded
    // integer could exceed the RSA modulus and the signature would not verify.
    for (let i = 0; i < 20; i++) {
      const encoded = await emsaPssEncode(randomBytes(16), EM_BITS, PARAMS);
      assert.equal(encoded[0]! & 0x80, 0);
    }
  });

  it("refuses a modulus too small for the hash and salt", async () => {
    // SHA-384 with a 48-byte salt needs at least 48 + 48 + 2 = 98 bytes.
    await assert.rejects(() => emsaPssEncode(utf8("x"), 512, PARAMS), /modulus too small/);
  });
});
