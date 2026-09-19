import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { constants, createPublicKey, verify as nodeVerify } from "node:crypto";

import { blind, finalize, generateCredential, verify } from "../src/blind-rsa/client.ts";
import { LocalBlindSigner, computeKeyId } from "../src/blind-rsa/issuer.ts";
import {
  generateIssuerKeyPair,
  privateKeyFromJwk,
  privateKeyToJwk,
  publicKeyToJwk,
  publicKeyFromJwk,
  publicKeyToPem,
} from "../src/blind-rsa/keygen.ts";
import { RSABSSA_SHA384_PSS_DETERMINISTIC } from "../src/blind-rsa/types.ts";
import { i2osp, os2ip, utf8 } from "../src/util/bytes.ts";
import { modPow } from "../src/util/bigint.ts";

const SUITE = RSABSSA_SHA384_PSS_DETERMINISTIC;

// 2048-bit keys keep the suite fast; one 3072-bit case covers the production size.
let keys: ReturnType<typeof generateIssuerKeyPair>;
let signer: LocalBlindSigner;

before(() => {
  keys = generateIssuerKeyPair(2048, SUITE);
  signer = new LocalBlindSigner(keys.privateKey);
});

describe("RSABSSA end-to-end", () => {
  it("issues a credential the voter can later prove", async () => {
    const credential = generateCredential();
    assert.equal(credential.length, 32);

    const { blindedMessage, inverse } = await blind(keys.publicKey, credential);
    const blindSignature = await signer.blindSign(blindedMessage);
    const signature = await finalize(keys.publicKey, credential, blindSignature, inverse);

    assert.ok(await verify(keys.publicKey, credential, signature));
  });

  it("works at the 3072-bit production modulus size", async () => {
    const big = generateIssuerKeyPair(3072, SUITE);
    const bigSigner = new LocalBlindSigner(big.privateKey);

    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(big.publicKey, credential);
    const signature = await finalize(
      big.publicKey,
      credential,
      await bigSigner.blindSign(blindedMessage),
      inverse,
    );

    assert.equal(signature.length, 384);
    assert.ok(await verify(big.publicKey, credential, signature));
  });
});

describe("interoperability with Node's own RSA-PSS", () => {
  // This is the strongest correctness evidence available without official test
  // vectors: a signature produced through the blind protocol is validated by a
  // completely independent (OpenSSL-backed) PSS implementation. If our PSS
  // encoding were subtly wrong, this would fail.
  it("produces signatures Node accepts as standard RSA-PSS", async () => {
    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(keys.publicKey, credential);
    const signature = await finalize(
      keys.publicKey,
      credential,
      await signer.blindSign(blindedMessage),
      inverse,
    );

    const nodePublicKey = createPublicKey(publicKeyToPem(keys.publicKey));
    const accepted = nodeVerify(
      "sha384",
      credential,
      {
        key: nodePublicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: SUITE.saltLength,
      },
      signature,
    );

    assert.ok(accepted, "Node's RSA-PSS verifier rejected our blind signature");
  });
});

describe("unlinkability", () => {
  it("produces a different blinded message every time for the same credential", async () => {
    const credential = utf8("a fixed credential");
    const seen = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const { blindedMessage } = await blind(keys.publicKey, credential);
      seen.add(Buffer.from(blindedMessage).toString("hex"));
    }
    assert.equal(seen.size, 10, "blinded messages repeated -- blinding factor is not random");
  });

  it("leaks nothing linkable: the blinded message is independent of the credential", async () => {
    // Statistical smoke test of the information-theoretic argument. Blinding two
    // *different* credentials must be indistinguishable from blinding the same
    // one twice -- there is no correlation an issuer could exploit.
    const a = await blind(keys.publicKey, utf8("candidate-alpha"));
    const b = await blind(keys.publicKey, utf8("candidate-beta"));
    assert.notDeepEqual(Array.from(a.blindedMessage), Array.from(b.blindedMessage));
    assert.equal(a.blindedMessage.length, b.blindedMessage.length);
  });
});

describe("forgery resistance", () => {
  it("rejects a signature on a credential that was never signed", async () => {
    const issued = generateCredential();
    const notIssued = generateCredential();

    const { blindedMessage, inverse } = await blind(keys.publicKey, issued);
    const signature = await finalize(
      keys.publicKey,
      issued,
      await signer.blindSign(blindedMessage),
      inverse,
    );

    assert.ok(!(await verify(keys.publicKey, notIssued, signature)));
  });

  it("defeats the multiplicative forgery that breaks textbook blind RSA", async () => {
    // THE attack that motivates PSS encoding. Raw RSA satisfies
    //     sig(m1) * sig(m2) = sig(m1 * m2)
    // so with two legitimately issued credentials an attacker could mint a
    // third signature for free -- one extra ballot per pair of colluding
    // voters, undetectable at the ballot box.
    const c1 = generateCredential();
    const c2 = generateCredential();

    const b1 = await blind(keys.publicKey, c1);
    const b2 = await blind(keys.publicKey, c2);
    const s1 = await finalize(keys.publicKey, c1, await signer.blindSign(b1.blindedMessage), b1.inverse);
    const s2 = await finalize(keys.publicKey, c2, await signer.blindSign(b2.blindedMessage), b2.inverse);

    const n = keys.publicKey.n;
    const forgedSig = i2osp((os2ip(s1) * os2ip(s2)) % n, s1.length);

    // The forged signature IS a valid raw-RSA signature on the product of the
    // two PSS encodings -- but that product is not itself a valid PSS encoding
    // of anything, so verification fails. That is precisely what PSS buys us.
    const forgedRawMessage = i2osp(
      (modPow(os2ip(s1), keys.publicKey.e, n) * modPow(os2ip(s2), keys.publicKey.e, n)) % n,
      s1.length,
    );
    assert.equal(os2ip(forgedRawMessage), (modPow(os2ip(forgedSig), keys.publicKey.e, n)) % n);

    assert.ok(!(await verify(keys.publicKey, c1, forgedSig)));
    assert.ok(!(await verify(keys.publicKey, c2, forgedSig)));
  });

  it("rejects a signature made with a different issuer key", async () => {
    const other = generateIssuerKeyPair(2048, SUITE);
    const otherSigner = new LocalBlindSigner(other.privateKey);

    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(other.publicKey, credential);
    const signature = await finalize(
      other.publicKey,
      credential,
      await otherSigner.blindSign(blindedMessage),
      inverse,
    );

    assert.ok(await verify(other.publicKey, credential, signature));
    assert.ok(!(await verify(keys.publicKey, credential, signature)));
  });

  it("rejects tampered signatures", async () => {
    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(keys.publicKey, credential);
    const signature = await finalize(
      keys.publicKey,
      credential,
      await signer.blindSign(blindedMessage),
      inverse,
    );

    const tampered = Uint8Array.from(signature);
    tampered[10] = tampered[10]! ^ 0xff;
    assert.ok(!(await verify(keys.publicKey, credential, tampered)));
  });
});

describe("protocol input validation", () => {
  it("finalize refuses a malicious issuer's garbage response", async () => {
    const credential = generateCredential();
    const { inverse } = await blind(keys.publicKey, credential);
    const garbage = new Uint8Array(256).fill(7);

    await assert.rejects(
      () => finalize(keys.publicKey, credential, garbage, inverse),
      /invalid signature/,
    );
  });

  it("blindSign rejects wrong-length input", async () => {
    await assert.rejects(() => signer.blindSign(new Uint8Array(10)), /wrong length/);
  });

  it("blindSign rejects a value >= the modulus", async () => {
    const tooBig = i2osp(keys.publicKey.n, 256);
    await assert.rejects(() => signer.blindSign(tooBig), /not less than the modulus/);
  });

  it("verify returns false rather than throwing on malformed input", async () => {
    assert.equal(await verify(keys.publicKey, utf8("m"), new Uint8Array(5)), false);
    assert.equal(await verify(keys.publicKey, utf8("m"), i2osp(keys.publicKey.n, 256)), false);
  });

  it("refuses undersized moduli", () => {
    assert.throws(() => generateIssuerKeyPair(1024, SUITE), /minimum modulus/);
  });
});

describe("key handling", () => {
  it("round-trips a private key through JWK", () => {
    const jwk = privateKeyToJwk(keys.privateKey);
    const restored = privateKeyFromJwk(jwk, SUITE);
    assert.equal(restored.n, keys.privateKey.n);
    assert.equal(restored.d, keys.privateKey.d);
    assert.equal(restored.qInv, keys.privateKey.qInv);
  });

  it("round-trips a public key through JWK", () => {
    const restored = publicKeyFromJwk(publicKeyToJwk(keys.publicKey), SUITE);
    assert.equal(restored.n, keys.publicKey.n);
    assert.equal(restored.e, keys.publicKey.e);
  });

  it("rejects an inconsistent private key", () => {
    const jwk = privateKeyToJwk(keys.privateKey);
    const corrupted = { ...jwk, dp: privateKeyToJwk(generateIssuerKeyPair(2048, SUITE).privateKey).dp };
    assert.throws(() => privateKeyFromJwk(corrupted, SUITE), /key check/);
  });

  it("derives a stable key id", async () => {
    const id1 = await computeKeyId(keys.publicKey);
    const id2 = await computeKeyId(keys.publicKey);
    assert.equal(id1, id2);

    const other = generateIssuerKeyPair(2048, SUITE);
    assert.notEqual(await computeKeyId(other.publicKey), id1);
  });
});
