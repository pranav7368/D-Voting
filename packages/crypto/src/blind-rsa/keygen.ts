/**
 * Issuer key generation and serialisation. SERVER-ONLY.
 *
 * This is the one module in @dvoting/crypto that imports `node:crypto`, because
 * RSA key generation needs primality testing that WebCrypto does not expose in a
 * usable form. It is a separate entry point (`@dvoting/crypto/keygen`) precisely
 * so that bundling the voter app can never accidentally pull it in.
 */

import { generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";
import { fromBase64Url, os2ip, toBase64Url, i2osp } from "../util/bytes.ts";
import { bitLength } from "../util/bigint.ts";
import { assertKeyPairConsistent } from "./issuer.ts";
import {
  BlindRsaError,
  MIN_MODULUS_BITS,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  type BlindRsaPrivateKey,
  type BlindRsaPublicKey,
  type BlindRsaSuite,
} from "./types.ts";

/** JWK is used as the on-disk/at-rest format: standard, self-describing, no ASN.1 parsing. */
export interface RsaPrivateJwk {
  kty: "RSA";
  n: string;
  e: string;
  d: string;
  p: string;
  q: string;
  dp: string;
  dq: string;
  qi: string;
}

export interface RsaPublicJwk {
  kty: "RSA";
  n: string;
  e: string;
}

/**
 * Generate a fresh issuer key pair.
 *
 * 3072 bits is the default: NIST SP 800-57 rates it at the 128-bit security
 * level and it is the smallest size that stays credible past 2030. 2048 would
 * be faster but is only ~112-bit; for a key whose compromise means unlimited
 * forged voting credentials, the extra few milliseconds per issuance is not a
 * trade worth making.
 */
export function generateIssuerKeyPair(
  modulusBits = 3072,
  suite: BlindRsaSuite = RSABSSA_SHA384_PSS_DETERMINISTIC,
): { privateKey: BlindRsaPrivateKey; publicKey: BlindRsaPublicKey } {
  if (modulusBits < MIN_MODULUS_BITS) {
    throw new BlindRsaError(`generateIssuerKeyPair: minimum modulus is ${MIN_MODULUS_BITS} bits`);
  }

  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: modulusBits,
    publicExponent: 65537,
  });

  const jwk = privateKey.export({ format: "jwk" }) as unknown as RsaPrivateJwk;
  const parsed = privateKeyFromJwk(jwk, suite);
  return { privateKey: parsed, publicKey: { n: parsed.n, e: parsed.e, suite } };
}

export function privateKeyFromJwk(jwk: RsaPrivateJwk, suite: BlindRsaSuite): BlindRsaPrivateKey {
  for (const field of ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const) {
    if (typeof jwk[field] !== "string" || jwk[field].length === 0) {
      throw new BlindRsaError(`privateKeyFromJwk: missing or invalid field "${field}"`);
    }
  }

  const key: BlindRsaPrivateKey = {
    n: os2ip(fromBase64Url(jwk.n)),
    e: os2ip(fromBase64Url(jwk.e)),
    d: os2ip(fromBase64Url(jwk.d)),
    p: os2ip(fromBase64Url(jwk.p)),
    q: os2ip(fromBase64Url(jwk.q)),
    dp: os2ip(fromBase64Url(jwk.dp)),
    dq: os2ip(fromBase64Url(jwk.dq)),
    qInv: os2ip(fromBase64Url(jwk.qi)),
    suite,
  };

  if (bitLength(key.n) < MIN_MODULUS_BITS) {
    throw new BlindRsaError("privateKeyFromJwk: modulus is below the minimum size");
  }
  // Never serve traffic with a key we have not verified is internally consistent:
  // a corrupted CRT parameter produces signatures that leak the private key.
  assertKeyPairConsistent(key);
  return key;
}

export function privateKeyToJwk(key: BlindRsaPrivateKey): RsaPrivateJwk {
  const half = Math.ceil(bitLength(key.n) / 16);
  const full = Math.ceil(bitLength(key.n) / 8);
  return {
    kty: "RSA",
    n: toBase64Url(i2osp(key.n, full)),
    e: toBase64Url(i2osp(key.e, 3)),
    d: toBase64Url(i2osp(key.d, full)),
    p: toBase64Url(i2osp(key.p, half)),
    q: toBase64Url(i2osp(key.q, half)),
    dp: toBase64Url(i2osp(key.dp, half)),
    dq: toBase64Url(i2osp(key.dq, half)),
    qi: toBase64Url(i2osp(key.qInv, half)),
  };
}

export function publicKeyToJwk(key: BlindRsaPublicKey): RsaPublicJwk {
  return {
    kty: "RSA",
    n: toBase64Url(i2osp(key.n, Math.ceil(bitLength(key.n) / 8))),
    e: toBase64Url(i2osp(key.e, 3)),
  };
}

export function publicKeyFromJwk(jwk: RsaPublicJwk, suite: BlindRsaSuite): BlindRsaPublicKey {
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new BlindRsaError("publicKeyFromJwk: missing n or e");
  }
  const key: BlindRsaPublicKey = {
    n: os2ip(fromBase64Url(jwk.n)),
    e: os2ip(fromBase64Url(jwk.e)),
    suite,
  };
  if (bitLength(key.n) < MIN_MODULUS_BITS) {
    throw new BlindRsaError("publicKeyFromJwk: modulus is below the minimum size");
  }
  return key;
}

/** Convenience for tooling that wants a PEM (e.g. to load the key into KMS later). */
export function privateKeyToPem(key: BlindRsaPrivateKey): string {
  const keyObject = createPrivateKey({
    key: privateKeyToJwk(key) as unknown as import("node:crypto").JsonWebKey,
    format: "jwk",
  });
  return keyObject.export({ type: "pkcs8", format: "pem" }).toString();
}

export function publicKeyToPem(key: BlindRsaPublicKey): string {
  const keyObject = createPublicKey({
    key: publicKeyToJwk(key) as unknown as import("node:crypto").JsonWebKey,
    format: "jwk",
  });
  return keyObject.export({ type: "spki", format: "pem" }).toString();
}
