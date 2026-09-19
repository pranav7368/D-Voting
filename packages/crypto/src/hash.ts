/**
 * Hashing and mask generation, built on WebCrypto so the exact same module runs
 * on the server (Node), in the admin portal (browser) and in the voter app
 * (React Native, with a WebCrypto polyfill).
 */

import { concatBytes, i2osp } from "./util/bytes.ts";

export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";

export const HASH_OUTPUT_BYTES: Record<HashAlgorithm, number> = {
  "SHA-256": 32,
  "SHA-384": 48,
  "SHA-512": 64,
};

export async function digest(algorithm: HashAlgorithm, data: Uint8Array): Promise<Uint8Array> {
  const out = await globalThis.crypto.subtle.digest(algorithm, data);
  return new Uint8Array(out);
}

/**
 * MGF1 mask generation function (RFC 8017, appendix B.2.1).
 *
 * MGF1 stretches a short hash into an arbitrary-length pseudorandom mask by
 * hashing `seed || counter` for an incrementing 4-byte counter. PSS uses it to
 * mask the salt+padding block, which is what makes the encoding randomized and
 * gives PSS its tight security reduction to the RSA problem.
 */
export async function mgf1(
  seed: Uint8Array,
  maskLength: number,
  algorithm: HashAlgorithm,
): Promise<Uint8Array> {
  const hLen = HASH_OUTPUT_BYTES[algorithm];
  if (maskLength > 0xffffffff * hLen) throw new RangeError("mgf1: mask too long");

  const blocks: Uint8Array[] = [];
  const iterations = Math.ceil(maskLength / hLen);
  for (let counter = 0; counter < iterations; counter++) {
    blocks.push(await digest(algorithm, concatBytes(seed, i2osp(BigInt(counter), 4))));
  }
  return concatBytes(...blocks).subarray(0, maskLength);
}
