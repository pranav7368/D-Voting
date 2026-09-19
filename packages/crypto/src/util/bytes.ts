/**
 * Byte-string helpers.
 *
 * The integer<->octet-string conversions here are I2OSP and OS2IP from PKCS#1
 * (RFC 8017 section 4). Getting these exactly right matters: RSA operates on
 * integers, but every wire format and hash input is a fixed-length byte string.
 * A length-flexible encoding (e.g. dropping leading zero bytes) would change the
 * bytes that get hashed and silently break interop -- or, worse, open a
 * malleability gap where two encodings map to the same integer.
 */

/** I2OSP: integer -> big-endian octet string of exactly `length` bytes. */
export function i2osp(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new RangeError("i2osp: value must be non-negative");
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  // Anything left over means the integer did not fit in `length` bytes.
  if (v !== 0n) throw new RangeError("i2osp: integer too large for the requested length");
  return out;
}

/** OS2IP: big-endian octet string -> integer. */
export function os2ip(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError("xorBytes: length mismatch");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/**
 * Length-independent, data-independent equality check.
 *
 * Used for comparing hashes and MACs. A short-circuiting `===` style comparison
 * leaks how many leading bytes matched via timing, which is enough to forge a
 * MAC byte-by-byte. Note this still leaks *length*, which is not secret here.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  // globalThis.crypto is the WebCrypto API: available in Node >=19, all modern
  // browsers, and React Native via expo-crypto / react-native-quick-crypto.
  globalThis.crypto.getRandomValues(out);
  return out;
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** base64url encode, no padding (RFC 4648 section 5). Isomorphic: no Buffer, no atob. */
export function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64URL_ALPHABET[b0 >> 2];
    out += B64URL_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += B64URL_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += B64URL_ALPHABET[b2 & 0x3f];
  }
  return out;
}

/** base64url decode. Rejects malformed input rather than silently truncating. */
export function fromBase64Url(text: string): Uint8Array {
  const clean = text.replace(/=+$/, "");
  if (!/^[A-Za-z0-9\-_]*$/.test(clean)) {
    throw new SyntaxError("fromBase64Url: input is not valid base64url");
  }
  if (clean.length % 4 === 1) {
    throw new SyntaxError("fromBase64Url: invalid input length");
  }
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let pos = 0;
  for (const ch of clean) {
    acc = (acc << 6) | B64URL_ALPHABET.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[pos++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
