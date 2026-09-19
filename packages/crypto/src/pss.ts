/**
 * EMSA-PSS encoding and verification (RFC 8017, section 9.1).
 *
 * WHY THIS EXISTS AT ALL -- the single most important thing to be able to
 * explain about the registration layer:
 *
 * Textbook RSA is multiplicatively homomorphic: sig(a) * sig(b) = sig(a*b).
 * A "blind signature" built by blinding the *raw* message therefore hands an
 * attacker existential forgery for free -- collect signatures on two
 * credentials and you can derive a valid signature on a third credential you
 * were never issued. In a voting system that is a ballot-stuffing vulnerability
 * with no detection path.
 *
 * The fix is to sign a structured, randomized *encoding* of the message rather
 * than the message itself, so that the product of two valid encodings is
 * essentially never itself a valid encoding. PSS provides that structure, and
 * RFC 9474 specifies exactly how to blind a PSS-encoded message.
 *
 * Encoded message layout (emLen bytes total):
 *
 *   +---------------------------+-------------+------+
 *   | maskedDB                  | H           | 0xbc |
 *   +---------------------------+-------------+------+
 *     emLen - hLen - 1 bytes      hLen bytes    1
 *
 *   DB = PS (zeros) || 0x01 || salt      H = Hash(0x00*8 || mHash || salt)
 */

import { HASH_OUTPUT_BYTES, digest, mgf1, type HashAlgorithm } from "./hash.ts";
import { concatBytes, constantTimeEqual, randomBytes, xorBytes } from "./util/bytes.ts";

export class PssError extends Error {
  override name = "PssError";
}

/** The 8 zero bytes prefixed before mHash when computing H. Fixed by RFC 8017. */
const M_PRIME_PAD = new Uint8Array(8);

export interface PssParams {
  hash: HashAlgorithm;
  /** Salt length in bytes. RFC 9474 fixes this to hLen for all its suites. */
  saltLength: number;
}

/**
 * EMSA-PSS-ENCODE. `emBits` is the intended bit length of the encoded integer,
 * which for RSA is bitLength(n) - 1 so the result is always < n.
 */
export async function emsaPssEncode(
  message: Uint8Array,
  emBits: number,
  params: PssParams,
  salt?: Uint8Array,
): Promise<Uint8Array> {
  const hLen = HASH_OUTPUT_BYTES[params.hash];
  const sLen = params.saltLength;
  const emLen = Math.ceil(emBits / 8);

  if (emLen < hLen + sLen + 2) {
    throw new PssError("emsaPssEncode: modulus too small for this hash and salt length");
  }

  const mHash = await digest(params.hash, message);
  const usedSalt = salt ?? randomBytes(sLen);
  if (usedSalt.length !== sLen) throw new PssError("emsaPssEncode: salt length mismatch");

  const h = await digest(params.hash, concatBytes(M_PRIME_PAD, mHash, usedSalt));

  // DB = PS || 0x01 || salt, left-padded with zeros to emLen - hLen - 1 bytes.
  const db = new Uint8Array(emLen - hLen - 1);
  db[db.length - sLen - 1] = 0x01;
  db.set(usedSalt, db.length - sLen);

  const dbMask = await mgf1(h, db.length, params.hash);
  const maskedDb = xorBytes(db, dbMask);

  // Clear the leftmost (8*emLen - emBits) bits so the encoded value is < 2^emBits.
  // Without this the encoding could exceed the modulus and the signature would
  // not round-trip.
  clearLeadingBits(maskedDb, 8 * emLen - emBits);

  return concatBytes(maskedDb, h, new Uint8Array([0xbc]));
}

/** EMSA-PSS-VERIFY. Returns a boolean rather than throwing on invalid input. */
export async function emsaPssVerify(
  message: Uint8Array,
  encoded: Uint8Array,
  emBits: number,
  params: PssParams,
): Promise<boolean> {
  const hLen = HASH_OUTPUT_BYTES[params.hash];
  const sLen = params.saltLength;
  const emLen = Math.ceil(emBits / 8);

  if (encoded.length !== emLen) return false;
  if (emLen < hLen + sLen + 2) return false;
  if (encoded[encoded.length - 1] !== 0xbc) return false;

  const maskedDb = encoded.subarray(0, emLen - hLen - 1);
  const h = encoded.subarray(emLen - hLen - 1, emLen - 1);

  // The bits the encoder cleared must still be clear.
  const unusedBits = 8 * emLen - emBits;
  if (unusedBits > 0 && (maskedDb[0]! & (0xff << (8 - unusedBits) & 0xff)) !== 0) return false;

  const dbMask = await mgf1(h, maskedDb.length, params.hash);
  const db = xorBytes(maskedDb, dbMask);
  clearLeadingBits(db, unusedBits);

  // Structural check: DB must be zeros, then a single 0x01, then the salt.
  const separatorIndex = db.length - sLen - 1;
  for (let i = 0; i < separatorIndex; i++) {
    if (db[i] !== 0x00) return false;
  }
  if (db[separatorIndex] !== 0x01) return false;

  const salt = db.subarray(db.length - sLen);
  const mHash = await digest(params.hash, message);
  const expectedH = await digest(params.hash, concatBytes(M_PRIME_PAD, mHash, salt));

  return constantTimeEqual(h, expectedH);
}

function clearLeadingBits(bytes: Uint8Array, bitCount: number): void {
  if (bitCount <= 0) return;
  if (bitCount >= 8) throw new PssError("clearLeadingBits: expected fewer than 8 bits");
  bytes[0] = bytes[0]! & (0xff >> bitCount);
}
