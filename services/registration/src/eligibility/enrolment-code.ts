/**
 * Enrolment codes: the secret printed on a voter's polling card.
 *
 * FORMAT. 160 bits of CSPRNG output, rendered in a 32-character alphabet that
 * omits I, L, O and U — the characters people misread as 1, 1, 0 and V, and the
 * one that occasionally forms unfortunate words. Grouped in fives with hyphens,
 * because these get typed by hand off a piece of paper.
 *
 * WHY NO PASSWORD HASHING. Codes are 160-bit uniformly random, so there is
 * nothing to guess: an attacker cannot enumerate a keyspace of 2^160 no matter
 * how fast the hash is. Argon2/scrypt exist to slow down guessing of
 * LOW-entropy human-chosen secrets, and would only add latency here. Instead the
 * stored value is an HMAC under a server-held pepper, which means a database
 * dump alone does not even reveal which codes are valid.
 */

import { concatBytes, constantTimeEqual, randomBytes, toBase64Url, utf8 } from "@dvoting/crypto";

/** Crockford-style alphabet minus I, L, O, U. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_CHARS = 32; // 32 chars x 5 bits = 160 bits
const GROUP_SIZE = 5;

export class EnrolmentCodeError extends Error {
  override name = "EnrolmentCodeError";
}

/** Generate a fresh enrolment code, formatted for printing. */
export function generateEnrolmentCode(
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): string {
  // Draw one byte per character and reduce; rejection is unnecessary because
  // 256 is an exact multiple of 32, so the reduction is unbiased.
  const raw = getRandomBytes(CODE_CHARS);
  let code = "";
  for (const byte of raw) code += ALPHABET[byte % ALPHABET.length];

  const groups: string[] = [];
  for (let i = 0; i < code.length; i += GROUP_SIZE) {
    groups.push(code.slice(i, i + GROUP_SIZE));
  }
  return groups.join("-");
}

/**
 * Normalise a code as typed by a human.
 *
 * Uppercases, strips separators and whitespace, and maps the characters people
 * substitute for the ones the alphabet omits. Without this, a voter who types a
 * lowercase l for a 1 is simply told they are not eligible to vote.
 */
export function normaliseEnrolmentCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s\-_]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0")
    .replace(/U/g, "V");
}

export function isWellFormedEnrolmentCode(input: string): boolean {
  const normalised = normaliseEnrolmentCode(input);
  if (normalised.length !== CODE_CHARS) return false;
  for (const character of normalised) {
    if (!ALPHABET.includes(character)) return false;
  }
  return true;
}

/**
 * HMAC-SHA256 of the normalised code under the server pepper.
 *
 * The roll id is bound into the input so a code is only valid for the entry it
 * was issued against — a code lifted from one polling card cannot be replayed
 * against a different roll number.
 */
export async function hashEnrolmentCode(
  pepper: string,
  rollId: string,
  code: string,
): Promise<Uint8Array> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    utf8(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  // Domain-separated and length-prefixed, so this can never collide with the
  // identity hash that shares the same pepper, and so ("ab","c") cannot be
  // confused with ("a","bc").
  const input = concatBytes(
    utf8("dvoting/enrolment-code/v1:"),
    utf8(String(rollId.length)),
    utf8(":"),
    utf8(rollId),
    utf8(":"),
    utf8(normaliseEnrolmentCode(code)),
  );

  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, input));
}

export function enrolmentCodeMatches(expected: Uint8Array, actual: Uint8Array): boolean {
  return constantTimeEqual(expected, actual);
}

/** Stable, non-secret label for logs and audit entries. */
export function enrolmentCodeFingerprint(hash: Uint8Array): string {
  return toBase64Url(hash).slice(0, 12);
}
