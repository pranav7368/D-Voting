/**
 * Identity hashing.
 *
 * Turns a KYC subject ID into the only identity artefact the RA ever stores.
 *
 * Design notes worth defending in a viva:
 *
 *  - HMAC, not a bare hash. National ID numbers live in a small enumerable
 *    space (an Aadhaar-style 12-digit number is only ~10^12 possibilities), so
 *    SHA-256(id) is trivially reversible by exhaustive search. HMAC under a
 *    secret pepper held outside the database means a database dump alone
 *    reveals nothing about who registered.
 *
 *  - The election ID is bound into the input. The same person registering in
 *    two different elections produces two unrelated hashes, so the RA's records
 *    cannot be cross-referenced between elections to build a participation
 *    profile. This is domain separation.
 */

import { concatBytes, utf8 } from "@dvoting/crypto";

export async function deriveIdentityHash(
  pepper: string,
  electionId: string,
  subjectId: string,
): Promise<Uint8Array> {
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    utf8(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  // Length-prefix the election ID so that ("ab", "c") and ("a", "bc") cannot
  // collide into the same HMAC input. Without this separator, a crafted
  // election ID could make two distinct voters hash identically and silently
  // block one of them from registering.
  const input = concatBytes(
    utf8(String(electionId.length)),
    utf8(":"),
    utf8(electionId),
    utf8(":"),
    utf8(subjectId),
  );

  const mac = await globalThis.crypto.subtle.sign("HMAC", key, input);
  return new Uint8Array(mac);
}
