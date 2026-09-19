/**
 * RSABSSA -- RSA Blind Signatures with Appendix (RFC 9474).
 *
 * Protocol roles and what each party learns:
 *
 *   Voter (client)                          Registration Authority (issuer)
 *   --------------                          -------------------------------
 *   credential <- random 32 bytes
 *   blinded, inv <- Blind(pk, credential)
 *                        --- blinded --->
 *                                            checks eligibility (KYC + not
 *                                            already issued), then
 *                                            blindSig <- BlindSign(sk, blinded)
 *                        <-- blindSig ---
 *   sig <- Finalize(pk, credential, blindSig, inv)
 *
 * The issuer sees only `blinded = pssEncode(credential) * r^e mod n`. Because r
 * is drawn uniformly from the invertible residues mod n, `blinded` is uniformly
 * distributed and statistically independent of `credential`. That independence
 * is *information-theoretic*, not computational: for ANY candidate credential,
 * there exists exactly one r consistent with the observed `blinded`. So even an
 * issuer with unbounded compute cannot link an issued credential to the voter
 * it was issued to. This is the property that separates "who may vote" from
 * "how they voted".
 */

import type { HashAlgorithm } from "../hash.ts";

/** RFC 9474 named ciphersuites. */
export type BlindRsaVariant = "RSABSSA-SHA384-PSS-Deterministic" | "RSABSSA-SHA384-PSSZERO-Deterministic";

export interface BlindRsaSuite {
  readonly name: BlindRsaVariant;
  readonly hash: HashAlgorithm;
  readonly saltLength: number;
  /**
   * Randomized variants prepend 32 random bytes to the message before encoding,
   * to protect *low-entropy* messages from a dictionary attack by the issuer.
   * D-Voting credentials are already 32 uniformly random bytes, so the
   * deterministic variant is used and this stays 0. Documented rather than
   * hard-coded away, because the choice must be justified, not assumed.
   */
  readonly messagePrefixLength: number;
}

export const RSABSSA_SHA384_PSS_DETERMINISTIC: BlindRsaSuite = {
  name: "RSABSSA-SHA384-PSS-Deterministic",
  hash: "SHA-384",
  saltLength: 48,
  messagePrefixLength: 0,
};

/** Public half of the issuer key. Safe to publish; clients need it to blind. */
export interface BlindRsaPublicKey {
  readonly n: bigint;
  readonly e: bigint;
  readonly suite: BlindRsaSuite;
}

/**
 * Private half. Includes CRT parameters so the signing operation can use the
 * Chinese Remainder Theorem (~3-4x faster than a plain modexp with d).
 */
export interface BlindRsaPrivateKey {
  readonly n: bigint;
  readonly e: bigint;
  readonly d: bigint;
  readonly p: bigint;
  readonly q: bigint;
  readonly dp: bigint;
  readonly dq: bigint;
  readonly qInv: bigint;
  readonly suite: BlindRsaSuite;
}

/** Result of the client-side Blind step. `inverse` is a SECRET the client keeps. */
export interface BlindResult {
  /** Sent to the issuer. Reveals nothing about the credential. */
  readonly blindedMessage: Uint8Array;
  /**
   * r^-1 mod n. Must never leave the client -- combined with the blinded
   * message it would let the issuer recover and therefore link the credential.
   */
  readonly inverse: Uint8Array;
}

export class BlindRsaError extends Error {
  override name = "BlindRsaError";
}

/** Minimum modulus size accepted anywhere in this package. RFC 9474 requires >= 2048. */
export const MIN_MODULUS_BITS = 2048;
