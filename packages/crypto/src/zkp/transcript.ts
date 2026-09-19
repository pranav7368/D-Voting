/**
 * Fiat-Shamir transcript.
 *
 * Sigma protocols (Schnorr, Chaum-Pedersen) are interactive: the verifier sends
 * a random challenge. The Fiat-Shamir transform makes them non-interactive by
 * replacing that challenge with a hash. Getting the hash input right is the
 * whole security of the transform.
 *
 * ---------------------------------------------------------------------------
 * STRONG vs WEAK FIAT-SHAMIR -- the single most important detail in this file,
 * and a real vulnerability that hit a real voting system.
 *
 * WEAK Fiat-Shamir hashes only the prover's commitments:
 *     c = H(commitments)
 *
 * STRONG Fiat-Shamir hashes the commitments AND the full statement being
 * proven -- public key, ciphertexts, election context:
 *     c = H(statement, commitments)
 *
 * Bernhard, Pereira and Warinschi ("How not to prove yourself", ASIACRYPT 2012)
 * showed that Helios used weak Fiat-Shamir, and that this let an attacker forge
 * ballot-validity proofs: because the challenge did not depend on the
 * ciphertext, a proof could be manufactured for a statement chosen AFTER the
 * commitments were fixed. Helios was subsequently fixed to use strong
 * Fiat-Shamir.
 *
 * This implementation is strong-Fiat-Shamir by construction: the challenge
 * cannot be produced without first absorbing the statement, because the
 * statement is what the caller absorbs before any commitment.
 * ---------------------------------------------------------------------------
 *
 * ENCODING. Every absorbed field is length-prefixed and labelled. Without that,
 * absorbing ("ab", "c") and ("a", "bc") would produce identical hash input --
 * a concatenation ambiguity that lets an attacker shift bytes between fields to
 * make two different statements collide.
 */

import { digest, mgf1 } from "../hash.ts";
import { concatBytes, i2osp, os2ip, utf8 } from "../util/bytes.ts";
import { encodeElement, encodeScalar } from "../elgamal/group.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";

/** Extra bytes hashed beyond the size of q, to make the reduction bias negligible. */
const CHALLENGE_OVERSAMPLE_BYTES = 16;

export class Transcript {
  readonly #parts: Uint8Array[] = [];

  constructor(domain: string) {
    // Domain separation: proofs of different kinds can never collide, even if
    // every other absorbed value happens to match.
    this.absorbBytes("domain", utf8(domain));
  }

  absorbBytes(label: string, bytes: Uint8Array): this {
    const labelBytes = utf8(label);
    this.#parts.push(
      i2osp(BigInt(labelBytes.length), 4),
      labelBytes,
      i2osp(BigInt(bytes.length), 4),
      bytes,
    );
    return this;
  }

  absorbString(label: string, value: string): this {
    return this.absorbBytes(label, utf8(value));
  }

  absorbNumber(label: string, value: number): this {
    if (!Number.isInteger(value) || value < 0) {
      throw new RangeError("Transcript.absorbNumber: expected a non-negative integer");
    }
    return this.absorbBytes(label, i2osp(BigInt(value), 8));
  }

  /** Absorb a group element in canonical fixed-width form. */
  absorbElement(group: PrimeOrderGroup, label: string, value: bigint): this {
    return this.absorbBytes(label, encodeElement(group, value));
  }

  absorbScalar(group: PrimeOrderGroup, label: string, value: bigint): this {
    return this.absorbBytes(label, encodeScalar(group, value));
  }

  /**
   * Derive a challenge uniformly distributed in [0, q).
   *
   * Hashing to exactly bitlen(q) bits and reducing would bias the result toward
   * small values. Bias matters here beyond tidiness: in the disjunctive proof
   * the simulated branch challenges are drawn uniformly from Z_q, so if the
   * real challenge came from a visibly different distribution, the branches
   * would be distinguishable and the proof would leak which one is real -- i.e.
   * it would leak the vote. Oversampling by 128 bits before reduction keeps the
   * statistical distance from uniform below 2^-128.
   */
  async challenge(group: PrimeOrderGroup): Promise<bigint> {
    const seed = await digest("SHA-512", concatBytes(...this.#parts));
    const wide = await mgf1(seed, group.qByteLength + CHALLENGE_OVERSAMPLE_BYTES, "SHA-512");
    return os2ip(wide) % group.q;
  }

  /** Fork the transcript so sibling proofs share a statement but diverge cleanly. */
  fork(label: string): Transcript {
    const child = new Transcript("dvoting/fork");
    child.#parts.length = 0;
    child.#parts.push(...this.#parts);
    child.absorbString("fork", label);
    return child;
  }
}
