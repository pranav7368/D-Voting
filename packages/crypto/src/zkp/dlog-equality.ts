/**
 * Chaum-Pedersen proof of discrete-logarithm equality.
 *
 * Proves knowledge of a secret x such that
 *
 *     y1 = base1^x   AND   y2 = base2^x
 *
 * with the SAME x, without revealing x. This one primitive covers two different
 * jobs in D-Voting:
 *
 *   1. "This ciphertext encrypts m."  base1 = g, base2 = y (election key),
 *      y1 = alpha, y2 = beta/g^m, secret = the encryption randomness r.
 *      Used as a branch inside the disjunctive ballot-validity proof.
 *
 *   2. "This trustee decrypted honestly."  base1 = g, base2 = alpha,
 *      y1 = the trustee's published public share g^x_i, y2 = its partial
 *      decryption alpha^x_i, secret = x_i.
 *      Without this proof a malicious trustee could submit a bogus partial
 *      decryption and silently corrupt the election result -- and because the
 *      tally is only checked at the end, nobody would be able to tell which
 *      trustee did it.
 *
 * Protocol (sigma protocol, made non-interactive by Fiat-Shamir):
 *      commit    w <- random;  a1 = base1^w,  a2 = base2^w
 *      challenge c = H(statement, a1, a2)          <- STRONG Fiat-Shamir
 *      respond   s = w + c*x  (mod q)
 *      verify    base1^s == a1 * y1^c   and   base2^s == a2 * y2^c
 *
 * Soundness: a prover who can answer two different challenges for the same
 * commitment can be rewound to extract x, so producing a valid proof without
 * knowing x is as hard as computing discrete logs.
 * Zero-knowledge: (a1, a2, s) is perfectly simulatable given c, so the proof
 * reveals nothing beyond the truth of the statement.
 */

import {
  assertInSubgroup,
  groupExp,
  groupExpFixed,
  groupInv,
  groupMul,
  randomScalar,
  scalarAdd,
  scalarMul,
} from "../elgamal/group.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";
import { randomBytes } from "../util/bytes.ts";
import { Transcript } from "./transcript.ts";

export interface DlogEqualityProof {
  readonly commitment1: bigint;
  readonly commitment2: bigint;
  readonly challenge: bigint;
  readonly response: bigint;
}

export class ProofError extends Error {
  override name = "ProofError";
}

export interface DlogEqualityStatement {
  readonly group: PrimeOrderGroup;
  readonly base1: bigint;
  readonly base2: bigint;
  readonly y1: bigint;
  readonly y2: bigint;
}

/** Absorb the statement. Both prover and verifier must do this identically. */
function absorbStatement(transcript: Transcript, statement: DlogEqualityStatement): void {
  const { group } = statement;
  transcript
    .absorbElement(group, "base1", statement.base1)
    .absorbElement(group, "base2", statement.base2)
    .absorbElement(group, "y1", statement.y1)
    .absorbElement(group, "y2", statement.y2);
}

export async function proveDlogEquality(
  statement: DlogEqualityStatement,
  secret: bigint,
  transcript: Transcript,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): Promise<DlogEqualityProof> {
  const { group } = statement;

  const w = randomScalar(group, getRandomBytes);
  // base1 is the generator in every current caller, so it benefits from the
  // fixed-base table; base2 varies per ciphertext and uses the generic path.
  const commitment1 = groupExpFixed(group, statement.base1, w);
  const commitment2 = groupExp(group, statement.base2, w);

  absorbStatement(transcript, statement);
  transcript
    .absorbElement(group, "commitment1", commitment1)
    .absorbElement(group, "commitment2", commitment2);

  const challenge = await transcript.challenge(group);
  const response = scalarAdd(group, w, scalarMul(group, challenge, secret));

  return { commitment1, commitment2, challenge, response };
}

export async function verifyDlogEquality(
  statement: DlogEqualityStatement,
  proof: DlogEqualityProof,
  transcript: Transcript,
): Promise<boolean> {
  const { group } = statement;

  // Everything supplied by the prover must be a genuine group element before it
  // is used in an exponentiation, or a small-order element could be smuggled in.
  try {
    assertInSubgroup(group, proof.commitment1, "commitment1");
    assertInSubgroup(group, proof.commitment2, "commitment2");
    assertInSubgroup(group, statement.y1, "y1");
    assertInSubgroup(group, statement.y2, "y2");
  } catch {
    return false;
  }
  if (proof.challenge < 0n || proof.challenge >= group.q) return false;
  if (proof.response < 0n || proof.response >= group.q) return false;

  absorbStatement(transcript, statement);
  transcript
    .absorbElement(group, "commitment1", proof.commitment1)
    .absorbElement(group, "commitment2", proof.commitment2);

  // Recompute the challenge. If the prover chose it freely rather than deriving
  // it from the statement, this mismatches -- which is exactly the weak
  // Fiat-Shamir attack that this check closes.
  const expectedChallenge = await transcript.challenge(group);
  if (expectedChallenge !== proof.challenge) return false;

  const lhs1 = groupExpFixed(group, statement.base1, proof.response);
  const rhs1 = groupMul(group, proof.commitment1, groupExp(group, statement.y1, proof.challenge));
  if (lhs1 !== rhs1) return false;

  const lhs2 = groupExp(group, statement.base2, proof.response);
  const rhs2 = groupMul(group, proof.commitment2, groupExp(group, statement.y2, proof.challenge));
  return lhs2 === rhs2;
}

/** Helper: the statement "ciphertext (alpha, beta) encrypts `message`". */
export function encryptionStatement(
  group: PrimeOrderGroup,
  electionPublicKey: bigint,
  alpha: bigint,
  beta: bigint,
  message: bigint,
): DlogEqualityStatement {
  return {
    group,
    base1: group.g,
    base2: electionPublicKey,
    y1: alpha,
    // beta / g^message == y^r when the ciphertext really encrypts `message`.
    y2: groupMul(group, beta, groupInv(group, groupExp(group, group.g, message))),
  };
}
