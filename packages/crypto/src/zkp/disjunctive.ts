/**
 * Disjunctive Chaum-Pedersen proof (Cramer-Damgard-Schoenmakers OR-proof).
 *
 * Proves that a ciphertext encrypts SOME value from a public list, without
 * revealing which one:
 *
 *     "Enc(m) where m is one of {v_0, ..., v_n}"
 *
 * This is what makes a ballot verifiable without being readable. For a
 * single-candidate field the list is {0, 1}, proving the voter selected the
 * candidate or did not -- and nothing else. Without it, a voter could encrypt
 * 1000 for their preferred candidate and the homomorphic tally would happily
 * add it, because encrypted values are never inspected.
 *
 * HOW THE OR IS ACHIEVED. A sigma protocol can be *simulated* for a false
 * statement if you get to pick the challenge first: choose the challenge and
 * response at random, then solve for the commitment. The CDS trick is to let
 * the prover simulate every branch except the true one, while a hash pins down
 * the SUM of all branch challenges:
 *
 *   - for each false branch: pick c_i and s_i at random, back-compute the
 *     commitments so the verification equation holds by construction;
 *   - for the true branch: commit honestly with a random w;
 *   - derive c = H(statement, all commitments);
 *   - set the true branch's challenge to c - (sum of the fake ones) mod q, and
 *     answer it honestly using the witness.
 *
 * A cheating prover would have to control the sum of challenges before seeing
 * the hash, which means predicting the hash -- and could only ever answer
 * honestly on a branch whose witness they actually hold.
 *
 * ZERO KNOWLEDGE: real and simulated branches are identically distributed --
 * all challenges are uniform in Z_q, all responses are uniform in Z_q -- so the
 * verifier cannot tell which branch was real. That indistinguishability IS the
 * ballot secrecy.
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
  scalarSub,
} from "../elgamal/group.ts";
import type { PrimeOrderGroup } from "../elgamal/group.ts";
import type { Ciphertext, ElGamalPublicKey } from "../elgamal/cipher.ts";
import { randomBytes } from "../util/bytes.ts";
import { ProofError } from "./dlog-equality.ts";
import { Transcript } from "./transcript.ts";

export interface DisjunctiveBranch {
  readonly commitment1: bigint;
  readonly commitment2: bigint;
  readonly challenge: bigint;
  readonly response: bigint;
}

export interface DisjunctiveProof {
  readonly branches: readonly DisjunctiveBranch[];
}

/** For value v: y1 = alpha, y2 = beta / g^v. */
function branchTargets(
  group: PrimeOrderGroup,
  ciphertext: Ciphertext,
  value: bigint,
): { y1: bigint; y2: bigint } {
  return {
    y1: ciphertext.alpha,
    y2: groupMul(group, ciphertext.beta, groupInv(group, groupExp(group, group.g, value))),
  };
}

function absorbStatement(
  transcript: Transcript,
  publicKey: ElGamalPublicKey,
  ciphertext: Ciphertext,
  allowedValues: readonly bigint[],
): void {
  const { group } = publicKey;
  transcript
    .absorbElement(group, "electionKey", publicKey.y)
    .absorbElement(group, "alpha", ciphertext.alpha)
    .absorbElement(group, "beta", ciphertext.beta)
    .absorbNumber("optionCount", allowedValues.length);
  for (const [index, value] of allowedValues.entries()) {
    transcript.absorbScalar(group, `option${index}`, value);
  }
}

/**
 * Prove `ciphertext` encrypts `allowedValues[actualIndex]`, hiding which.
 *
 * `randomness` is the encryption randomness r -- the witness. The caller must
 * discard it immediately afterwards: r alone decrypts the ballot.
 */
export async function proveOneOf(
  publicKey: ElGamalPublicKey,
  ciphertext: Ciphertext,
  randomness: bigint,
  actualIndex: number,
  allowedValues: readonly bigint[],
  transcript: Transcript,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): Promise<DisjunctiveProof> {
  const { group } = publicKey;

  if (allowedValues.length === 0) throw new ProofError("proveOneOf: no allowed values");
  if (actualIndex < 0 || actualIndex >= allowedValues.length) {
    throw new ProofError("proveOneOf: actualIndex out of range");
  }

  // Fail loudly if the witness does not actually prove the claimed branch --
  // otherwise we would emit a proof that silently fails verification later,
  // after the voter believes their ballot was cast.
  const claimed = branchTargets(group, ciphertext, allowedValues[actualIndex]!);
  if (groupExpFixed(group, group.g, randomness) !== claimed.y1) {
    throw new ProofError("proveOneOf: randomness does not match the ciphertext");
  }
  if (groupExpFixed(group, publicKey.y, randomness) !== claimed.y2) {
    throw new ProofError("proveOneOf: ciphertext does not encrypt the claimed value");
  }

  const commitments1: bigint[] = [];
  const commitments2: bigint[] = [];
  const challenges: bigint[] = [];
  const responses: bigint[] = [];

  // Simulate every branch except the real one.
  let w = 0n;
  for (const [index, value] of allowedValues.entries()) {
    if (index === actualIndex) {
      w = randomScalar(group, getRandomBytes);
      commitments1.push(groupExpFixed(group, group.g, w));
      commitments2.push(groupExpFixed(group, publicKey.y, w));
      challenges.push(0n); // placeholder, filled once the hash is known
      responses.push(0n);
      continue;
    }

    const fakeChallenge = randomScalar(group, getRandomBytes);
    const fakeResponse = randomScalar(group, getRandomBytes);
    const { y1, y2 } = branchTargets(group, ciphertext, value);

    // Back-compute commitments so g^s == a1 * y1^c holds by construction.
    // y1^(-c) is computed as y1^(q-c): cheaper than a modular inverse, and
    // exact because y1 has order q.
    const negChallenge = scalarSub(group, 0n, fakeChallenge);
    commitments1.push(
      groupMul(group, groupExpFixed(group, group.g, fakeResponse), groupExp(group, y1, negChallenge)),
    );
    commitments2.push(
      groupMul(
        group,
        groupExpFixed(group, publicKey.y, fakeResponse),
        groupExp(group, y2, negChallenge),
      ),
    );
    challenges.push(fakeChallenge);
    responses.push(fakeResponse);
  }

  absorbStatement(transcript, publicKey, ciphertext, allowedValues);
  for (const [index, commitment] of commitments1.entries()) {
    transcript.absorbElement(group, `commitment1_${index}`, commitment);
    transcript.absorbElement(group, `commitment2_${index}`, commitments2[index]!);
  }

  const totalChallenge = await transcript.challenge(group);

  // The real branch gets whatever challenge makes the sum come out right.
  let fakeSum = 0n;
  for (const [index, challenge] of challenges.entries()) {
    if (index !== actualIndex) fakeSum = scalarAdd(group, fakeSum, challenge);
  }
  const realChallenge = scalarSub(group, totalChallenge, fakeSum);
  challenges[actualIndex] = realChallenge;
  responses[actualIndex] = scalarAdd(group, w, scalarMul(group, realChallenge, randomness));

  return {
    branches: allowedValues.map((_, index) => ({
      commitment1: commitments1[index]!,
      commitment2: commitments2[index]!,
      challenge: challenges[index]!,
      response: responses[index]!,
    })),
  };
}

export async function verifyOneOf(
  publicKey: ElGamalPublicKey,
  ciphertext: Ciphertext,
  allowedValues: readonly bigint[],
  proof: DisjunctiveProof,
  transcript: Transcript,
): Promise<boolean> {
  const { group } = publicKey;

  if (proof.branches.length !== allowedValues.length) return false;
  if (allowedValues.length === 0) return false;

  // Validate every prover-supplied value before exponentiating with it.
  try {
    assertInSubgroup(group, ciphertext.alpha, "alpha");
    assertInSubgroup(group, ciphertext.beta, "beta");
    for (const branch of proof.branches) {
      assertInSubgroup(group, branch.commitment1, "commitment1");
      assertInSubgroup(group, branch.commitment2, "commitment2");
    }
  } catch {
    return false;
  }
  for (const branch of proof.branches) {
    if (branch.challenge < 0n || branch.challenge >= group.q) return false;
    if (branch.response < 0n || branch.response >= group.q) return false;
  }

  absorbStatement(transcript, publicKey, ciphertext, allowedValues);
  for (const [index, branch] of proof.branches.entries()) {
    transcript.absorbElement(group, `commitment1_${index}`, branch.commitment1);
    transcript.absorbElement(group, `commitment2_${index}`, branch.commitment2);
  }

  // The challenges must sum to the hash. This is what stops a prover from
  // simulating ALL branches: they could choose any n-1 challenges freely, but
  // the last one is pinned by a hash they cannot control.
  const expectedTotal = await transcript.challenge(group);
  let actualTotal = 0n;
  for (const branch of proof.branches) {
    actualTotal = scalarAdd(group, actualTotal, branch.challenge);
  }
  if (actualTotal !== expectedTotal) return false;

  for (const [index, branch] of proof.branches.entries()) {
    const { y1, y2 } = branchTargets(group, ciphertext, allowedValues[index]!);

    const lhs1 = groupExpFixed(group, group.g, branch.response);
    const rhs1 = groupMul(group, branch.commitment1, groupExp(group, y1, branch.challenge));
    if (lhs1 !== rhs1) return false;

    const lhs2 = groupExpFixed(group, publicKey.y, branch.response);
    const rhs2 = groupMul(group, branch.commitment2, groupExp(group, y2, branch.challenge));
    if (lhs2 !== rhs2) return false;
  }

  return true;
}
