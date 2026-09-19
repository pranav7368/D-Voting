/**
 * Pedersen Distributed Key Generation.
 *
 * ===========================================================================
 * THE PROBLEM WITH THE DEALER.
 *
 * `setupTrustees` generates the election private key in one place, splits it,
 * and trusts that process to erase it. For the duration of that ceremony a
 * single party holds the key that decrypts the entire election. Feldman VSS
 * lets trustees detect a dealer handing out *inconsistent* shares, but it
 * cannot un-know what the dealer saw. The strongest claim that setup supports
 * is "no single party can decrypt AFTER a correctly-run ceremony" -- which is a
 * procedural promise, not a cryptographic one.
 *
 * THE FIX.
 *
 * In a DKG the key is never generated anywhere. Each participant contributes
 * its own random polynomial; the election key is the SUM of everyone's
 * contributions, and exists only implicitly:
 *
 *     x = sum of z_i        y = product of g^{z_i}
 *
 * Every participant knows their own z_i and their share x_j of the total. No
 * one -- at any point, including setup -- ever holds x. "No single party can
 * decrypt" becomes a fact about the protocol rather than a promise about a
 * ceremony.
 *
 * ===========================================================================
 * PROTOCOL (Pedersen, using Feldman VSS for share verification)
 *
 *   Round 1. Participant i picks a random degree-(t-1) polynomial f_i with
 *            f_i(0) = z_i, broadcasts Feldman commitments C_{i,k} = g^{a_{i,k}},
 *            and privately sends s_{i,j} = f_i(j) to each participant j.
 *
 *   Round 2. Participant j verifies every received share against the sender's
 *            broadcast commitments:  g^{s_{i,j}} == product of C_{i,k}^{j^k}.
 *            A share that fails is a complaint; the sender is disqualified.
 *
 *   Output.  Let Q be the qualified participants.
 *              joint public key   y   = product over Q of C_{i,0}
 *              participant share  x_j = sum over Q of s_{i,j}
 *              public share       h_j = g^{x_j}, derivable from public data
 *
 * The shares x_j lie on F(X) = sum over Q of f_i(X), a degree-(t-1) polynomial
 * with F(0) = x. So any t of them reconstruct x by Lagrange interpolation --
 * exactly the same threshold decryption path as before. DKG is a drop-in
 * replacement for the dealer; nothing downstream changes.
 *
 * ===========================================================================
 * KNOWN LIMITATION -- say this precisely, it is a real published result.
 *
 * Gennaro, Jarecki, Krawczyk and Rabin showed that Pedersen's DKG does NOT
 * produce a uniformly distributed public key: a rushing adversary who sees
 * others' contributions before deciding whether to disqualify a participant can
 * bias the distribution of y. It does NOT let the adversary learn x, and it does
 * NOT let them steer y to a chosen value -- it skews some bits of its
 * distribution.
 *
 * The same authors later showed ("Secure Applications of Pedersen's Distributed
 * Key Generation Protocol", CT-RSA 2003) that this bias is harmless for a class
 * of applications including threshold ElGamal decryption, which is exactly the
 * use here. The fully unbiased variant needs an extra commit-then-reveal round.
 * That is the honest position: a known, published, quantified weakness that does
 * not apply to this use case.
 */

import { randomBytes } from "../util/bytes.ts";
import {
  assertInSubgroup,
  groupExp,
  groupMul,
  scalarAdd,
  type PrimeOrderGroup,
} from "../elgamal/group.ts";
import type { ElGamalPublicKey } from "../elgamal/cipher.ts";
import { evaluatePolynomial, splitSecret } from "./shamir.ts";
import { randomScalar } from "../elgamal/group.ts";
import type { TrusteeKeyShare, TrusteePublicShare } from "./trustee.ts";

export class DkgError extends Error {
  override name = "DkgError";
}

/** What participant i broadcasts and sends in round 1. */
export interface DkgContribution {
  readonly index: number;
  /** Feldman commitments C_{i,k} = g^{a_{i,k}}. BROADCAST to everyone. */
  readonly commitments: readonly bigint[];
  /**
   * s_{i,j} = f_i(j), keyed by recipient.
   *
   * Each entry is delivered PRIVATELY to its recipient over an authenticated,
   * confidential channel. A share seen by anyone else erodes the threshold: an
   * eavesdropper collecting t shares reconstructs the election key.
   */
  readonly shares: ReadonlyMap<number, bigint>;
}

/** The public half of a contribution -- everything needed to verify shares. */
export interface DkgBroadcast {
  readonly index: number;
  readonly commitments: readonly bigint[];
}

export interface DkgComplaint {
  /** Participant who raised it. */
  readonly by: number;
  /** Participant accused of sending a bad share. */
  readonly against: number;
  readonly reason: string;
}

/**
 * Round 1 for one participant.
 *
 * The returned polynomial coefficients are never exposed; only the commitments
 * and the per-recipient shares leave this function.
 */
export function createDkgContribution(
  group: PrimeOrderGroup,
  index: number,
  threshold: number,
  participantCount: number,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): DkgContribution {
  if (!Number.isInteger(index) || index < 1 || index > participantCount) {
    throw new DkgError("createDkgContribution: index must be in [1, participantCount]");
  }
  if (threshold < 1 || threshold > participantCount) {
    throw new DkgError("createDkgContribution: require 1 <= threshold <= participantCount");
  }

  // This participant's own secret contribution to the election key.
  const ownSecret = randomScalar(group, getRandomBytes);
  const { shares, coefficients } = splitSecret(
    group,
    ownSecret,
    threshold,
    participantCount,
    getRandomBytes,
  );

  return {
    index,
    commitments: coefficients.map((coefficient) => groupExp(group, group.g, coefficient)),
    shares: new Map(shares.map((share) => [share.index, share.value])),
  };
}

/**
 * Verify a share received from another participant against their broadcast
 * commitments.
 *
 *     g^{s_{i,j}} == product of C_{i,k}^{j^k}
 *
 * This is what makes the DKG *verifiable*: a participant cannot send a share
 * inconsistent with what they publicly committed to without being caught
 * immediately, by the recipient, using only public data.
 */
export function verifyDkgShare(
  group: PrimeOrderGroup,
  broadcast: DkgBroadcast,
  recipientIndex: number,
  share: bigint,
): boolean {
  if (recipientIndex < 1) return false;
  if (broadcast.commitments.length === 0) return false;
  if (share < 0n || share >= group.q) return false;

  try {
    for (const commitment of broadcast.commitments) {
      assertInSubgroup(group, commitment, "commitment");
    }
  } catch {
    return false;
  }

  return groupExp(group, group.g, share) === expectedShareCommitment(group, broadcast, recipientIndex);
}

/** product of C_{i,k}^{j^k} -- the public commitment to f_i(j). */
function expectedShareCommitment(
  group: PrimeOrderGroup,
  broadcast: DkgBroadcast,
  recipientIndex: number,
): bigint {
  let expected = 1n;
  let power = 1n;
  const j = BigInt(recipientIndex);
  for (const commitment of broadcast.commitments) {
    expected = groupMul(group, expected, groupExp(group, commitment, power));
    power = (power * j) % group.q;
  }
  return expected;
}

/**
 * Round 2: every participant checks every share they received.
 *
 * Returns the qualified set and any complaints. A participant is disqualified
 * the moment ONE recipient can prove a bad share -- the proof is public and
 * checkable by everyone, so a false accusation is not possible.
 */
export function collectComplaints(
  group: PrimeOrderGroup,
  contributions: readonly DkgContribution[],
  threshold: number,
): { qualified: number[]; complaints: DkgComplaint[] } {
  const complaints: DkgComplaint[] = [];
  const disqualified = new Set<number>();

  for (const sender of contributions) {
    if (sender.commitments.length !== threshold) {
      complaints.push({
        by: 0,
        against: sender.index,
        reason: `published ${sender.commitments.length} commitments, expected ${threshold}`,
      });
      disqualified.add(sender.index);
      continue;
    }

    for (const recipient of contributions) {
      const share = sender.shares.get(recipient.index);
      if (share === undefined) {
        complaints.push({
          by: recipient.index,
          against: sender.index,
          reason: "no share delivered",
        });
        disqualified.add(sender.index);
        continue;
      }
      if (!verifyDkgShare(group, sender, recipient.index, share)) {
        complaints.push({
          by: recipient.index,
          against: sender.index,
          reason: "share is inconsistent with the broadcast commitments",
        });
        disqualified.add(sender.index);
      }
    }
  }

  const qualified = contributions
    .map((contribution) => contribution.index)
    .filter((index) => !disqualified.has(index));

  return { qualified, complaints };
}

/** Joint public key: y = product over the qualified set of C_{i,0}. */
export function computeJointPublicKey(
  group: PrimeOrderGroup,
  broadcasts: readonly DkgBroadcast[],
): ElGamalPublicKey {
  if (broadcasts.length === 0) {
    throw new DkgError("computeJointPublicKey: no qualified contributions");
  }
  let y = 1n;
  for (const broadcast of broadcasts) {
    const constantTerm = broadcast.commitments[0];
    if (constantTerm === undefined) {
      throw new DkgError(`participant ${broadcast.index} published no commitments`);
    }
    assertInSubgroup(group, constantTerm, "commitment");
    y = groupMul(group, y, constantTerm);
  }
  return { group, y };
}

/**
 * A participant's share of the joint key: x_j = sum over Q of s_{i,j}.
 *
 * Computed locally by participant j from the shares they received. Nobody else
 * can compute it, and participant j learns nothing about x from it.
 */
export function computeKeyShare(
  group: PrimeOrderGroup,
  recipientIndex: number,
  receivedShares: readonly bigint[],
): TrusteeKeyShare {
  let total = 0n;
  for (const share of receivedShares) {
    if (share < 0n || share >= group.q) {
      throw new DkgError("computeKeyShare: received share out of range");
    }
    total = scalarAdd(group, total, share);
  }
  return { index: recipientIndex, share: total };
}

/**
 * A participant's PUBLIC share h_j = g^{x_j}, derived from broadcast data alone.
 *
 * Everyone can compute this for everyone else without trusting anybody, which
 * is what makes the partial-decryption proofs at tally time checkable: the
 * verifier already knows what g^{x_j} must be.
 */
export function computePublicShare(
  group: PrimeOrderGroup,
  recipientIndex: number,
  broadcasts: readonly DkgBroadcast[],
): TrusteePublicShare {
  let publicShare = 1n;
  for (const broadcast of broadcasts) {
    publicShare = groupMul(
      group,
      publicShare,
      expectedShareCommitment(group, broadcast, recipientIndex),
    );
  }
  return { index: recipientIndex, publicShare };
}

export interface DkgOutcome {
  readonly group: PrimeOrderGroup;
  readonly threshold: number;
  readonly qualified: readonly number[];
  readonly complaints: readonly DkgComplaint[];
  readonly publicKey: ElGamalPublicKey;
  /**
   * Per-participant private shares.
   *
   * In a real deployment each participant computes ONLY their own, from the
   * shares delivered to them; they are collected here so a single process can
   * simulate the whole protocol for tests and demos.
   */
  readonly keyShares: readonly TrusteeKeyShare[];
  readonly publicShares: readonly TrusteePublicShare[];
}

/**
 * Finalise a DKG from a set of contributions.
 *
 * `contributions` must include every participant that took part; disqualified
 * ones are excluded automatically and reported in `complaints`.
 */
export function finalizeDkg(
  group: PrimeOrderGroup,
  threshold: number,
  contributions: readonly DkgContribution[],
): DkgOutcome {
  if (contributions.length === 0) throw new DkgError("finalizeDkg: no contributions");

  const indices = contributions.map((c) => c.index);
  if (new Set(indices).size !== indices.length) {
    throw new DkgError("finalizeDkg: duplicate participant indices");
  }

  const { qualified, complaints } = collectComplaints(group, contributions, threshold);

  // Below the threshold there are not enough honest participants to ever
  // decrypt, so the ceremony has failed and must be re-run.
  if (qualified.length < threshold) {
    throw new DkgError(
      `finalizeDkg: only ${qualified.length} participants qualified, threshold is ${threshold} ` +
        `(${complaints.length} complaint(s))`,
    );
  }

  const qualifiedSet = new Set(qualified);
  const qualifiedContributions = contributions.filter((c) => qualifiedSet.has(c.index));
  const broadcasts: DkgBroadcast[] = qualifiedContributions.map((c) => ({
    index: c.index,
    commitments: c.commitments,
  }));

  const keyShares: TrusteeKeyShare[] = [];
  const publicShares: TrusteePublicShare[] = [];
  for (const index of qualified) {
    const received = qualifiedContributions.map((c) => {
      const share = c.shares.get(index);
      if (share === undefined) {
        throw new DkgError(`finalizeDkg: participant ${c.index} sent no share to ${index}`);
      }
      return share;
    });
    keyShares.push(computeKeyShare(group, index, received));
    publicShares.push(computePublicShare(group, index, broadcasts));
  }

  return {
    group,
    threshold,
    qualified,
    complaints,
    publicKey: computeJointPublicKey(group, broadcasts),
    keyShares,
    publicShares,
  };
}

/**
 * Run a complete DKG in one process.
 *
 * FOR TESTS AND DEMOS ONLY. A real ceremony runs `createDkgContribution` on each
 * participant's own machine and exchanges commitments and shares over the
 * network; running it here defeats the purpose, because this process
 * momentarily sees every share. The individual functions above are the ones a
 * distributed deployment calls.
 */
export function runDkg(
  group: PrimeOrderGroup,
  threshold: number,
  participantCount: number,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): DkgOutcome {
  const contributions: DkgContribution[] = [];
  for (let index = 1; index <= participantCount; index++) {
    contributions.push(
      createDkgContribution(group, index, threshold, participantCount, getRandomBytes),
    );
  }
  return finalizeDkg(group, threshold, contributions);
}

/** Re-exported for tests that need to construct a deliberately bad contribution. */
export { evaluatePolynomial };
