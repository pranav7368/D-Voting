/**
 * Benaloh cast-or-audit challenge -- "cast as intended" verification.
 *
 * ===========================================================================
 * THE PROBLEM THIS SOLVES, AND WHY NOTHING ELSE IN THE SYSTEM SOLVES IT.
 *
 * Every other defence here protects the ballot AFTER it is encrypted. None of
 * them protects the moment of encryption itself. A compromised voting app can
 * simply encrypt Bob when the voter selected Alice, and:
 *
 *   - the ciphertext is perfectly well-formed;
 *   - the zero-knowledge validity proofs all verify, because they prove the
 *     ciphertext encrypts 0 or 1 -- NOT that it encrypts what the voter chose;
 *   - the ledger records it, the tally counts it, the result is wrong, and
 *     nothing anywhere is detectably broken.
 *
 * This is the attack MIT flags as unsolved for ALL internet voting, and it is
 * the single largest residual risk in this system.
 *
 * ===========================================================================
 * THE DEFENCE.
 *
 * The client must COMMIT to an encrypted ballot before learning what will
 * happen to it. Only then does the voter choose:
 *
 *   CAST  -- submit it. The randomness is destroyed and the vote is secret
 *            forever.
 *   AUDIT -- the client must reveal the randomness. The voter re-encrypts their
 *            intended selections with that randomness and checks the result is
 *            byte-identical to the ballot they were shown. If the app encrypted
 *            something else, the check fails and the cheating is exposed.
 *
 * An audited ballot is SPOILED: its randomness is public, so anyone can decrypt
 * it. It can never be cast, and the voter starts over with a fresh ballot.
 *
 * Why this works: the client cannot know in advance whether a given ballot will
 * be audited or cast, so it cannot cheat only on the ones nobody will check. An
 * app that cheats on a fraction p of ballots is caught by any single audit with
 * probability p. A voter who audits twice before casting leaves a cheating app
 * a (1-p)^2 chance of surviving -- and across an electorate, systematic fraud is
 * detected with overwhelming probability.
 *
 * ===========================================================================
 * WHAT IT DOES NOT SOLVE (say this in the viva).
 *
 * The audit must be performed by something the malicious app does not control.
 * If the voter verifies on the same compromised device, the app can simply lie
 * about the result. A genuine deployment needs the audit checked on a separate
 * device, or by an independent verifier application. This module provides the
 * verification function; WHERE it runs is a deployment property, not a
 * cryptographic one.
 *
 * It also cannot stop an app that shows the voter a different candidate list
 * than it encrypts against -- that is a UI-integrity problem, not a crypto one.
 */

import { encrypt, type ElGamalPublicKey } from "../elgamal/cipher.ts";
import { toBase64Url } from "../util/bytes.ts";
import { digest } from "../hash.ts";
import { encodeElement } from "../elgamal/group.ts";
import {
  createBallotWithSecrets,
  verifyBallot,
  type BallotCreationOptions,
  type ElectionParameters,
  type EncryptedBallot,
} from "./ballot.ts";

export class AuditError extends Error {
  override name = "AuditError";
}

/**
 * A ballot the voter has not yet committed to casting.
 *
 * Hold this only until the voter decides. On CAST, drop `secret` and submit
 * `ballot`. On AUDIT, publish `secret` and discard the ballot entirely.
 */
export interface PreparedBallot {
  readonly ballot: EncryptedBallot;
  /** The commitment the voter records BEFORE choosing cast or audit. */
  readonly commitment: string;
  readonly secret: BallotAuditSecret;
}

export interface BallotAuditSecret {
  readonly ballotId: string;
  /** What the client claims it encrypted. */
  readonly selections: readonly number[];
  /** Per-choice encryption randomness. */
  readonly randomness: readonly bigint[];
}

export interface AuditResult {
  readonly ok: boolean;
  readonly reason?: string;
  /** The selections the ballot provably encodes, recovered from the randomness. */
  readonly encodedSelections?: readonly number[];
}

/**
 * Commitment to a prepared ballot: a hash over every ciphertext.
 *
 * The voter records this BEFORE choosing cast or audit. It is what stops a
 * malicious client from producing one ballot, seeing the voter ask for an
 * audit, and then revealing the secrets of a DIFFERENT, honest ballot instead.
 */
export async function ballotCommitment(
  publicKey: ElGamalPublicKey,
  ballot: EncryptedBallot,
): Promise<string> {
  const parts: Uint8Array[] = [new TextEncoder().encode(`dvoting/ballot-commitment/v1|${ballot.ballotId}|`)];
  for (const choice of ballot.choices) {
    parts.push(encodeElement(publicKey.group, choice.alpha));
    parts.push(encodeElement(publicKey.group, choice.beta));
  }

  let total = 0;
  for (const part of parts) total += part.length;
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }

  return toBase64Url(await digest("SHA-256", combined));
}

/**
 * Prepare a ballot without committing to cast it.
 *
 * The client MUST show the returned commitment to the voter before asking
 * whether to cast or audit. Asking first, then encrypting, destroys the entire
 * guarantee.
 */
export async function prepareBallot(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  selections: readonly number[],
  options: BallotCreationOptions = {},
): Promise<PreparedBallot> {
  const built = await createBallotWithSecrets(election, publicKey, selections, options);
  return {
    ballot: built.ballot,
    commitment: await ballotCommitment(publicKey, built.ballot),
    secret: {
      ballotId: built.ballot.ballotId,
      selections: built.selections,
      randomness: built.randomness,
    },
  };
}

/**
 * Audit a prepared ballot: does it actually encrypt what the voter chose?
 *
 * Re-encrypts each claimed selection with the revealed randomness and demands
 * a byte-exact match against the ballot's ciphertexts. ElGamal is deterministic
 * given (message, randomness), so a match is proof that this ballot encodes
 * exactly these selections -- and a mismatch is proof that it does not.
 *
 * `expectedSelections` is what the VOTER believes they chose. Passing it is what
 * turns "this ballot is internally consistent" into "this ballot records my
 * intent"; without it a malicious client could reveal a consistent secret for
 * the wrong vote and pass the check.
 */
export async function auditBallot(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  ballot: EncryptedBallot,
  secret: BallotAuditSecret,
  expectedSelections?: readonly number[],
): Promise<AuditResult> {
  if (secret.ballotId !== ballot.ballotId) {
    return { ok: false, reason: "audit data is for a different ballot" };
  }
  if (secret.selections.length !== ballot.choices.length) {
    return { ok: false, reason: "revealed selections do not match the ballot size" };
  }
  if (secret.randomness.length !== ballot.choices.length) {
    return { ok: false, reason: "revealed randomness does not match the ballot size" };
  }

  // The ballot must be a genuine, well-formed ballot -- auditing a malformed one
  // proves nothing.
  if (!(await verifyBallot(election, publicKey, ballot))) {
    return { ok: false, reason: "ballot failed zero-knowledge verification" };
  }

  // Re-encrypt each selection with the revealed randomness.
  for (const [index, choice] of ballot.choices.entries()) {
    const selection = secret.selections[index]!;
    if (selection !== 0 && selection !== 1) {
      return { ok: false, reason: `revealed selection ${index} is not 0 or 1` };
    }

    let recomputed;
    try {
      recomputed = encrypt(publicKey, BigInt(selection), {
        randomness: secret.randomness[index]!,
      }).ciphertext;
    } catch {
      return { ok: false, reason: `revealed randomness ${index} is out of range` };
    }

    if (recomputed.alpha !== choice.alpha || recomputed.beta !== choice.beta) {
      // The client encrypted something other than what it now claims.
      return {
        ok: false,
        reason:
          `ballot does not encrypt the revealed selection for "${election.candidates[index] ?? index}" ` +
          "-- the voting client is misbehaving",
      };
    }
  }

  // At this point the ballot PROVABLY encodes secret.selections. That is
  // everything a third party can establish -- and it is all the ballot box is
  // allowed to establish, because knowing the voter's intent would destroy
  // ballot secrecy.
  //
  // The remaining question, "is that what the voter actually chose?", can only
  // be answered by the voter, who is the sole holder of that information.
  if (expectedSelections) {
    if (expectedSelections.length !== secret.selections.length) {
      return { ok: false, reason: "expected selections have the wrong length" };
    }
    for (const [index, expected] of expectedSelections.entries()) {
      if (expected !== secret.selections[index]) {
        return {
          ok: false,
          reason:
            `the ballot encrypts ${describeSelections(election, secret.selections)} ` +
            `but the voter selected ${describeSelections(election, expectedSelections)} ` +
            "-- the voting client is CHEATING",
          encodedSelections: secret.selections,
        };
      }
    }
  }

  return { ok: true, encodedSelections: secret.selections };
}

/** Render a selection vector as candidate names, for human-readable findings. */
export function describeSelections(
  election: ElectionParameters,
  selections: readonly number[],
): string {
  const chosen = selections
    .map((value, index) => (value === 1 ? (election.candidates[index] ?? `#${index}`) : null))
    .filter((name): name is string => name !== null);
  return chosen.length === 0 ? "(no candidate)" : chosen.join(" + ");
}

/**
 * Verify a client's audit response against a previously recorded commitment.
 *
 * Closes the substitution attack: a malicious client shows commitment C for a
 * dishonest ballot, then on audit reveals an entirely different, honest ballot.
 * Binding the audit to the commitment the voter wrote down makes that fail.
 */
export async function auditAgainstCommitment(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  ballot: EncryptedBallot,
  secret: BallotAuditSecret,
  recordedCommitment: string,
  expectedSelections?: readonly number[],
): Promise<AuditResult> {
  const actual = await ballotCommitment(publicKey, ballot);
  if (actual !== recordedCommitment) {
    return {
      ok: false,
      reason:
        "the audited ballot is not the one the voter was shown -- the client substituted a different ballot",
    };
  }
  return auditBallot(election, publicKey, ballot, secret, expectedSelections);
}

/**
 * Probability that a client cheating on a `cheatRate` fraction of ballots
 * survives `auditCount` independent audits undetected.
 *
 * Useful for telling voters how many audits are worth performing, and for
 * arguing detection probability across an electorate.
 */
export function cheatSurvivalProbability(cheatRate: number, auditCount: number): number {
  if (cheatRate < 0 || cheatRate > 1) throw new AuditError("cheatRate must be in [0, 1]");
  if (!Number.isInteger(auditCount) || auditCount < 0) {
    throw new AuditError("auditCount must be a non-negative integer");
  }
  return (1 - cheatRate) ** auditCount;
}
