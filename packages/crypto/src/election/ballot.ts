/**
 * Ballot construction and verification.
 *
 * A ballot is one ElGamal ciphertext per candidate, each encrypting 0 or 1,
 * accompanied by proofs that make it verifiable WITHOUT being readable:
 *
 *   - a per-candidate proof that the ciphertext encrypts 0 or 1, so nobody can
 *     smuggle in a vote worth 1000;
 *   - an aggregate proof that the homomorphic sum of all candidate ciphertexts
 *     encrypts a permitted total, so nobody can vote for every candidate at once.
 *
 * Both are disjunctive Chaum-Pedersen proofs (see zkp/disjunctive.ts). Anyone
 * can check them; nobody learns the vote.
 *
 * REPLAY AND MALLEABILITY. ElGamal is malleable by design -- that is what makes
 * homomorphic tallying possible -- so an attacker can trivially re-randomize
 * someone else's ciphertext into a fresh-looking one encrypting the same vote.
 * Every proof here is therefore bound, through the Fiat-Shamir transcript, to
 * the election id, the ballot id, and the FULL list of ciphertexts in the
 * ballot. A copied or spliced ballot changes that context, so its proofs stop
 * verifying. The ledger must additionally reject duplicate ballot ids.
 */

import type { Ciphertext, ElGamalPublicKey } from "../elgamal/cipher.ts";
import { addCiphertexts, assertValidCiphertext, encrypt } from "../elgamal/cipher.ts";
import { randomBytes, toBase64Url } from "../util/bytes.ts";
import { Transcript } from "../zkp/transcript.ts";
import { proveOneOf, verifyOneOf, type DisjunctiveProof } from "../zkp/disjunctive.ts";

export class BallotError extends Error {
  override name = "BallotError";
}

export interface ElectionParameters {
  readonly electionId: string;
  readonly candidates: readonly string[];
  /** Minimum selections a valid ballot may contain. 0 permits abstention. */
  readonly minSelections: number;
  /** Maximum selections. 1 for single-choice; higher for approval voting. */
  readonly maxSelections: number;
}

export interface EncryptedBallot {
  readonly electionId: string;
  /** Unique per cast ballot. The ledger MUST reject duplicates. */
  readonly ballotId: string;
  /**
   * Fingerprint of the anonymous credential this ballot is cast with.
   *
   * Bound into every proof, which is what stops a ballot from being cast by
   * anyone other than the credential holder. Without it, an attacker who
   * observed a submission could re-submit the identical ballot under their own
   * credential, consuming the ballot id and blocking the real voter.
   *
   * It carries no identity: the credential is anonymous by construction (the
   * Registration Authority never saw it). It does reveal that the SAME
   * anonymous voter cast several ballots -- see the re-voting note in the
   * ballot-box docs.
   */
  readonly credentialFingerprint: string;
  readonly choices: readonly Ciphertext[];
  readonly choiceProofs: readonly DisjunctiveProof[];
  readonly aggregateProof: DisjunctiveProof;
}

const BINARY_OPTIONS: readonly bigint[] = [0n, 1n];

export function validateElectionParameters(election: ElectionParameters): void {
  if (election.candidates.length === 0) {
    throw new BallotError("election must have at least one candidate");
  }
  if (election.minSelections < 0 || election.maxSelections < election.minSelections) {
    throw new BallotError("require 0 <= minSelections <= maxSelections");
  }
  if (election.maxSelections > election.candidates.length) {
    throw new BallotError("maxSelections cannot exceed the number of candidates");
  }
}

/** Permitted values for the aggregate: [min, min+1, ..., max]. */
function aggregateOptions(election: ElectionParameters): bigint[] {
  const options: bigint[] = [];
  for (let value = election.minSelections; value <= election.maxSelections; value++) {
    options.push(BigInt(value));
  }
  return options;
}

/**
 * Base transcript shared by every proof in a ballot.
 *
 * Absorbing the complete ciphertext list is what prevents proof-splicing: a
 * proof lifted from another ballot was computed over a different list, so its
 * challenge will not reproduce.
 */
function ballotTranscript(
  domain: string,
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  ballotId: string,
  credentialFingerprint: string,
  choices: readonly Ciphertext[],
): Transcript {
  const transcript = new Transcript(domain)
    .absorbString("electionId", election.electionId)
    .absorbString("ballotId", ballotId)
    .absorbString("credentialFingerprint", credentialFingerprint)
    .absorbElement(publicKey.group, "electionKey", publicKey.y)
    .absorbNumber("candidateCount", election.candidates.length)
    .absorbNumber("minSelections", election.minSelections)
    .absorbNumber("maxSelections", election.maxSelections);

  for (const [index, candidate] of election.candidates.entries()) {
    transcript.absorbString(`candidate${index}`, candidate);
  }
  for (const [index, ciphertext] of choices.entries()) {
    transcript.absorbElement(publicKey.group, `alpha${index}`, ciphertext.alpha);
    transcript.absorbElement(publicKey.group, `beta${index}`, ciphertext.beta);
  }
  return transcript;
}

/** Generate an unpredictable ballot id. */
export function generateBallotId(): string {
  return toBase64Url(randomBytes(16));
}

export interface BallotCreationOptions {
  ballotId?: string;
  /** Fingerprint of the credential this ballot is cast with. */
  credentialFingerprint?: string;
  getRandomBytes?: (n: number) => Uint8Array;
}

/**
 * A ballot together with the secrets used to build it.
 *
 * The randomness here DECRYPTS THE BALLOT: anyone holding it can recover the
 * vote without the election private key, since g^m = beta / y^r. It exists so
 * the voter can run a Benaloh cast-or-audit challenge (see benaloh.ts). A
 * ballot whose randomness has been revealed is spoiled and must never be cast.
 */
export interface BallotWithSecrets {
  readonly ballot: EncryptedBallot;
  readonly selections: readonly number[];
  /** Per-choice encryption randomness. SECRET unless the ballot is audited. */
  readonly randomness: readonly bigint[];
}

/**
 * Encrypt and prove a ballot. RUNS ON THE VOTER'S DEVICE ONLY.
 *
 * `selections` is one 0 or 1 per candidate, in candidate order. The randomness
 * is dropped on return, at which point the ballot is no longer decryptable by
 * anyone -- including the voter. Use `createBallotWithSecrets` only when
 * implementing an audit flow.
 */
export async function createBallot(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  selections: readonly number[],
  options: BallotCreationOptions = {},
): Promise<EncryptedBallot> {
  return (await createBallotWithSecrets(election, publicKey, selections, options)).ballot;
}

/**
 * Build a ballot AND retain its encryption randomness.
 *
 * Only for the cast-or-audit flow. The returned randomness must either be
 * revealed (audit -- and the ballot then discarded) or destroyed (cast). It must
 * never be transmitted alongside a ballot that will be counted.
 */
export async function createBallotWithSecrets(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  selections: readonly number[],
  options: BallotCreationOptions = {},
): Promise<BallotWithSecrets> {
  validateElectionParameters(election);
  const getRandomBytes = options.getRandomBytes ?? randomBytes;
  const { group } = publicKey;

  if (selections.length !== election.candidates.length) {
    throw new BallotError("selections length does not match the candidate count");
  }
  let selectedTotal = 0;
  for (const selection of selections) {
    if (selection !== 0 && selection !== 1) {
      throw new BallotError("each selection must be exactly 0 or 1");
    }
    selectedTotal += selection;
  }
  if (selectedTotal < election.minSelections || selectedTotal > election.maxSelections) {
    throw new BallotError(
      `ballot selects ${selectedTotal} candidates, but this election permits ` +
        `${election.minSelections}..${election.maxSelections}`,
    );
  }

  const ballotId = options.ballotId ?? generateBallotId();
  const credentialFingerprint = options.credentialFingerprint ?? "";

  const choices: Ciphertext[] = [];
  const randomness: bigint[] = [];
  for (const selection of selections) {
    const result = encrypt(publicKey, BigInt(selection), { getRandomBytes });
    choices.push(result.ciphertext);
    randomness.push(result.randomness);
  }

  // Proofs are built only after every ciphertext exists, because each proof's
  // transcript commits to the whole list.
  const choiceProofs: DisjunctiveProof[] = [];
  for (const [index, ciphertext] of choices.entries()) {
    const transcript = ballotTranscript(
      "dvoting/ballot-choice/v1",
      election,
      publicKey,
      ballotId,
      credentialFingerprint,
      choices,
    ).absorbNumber("choiceIndex", index);

    choiceProofs.push(
      await proveOneOf(
        publicKey,
        ciphertext,
        randomness[index]!,
        selections[index]!,
        BINARY_OPTIONS,
        transcript,
        getRandomBytes,
      ),
    );
  }

  // The aggregate ciphertext encrypts the number of selections, with randomness
  // equal to the sum of the individual randomness values -- the homomorphism
  // applies to the witness as well as the plaintext.
  const aggregate = addCiphertexts(group, choices);
  let aggregateRandomness = 0n;
  for (const value of randomness) aggregateRandomness = (aggregateRandomness + value) % group.q;

  const options_ = aggregateOptions(election);
  const aggregateIndex = options_.indexOf(BigInt(selectedTotal));
  if (aggregateIndex < 0) throw new BallotError("internal: aggregate total not in permitted set");

  const aggregateProof = await proveOneOf(
    publicKey,
    aggregate,
    aggregateRandomness,
    aggregateIndex,
    options_,
    ballotTranscript(
      "dvoting/ballot-aggregate/v1",
      election,
      publicKey,
      ballotId,
      credentialFingerprint,
      choices,
    ),
    getRandomBytes,
  );

  return {
    ballot: {
      electionId: election.electionId,
      ballotId,
      credentialFingerprint,
      choices,
      choiceProofs,
      aggregateProof,
    },
    selections: [...selections],
    randomness,
  };
}

/**
 * Verify a ballot. Public: any voter, observer, or auditor can run this over
 * the bulletin board without any secret.
 */
export async function verifyBallot(
  election: ElectionParameters,
  publicKey: ElGamalPublicKey,
  ballot: EncryptedBallot,
): Promise<boolean> {
  try {
    validateElectionParameters(election);
  } catch {
    return false;
  }
  const { group } = publicKey;

  if (ballot.electionId !== election.electionId) return false;
  if (ballot.choices.length !== election.candidates.length) return false;
  if (ballot.choiceProofs.length !== election.candidates.length) return false;

  try {
    for (const ciphertext of ballot.choices) assertValidCiphertext(group, ciphertext);
  } catch {
    return false;
  }

  for (const [index, ciphertext] of ballot.choices.entries()) {
    const transcript = ballotTranscript(
      "dvoting/ballot-choice/v1",
      election,
      publicKey,
      ballot.ballotId,
      ballot.credentialFingerprint,
      ballot.choices,
    ).absorbNumber("choiceIndex", index);

    const ok = await verifyOneOf(
      publicKey,
      ciphertext,
      BINARY_OPTIONS,
      ballot.choiceProofs[index]!,
      transcript,
    );
    if (!ok) return false;
  }

  const aggregate = addCiphertexts(group, ballot.choices);
  return verifyOneOf(
    publicKey,
    aggregate,
    aggregateOptions(election),
    ballot.aggregateProof,
    ballotTranscript(
      "dvoting/ballot-aggregate/v1",
      election,
      publicKey,
      ballot.ballotId,
      ballot.credentialFingerprint,
      ballot.choices,
    ),
  );
}
