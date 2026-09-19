/**
 * Eligibility verification port.
 *
 * ===========================================================================
 * WHY AN ELECTORAL ROLL RATHER THAN IDENTITY VERIFICATION AT VOTE TIME.
 *
 * An earlier design delegated this to an external KYC provider (document OCR +
 * face match + liveness). That was both an external dependency and, on
 * reflection, the wrong model for an election.
 *
 * Real elections do not establish who you are at the moment you vote. They
 * establish it beforehand, once, and publish the result: an electoral roll. On
 * polling day you prove you are an entry ON THAT ROLL — you do not re-prove
 * your identity from first principles.
 *
 * Modelling it that way is better here for three reasons:
 *
 *   1. SYBIL RESISTANCE BY CONSTRUCTION. The threat model's "attacker registers
 *      fake identities" is not mitigated, it is impossible: you cannot be on the
 *      roll unless the Election Commission put you there. Liveness detection can
 *      be fooled; a closed roll cannot be argued with.
 *   2. NO BIOMETRICS. The system never handles a face, a document image, or a
 *      date of birth, so none of it can leak from the system. The most private
 *      data is data you never collected.
 *   3. NO EXTERNAL DEPENDENCY. Nothing outside this repository has to be
 *      running, reachable, or trusted for an election to proceed.
 *
 * The roll itself is an input to the system, produced by whatever statutory
 * process governs the electorate. D-Voting's job is to authenticate against it
 * correctly, not to decide who belongs on it.
 * ===========================================================================
 */

export interface EligibilityCredentials {
  /** The voter's roll number, as printed on their polling card. */
  readonly rollId: string;
  /** The single-use enrolment secret delivered out of band. */
  readonly enrolmentCode: string;
}

export interface EligibilitySuccess {
  readonly ok: true;
  /**
   * Stable pseudonymous identifier for this entry. Never persisted raw — the
   * Registration Authority hashes it under a secret pepper.
   */
  readonly subjectId: string;
  readonly source: string;
}

export interface EligibilityFailure {
  readonly ok: false;
  readonly source: string;
  /**
   * Safe to return to the caller.
   *
   * Deliberately coarse: a reason that distinguished "no such roll entry" from
   * "wrong code" would turn this endpoint into an oracle for enumerating who is
   * registered to vote.
   */
  readonly reason: string;
}

export type EligibilityResult = EligibilitySuccess | EligibilityFailure;

export interface EligibilityVerifier {
  readonly name: string;
  verify(credentials: EligibilityCredentials): Promise<EligibilityResult>;
}
