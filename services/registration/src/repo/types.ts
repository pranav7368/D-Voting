/**
 * Storage port for the Registration Authority.
 *
 * The interface is intentionally narrow and expresses the *security invariant*
 * rather than raw CRUD: `issueCredential` is the only way to obtain a
 * signature, and it is responsible for guaranteeing at-most-one issuance per
 * voter. Pushing that rule down into the storage layer (instead of doing a
 * read-then-write in the route handler) is what makes it race-free.
 */

export interface VoterRecord {
  id: string;
  electionId: string;
  identityHash: Uint8Array;
  kycProvider: string;
  kycVerifiedAt: Date;
  credentialIssuedAt: Date | null;
  blindedMessageHash: Uint8Array | null;
  blindSignature: Uint8Array | null;
}

export interface FindOrCreateVoterInput {
  electionId: string;
  identityHash: Uint8Array;
  kycProvider: string;
}

export type IssueOutcome =
  /** First issuance for this voter. */
  | { status: "issued"; blindSignature: Uint8Array }
  /** Same blinded message presented again -- safe to replay the stored answer. */
  | { status: "replayed"; blindSignature: Uint8Array }
  /** A credential was already issued for a DIFFERENT blinded message. Refused. */
  | { status: "already_issued" };

export interface VoterRepository {
  findOrCreateVoter(input: FindOrCreateVoterInput): Promise<VoterRecord>;
  findVoterById(id: string): Promise<VoterRecord | null>;

  /**
   * Atomically claim this voter's single issuance and produce a signature.
   *
   * `sign` is invoked at most once, while the voter's row is exclusively
   * locked. Implementations MUST NOT mark the credential as issued if `sign`
   * throws -- otherwise a transient signer failure would permanently
   * disenfranchise the voter with no recovery path.
   */
  issueCredential(
    voterId: string,
    blindedMessageHash: Uint8Array,
    sign: () => Promise<Uint8Array>,
  ): Promise<IssueOutcome>;

  recordAudit(entry: {
    electionId: string;
    action: string;
    subjectRef?: string;
    detail?: string;
  }): Promise<void>;

  close(): Promise<void>;
}
