/**
 * The ballot box.
 *
 * Accepts a ballot only when BOTH of these hold, and it can check each without
 * learning anything about the vote or the voter:
 *
 *   1. ELIGIBILITY -- the submitted credential carries a valid blind signature
 *      from the Registration Authority. The RA cannot link this credential back
 *      to the person it was issued to, so verifying eligibility here reveals no
 *      identity.
 *   2. VALIDITY -- the ballot's zero-knowledge proofs show every ciphertext
 *      encrypts 0 or 1 and the total is within the permitted range.
 *
 * Accepted ballots are batched into blocks and sealed onto the permissioned
 * ledger, which makes the record tamper-evident and gives each voter a Merkle
 * inclusion proof they can check themselves.
 */

import {
  auditBallot,
  computeKeyId,
  digest,
  encodeElement,
  toBase64Url,
  verify as verifyCredentialSignature,
  verifyBallot,
  type BlindRsaPublicKey,
  type ElGamalPublicKey,
  type ElectionParameters,
  type EncryptedBallot,
} from "@dvoting/crypto";
import {
  Ledger,
  nextSealRequest,
  type Block,
  type BlockSealer,
  type LedgerEntry,
} from "@dvoting/ledger";

import {
  assertIdentityMatches,
  closeEntry,
  configEntry,
  ElectionRecordError,
  normaliseCommitment,
  normaliseElectionName,
  readCloseRecord,
  readElectionRecord,
  validateCandidates,
  type ElectionCloseRecord,
  type ElectionRecord,
  type TrusteeRoster,
} from "./election-record.ts";
import { auditSecretToWire, ballotToWire } from "./wire.ts";

export const BALLOT_ENTRY_KIND = "ballot";
export { CONFIG_ENTRY_KIND, CLOSE_ENTRY_KIND } from "./election-record.ts";
/** Audited ballots. Their randomness is public, so they must never be counted. */
export const SPOILED_ENTRY_KIND = "spoiled-ballot";
/** The final, publicly recountable result. */
export const TALLY_ENTRY_KIND = "tally-result";

/**
 * Where an election is in its life.
 *
 *   setup     nothing sealed yet; the administrator is still composing it
 *   scheduled sealed, but the opening time has not arrived
 *   voting    accepting ballots
 *   closed    voting has ended, permanently
 *
 * Every one of these is derived from the chain plus the clock, never from a
 * variable an operator can flip.
 */
export type ElectionPhase = "setup" | "scheduled" | "voting" | "closed";

export class BallotBoxError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
  override name = "BallotBoxError";
}

export interface BallotSubmission {
  /** The 32-byte anonymous credential. */
  readonly credential: Uint8Array;
  /** The RA's unblinded signature over that credential. */
  readonly credentialSignature: Uint8Array;
  readonly ballot: EncryptedBallot;
}

export interface SpoilResult {
  readonly ballotId: string;
  /**
   * Whether the ballot's ciphertexts match the revealed randomness.
   *
   * This is NOT "the voter got what they wanted". It establishes only what the
   * ballot encrypts; comparing that against the voter's actual intent is done
   * by the voter, because the server must never learn their intent.
   */
  readonly encryptionConsistent: boolean;
  /** What the ballot provably encrypts. The voter compares this to their choice. */
  readonly encodedSelections?: readonly number[];
  readonly reason?: string;
}

export interface CastResult {
  readonly ballotId: string;
  /** What the voter keeps in order to look their ballot up later. */
  readonly trackingCode: string;
  readonly status: "pending" | "recorded";
  /** How many earlier ballots this credential has cast (re-voting). */
  readonly supersedes: number;
}

export interface BallotBoxConfig {
  /**
   * The election as configured at boot.
   *
   * Treated as a DRAFT until the poll opens: while the election is in setup the
   * administrator may change it, and once it is sealed the chain becomes
   * authoritative and this is overwritten by what was sealed.
   */
  readonly election: ElectionParameters;
  /** RA issuer key, for checking credentials. */
  readonly issuerPublicKey: BlindRsaPublicKey;
  /** Joint trustee key that ballots are encrypted to. */
  readonly electionPublicKey: ElGamalPublicKey;
  /**
   * Who the trustees are and how many must cooperate to decrypt.
   *
   * Public shares only. The ballot box needs them to check decryption proofs
   * during the ceremony; it must never hold a private share, and there is no
   * field here for one.
   */
  readonly trustees: TrusteeRoster;
  readonly ledger: Ledger;
  /**
   * How blocks get sealed.
   *
   * `DistributedSealer` is the real topology: each validator is a separate node
   * holding only its own key, and each independently re-validates a proposed
   * block before attesting. `SingleProcessSealer` exists for tests and
   * single-machine demos and must never be used in production -- a quorum
   * produced entirely inside one process proves nothing.
   */
  readonly sealer: BlockSealer;
  /** Seal a block automatically once this many ballots are pending. */
  readonly maxPendingBeforeSeal?: number;
  /**
   * Public URL of the Registration Authority, published so a voter's browser
   * can talk to it DIRECTLY.
   *
   * It must not be proxied through this service. The RA learns which roll entry
   * is registering; this service learns which ballot is cast. Routing the first
   * through the second would let one party correlate the two by session or
   * timing, which is exactly the link blind signatures exist to destroy.
   */
  readonly registrationUrl?: string;
}

/**
 * Fingerprint of an anonymous credential.
 *
 * Domain-separated so it can never collide with any other hash in the system.
 * This value links a voter's own ballots together (needed for re-voting) but
 * carries no identity, because the credential itself is anonymous.
 */
export async function credentialFingerprint(credential: Uint8Array): Promise<string> {
  const tag = new TextEncoder().encode("dvoting/credential-fingerprint/v1");
  const combined = new Uint8Array(tag.length + credential.length);
  combined.set(tag);
  combined.set(credential, tag.length);
  return toBase64Url(await digest("SHA-256", combined));
}

export class BallotBox {
  readonly #config: BallotBoxConfig;
  readonly #pending: LedgerEntry[] = [];
  /** credentialFingerprint -> number of ballots cast so far. */
  readonly #castCounts = new Map<string, number>();
  /** Ballot ids spoiled by an audit but not yet sealed onto the chain. */
  readonly #spoiled = new Set<string>();
  readonly #adminAudit: { action: string; detail: string; at: string }[] = [];

  /** The draft while in setup; a copy of what was sealed once the poll opens. */
  #election: ElectionParameters;
  /** Display name only. Never bound into a proof -- see ElectionRecord.name. */
  #name: string | null = null;
  #record: ElectionRecord | null = null;
  #closeRecord: ElectionCloseRecord | null = null;
  #issuerKeyId: string | null = null;

  constructor(config: BallotBoxConfig) {
    this.#config = config;
    this.#election = { ...config.election, candidates: [...config.election.candidates] };
  }

  /**
   * Adopt the election state recorded on the chain.
   *
   * Must be called before serving. Everything about the election's life comes
   * from here: whether it was ever opened, what it was configured to be, and
   * whether voting has ended. That is the whole point -- a restarted process
   * must reach exactly the same conclusions as the one it replaced, and an
   * operator must not be able to change any of them by editing an environment
   * variable and restarting.
   */
  async load(): Promise<void> {
    const record = await readElectionRecord(this.#config.ledger, this.#config.election.electionId);
    this.#issuerKeyId = await computeKeyId(this.#config.issuerPublicKey);

    if (!record) return; // still in setup: the draft stands

    assertIdentityMatches(record, {
      group: this.#config.electionPublicKey.group.name,
      issuerKeyId: this.#issuerKeyId,
      electionPublicKey: this.#encodedElectionPublicKey(),
      validators: this.#config.ledger.validatorSet.validators.map((v) => ({
        id: v.id,
        publicKey: toBase64Url(v.publicKey),
      })),
      quorum: this.#config.ledger.validatorSet.quorum,
    });

    // The chain is authoritative for ballot content. If the environment says
    // something different, the environment is stale -- the sealed record is what
    // voters were shown and what auditors will check against.
    this.#record = record;
    this.#election = {
      electionId: record.electionId,
      candidates: [...record.candidates],
      minSelections: record.minSelections,
      maxSelections: record.maxSelections,
    };
    this.#name = record.name;
    this.#closeRecord = await readCloseRecord(this.#config.ledger, record.electionId);
  }

  get election(): ElectionParameters {
    return this.#election;
  }

  /** Display name, or null. Editable only before the poll opens. */
  get name(): string | null {
    return this.#name;
  }

  /** The sealed record, or null while the election is still being composed. */
  get record(): ElectionRecord | null {
    return this.#record;
  }

  get closeRecord(): ElectionCloseRecord | null {
    return this.#closeRecord;
  }

  get trustees(): TrusteeRoster {
    return this.#config.trustees;
  }

  /**
   * Where the election is in its life -- computed, never stored.
   *
   * Note the schedule branch: an election with a `closesAt` in the past is
   * closed whether or not anyone pressed a button. A deadline that only takes
   * effect if an operator remembers to act is not a deadline.
   */
  get phase(): ElectionPhase {
    const record = this.#record;
    if (!record) return "setup";
    if (this.#closeRecord) return "closed";

    const now = Date.now();
    if (record.closesAt && now >= Date.parse(record.closesAt)) return "closed";
    if (record.opensAt && now < Date.parse(record.opensAt)) return "scheduled";
    return "voting";
  }

  get ledger(): Ledger {
    return this.#config.ledger;
  }

  get electionPublicKey(): ElGamalPublicKey {
    return this.#config.electionPublicKey;
  }

  get electionPublicKeyGroup() {
    return this.#config.electionPublicKey.group;
  }

  get registrationUrl(): string | null {
    return this.#config.registrationUrl ?? null;
  }

  /**
   * Append-only record of operator actions.
   *
   * Kept in memory alongside the service rather than on the chain: it is
   * operational accountability, not part of the election record, and putting
   * operator activity on a public bulletin board would leak the rhythm of the
   * count. A production deployment ships these to write-once storage.
   */
  async recordAdminAction(action: string, detail: string): Promise<void> {
    this.#adminAudit.push({ action, detail, at: new Date().toISOString() });
    // Bounded so a long-running election cannot grow this without limit.
    if (this.#adminAudit.length > 5_000) this.#adminAudit.shift();
  }

  async recentAudit(limit: number): Promise<readonly { action: string; detail: string; at: string }[]> {
    return this.#adminAudit.slice(-limit).reverse();
  }

  get pendingCount(): number {
    return this.#pending.length;
  }

  get isOpen(): boolean {
    return this.phase === "voting";
  }

  #encodedElectionPublicKey(): string {
    return toBase64Url(
      encodeElement(this.#config.electionPublicKey.group, this.#config.electionPublicKey.y),
    );
  }

  /**
   * Amend the election while it is still being composed.
   *
   * Refused the moment anything is sealed. Editing a ballot after voting has
   * begun is the single most damaging thing an administrator could do, so the
   * ability simply stops existing rather than being guarded by a confirmation.
   */
  updateDraft(patch: {
    name?: string | null;
    candidates?: readonly string[];
    minSelections?: number;
    maxSelections?: number;
  }): ElectionParameters & { name: string | null } {
    if (this.#record) {
      throw new BallotBoxError(
        "election_sealed",
        "This election is already sealed on the chain and can no longer be edited.",
      );
    }

    const candidates =
      patch.candidates !== undefined
        ? validateCandidates(patch.candidates)
        : [...this.#election.candidates];
    const minSelections = patch.minSelections ?? this.#election.minSelections;
    const maxSelections = patch.maxSelections ?? this.#election.maxSelections;
    const name = patch.name !== undefined ? normaliseElectionName(patch.name) : this.#name;

    if (!Number.isInteger(minSelections) || minSelections < 0) {
      throw new BallotBoxError("invalid_selections", "minSelections must be zero or more.");
    }
    if (!Number.isInteger(maxSelections) || maxSelections < 1) {
      throw new BallotBoxError("invalid_selections", "maxSelections must be at least one.");
    }
    if (maxSelections < minSelections) {
      throw new BallotBoxError("invalid_selections", "maxSelections cannot be below minSelections.");
    }
    if (maxSelections > candidates.length) {
      throw new BallotBoxError(
        "invalid_selections",
        "maxSelections cannot exceed the number of candidates.",
      );
    }

    this.#election = {
      electionId: this.#election.electionId,
      candidates,
      minSelections,
      maxSelections,
    };
    this.#name = name;
    return { ...this.#election, name };
  }

  /**
   * Seal the election and open the poll.
   *
   * This is the one-way door. Before it, an administrator is composing a draft
   * that exists only in this process; after it, the election's definition is on
   * a chain that a quorum of independent validators has signed, and the only
   * remaining administrative powers are to observe and to close.
   */
  async openPoll(input: {
    rollCommitment?: string | null;
    opensAt?: string | null;
    closesAt?: string | null;
  } = {}): Promise<ElectionRecord> {
    if (this.#record) {
      throw new BallotBoxError("already_open", "This election has already been sealed.");
    }
    if (this.#issuerKeyId === null) {
      throw new BallotBoxError("not_loaded", "load() must run before the poll can be opened.");
    }

    const candidates = validateCandidates(this.#election.candidates);
    const opensAt = parseInstant(input.opensAt ?? null, "opensAt");
    const closesAt = parseInstant(input.closesAt ?? null, "closesAt");
    if (opensAt && closesAt && Date.parse(closesAt) <= Date.parse(opensAt)) {
      throw new BallotBoxError("invalid_schedule", "The poll cannot close before it opens.");
    }
    if (closesAt && Date.parse(closesAt) <= Date.now()) {
      // Sealing an already-expired election would disenfranchise everyone and
      // could not be undone.
      throw new BallotBoxError("invalid_schedule", "closesAt is already in the past.");
    }

    let rollCommitment: string | null;
    try {
      rollCommitment = normaliseCommitment(input.rollCommitment ?? null);
    } catch (error) {
      throw new BallotBoxError(
        "invalid_roll_commitment",
        error instanceof ElectionRecordError ? error.message : "Invalid roll commitment.",
      );
    }

    const record: ElectionRecord = {
      recordVersion: "dvoting/election-config/v1",
      electionId: this.#election.electionId,
      name: this.#name,
      candidates,
      minSelections: this.#election.minSelections,
      maxSelections: this.#election.maxSelections,
      group: this.#config.electionPublicKey.group.name,
      issuerKeyId: this.#issuerKeyId,
      electionPublicKey: this.#encodedElectionPublicKey(),
      trustees: {
        threshold: this.#config.trustees.threshold,
        total: this.#config.trustees.total,
        publicShares: this.#config.trustees.publicShares.map((share) => ({ ...share })),
      },
      validators: this.#config.ledger.validatorSet.validators.map((v) => ({
        id: v.id,
        publicKey: toBase64Url(v.publicKey),
      })),
      quorum: this.#config.ledger.validatorSet.quorum,
      rollCommitment,
      opensAt,
      closesAt,
      sealedAt: new Date().toISOString(),
    };

    await this.#appendAndReplicate(await this.#buildBlock([configEntry(record)]));

    this.#record = record;
    this.#election = { ...this.#election, candidates };
    return record;
  }

  /**
   * End the poll, permanently.
   *
   * The close is an entry on the chain, sealed in the same block as any ballot
   * still waiting. Two consequences follow, and both are the reason it is done
   * this way: a ballot accepted moments before the deadline cannot be stranded
   * outside the record, and "voting has ended" survives a restart -- it is not a
   * flag in memory that a process crash quietly clears.
   */
  async closePoll(reason: "administrator" | "schedule" = "administrator"): Promise<ElectionCloseRecord> {
    if (!this.#record) {
      throw new BallotBoxError("not_open", "This election was never opened.");
    }
    if (this.#closeRecord) {
      throw new BallotBoxError("already_closed", "This election is already closed.");
    }

    const record: ElectionCloseRecord = {
      recordVersion: "dvoting/election-closed/v1",
      electionId: this.#record.electionId,
      closedAt: new Date().toISOString(),
      reason,
      // The block this record lands in, so the last counted ballot is pinned.
      finalHeight: await this.#config.ledger.height(),
    };

    await this.sealBlock([closeEntry(record)]);
    this.#closeRecord = record;
    return record;
  }

  /**
   * Cast a ballot.
   *
   * Order of checks is deliberate: cheap structural checks first, then the
   * credential signature, then the expensive zero-knowledge verification last.
   * An attacker spraying junk should be rejected before consuming the costly
   * path.
   */
  async cast(submission: BallotSubmission): Promise<CastResult> {
    switch (this.phase) {
      case "setup":
        throw new BallotBoxError("election_not_open", "This election has not opened yet.");
      case "scheduled":
        throw new BallotBoxError(
          "election_not_open",
          `Voting opens at ${this.#record?.opensAt ?? "the scheduled time"}.`,
        );
      case "closed":
        throw new BallotBoxError("election_closed", "This election is no longer accepting ballots.");
      case "voting":
        break;
    }

    const { ballot } = submission;

    if (ballot.electionId !== this.#election.electionId) {
      throw new BallotBoxError("wrong_election", "Ballot is for a different election.");
    }
    if (!ballot.ballotId || ballot.ballotId.length > 128) {
      throw new BallotBoxError("invalid_ballot_id", "Ballot id is missing or too long.");
    }

    // Spoiled first: it is the more specific condition, and reporting it as a
    // generic duplicate would tell the voter to retry when what they actually
    // need is to prepare a brand new ballot.
    //
    // A spoiled (audited) ballot has had its randomness published, so anyone can
    // decrypt it. Casting one would put a publicly-readable vote in the tally.
    if (
      this.#spoiled.has(ballot.ballotId) ||
      (await this.#config.ledger.hasEntry(SPOILED_ENTRY_KIND, ballot.ballotId))
    ) {
      throw new BallotBoxError(
        "ballot_spoiled",
        "This ballot was audited and can never be cast. Prepare a fresh ballot.",
      );
    }

    // A ballot id may be used exactly once, ever. This is what makes an exact
    // replay of a captured submission a no-op. The pending check is filtered by
    // kind so a pending SPOILED entry cannot masquerade as a duplicate ballot.
    if (await this.#config.ledger.hasEntry(BALLOT_ENTRY_KIND, ballot.ballotId)) {
      throw new BallotBoxError("duplicate_ballot", "This ballot id has already been recorded.");
    }
    if (
      this.#pending.some(
        (entry) => entry.kind === BALLOT_ENTRY_KIND && entry.id === ballot.ballotId,
      )
    ) {
      throw new BallotBoxError("duplicate_ballot", "This ballot id is already pending.");
    }

    // 1. Eligibility. Verifying the RA's blind signature proves the holder was
    //    issued a credential, without revealing which voter that was.
    const signatureOk = await verifyCredentialSignature(
      this.#config.issuerPublicKey,
      submission.credential,
      submission.credentialSignature,
    );
    if (!signatureOk) {
      throw new BallotBoxError(
        "invalid_credential",
        "Credential is not signed by this election's Registration Authority.",
      );
    }

    // The ballot's proofs are bound to this fingerprint, so a ballot cannot be
    // cast by anyone other than the credential holder.
    const fingerprint = await credentialFingerprint(submission.credential);
    if (ballot.credentialFingerprint !== fingerprint) {
      throw new BallotBoxError(
        "credential_mismatch",
        "Ballot is not bound to the supplied credential.",
      );
    }

    // 2. Validity. The expensive check, done last. Verified against the SEALED
    // election, so a ballot can only ever be valid for the race that was
    // committed to the chain before voting opened.
    const ballotOk = await verifyBallot(
      this.#election,
      this.#config.electionPublicKey,
      ballot,
    );
    if (!ballotOk) {
      throw new BallotBoxError("invalid_ballot", "Ballot failed zero-knowledge verification.");
    }

    const supersedes = this.#castCounts.get(fingerprint) ?? 0;
    this.#castCounts.set(fingerprint, supersedes + 1);

    this.#pending.push({
      kind: BALLOT_ENTRY_KIND,
      id: ballot.ballotId,
      data: new TextEncoder().encode(
        JSON.stringify(ballotToWire(this.#config.electionPublicKey.group, ballot)),
      ),
    });

    let status: CastResult["status"] = "pending";
    const threshold = this.#config.maxPendingBeforeSeal ?? 0;
    if (threshold > 0 && this.#pending.length >= threshold) {
      await this.sealBlock();
      status = "recorded";
    }

    return { ballotId: ballot.ballotId, trackingCode: ballot.ballotId, status, supersedes };
  }

  /**
   * Spoil a ballot the voter chose to audit.
   *
   * The revealed randomness is published on the bulletin board alongside the
   * ballot, so ANY observer can re-run the audit and confirm the voting client
   * encrypted what it claimed. That public record is what turns one voter's
   * private check into evidence the whole electorate can rely on.
   *
   * The ballot id is burned permanently: its randomness is now public, so the
   * ballot is decryptable by anyone and must never enter the tally.
   */
  async spoil(input: {
    ballot: EncryptedBallot;
    auditSecret: { ballotId: string; selections: readonly number[]; randomness: readonly bigint[] };
  }): Promise<SpoilResult> {
    const { ballot, auditSecret } = input;

    if (!this.isOpen) {
      // An audit publishes a ballot's randomness. Accepting one outside the
      // voting window would add a decryptable entry to a sealed record.
      throw new BallotBoxError(
        "election_closed",
        "This election is not open, so a ballot cannot be audited.",
      );
    }
    if (ballot.electionId !== this.#election.electionId) {
      throw new BallotBoxError("wrong_election", "Ballot is for a different election.");
    }
    if (auditSecret.ballotId !== ballot.ballotId) {
      throw new BallotBoxError("audit_mismatch", "Audit data is for a different ballot.");
    }
    if (await this.#config.ledger.hasEntry(BALLOT_ENTRY_KIND, ballot.ballotId)) {
      // Auditing an already-cast ballot would expose a counted vote.
      throw new BallotBoxError(
        "already_cast",
        "This ballot has already been cast and cannot be audited.",
      );
    }
    // Filtered by kind, so re-auditing an already-spoiled ballot is not
    // misreported as an attempt to audit a cast one.
    if (
      this.#pending.some(
        (entry) => entry.kind === BALLOT_ENTRY_KIND && entry.id === ballot.ballotId,
      )
    ) {
      throw new BallotBoxError(
        "already_cast",
        "This ballot is pending and cannot be audited.",
      );
    }
    if (this.#spoiled.has(ballot.ballotId)) {
      throw new BallotBoxError("ballot_spoiled", "This ballot has already been audited.");
    }

    // NOTE the missing `expectedSelections` argument, and note that its absence
    // is deliberate. The ballot box can only establish that the ballot is
    // internally consistent with the revealed randomness. It must NOT be told
    // what the voter intended -- that would hand the server the plaintext vote
    // and destroy ballot secrecy. Comparing against intent is the voter's job,
    // performed on a device the malicious client does not control.
    const audit = await auditBallot(
      this.#election,
      this.#config.electionPublicKey,
      ballot,
      auditSecret,
    );

    // The ballot id is burned either way. An inconsistent audit is evidence of a
    // misbehaving client and is recorded as such, not quietly dropped.
    this.#spoiled.add(ballot.ballotId);
    this.#pending.push({
      kind: SPOILED_ENTRY_KIND,
      id: ballot.ballotId,
      data: new TextEncoder().encode(
        JSON.stringify({
          ballot: ballotToWire(this.#config.electionPublicKey.group, ballot),
          audit: auditSecretToWire(this.#config.electionPublicKey.group, auditSecret),
          encryptionConsistent: audit.ok,
          encodedSelections: audit.encodedSelections ?? null,
          ...(audit.reason !== undefined ? { reason: audit.reason } : {}),
        }),
      ),
    });

    return {
      ballotId: ballot.ballotId,
      encryptionConsistent: audit.ok,
      ...(audit.encodedSelections !== undefined
        ? { encodedSelections: audit.encodedSelections }
        : {}),
      ...(audit.reason !== undefined ? { reason: audit.reason } : {}),
    };
  }

  /**
   * Seal the final result onto the chain.
   *
   * Refuses while voting is open. Publishing a tally mid-election would leak a
   * running total, which lets late voters see the state of the race — and lets
   * an operator decide whether to keep counting based on who is winning.
   *
   * Refuses to publish twice for the same reason a ledger never rewrites: a
   * second, different result would make the record ambiguous.
   */
  async publishTally(tally: { encode(): Uint8Array }): Promise<Block> {
    if (this.phase !== "closed") {
      throw new BallotBoxError(
        "election_open",
        "Close the election before publishing a tally: a running total would leak the state of the race.",
      );
    }
    if (await this.#config.ledger.hasEntry(TALLY_ENTRY_KIND, this.#election.electionId)) {
      throw new BallotBoxError("tally_already_published", "A result is already on the chain.");
    }

    // Any ballots still pending are sealed first, so the published tally cannot
    // omit a ballot that was accepted before the election closed.
    if (this.#pending.length > 0) await this.sealBlock();

    return this.#appendAndReplicate(
      await this.#buildBlock([
        {
          kind: TALLY_ENTRY_KIND,
          id: this.#election.electionId,
          data: tally.encode(),
        },
      ]),
    );
  }

  /** Seal all pending entries into a block and append it to the ledger. */
  async sealBlock(extraEntries: readonly LedgerEntry[] = []): Promise<Block | null> {
    const entries = [...this.#pending, ...extraEntries];
    if (entries.length === 0) return null;

    const block = await this.#appendAndReplicate(await this.#buildBlock(entries));
    this.#pending.length = 0;
    return block;
  }

  /**
   * Append locally first, then replicate.
   *
   * Ordering matters: this node must have durably accepted the block before
   * telling anyone else to, so a replication failure can never leave peers
   * holding a block this node does not have.
   */
  async #appendAndReplicate(block: Block): Promise<Block> {
    await this.#config.ledger.append(block);
    await this.#config.sealer.broadcastCommit?.(block);
    return block;
  }

  async #buildBlock(entries: readonly LedgerEntry[]): Promise<Block> {
    const request = await nextSealRequest(
      this.#config.ledger,
      this.#election.electionId,
      entries,
    );
    return this.#config.sealer.seal(request);
  }

  /** Public election descriptor, safe to serve to anyone. */
  async describe() {
    return {
      electionId: this.#election.electionId,
      name: this.#name,
      candidates: this.#election.candidates,
      minSelections: this.#election.minSelections,
      maxSelections: this.#election.maxSelections,
      phase: this.phase,
      open: this.isOpen,
      opensAt: this.#record?.opensAt ?? null,
      closesAt: this.#record?.closesAt ?? null,
      closedAt: this.#closeRecord?.closedAt ?? null,
      /**
       * The commitment to the electoral roll, as frozen before the poll opened.
       * Published so anyone holding the roll can prove it is the one that was
       * used -- and so a name added afterwards no longer matches.
       */
      rollCommitment: this.#record?.rollCommitment ?? null,
      /** Height of the block that sealed this election's configuration. */
      configSealed: this.#record !== null,
      issuerKeyId: this.#issuerKeyId ?? (await computeKeyId(this.#config.issuerPublicKey)),
      group: this.#config.electionPublicKey.group.name,
      electionPublicKey: this.#encodedElectionPublicKey(),
      trustees: {
        threshold: this.#config.trustees.threshold,
        total: this.#config.trustees.total,
      },
      validators: this.#config.ledger.validatorSet.validators.map((v) => ({
        id: v.id,
        publicKey: toBase64Url(v.publicKey),
      })),
      quorum: this.#config.ledger.validatorSet.quorum,
      blockHeight: await this.#config.ledger.height(),
      pending: this.#pending.length,
      // Where the voter's browser goes to prove eligibility. Never proxied.
      registrationUrl: this.#config.registrationUrl ?? null,
    };
  }
}

/** ISO-8601 instant, or null. Rejects anything a Date cannot pin down. */
function parseInstant(value: string | null, field: string): string | null {
  if (value === null || value === "") return null;
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    throw new BallotBoxError("invalid_schedule", `${field} is not a valid date and time.`);
  }
  return new Date(parsed).toISOString();
}
