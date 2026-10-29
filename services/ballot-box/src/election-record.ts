/**
 * The election record: what this election IS, committed to the chain.
 *
 * ===========================================================================
 * WHY THIS FILE EXISTS.
 *
 * Everything else in the system is verifiable against something. A ballot is
 * verifiable against the election's public key. A block is verifiable against a
 * validator quorum. A tally is verifiable against the ballots.
 *
 * But the election's own configuration -- who the candidates are, which issuer
 * key confers eligibility, which key ballots are encrypted to, who the
 * validators are -- had nowhere to be verified against. It lived in environment
 * variables. An operator could add a candidate mid-election, swap the issuer
 * key, or quietly change the validator set, and no observer could tell, because
 * there was nothing recording what the election was supposed to be.
 *
 * So the configuration is sealed into the chain's first block, before a single
 * ballot is accepted, and the service refuses to serve any configuration that
 * disagrees with it. After that moment the election's definition is as
 * tamper-evident as its ballots.
 *
 * The close is recorded the same way. "Voting has ended" used to be a boolean
 * in memory, which meant a restart silently reopened a closed election -- the
 * one thing the admin console promises cannot happen. It is now an entry on the
 * chain: irreversible, publicly visible, and the same after a restart as before
 * one.
 * ===========================================================================
 */

import { toBase64Url } from "@dvoting/crypto";
import type { Ledger, LedgerEntry } from "@dvoting/ledger";

export const CONFIG_ENTRY_KIND = "election-config";
/** Voting has ended. Its presence on the chain is what "closed" means. */
export const CLOSE_ENTRY_KIND = "election-closed";

export class ElectionRecordError extends Error {
  override name = "ElectionRecordError";
}

/**
 * Ballot symbols a candidate may be shown with.
 *
 * A fixed, neutral set rather than uploaded images: an uploaded file is markup
 * the voter's browser would have to render, and a real party's registered
 * symbol is not the commission's to reproduce. The browser draws these from
 * its own copy (public/symbols.js), so the chain records only the name.
 */
export const BALLOT_SYMBOLS = [
  "lamp", "tree", "star", "book", "bicycle", "sun",
  "boat", "key", "kite", "umbrella", "flower", "clock",
] as const;

export type BallotSymbol = (typeof BALLOT_SYMBOLS)[number];

export interface CandidateDetail {
  readonly party: string | null;
  readonly symbol: BallotSymbol | null;
  /** "None of the Above": a valid, counted choice that elects nobody. */
  readonly nota: boolean;
}

/**
 * Independent observers who countersign the board's head (see
 * packages/ledger/src/checkpoint.ts). Sealed so a voter's device knows whose
 * checkpoints to ask for, and so the list cannot be swapped once voting opens.
 */
export interface WitnessRoster {
  /** How many witnesses must vouch for a head before a device trusts it. */
  readonly quorum: number;
  readonly witnesses: readonly { id: string; publicKey: string; url: string }[];
}

export interface TrusteeRoster {
  readonly threshold: number;
  readonly total: number;
  /** g^{x_i} for each trustee, base64url. Ceremony submissions verify against these. */
  readonly publicShares: readonly { index: number; publicShare: string }[];
}

/**
 * The sealed definition of an election.
 *
 * Split deliberately into two kinds of field:
 *
 *   - CRYPTOGRAPHIC IDENTITY (group, issuerKeyId, electionPublicKey, trustees,
 *     validators, quorum). A mismatch between this and the running service's
 *     configuration is never benign, so the service refuses to start.
 *   - BALLOT CONTENT (candidates, selection limits, schedule, rollCommitment).
 *     The chain is authoritative; the service adopts what was sealed.
 */
export interface ElectionRecord {
  readonly recordVersion: "dvoting/election-config/v1";
  readonly electionId: string;
  /**
   * Human-facing name -- "Lok Sabha General Election 2026", not
   * "dvoting-local-2026". Purely descriptive: nothing verifies against it, and
   * it plays no role in any proof. `electionId` remains the identifier every
   * cryptographic check is bound to, so renaming an election can never be
   * confused with running a different one.
   */
  readonly name: string | null;
  readonly candidates: readonly string[];
  /**
   * How each candidate is presented on the ballot: party, symbol, and whether
   * the entry is "None of the Above". Aligned index-for-index with
   * `candidates`. Absent on records sealed before this field existed.
   *
   * Sealed for the same reason the names are: a voter who recognises a
   * candidate by symbol is voting for the symbol, so swapping two symbols after
   * opening would misdirect votes as surely as swapping two names.
   */
  readonly candidateDetails?: readonly CandidateDetail[] | null;
  readonly minSelections: number;
  readonly maxSelections: number;
  readonly group: string;
  /** Fingerprint of the RA issuer key that confers eligibility. */
  readonly issuerKeyId: string;
  /** Joint trustee public key, base64url. Ballots are encrypted to this. */
  readonly electionPublicKey: string;
  readonly trustees: TrusteeRoster;
  readonly validators: readonly { id: string; publicKey: string }[];
  readonly quorum: number;
  /** Absent on records sealed before witnesses existed. */
  readonly witnesses?: WitnessRoster | null;
  /**
   * Commitment to the electoral roll as frozen before the poll opened.
   *
   * The roll itself lives at the Registration Authority and is not published
   * here -- an electoral roll is personal data. What is published is a hash over
   * it, which is enough for anyone holding the roll to prove it is the one that
   * was used, and enough to make a later addition detectable.
   */
  readonly rollCommitment: string | null;
  readonly opensAt: string | null;
  readonly closesAt: string | null;
  readonly sealedAt: string;
}

export interface ElectionCloseRecord {
  readonly recordVersion: "dvoting/election-closed/v1";
  readonly electionId: string;
  readonly closedAt: string;
  readonly reason: "administrator" | "schedule";
  /** Chain height at the moment of closing, so the final ballot is pinned. */
  readonly finalHeight: number;
}

export function configEntry(record: ElectionRecord): LedgerEntry {
  return {
    kind: CONFIG_ENTRY_KIND,
    id: record.electionId,
    data: new TextEncoder().encode(JSON.stringify(record)),
  };
}

export function closeEntry(record: ElectionCloseRecord): LedgerEntry {
  return {
    kind: CLOSE_ENTRY_KIND,
    id: record.electionId,
    data: new TextEncoder().encode(JSON.stringify(record)),
  };
}

export async function readElectionRecord(
  ledger: Ledger,
  electionId: string,
): Promise<ElectionRecord | null> {
  const located = await ledger.locateEntry(CONFIG_ENTRY_KIND, electionId);
  if (!located) return null;
  let parsed: ElectionRecord;
  try {
    parsed = JSON.parse(new TextDecoder().decode(located.entry.data)) as ElectionRecord;
  } catch {
    throw new ElectionRecordError("the election configuration on the chain is not valid JSON");
  }
  if (parsed.recordVersion !== "dvoting/election-config/v1") {
    throw new ElectionRecordError(
      `unsupported election record version "${String(parsed.recordVersion)}"`,
    );
  }
  return parsed;
}

export async function readCloseRecord(
  ledger: Ledger,
  electionId: string,
): Promise<ElectionCloseRecord | null> {
  const located = await ledger.locateEntry(CLOSE_ENTRY_KIND, electionId);
  if (!located) return null;
  try {
    return JSON.parse(new TextDecoder().decode(located.entry.data)) as ElectionCloseRecord;
  } catch {
    throw new ElectionRecordError("the close record on the chain is not valid JSON");
  }
}

/**
 * Refuse to serve an election whose cryptographic identity has drifted.
 *
 * These four values decide whether a ballot can be read and whether the record
 * can be trusted. If the sealed election says one thing and this process was
 * configured with another, exactly one of them is wrong -- and continuing would
 * mean encrypting ballots to a key nobody can decrypt, accepting credentials
 * from an issuer the election never recognised, or serving a chain signed by
 * validators the election never named. There is no safe way to guess which side
 * is right, so the service stops.
 */
export function assertIdentityMatches(
  sealed: ElectionRecord,
  running: {
    group: string;
    issuerKeyId: string;
    electionPublicKey: string;
    validators: readonly { id: string; publicKey: string }[];
    quorum: number;
  },
): void {
  const problems: string[] = [];

  if (sealed.group !== running.group) {
    problems.push(`group: chain says "${sealed.group}", this process is configured for "${running.group}"`);
  }
  if (sealed.issuerKeyId !== running.issuerKeyId) {
    problems.push(
      `issuer key: chain says "${sealed.issuerKeyId}", this process holds "${running.issuerKeyId}"`,
    );
  }
  if (sealed.electionPublicKey !== running.electionPublicKey) {
    problems.push("election public key does not match the one sealed on the chain");
  }
  if (sealed.quorum !== running.quorum) {
    problems.push(`quorum: chain says ${sealed.quorum}, this process is configured for ${running.quorum}`);
  }

  const sealedValidators = [...sealed.validators]
    .map((v) => `${v.id}:${v.publicKey}`)
    .sort()
    .join(",");
  const runningValidators = [...running.validators]
    .map((v) => `${v.id}:${v.publicKey}`)
    .sort()
    .join(",");
  if (sealedValidators !== runningValidators) {
    problems.push("validator set does not match the one sealed on the chain");
  }

  if (problems.length > 0) {
    throw new ElectionRecordError(
      `refusing to start: this process disagrees with the election sealed on the chain:\n  - ${problems.join(
        "\n  - ",
      )}`,
    );
  }
}

/** A witness roster that can actually be checked against, or an error. */
export function validateWitnessRoster(roster: unknown): WitnessRoster {
  const value = roster as Partial<WitnessRoster> | null;
  if (!value || !Array.isArray(value.witnesses) || value.witnesses.length === 0) {
    throw new ElectionRecordError("witnesses must list at least one witness");
  }
  const ids = new Set<string>();
  const witnesses = value.witnesses.map((w, i) => {
    if (typeof w?.id !== "string" || !/^[A-Za-z0-9_.-]{1,64}$/.test(w.id)) {
      throw new ElectionRecordError(`witness ${i}: id must be 1-64 letters, digits, . _ or -`);
    }
    if (ids.has(w.id)) throw new ElectionRecordError(`witness id "${w.id}" appears twice`);
    ids.add(w.id);
    if (typeof w.publicKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(w.publicKey)) {
      throw new ElectionRecordError(`witness "${w.id}": publicKey must be a 32-byte base64url Ed25519 key`);
    }
    let url: URL;
    try {
      url = new URL(String(w.url));
    } catch {
      throw new ElectionRecordError(`witness "${w.id}": url is not a valid URL`);
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new ElectionRecordError(`witness "${w.id}": url must be http(s)`);
    }
    // Origin plus path: a witness may be served under a prefix (one public
    // host fronting several observers), but never with a query or fragment.
    return { id: w.id, publicKey: w.publicKey, url: url.origin + url.pathname.replace(/\/+$/, "") };
  });
  const quorum = value.quorum;
  if (typeof quorum !== "number" || !Number.isInteger(quorum) || quorum < 1 || quorum > witnesses.length) {
    throw new ElectionRecordError(`witness quorum must be between 1 and ${witnesses.length}`);
  }
  return { quorum, witnesses };
}

/** Candidate names must be usable as a ballot: present, distinct, and readable. */
export function validateCandidates(candidates: readonly string[]): string[] {
  const cleaned = candidates.map((name) => name.trim()).filter((name) => name.length > 0);
  if (cleaned.length < 2) {
    throw new ElectionRecordError("an election needs at least two candidates");
  }
  if (cleaned.length > 64) {
    throw new ElectionRecordError("at most 64 candidates are supported");
  }
  for (const name of cleaned) {
    if (name.length > 120) {
      throw new ElectionRecordError(`candidate name is too long: "${name.slice(0, 40)}..."`);
    }
  }
  if (new Set(cleaned).size !== cleaned.length) {
    // Two identical names on a ballot are indistinguishable to the voter, and
    // the result would be unattributable.
    throw new ElectionRecordError("candidate names must be distinct");
  }
  return cleaned;
}

/**
 * Ballot presentation for each candidate, or null when none is given.
 *
 * Every entry must line up with a candidate; a symbol may be used once, so two
 * candidates are never visually interchangeable; and at most one entry may be
 * NOTA, because two "None of the Above" lines would split the same intent.
 */
export function normaliseCandidateDetails(
  value: unknown,
  candidateCount: number,
): CandidateDetail[] | null {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) {
    throw new ElectionRecordError("candidateDetails must be a list");
  }
  if (value.length !== candidateCount) {
    throw new ElectionRecordError(
      `candidateDetails has ${value.length} entries but the ballot has ${candidateCount} candidates`,
    );
  }

  const seenSymbols = new Set<string>();
  let notaCount = 0;
  const details = value.map((raw, index): CandidateDetail => {
    if (typeof raw !== "object" || raw === null) {
      throw new ElectionRecordError(`candidateDetails[${index}] must be an object`);
    }
    const entry = raw as Record<string, unknown>;

    let party: string | null = null;
    if (entry.party !== null && entry.party !== undefined) {
      if (typeof entry.party !== "string") {
        throw new ElectionRecordError(`candidateDetails[${index}].party must be a string`);
      }
      const trimmed = entry.party.trim();
      if (trimmed.length > 120) {
        throw new ElectionRecordError(`candidateDetails[${index}].party is too long`);
      }
      party = trimmed.length > 0 ? trimmed : null;
    }

    let symbol: BallotSymbol | null = null;
    if (entry.symbol !== null && entry.symbol !== undefined && entry.symbol !== "") {
      if (!(BALLOT_SYMBOLS as readonly unknown[]).includes(entry.symbol)) {
        throw new ElectionRecordError(
          `candidateDetails[${index}].symbol must be one of: ${BALLOT_SYMBOLS.join(", ")}`,
        );
      }
      symbol = entry.symbol as BallotSymbol;
      if (seenSymbols.has(symbol)) {
        throw new ElectionRecordError(`symbol "${symbol}" is used by more than one candidate`);
      }
      seenSymbols.add(symbol);
    }

    const nota = entry.nota === true;
    if (nota) notaCount++;
    return { party, symbol, nota };
  });

  if (notaCount > 1) {
    throw new ElectionRecordError("at most one candidate can be None of the Above");
  }
  return details;
}

/**
 * The election's display name, or null.
 *
 * Deliberately permissive on characters -- it is prose for a header, not an
 * identifier anything is bound to -- but still bounded and never blank
 * (whitespace-only collapses to null rather than being sealed as "the name").
 */
export function normaliseElectionName(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    throw new ElectionRecordError("name must be a string");
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.length > 200) {
    throw new ElectionRecordError("name must be at most 200 characters");
  }
  return trimmed;
}

/** Hex/base64url-ish opaque commitment, or null. Never store an arbitrary blob. */
export function normaliseCommitment(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(value)) {
    throw new ElectionRecordError("rollCommitment must be a base64url digest");
  }
  return value;
}

export function digestToCommitment(digest: Uint8Array): string {
  return toBase64Url(digest);
}
