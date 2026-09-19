/**
 * In-memory voter repository for tests and the offline demo.
 *
 * Mirrors the Postgres implementation's concurrency semantics: `issueCredential`
 * takes a per-voter lock so the single-issuance invariant can be tested without
 * a database. Refuses to be used in production (see config.ts).
 */

import { constantTimeEqual, toBase64Url } from "@dvoting/crypto";

import type {
  FindOrCreateVoterInput,
  IssueOutcome,
  VoterRecord,
  VoterRepository,
} from "./types.ts";

export interface AuditEntry {
  electionId: string;
  action: string;
  subjectRef?: string;
  detail?: string;
  occurredAt: Date;
}

export class InMemoryVoterRepository implements VoterRepository {
  readonly #byId = new Map<string, VoterRecord>();
  readonly #byIdentity = new Map<string, string>();
  readonly #locks = new Map<string, Promise<unknown>>();
  readonly audit: AuditEntry[] = [];

  async findOrCreateVoter(input: FindOrCreateVoterInput): Promise<VoterRecord> {
    const key = `${input.electionId}:${toBase64Url(input.identityHash)}`;
    const existingId = this.#byIdentity.get(key);
    if (existingId) return { ...this.#byId.get(existingId)! };

    const record: VoterRecord = {
      id: globalThis.crypto.randomUUID(),
      electionId: input.electionId,
      identityHash: input.identityHash,
      kycProvider: input.kycProvider,
      kycVerifiedAt: new Date(),
      credentialIssuedAt: null,
      blindedMessageHash: null,
      blindSignature: null,
    };
    this.#byId.set(record.id, record);
    this.#byIdentity.set(key, record.id);
    return { ...record };
  }

  async findVoterById(id: string): Promise<VoterRecord | null> {
    const record = this.#byId.get(id);
    return record ? { ...record } : null;
  }

  async issueCredential(
    voterId: string,
    blindedMessageHash: Uint8Array,
    sign: () => Promise<Uint8Array>,
  ): Promise<IssueOutcome> {
    // Serialise per voter by chaining onto that voter's pending operation.
    // This is the in-memory equivalent of SELECT ... FOR UPDATE.
    const previous = this.#locks.get(voterId) ?? Promise.resolve();
    const current = previous
      .catch(() => undefined)
      .then(() => this.#issueLocked(voterId, blindedMessageHash, sign));
    this.#locks.set(voterId, current);
    try {
      return await current;
    } finally {
      if (this.#locks.get(voterId) === current) this.#locks.delete(voterId);
    }
  }

  async #issueLocked(
    voterId: string,
    blindedMessageHash: Uint8Array,
    sign: () => Promise<Uint8Array>,
  ): Promise<IssueOutcome> {
    const record = this.#byId.get(voterId);
    if (!record) throw new Error("issueCredential: voter not found");

    if (record.credentialIssuedAt !== null) {
      if (
        record.blindedMessageHash &&
        record.blindSignature &&
        constantTimeEqual(record.blindedMessageHash, blindedMessageHash)
      ) {
        return { status: "replayed", blindSignature: record.blindSignature };
      }
      return { status: "already_issued" };
    }

    // If signing throws, nothing below runs and the issuance stays unspent.
    const blindSignature = await sign();

    record.credentialIssuedAt = new Date();
    record.blindedMessageHash = blindedMessageHash;
    record.blindSignature = blindSignature;
    return { status: "issued", blindSignature };
  }

  async recordAudit(entry: {
    electionId: string;
    action: string;
    subjectRef?: string;
    detail?: string;
  }): Promise<void> {
    this.audit.push({ ...entry, occurredAt: new Date() });
  }

  async close(): Promise<void> {
    this.#byId.clear();
    this.#byIdentity.clear();
  }
}
