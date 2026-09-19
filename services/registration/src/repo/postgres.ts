/**
 * PostgreSQL implementation of the voter repository.
 *
 * The interesting part is `issueCredential`, which is where the
 * one-person-one-credential invariant is actually enforced.
 */

import { and, eq, isNull, sql } from "drizzle-orm";
import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { constantTimeEqual } from "@dvoting/crypto";
import pg from "pg";

import { auditLog, voters } from "../db/schema.ts";
import type {
  FindOrCreateVoterInput,
  IssueOutcome,
  VoterRecord,
  VoterRepository,
} from "./types.ts";

type Row = typeof voters.$inferSelect;

function toRecord(row: Row): VoterRecord {
  return {
    id: row.id,
    electionId: row.electionId,
    identityHash: row.identityHash,
    kycProvider: row.kycProvider,
    kycVerifiedAt: row.kycVerifiedAt,
    credentialIssuedAt: row.credentialIssuedAt,
    blindedMessageHash: row.blindedMessageHash,
    blindSignature: row.blindSignature,
  };
}

export class PostgresVoterRepository implements VoterRepository {
  readonly #pool: pg.Pool;
  readonly #db: NodePgDatabase;

  constructor(connectionString: string) {
    this.#pool = new pg.Pool({ connectionString, max: 10 });
    this.#db = drizzle(this.#pool);
  }

  async findOrCreateVoter(input: FindOrCreateVoterInput): Promise<VoterRecord> {
    // ON CONFLICT DO UPDATE (rather than DO NOTHING) so the statement always
    // returns the row, making this a single round trip and race-free against a
    // concurrent registration of the same identity.
    const [row] = await this.#db
      .insert(voters)
      .values({
        electionId: input.electionId,
        identityHash: input.identityHash,
        kycProvider: input.kycProvider,
        kycVerifiedAt: new Date(),
      })
      .onConflictDoUpdate({
        target: [voters.electionId, voters.identityHash],
        set: { updatedAt: new Date() },
      })
      .returning();

    if (!row) throw new Error("findOrCreateVoter: insert returned no row");
    return toRecord(row);
  }

  async findVoterById(id: string): Promise<VoterRecord | null> {
    const [row] = await this.#db.select().from(voters).where(eq(voters.id, id)).limit(1);
    return row ? toRecord(row) : null;
  }

  async issueCredential(
    voterId: string,
    blindedMessageHash: Uint8Array,
    sign: () => Promise<Uint8Array>,
  ): Promise<IssueOutcome> {
    return this.#db.transaction(async (tx) => {
      // SELECT ... FOR UPDATE serialises concurrent issuance attempts for this
      // voter. Two simultaneous requests cannot both observe "not yet issued".
      const [locked] = await tx
        .select()
        .from(voters)
        .where(eq(voters.id, voterId))
        .for("update")
        .limit(1);

      if (!locked) throw new Error("issueCredential: voter not found");

      if (locked.credentialIssuedAt !== null) {
        // Already spent. The only acceptable follow-up is an exact retry of the
        // same blinded message, which we answer from storage.
        if (
          locked.blindedMessageHash &&
          locked.blindSignature &&
          constantTimeEqual(locked.blindedMessageHash, blindedMessageHash)
        ) {
          return { status: "replayed", blindSignature: locked.blindSignature } satisfies IssueOutcome;
        }
        return { status: "already_issued" } satisfies IssueOutcome;
      }

      // Sign inside the transaction. If this throws, the transaction rolls back
      // and the voter keeps their unspent issuance -- no disenfranchisement.
      const blindSignature = await sign();

      const updated = await tx
        .update(voters)
        .set({
          credentialIssuedAt: new Date(),
          blindedMessageHash,
          blindSignature,
          updatedAt: new Date(),
        })
        .where(and(eq(voters.id, voterId), isNull(voters.credentialIssuedAt)))
        .returning({ id: voters.id });

      // Belt and braces: the row lock should make this impossible, but if the
      // guard ever did fail we must not hand out a second signature.
      if (updated.length !== 1) {
        throw new Error("issueCredential: concurrent issuance detected, rolling back");
      }

      return { status: "issued", blindSignature } satisfies IssueOutcome;
    });
  }

  async recordAudit(entry: {
    electionId: string;
    action: string;
    subjectRef?: string;
    detail?: string;
  }): Promise<void> {
    await this.#db.insert(auditLog).values({
      electionId: entry.electionId,
      action: entry.action,
      subjectRef: entry.subjectRef ?? null,
      detail: entry.detail ?? null,
    });
  }

  async ping(): Promise<void> {
    await this.#db.execute(sql`select 1`);
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}
