/**
 * Drizzle schema for the Registration Authority.
 *
 * WHAT IS DELIBERATELY ABSENT FROM THIS SCHEMA:
 *   - the voter's national ID / name / address (only a keyed hash is stored)
 *   - the unblinded credential
 *   - the final (unblinded) signature
 *   - anything at all about how anyone voted
 *
 * The RA's job ends at "this verified human received exactly one credential".
 * It must not be able to answer "which credential" -- so it never sees one.
 */

import { relations, sql } from "drizzle-orm";
import {
  customType,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

/** Postgres BYTEA <-> Uint8Array. */
const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
  toDriver(value) {
    return Buffer.from(value);
  },
  fromDriver(value) {
    return new Uint8Array(value);
  },
});

export const elections = pgTable("elections", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  status: text("status", { enum: ["setup", "registration", "voting", "tallying", "closed"] })
    .notNull()
    .default("setup"),
  registrationOpensAt: timestamp("registration_opens_at", { withTimezone: true }),
  registrationClosesAt: timestamp("registration_closes_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

/**
 * Public half of the issuer key, per election.
 *
 * The PRIVATE key is deliberately not a column here. It lives in the secrets
 * manager / KMS. A database compromise must not yield the power to mint voting
 * credentials.
 *
 * Publishing the public key with a stable `keyId` is what defends against the
 * key-substitution attack described in @dvoting/crypto's issuer.ts: every voter
 * must be able to confirm they were handed the same issuer key as everyone else.
 */
export const issuerKeys = pgTable(
  "issuer_keys",
  {
    keyId: text("key_id").primaryKey(),
    electionId: text("election_id")
      .notNull()
      .references(() => elections.id),
    suite: text("suite").notNull(),
    modulusBits: integer("modulus_bits").notNull(),
    publicKeyJwk: text("public_key_jwk").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
  },
  (table) => [index("issuer_keys_election_idx").on(table.electionId)],
);

export const voters = pgTable(
  "voters",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    electionId: text("election_id")
      .notNull()
      .references(() => elections.id),

    /** HMAC(pepper, electionId || subjectId). Never the raw identifier. */
    identityHash: bytea("identity_hash").notNull(),

    kycProvider: text("kyc_provider").notNull(),
    kycVerifiedAt: timestamp("kyc_verified_at", { withTimezone: true }).notNull(),

    /** Non-null means this voter has spent their single issuance. */
    credentialIssuedAt: timestamp("credential_issued_at", { withTimezone: true }),

    /**
     * SHA-256 of the blinded message we signed.
     *
     * Storing this is safe: the blinded message is statistically independent of
     * the credential, so it cannot be used to link a voter to a ballot even by
     * an adversary with unbounded compute. It exists so that a retry with the
     * IDENTICAL blinded message can be served idempotently, while a retry with
     * a DIFFERENT one is refused -- that distinction is what stops a voter from
     * harvesting two valid credentials by crashing mid-issuance.
     */
    blindedMessageHash: bytea("blinded_message_hash"),

    /** The blind signature we returned, kept solely to serve idempotent retries. */
    blindSignature: bytea("blind_signature"),

    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    // The one-person-one-credential guarantee starts here: the database itself
    // refuses a second registration for the same human in the same election,
    // regardless of what the application layer does.
    uniqueIndex("voters_election_identity_idx").on(table.electionId, table.identityHash),
  ],
);

/**
 * Append-only administrative audit log.
 *
 * Kept structurally separate from vote data, and it records only *that* an
 * action happened, never any value that could deanonymise a voter.
 */
export const auditLog = pgTable(
  "audit_log",
  {
    id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
    electionId: text("election_id").notNull(),
    action: text("action").notNull(),
    subjectRef: text("subject_ref"),
    detail: text("detail"),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("audit_log_election_time_idx").on(table.electionId, table.occurredAt)],
);

export const electionsRelations = relations(elections, ({ many }) => ({
  voters: many(voters),
  issuerKeys: many(issuerKeys),
}));

export const votersRelations = relations(voters, ({ one }) => ({
  election: one(elections, { fields: [voters.electionId], references: [elections.id] }),
}));
