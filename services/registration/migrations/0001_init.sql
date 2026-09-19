-- Registration Authority schema, v1.
--
-- Hand-written rather than generated: this is election infrastructure, and the
-- DDL that a reviewer audits should be exactly the DDL that runs. Keep this file
-- in sync with src/db/schema.ts (which provides the typed query layer).
--
-- Applied by: npm run db:migrate

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- gen_random_uuid() lives in pgcrypto on PostgreSQL < 13; built in from 13 on.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS elections (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'setup'
                            CHECK (status IN ('setup', 'registration', 'voting', 'tallying', 'closed')),
    registration_opens_at   TIMESTAMPTZ,
    registration_closes_at  TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Public issuer key material only. The PRIVATE key is deliberately absent:
-- it belongs in KMS/HSM, so that a database compromise cannot mint credentials.
CREATE TABLE IF NOT EXISTS issuer_keys (
    key_id          TEXT PRIMARY KEY,
    election_id     TEXT NOT NULL REFERENCES elections (id),
    suite           TEXT NOT NULL,
    modulus_bits    INTEGER NOT NULL,
    public_key_jwk  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS issuer_keys_election_idx ON issuer_keys (election_id);

CREATE TABLE IF NOT EXISTS voters (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id           TEXT NOT NULL REFERENCES elections (id),

    -- HMAC(pepper, electionId || subjectId). Never the raw national ID.
    identity_hash         BYTEA NOT NULL,

    kyc_provider          TEXT NOT NULL,
    kyc_verified_at       TIMESTAMPTZ NOT NULL,

    -- Non-null means this voter has spent their single issuance.
    credential_issued_at  TIMESTAMPTZ,

    -- SHA-256 of the blinded message, kept so an identical retry can be served
    -- idempotently while a different one is refused. Unlinkable to any ballot.
    blinded_message_hash  BYTEA,
    blind_signature       BYTEA,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- If a credential was issued, we must have recorded what we signed.
    -- Without this the idempotent-retry check could be silently bypassed.
    CONSTRAINT voters_issued_implies_recorded CHECK (
        credential_issued_at IS NULL
        OR (blinded_message_hash IS NOT NULL AND blind_signature IS NOT NULL)
    )
);

-- The one-person-one-credential guarantee, enforced by the database itself
-- rather than trusted to application logic.
CREATE UNIQUE INDEX IF NOT EXISTS voters_election_identity_idx
    ON voters (election_id, identity_hash);

CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    election_id  TEXT NOT NULL,
    action       TEXT NOT NULL,
    subject_ref  TEXT,
    detail       TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_election_time_idx ON audit_log (election_id, occurred_at);

-- The audit log is append-only. Revoking UPDATE/DELETE at the schema level means
-- a compromised application credential cannot rewrite the record of what it did.
-- Grant this to the application role in deployment:
--   REVOKE UPDATE, DELETE ON audit_log FROM dvoting_app;

INSERT INTO schema_migrations (version) VALUES ('0001_init')
ON CONFLICT (version) DO NOTHING;
