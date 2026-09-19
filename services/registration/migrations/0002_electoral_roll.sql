-- Electoral roll: the built-in source of voter eligibility.
--
-- Replaces the external KYC dependency. The roll is produced by whatever
-- statutory process governs the electorate; D-Voting's job is to authenticate
-- against it, not to decide who belongs on it.
--
-- Applied by: npm run db:migrate

CREATE TABLE IF NOT EXISTS roll_entries (
    election_id         TEXT NOT NULL REFERENCES elections (id),

    -- The voter's roll number, as printed on their polling card. Not secret:
    -- an electoral roll is typically a public document.
    roll_id             TEXT NOT NULL,

    -- HMAC(pepper, "dvoting/enrolment-code/v1" || roll_id || code).
    -- The code itself is never stored, and binding the roll id into the HMAC
    -- stops a code lifted from one polling card being replayed against another.
    enrolment_code_hash BYTEA NOT NULL,

    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at          TIMESTAMPTZ,

    PRIMARY KEY (election_id, roll_id)
);

-- Lookups are always (election, roll id); the primary key already serves them.
CREATE INDEX IF NOT EXISTS roll_entries_election_idx ON roll_entries (election_id);

INSERT INTO schema_migrations (version) VALUES ('0002_electoral_roll')
ON CONFLICT (version) DO NOTHING;
