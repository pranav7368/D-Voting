-- Freezing the electoral roll.
--
-- The roll is committed to the chain before the poll opens, and a digest of a
-- roll that can still change afterwards proves nothing. This table records the
-- moment the roll stopped changing; from then on `addEntry` refuses.
--
-- There is no unfreeze, and no row is ever deleted. An election commission that
-- needs to add a voter after the freeze must open that decision to the same
-- scrutiny as everything else on the chain -- which is the entire point.
--
-- Applied by: npm run db:migrate

CREATE TABLE IF NOT EXISTS roll_freezes (
    election_id  TEXT PRIMARY KEY REFERENCES elections (id),

    -- The commitment published on the chain, so the RA's own record of what it
    -- froze can be compared against what the election was opened with.
    commitment   TEXT,

    frozen_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES ('0003_roll_freeze')
ON CONFLICT (version) DO NOTHING;
