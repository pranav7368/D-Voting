/**
 * PostgreSQL-backed electoral roll.
 *
 * Deliberately thin: all the security-relevant logic (constant-time comparison,
 * equal work on a miss, coarse failure reasons) lives in ElectoralRollVerifier,
 * so swapping storage cannot weaken it.
 */

import pg from "pg";

import { RollFrozenError, type ElectoralRollStore, type RollEntry } from "./electoral-roll.ts";

interface Row {
  election_id: string;
  roll_id: string;
  enrolment_code_hash: Buffer;
  revoked_at: Date | null;
}

export class PostgresElectoralRollStore implements ElectoralRollStore {
  readonly #pool: pg.Pool;

  constructor(pool: pg.Pool) {
    this.#pool = pool;
  }

  async findEntry(electionId: string, rollId: string): Promise<RollEntry | null> {
    const result = await this.#pool.query<Row>(
      `SELECT election_id, roll_id, enrolment_code_hash, revoked_at
         FROM roll_entries
        WHERE election_id = $1 AND roll_id = $2`,
      [electionId, rollId],
    );

    const row = result.rows[0];
    if (!row) return null;
    return {
      electionId: row.election_id,
      rollId: row.roll_id,
      enrolmentCodeHash: new Uint8Array(row.enrolment_code_hash),
      revokedAt: row.revoked_at,
    };
  }

  async addEntry(entry: Omit<RollEntry, "revokedAt">): Promise<void> {
    if (await this.isFrozen(entry.electionId)) {
      throw new RollFrozenError("the electoral roll is frozen and cannot be added to");
    }
    // No ON CONFLICT DO UPDATE: silently overwriting an entry would silently
    // reissue a voter's enrolment code, invalidating the polling card already
    // in the post. A duplicate is an error the operator must resolve.
    await this.#pool.query(
      `INSERT INTO roll_entries (election_id, roll_id, enrolment_code_hash)
       VALUES ($1, $2, $3)`,
      [entry.electionId, entry.rollId, Buffer.from(entry.enrolmentCodeHash)],
    );
  }

  async revokeEntry(electionId: string, rollId: string): Promise<boolean> {
    const result = await this.#pool.query(
      `UPDATE roll_entries SET revoked_at = now()
        WHERE election_id = $1 AND roll_id = $2 AND revoked_at IS NULL`,
      [electionId, rollId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async countEntries(electionId: string): Promise<number> {
    const result = await this.#pool.query<{ count: string }>(
      `SELECT count(*)::text AS count FROM roll_entries WHERE election_id = $1`,
      [electionId],
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async listRollIds(electionId: string): Promise<string[]> {
    // Ordered in SQL as well as in the commitment helper: the digest must not
    // depend on the database's physical row order.
    const result = await this.#pool.query<{ roll_id: string }>(
      `SELECT roll_id FROM roll_entries WHERE election_id = $1 ORDER BY roll_id`,
      [electionId],
    );
    return result.rows.map((row) => row.roll_id);
  }

  async freeze(electionId: string): Promise<void> {
    // Idempotent, and the first freeze wins: re-freezing must not move the
    // recorded moment the roll stopped changing.
    await this.#pool.query(
      `INSERT INTO roll_freezes (election_id) VALUES ($1)
       ON CONFLICT (election_id) DO NOTHING`,
      [electionId],
    );
  }

  async isFrozen(electionId: string): Promise<boolean> {
    const result = await this.#pool.query(
      `SELECT 1 FROM roll_freezes WHERE election_id = $1`,
      [electionId],
    );
    return (result.rowCount ?? 0) > 0;
  }
}
