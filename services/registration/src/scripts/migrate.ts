/**
 * Apply pending SQL migrations.
 *
 * Deliberately tiny: it reads .sql files from ../migrations in lexical order and
 * runs each one inside a transaction, skipping any version already recorded in
 * schema_migrations. No migration framework, no code generation -- the SQL that
 * gets reviewed is the SQL that runs.
 *
 * Usage:  DATABASE_URL=postgres://... npm run db:migrate
 */

import { readFile, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString, max: 1 });

try {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version    TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);

  const applied = new Set(
    (await pool.query<{ version: string }>("SELECT version FROM schema_migrations")).rows.map(
      (row) => row.version,
    ),
  );

  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith(".sql")).sort();

  let ran = 0;
  for (const file of files) {
    const version = file.replace(/\.sql$/, "");
    if (applied.has(version)) {
      console.log(`  = ${version} (already applied)`);
      continue;
    }

    const sql = await readFile(join(migrationsDir, file), "utf8");
    const client = await pool.connect();
    try {
      // One transaction per migration: a failure leaves the schema untouched
      // rather than half-migrated.
      await client.query("BEGIN");
      await client.query(sql);
      await client.query("INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING", [
        version,
      ]);
      await client.query("COMMIT");
      console.log(`  + ${version} applied`);
      ran++;
    } catch (error) {
      await client.query("ROLLBACK");
      throw new Error(
        `migration ${version} failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      client.release();
    }
  }

  console.log(ran === 0 ? "Schema is up to date." : `Applied ${ran} migration(s).`);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
} finally {
  await pool.end();
}
