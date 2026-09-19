/**
 * Import an electoral roll and issue enrolment codes.
 *
 * Reads roll numbers (one per line, or the first CSV column) and writes a
 * polling-card file mapping each roll number to a freshly generated enrolment
 * code, while storing only the HMAC of each code.
 *
 * Usage:
 *   node src/scripts/import-roll.ts <roll-file> [--out cards.csv]
 *
 * ===========================================================================
 * OPERATIONAL WARNING.
 *
 * The output file contains every voter's enrolment secret. It is the one
 * artefact in this system whose disclosure would let someone else register as
 * those voters. It exists only so the codes can be printed and delivered out of
 * band (post, in person). Destroy it once the cards are produced; never keep it
 * on the server that runs the election.
 * ===========================================================================
 */

import { readFile, writeFile } from "node:fs/promises";
import pg from "pg";

import { loadConfig } from "../config.ts";
import {
  InMemoryElectoralRollStore,
  type ElectoralRollStore,
} from "../eligibility/electoral-roll.ts";
import { PostgresElectoralRollStore } from "../eligibility/postgres-roll.ts";
import { generateEnrolmentCode, hashEnrolmentCode } from "../eligibility/enrolment-code.ts";

const [rollFile, ...rest] = process.argv.slice(2);
if (!rollFile) {
  console.error("usage: import-roll.ts <roll-file> [--out cards.csv]");
  process.exit(1);
}

const outIndex = rest.indexOf("--out");
const outFile = outIndex >= 0 ? rest[outIndex + 1] : "enrolment-cards.csv";
if (!outFile) {
  console.error("--out requires a filename");
  process.exit(1);
}

const config = loadConfig();

const rollIds = (await readFile(rollFile, "utf8"))
  .split(/\r?\n/)
  .map((line) => line.split(",")[0]?.trim() ?? "")
  .filter((value) => value.length > 0 && !value.startsWith("#"));

if (rollIds.length === 0) {
  console.error(`${rollFile} contained no roll numbers`);
  process.exit(1);
}

const duplicates = rollIds.filter((id, index) => rollIds.indexOf(id) !== index);
if (duplicates.length > 0) {
  // A duplicate roll number would mean one person gets two credentials.
  console.error(`refusing to import: duplicate roll numbers (${[...new Set(duplicates)].join(", ")})`);
  process.exit(1);
}

let pool: pg.Pool | undefined;
let store: ElectoralRollStore;
if (config.STORAGE_DRIVER === "postgres") {
  pool = new pg.Pool({ connectionString: config.DATABASE_URL!, max: 4 });
  store = new PostgresElectoralRollStore(pool);
} else {
  console.warn("[import-roll] STORAGE_DRIVER=memory: this import will not persist");
  store = new InMemoryElectoralRollStore();
}

const cards: string[] = ["roll_id,enrolment_code"];
let imported = 0;

try {
  for (const rollId of rollIds) {
    const code = generateEnrolmentCode();
    const enrolmentCodeHash = await hashEnrolmentCode(config.IDENTITY_PEPPER, rollId, code);
    await store.addEntry({ rollId, electionId: config.ELECTION_ID, enrolmentCodeHash });
    cards.push(`${escapeCsv(rollId)},${code}`);
    imported++;
  }

  await writeFile(outFile, `${cards.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });

  console.log(`Imported ${imported} roll entries for election "${config.ELECTION_ID}".`);
  console.log(`Total entries on the roll: ${await store.countEntries(config.ELECTION_ID)}`);
  console.log(`
Enrolment codes written to ${outFile} (mode 0600).

  This file contains every voter's secret. Print the cards, deliver them out of
  band, then DESTROY it. Only the HMAC of each code is stored in the database,
  so codes cannot be recovered from a backup -- which also means a lost card
  must be re-issued, not looked up.
`);
} catch (error) {
  console.error(
    `import failed after ${imported} entries:`,
    error instanceof Error ? error.message : error,
  );
  process.exitCode = 1;
} finally {
  await pool?.end();
}

function escapeCsv(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
