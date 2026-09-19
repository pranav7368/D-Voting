/**
 * Bring the whole system up locally, in one command.
 *
 * Generates every key and secret, imports a demo electoral roll, then starts
 * four validator authorities, the Registration Authority and the ballot box —
 * each as its own process, exactly as they would run in deployment.
 *
 * Usage:  node scripts/dev-up.ts [voterCount]
 *
 * ===========================================================================
 * FOR LOCAL DEVELOPMENT ONLY.
 *
 * This script generates every party's keys in one place, which is precisely
 * what a real deployment must not do: the whole point of independent trustees
 * and independent validators is that no single machine ever holds them all.
 * In production each authority generates its own key on its own hardware and
 * publishes only the public half.
 * ===========================================================================
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  MODP_2048,
  encodeElement,
  randomBytes,
  runDkg,
  toBase64Url,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
} from "@dvoting/crypto";
import { generateIssuerKeyPair, privateKeyToJwk, publicKeyToJwk } from "@dvoting/crypto/keygen";
import { exportPrivateKey, generateValidatorKeyPair } from "@dvoting/ledger";
import {
  generateEnrolmentCode,
  hashEnrolmentCode,
} from "../services/registration/src/eligibility/enrolment-code.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const localDir = join(root, ".local");

const voterCount = Number(process.argv[2] ?? 20);
const ELECTION_ID = "dvoting-local-2026";
const CANDIDATES = "Alice,Bob,Carol";
const GROUP = MODP_2048; // fast for local work; production default is modp3072
const THRESHOLD = 3;
const TRUSTEES = 5;

const VALIDATORS = ["election-commission", "observer-press", "observer-university", "observer-ngo"];
/**
 * Who holds a share of the election key.
 *
 * Chosen to look like a real custody arrangement rather than five copies of the
 * same organisation: the point of a threshold is that the parties would have to
 * conspire, and parties with the same interests are not a threshold.
 */
const TRUSTEE_LABELS = [
  "Election Commission",
  "Supreme Court observer",
  "Governing party agent",
  "Opposition party agent",
  "University observer",
];
const VALIDATOR_BASE_PORT = 8090;
const TRUSTEE_BASE_PORT = 8100;
const REGISTRATION_PORT = 8081;
const BALLOT_BOX_PORT = 8082;

const secret = () => toBase64Url(randomBytes(32));

function log(text: string): void {
  console.log(`\x1b[36m[dev-up]\x1b[0m ${text}`);
}

// --- 1. Fresh workspace -----------------------------------------------------
await rm(localDir, { recursive: true, force: true });
await mkdir(localDir, { recursive: true });
log(`workspace: ${localDir}`);

// --- 2. Shared secrets ------------------------------------------------------
const IDENTITY_PEPPER = secret();
const REGISTRATION_TOKEN_SECRET = secret();
const PROPOSE_TOKEN = secret();
const ADMIN_TOKEN = secret();
/**
 * The Registration Authority's own administration token.
 *
 * Deliberately DIFFERENT from the ballot box's. They are separate authorities:
 * one knows who may vote, the other knows what was voted. A single token for
 * both would quietly merge them back into one.
 */
const ROLL_ADMIN_TOKEN = secret();

// --- 3. Registration Authority issuer key -----------------------------------
log("generating the issuer key (RSA-2048 for speed)…");
const issuer = generateIssuerKeyPair(2048, RSABSSA_SHA384_PSS_DETERMINISTIC);

// --- 4. Trustee key generation (Pedersen DKG — no dealer) --------------------
log(`running a ${THRESHOLD}-of-${TRUSTEES} distributed key generation…`);
const dkg = runDkg(GROUP, THRESHOLD, TRUSTEES);

const publicShares = dkg.publicShares.map((s) => ({
  index: s.index,
  publicShare: toBase64Url(encodeElement(GROUP, s.publicShare)),
}));

const trustees = dkg.keyShares.map((keyShare, index) => ({
  index: keyShare.index,
  label: TRUSTEE_LABELS[index] ?? `Trustee ${keyShare.index}`,
  share: keyShare.share.toString(16),
  token: secret(),
  port: TRUSTEE_BASE_PORT + index,
}));

await writeFile(
  join(localDir, "trustees.json"),
  JSON.stringify(
    {
      group: GROUP.name,
      threshold: THRESHOLD,
      electionId: ELECTION_ID,
      publicKey: toBase64Url(encodeElement(GROUP, dkg.publicKey.y)),
      // Local only. In deployment each share stays with its trustee, on their
      // own hardware, and this file does not exist anywhere.
      keyShares: trustees.map((t) => ({ index: t.index, label: t.label, share: t.share })),
      publicShares,
    },
    null,
    2,
  ),
  { mode: 0o600 },
);

// --- 5. Validator identities ------------------------------------------------
log("generating validator keys…");
const validators = [];
for (const [index, id] of VALIDATORS.entries()) {
  const keyPair = await generateValidatorKeyPair(id);
  validators.push({
    id,
    url: `http://127.0.0.1:${VALIDATOR_BASE_PORT + index}`,
    publicKey: toBase64Url(keyPair.identity.publicKey),
    privateKey: toBase64Url(await exportPrivateKey(keyPair.privateKey)),
    port: VALIDATOR_BASE_PORT + index,
  });
}
const validatorSet = JSON.stringify({
  validators: validators.map((v) => ({ id: v.id, publicKey: v.publicKey, url: v.url })),
});

// --- 6. Demo electoral roll -------------------------------------------------
// Generated here rather than via `roll:import`, because with in-memory storage
// a separate import process cannot reach the RA's memory. Only the HMACs go to
// the service; the codes go to the polling-card file.
log(`enrolling ${voterCount} voters…`);
const rollEntries: { rollId: string; enrolmentCodeHash: string }[] = [];
const cards: string[] = ["roll_id,enrolment_code"];

for (let i = 0; i < voterCount; i++) {
  const rollId = `R-${100001 + i}`;
  const enrolmentCode = generateEnrolmentCode();
  rollEntries.push({
    rollId,
    enrolmentCodeHash: toBase64Url(await hashEnrolmentCode(IDENTITY_PEPPER, rollId, enrolmentCode)),
  });
  cards.push(`${rollId},${enrolmentCode}`);
}

const rollSeedFile = join(localDir, "roll-seed.json");
await writeFile(rollSeedFile, JSON.stringify({ entries: rollEntries }, null, 2), { mode: 0o600 });
await writeFile(join(localDir, "cards.csv"), `${cards.join("\n")}\n`, { mode: 0o600 });

// --- 7. Launch --------------------------------------------------------------
const children: { name: string; child: ChildProcess }[] = [];
let shuttingDown = false;

function start(name: string, cwd: string, args: string[], env: Record<string, string>): void {
  const child = spawn(process.execPath, args, {
    cwd: join(root, cwd),
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const prefix = `\x1b[90m[${name}]\x1b[0m`;
  child.stdout?.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString().split("\n")) if (line.trim()) console.log(`${prefix} ${line}`);
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString().split("\n")) if (line.trim()) console.log(`${prefix} ${line}`);
  });
  child.on("exit", (code) => {
    if (!shuttingDown && code !== 0) console.log(`${prefix} exited with code ${code}`);
  });

  children.push({ name, child });
}

const baseEnv = { NODE_ENV: "development", ELECTION_ID };

for (const validator of validators) {
  start(validator.id, "services/validator", ["src/server.ts"], {
    ...baseEnv,
    VALIDATOR_ID: validator.id,
    VALIDATOR_PRIVATE_KEY: validator.privateKey,
    VALIDATOR_SET: validatorSet,
    PROPOSE_TOKEN,
    CHAIN_PATH: join(localDir, `chain-${validator.id}.jsonl`),
    PORT: String(validator.port),
  });
}

// Give the validators a moment to bind before anything talks to them.
await new Promise((resolve) => setTimeout(resolve, 1500));

start("registration", "services/registration", ["src/server.ts"], {
  ...baseEnv,
  PORT: String(REGISTRATION_PORT),
  STORAGE_DRIVER: "memory",
  IDENTITY_PEPPER,
  REGISTRATION_TOKEN_SECRET,
  ISSUER_PRIVATE_KEY_JWK: JSON.stringify(privateKeyToJwk(issuer.privateKey)),
  ROLL_SEED_FILE: rollSeedFile,
  ADMIN_TOKEN: ROLL_ADMIN_TOKEN,
  // The voter's browser calls the RA directly from the ballot box's origin, so
  // the RA must allow it explicitly. Strict allow-list, never a wildcard.
  CORS_ALLOWED_ORIGINS: `http://localhost:${BALLOT_BOX_PORT},http://127.0.0.1:${BALLOT_BOX_PORT}`,
});

start("ballot-box", "services/ballot-box", ["src/server.ts"], {
  ...baseEnv,
  PORT: String(BALLOT_BOX_PORT),
  // A starting point for the draft ballot only. Once the commission opens the
  // poll, the candidates come from the chain and this value is ignored.
  CANDIDATES,
  GROUP: GROUP.name,
  ISSUER_PUBLIC_KEY_JWK: JSON.stringify(publicKeyToJwk(issuer.publicKey)),
  ELECTION_PUBLIC_KEY: toBase64Url(encodeElement(GROUP, dkg.publicKey.y)),
  TRUSTEE_PUBLIC_SHARES: JSON.stringify(publicShares),
  TRUSTEE_THRESHOLD: String(THRESHOLD),
  VALIDATOR_SET: validatorSet,
  PROPOSE_TOKEN,
  ADMIN_TOKEN,
  CHAIN_PATH: join(localDir, "chain-ballot-box.jsonl"),
  // Seal every ballot immediately so a voter can verify their tracking code the
  // moment they cast. A real deployment batches, which is why the ballot box
  // defaults to 25 -- larger blocks also widen the anonymity set within a block.
  BALLOTS_PER_BLOCK: "1",
  REGISTRATION_URL: `http://localhost:${REGISTRATION_PORT}`,
});

// Each trustee is its own process holding exactly one share. In deployment they
// would be on five machines belonging to five organisations; running them here
// proves the protocol, not the custody.
for (const trustee of trustees) {
  start(`trustee-${trustee.index}`, "services/trustee", ["src/server.ts"], {
    ...baseEnv,
    PORT: String(trustee.port),
    GROUP: GROUP.name,
    TRUSTEE_INDEX: String(trustee.index),
    TRUSTEE_LABEL: trustee.label,
    TRUSTEE_SHARE: trustee.share,
    TRUSTEE_TOKEN: trustee.token,
    BALLOT_BOX_URL: `http://localhost:${BALLOT_BOX_PORT}`,
  });
}

await new Promise((resolve) => setTimeout(resolve, 2500));

const firstCard = cards[1]!.split(",");

console.log(`
\x1b[1m  D-Voting is running\x1b[0m

  \x1b[1mThe election has NOT been opened yet.\x1b[0m Open the commission console and
  run it yourself -- composing the ballot, freezing the roll and sealing the
  election to the chain is the part that makes this an election rather than a
  demonstration.

  \x1b[1m1. Election commission\x1b[0m  http://localhost:${BALLOT_BOX_PORT}/admin
       commission token   ${ADMIN_TOKEN}
       roll token         ${ROLL_ADMIN_TOKEN}

       Set the candidates, freeze the electoral roll, then open the poll.

  \x1b[1m2. Voters\x1b[0m               http://localhost:${BALLOT_BOX_PORT}/vote
       ${voterCount} polling cards are in .local/cards.csv
       Verify a ballot    http://localhost:${BALLOT_BOX_PORT}/verify

  \x1b[1m3. Trustees\x1b[0m            (after you close the poll)
${trustees
  .map(
    (t) =>
      `       ${t.label.padEnd(24)} http://localhost:${t.port}/\n` +
      `       ${" ".repeat(24)} ${t.token}`,
  )
  .join("\n")}

       Any ${THRESHOLD} of these ${TRUSTEES} must each contribute a share before the
       result can be decrypted. The commission cannot do it for them.

  \x1b[1m4. Result\x1b[0m               http://localhost:${BALLOT_BOX_PORT}/results

  Registration API      http://localhost:${REGISTRATION_PORT}/v1/issuer
  Validators            ${validators.map((v) => v.port).join(", ")}

  Try a voter from the command line instead:

      node services/registration/src/scripts/demo-voter.ts \\
        http://localhost:${REGISTRATION_PORT} ${firstCard[0]} ${firstCard[1]}

  Secrets and chain files are in .local/ — Ctrl+C to stop everything.
`);

// --- 8. Clean shutdown ------------------------------------------------------
const shutdown = (): void => {
  if (shuttingDown) return;
  shuttingDown = true;
  log("stopping…");
  for (const { child } of children) child.kill();
  setTimeout(() => process.exit(0), 500);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
