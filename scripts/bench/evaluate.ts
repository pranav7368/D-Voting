/**
 * Evaluation harness for the paper: measured, not assumed.
 *
 *   node scripts/bench/evaluate.ts            # full run (~10 min on a laptop)
 *   node scripts/bench/evaluate.ts --quick    # smoke run (~1 min)
 *
 * Writes docs/evaluation/results.json and docs/evaluation/results.md.
 *
 * Everything runs in ONE Node process on ONE core, through the real code
 * paths: the ballot box, four independent validator nodes (each re-verifying
 * every ballot), three witnesses, the second-device checks a phone runs, and
 * the standalone verifier. Network latency is deliberately excluded so the
 * numbers measure computation; a deployment adds round trips on top.
 */

import { execSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { cpus, platform, release, totalmem } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  MODP_2048,
  MODP_3072,
  auditAgainstCommitment,
  createDiscreteLogTable,
  decryptTally,
  partialDecrypt,
  prepareBallot,
  setupTrustees,
  toBase64Url,
  verifyBallot,
  type ElectionParameters,
  type PartialDecryption,
  type PrimeOrderGroup,
} from "@dvoting/crypto";
import {
  InMemoryBlockStore,
  blockHash,
  checkpointToWire,
  encodeHeader,
  generateValidatorKeyPair,
  signCheckpoint,
} from "@dvoting/ledger";
import { createApp } from "@dvoting/ballot-box/src/app.ts";
import { tallyFromChain } from "@dvoting/ballot-box/src/chain-tally.ts";
import { buildPublishedTally, encodeTally } from "@dvoting/ballot-box/src/tally-publication.ts";
import { ELECTION, GROUP, createHarness, makeVoter } from "@dvoting/ballot-box/test/helpers.ts";
// @ts-expect-error -- plain JS modules shipped to browsers
import * as checkLib from "@dvoting/ballot-box/public/check-lib.js";
// @ts-expect-error -- plain JS modules shipped to browsers
import * as verifyLib from "@dvoting/ballot-box/public/verify-lib.js";
import { Witness } from "@dvoting/witness/src/witness.ts";
import { toExport, verifyElection } from "@dvoting/verifier";

const quick = process.argv.includes("--quick");
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// --- statistics ---------------------------------------------------------------

interface Stat { n: number; mean: number; median: number; p95: number; min: number; max: number; sd: number }

function stat(samples: number[]): Stat {
  const s = [...samples].sort((a, b) => a - b);
  const n = s.length;
  const mean = s.reduce((a, b) => a + b, 0) / n;
  const pick = (q: number) => s[Math.min(n - 1, Math.ceil(q * n) - 1)]!;
  const sd = Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(1, n - 1));
  return { n, mean, median: pick(0.5), p95: pick(0.95), min: s[0]!, max: s[n - 1]!, sd };
}

async function measure(n: number, fn: () => Promise<unknown> | unknown): Promise<Stat> {
  await fn(); // warm-up, not recorded
  const samples: number[] = [];
  for (let i = 0; i < n; i++) {
    const t = performance.now();
    await fn();
    samples.push(performance.now() - t);
  }
  return stat(samples);
}

const results: Record<string, unknown> = {};
const rows: { section: string; metric: string; stat?: Stat; value?: string }[] = [];
const ms = (x: number) => (x >= 100 ? x.toFixed(0) : x >= 10 ? x.toFixed(1) : x.toFixed(2));
function record(section: string, metric: string, s: Stat) {
  rows.push({ section, metric, stat: s });
  results[`${section} / ${metric}`] = s;
  console.log(`  ${metric.padEnd(58)} median ${ms(s.median).padStart(7)} ms   p95 ${ms(s.p95).padStart(7)} ms   (n=${s.n})`);
}
function note(section: string, metric: string, value: string, raw?: unknown) {
  rows.push({ section, metric, value });
  results[`${section} / ${metric}`] = raw ?? value;
  console.log(`  ${metric.padEnd(58)} ${value}`);
}

// --- environment --------------------------------------------------------------

const commit = (() => {
  try { return execSync("git rev-parse --short HEAD", { cwd: root }).toString().trim(); } catch { return "unknown"; }
})();
const env = {
  date: new Date().toISOString(),
  commit,
  cpu: cpus()[0]?.model ?? "unknown",
  logicalCores: cpus().length,
  memoryGB: Math.round(totalmem() / 1e9),
  node: process.version,
  os: `${platform()} ${release()}`,
  mode: quick ? "quick" : "full",
  note: "single process, single core, no network latency",
};
results.environment = env;
console.log(`\nD-Voting evaluation (${env.mode}) on ${env.cpu}, ${env.node}, commit ${commit}\n`);

// --- 1. the voter's device ----------------------------------------------------

async function deviceCosts(group: PrimeOrderGroup, candidates: number, n: number) {
  const trustees = setupTrustees(group, 3, 5);
  const election: ElectionParameters = {
    electionId: "bench",
    candidates: Array.from({ length: candidates }, (_, i) => `C${i}`),
    minSelections: 1,
    maxSelections: 1,
  };
  const selection = election.candidates.map((_, i) => (i === 0 ? 1 : 0));
  const section = `Device, ${group.name}, ${candidates} candidates`;
  console.log(section);
  let prepared = await prepareBallot(election, trustees.publicKey, selection);
  record(section, "Prepare ballot (encrypt + proofs + commitment)", await measure(n, async () => {
    prepared = await prepareBallot(election, trustees.publicKey, selection);
  }));
  record(section, "Verify ballot proofs (any observer, per ballot)", await measure(n, () =>
    verifyBallot(election, trustees.publicKey, prepared.ballot)));
  record(section, "Second-device audit of a tested ballot", await measure(n, () =>
    auditAgainstCommitment(election, trustees.publicKey, prepared.ballot, prepared.secret, prepared.commitment)));
}

await deviceCosts(MODP_2048, 4, quick ? 3 : 10);
await deviceCosts(MODP_2048, 8, quick ? 2 : 5);
await deviceCosts(MODP_3072, 4, quick ? 2 : 5);

// --- 2. the running system ----------------------------------------------------

const N = quick ? 6 : 40;
console.log(`\nSystem, ${GROUP.name}, ${ELECTION.candidates.length} candidates, 4 validators, 3 witnesses, ${N} ballots`);
const witnessKeys = await Promise.all(["agent-a", "agent-b", "observer"].map((id) => generateValidatorKeyPair(id)));
const roster = {
  quorum: 2,
  witnesses: witnessKeys.map((k) => ({ id: k.identity.id, publicKey: toBase64Url(k.identity.publicKey), url: `http://${k.identity.id}.test` })),
};
const harness = await createHarness({ witnesses: roster, verifyingValidators: true });
const app = createApp({ ballotBox: harness.ballotBox });
const boxFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input), "http://box.test");
  return app.request(url.pathname + url.search);
}) as typeof fetch;
const witnesses = await Promise.all(witnessKeys.map(async (k) => {
  const store = new InMemoryBlockStore();
  const witness = await Witness.open({
    id: k.identity.id, privateKey: k.privateKey, electionId: ELECTION.electionId,
    ballotBoxUrl: "http://box.test", store, fetchImpl: boxFetch,
  });
  return { id: k.identity.id, witness };
}));
await Promise.all(witnesses.map((w) => w.witness.sync()));
const deviceFetch = (async (input: string | URL | Request) => {
  const url = new URL(String(input), "http://box.test");
  const w = witnesses.find((x) => url.host === `${x.id}.test`);
  if (w) {
    const latest = w.witness.latest;
    return Response.json({ checkpoint: latest ? checkpointToWire(latest) : null, alarm: null });
  }
  return app.request(url.pathname + url.search);
}) as typeof fetch;

const castMs: number[] = [];
const sealMs: number[] = [];
const syncMs: number[] = [];
const cast: { ballotId: string; commitment: string }[] = [];
for (let i = 0; i < N; i++) {
  const voter = await makeVoter();
  const choice = [0, 0, 0];
  choice[i % 3] = 1;
  const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, choice, { credentialFingerprint: voter.fingerprint });
  let t = performance.now();
  await harness.ballotBox.cast({ credential: voter.credential, credentialSignature: voter.signature, ballot: prepared.ballot });
  castMs.push(performance.now() - t);
  t = performance.now();
  await harness.ballotBox.sealBlock();
  sealMs.push(performance.now() - t);
  t = performance.now();
  await witnesses[0]!.witness.sync();
  syncMs.push(performance.now() - t);
  await Promise.all(witnesses.slice(1).map((w) => w.witness.sync()));
  cast.push({ ballotId: prepared.ballot.ballotId, commitment: prepared.commitment });
}
const sys = "System";
record(sys, "Ballot box admission (credential + proofs + duplicate checks)", stat(castMs));
// Each validator re-verifies the ballot against its own replica before
// signing (ballot-box/src/entry-validator.ts); here they run in one process,
// one after another. Deployed on separate machines they run in parallel.
record(sys, "Seal one block: 4 validators each re-verify the ballot and sign", stat(sealMs));
record(sys, "Witness: fetch, validate and countersign one new block", stat(syncMs));

// tested ballots, for the phone's tested-ballot check
const tested: { ballotId: string; commitment: string }[] = [];
for (let i = 0; i < Math.max(2, Math.floor(N / 8)); i++) {
  const voter = await makeVoter();
  const prepared = await prepareBallot(ELECTION, harness.trustees.publicKey, [1, 0, 0], { credentialFingerprint: voter.fingerprint });
  await harness.ballotBox.spoil({ ballot: prepared.ballot, auditSecret: prepared.secret });
  tested.push({ ballotId: prepared.ballot.ballotId, commitment: prepared.commitment });
}
await harness.ballotBox.sealBlock();
await Promise.all(witnesses.map((w) => w.witness.sync()));

const election = await (await app.request("/v1/election")).json();
const receipts = await Promise.all(cast.map(async (c) => (await app.request(`/v1/bulletin/ballots/${c.ballotId}`)).json()));
const auditReceipts = await Promise.all(tested.map(async (c) => (await app.request(`/v1/bulletin/audits/${c.ballotId}`)).json()));

const phone = "Phone (second device)";
console.log(phone);
let k = 0;
record(phone, "Check a cast ballot (inclusion + quorum + commitment)", await measure(Math.min(N, 20), () => {
  const i = k++ % cast.length;
  return checkLib.checkCast(receipts[i], election, { electionId: ELECTION.electionId, ...cast[i]! });
}));
k = 0;
record(phone, "Check a tested ballot (re-run the audit from public data)", await measure(tested.length, () => {
  const i = k++ % tested.length;
  return checkLib.checkTested(auditReceipts[i], election, { electionId: ELECTION.electionId, ...tested[i]! });
}));
k = 0;
record(phone, "Witness confirmation (3 checkpoints, headers to head)", await measure(Math.min(N, 20), () =>
  verifyLib.gatherWitnessEvidence(receipts[k++ % receipts.length], { fetchImpl: deviceFetch })));

// sizes
const sizes = "Sizes";
console.log(sizes);
const ballotEntryBytes = (await harness.ledger.blocks()).flatMap((b) => b.entries).filter((e) => e.kind === "ballot").map((e) => e.data.length);
note(sizes, "Ballot on the board (JSON, mean)", `${Math.round(ballotEntryBytes.reduce((a, b) => a + b, 0) / ballotEntryBytes.length)} bytes`, ballotEntryBytes);
note(sizes, "Inclusion receipt fetched by a device", `${JSON.stringify(receipts[0]).length} bytes`);
note(sizes, "Witness checkpoint", `${JSON.stringify(checkpointToWire(witnesses[0]!.witness.latest!)).length} bytes`);
note(sizes, "QR link (check page)", `${checkLib.checkLink("https://vote.example.in", { electionId: ELECTION.electionId, ...cast[0]! }).length} characters`);
note(sizes, "Block header (canonical)", `${encodeHeader((await harness.ledger.getBlock(1))!.header).length} bytes`);

// --- 3. tally, publication and a full independent audit ------------------------

await harness.ballotBox.closePoll();
const input = await tallyFromChain(harness.ledger, ELECTION, harness.trustees.publicKey);
const partialsByCandidate: PartialDecryption[][] = [];
const tallySection = "Tally";
console.log(tallySection);
const tPartial = performance.now();
for (const total of input.encryptedTotals) {
  const partials: PartialDecryption[] = [];
  for (const share of harness.trustees.keyShares.slice(0, harness.trustees.threshold)) {
    partials.push(await partialDecrypt(GROUP, ELECTION.electionId, share, total));
  }
  partialsByCandidate.push(partials);
}
note(tallySection, `Trustee partial decryptions (3 trustees x ${ELECTION.candidates.length} totals)`, `${ms(performance.now() - tPartial)} ms`);
const decrypted = await decryptTally(GROUP, ELECTION.electionId, ELECTION.candidates, input.encryptedTotals, partialsByCandidate, harness.trustees.publicShares, harness.trustees.threshold, input.counted.length);
await harness.ballotBox.publishTally({
  encode: () => encodeTally(buildPublishedTally({
    election: ELECTION, publicKey: harness.trustees.publicKey, threshold: harness.trustees.threshold,
    countedBallotIds: input.counted.map((c) => c.ballot.ballotId), supersededBallotIds: input.superseded.map((c) => c.ballot.ballotId),
    encryptedTotals: input.encryptedTotals, partialsByCandidate, publicShares: harness.trustees.publicShares, results: decrypted.results,
  })),
});
const dlogN = quick ? 10_000 : 100_000;
const tDlog = performance.now();
createDiscreteLogTable(GROUP, dlogN);
note(tallySection, `Discrete-log table for up to ${dlogN.toLocaleString("en-US")} votes per candidate`, `${ms(performance.now() - tDlog)} ms`);

const blocks = [...(await harness.ledger.blocks())];
const checkpoints = witnesses.map((w) => w.witness.latest!);
await Promise.all(witnesses.map((w) => w.witness.sync()));
const auditSection = "Independent audit";
console.log(auditSection);
let report: Awaited<ReturnType<typeof verifyElection>> | null = null;
const auditStat = await measure(quick ? 1 : 2, async () => {
  report = await verifyElection(blocks, { checkpoints: witnesses.map((w) => w.witness.latest!) });
});
record(auditSection, `dvoting-verify on the full board (${N} ballots, recount + witnesses)`, auditStat);
note(auditSection, "Audit verdict", report!.valid ? "VERIFIED" : `FAILED: ${JSON.stringify(report!.checks.filter((c) => !c.ok))}`);
note(auditSection, "Audit cost per ballot", `${ms(auditStat.median / N)} ms`);
const exportBytes = JSON.stringify(toExport(blocks, null)).length;
note(auditSection, "Exported board size per ballot", `${Math.round(exportBytes / N)} bytes`);
void checkpoints;

// --- 4. witness check vs. how far the head is from the voter's block -----------

const chainSection = "Witness check vs. chain length";
console.log(chainSection);
for (const L of quick ? [10, 100] : [10, 100, 1000, 5000]) {
  const headers: Record<string, unknown>[] = [];
  let previous = toBase64Url(new Uint8Array(32));
  for (let h = 0; h < L; h++) {
    const header = {
      height: h, electionId: "bench", previousHash: previous, merkleRoot: toBase64Url(new Uint8Array(32).fill(h % 251)),
      entryCount: 1, timestamp: 1_760_000_000_000 + h, proposer: "v1", view: 0,
    };
    previous = toBase64Url(await verifyLib.blockHash(header));
    headers.push(header);
  }
  const genesisHash = await verifyLib.blockHash(headers[0]);
  const keys = await Promise.all(["a", "b", "c"].map((id) => generateValidatorKeyPair(id)));
  const synthRoster = { quorum: 2, witnesses: keys.map((kp) => ({ id: kp.identity.id, publicKey: toBase64Url(kp.identity.publicKey), url: "x" })) };
  const responses = await Promise.all(keys.map(async (kp) => ({
    witness: kp.identity.id,
    body: {
      alarm: null,
      checkpoint: checkpointToWire(await signCheckpoint({
        electionId: "bench", height: L, headHash: Uint8Array.from(Buffer.from(previous, "base64url")),
        genesisHash, witnessedAt: new Date().toISOString(),
      }, kp.identity.id, kp.privateKey)),
    },
  })));
  const s = await measure(quick ? 2 : 5, () => verifyLib.verifyWitnessed({
    blockHeight: 0, blockHeader: headers[0], genesisHeader: headers[0], roster: synthRoster, responses, headers,
  }));
  record(chainSection, `Ballot ${L - 1} blocks below the witnessed head`, s);
}

// --- 5. scaling, from measured per-ballot costs --------------------------------

const perBallotAudit = auditStat.median / N;
const perBallotIngest = stat(castMs).median + stat(sealMs).median; // one ballot per block, worst case
const perBallotBytes = exportBytes / N;
const scaling = [1_000, 10_000, 100_000].map((n) => ({
  ballots: n,
  auditSingleCoreMin: (perBallotAudit * n) / 60_000,
  auditAllCoresMin: (perBallotAudit * n) / 60_000 / env.logicalCores,
  boardMB: (perBallotBytes * n) / 1e6,
  ingestOneBallotPerBlockHours: (perBallotIngest * n) / 3_600_000,
}));
results.scaling = { method: "linear extrapolation from measured per-ballot medians; audit parallelises across ballots", perBallotAudit, perBallotIngest, perBallotBytes, rows: scaling };
console.log("\nScaling (extrapolated from measured per-ballot costs)");
for (const r of scaling) {
  console.log(`  ${r.ballots.toLocaleString("en-US").padStart(8)} ballots: audit ${r.auditSingleCoreMin.toFixed(1)} min on 1 core, ${r.auditAllCoresMin.toFixed(1)} min on ${env.logicalCores}; board ${r.boardMB.toFixed(0)} MB`);
}

// --- write ----------------------------------------------------------------------

const outDir = join(root, "docs", "evaluation");
await mkdir(outDir, { recursive: true });
await writeFile(join(outDir, quick ? "results-quick.json" : "results.json"), `${JSON.stringify(results, null, 2)}\n`);

const md: string[] = [];
md.push(`# Evaluation results${quick ? " (quick run)" : ""}`, "");
md.push(`Generated by \`node scripts/bench/evaluate.ts${quick ? " --quick" : ""}\` on ${env.date.slice(0, 10)}, commit \`${env.commit}\`.`, "");
md.push(`Machine: ${env.cpu}, ${env.logicalCores} logical cores, ${env.memoryGB} GB, ${env.os}, Node ${env.node}. ${env.note}.`, "");
let section = "";
for (const row of rows) {
  if (row.section !== section) {
    section = row.section;
    md.push("", `## ${section}`, "", row.stat ? "| Operation | Median (ms) | p95 (ms) | n |" : "| Quantity | Value |", row.stat ? "|---|---:|---:|---:|" : "|---|---|");
  }
  md.push(row.stat ? `| ${row.metric} | ${ms(row.stat.median)} | ${ms(row.stat.p95)} | ${row.stat.n} |` : `| ${row.metric} | ${row.value} |`);
}
md.push("", "## Scaling (extrapolated)", "", "Linear in the number of ballots, from the measured per-ballot medians above. Ballot verification is independent per ballot, so the last-but-one column projects an 8-way parallel audit; the current CLI verifies on one core.", "");
md.push("| Ballots | Audit, 1 core (min) | Audit, 8 cores, projected (min) | Board size (MB) |", "|---:|---:|---:|---:|");
for (const r of scaling) md.push(`| ${r.ballots.toLocaleString("en-US")} | ${r.auditSingleCoreMin.toFixed(1)} | ${r.auditAllCoresMin.toFixed(1)} | ${r.boardMB.toFixed(0)} |`);
md.push("");
await writeFile(join(outDir, quick ? "results-quick.md" : "results.md"), md.join("\n"));
console.log(`\nWrote docs/evaluation/${quick ? "results-quick" : "results"}.{json,md}`);
