/**
 * A complete election, end to end, narrated.
 *
 * Run this in the viva. It exercises the whole cryptographic protocol --
 * trustee setup, client-side ballot encryption, zero-knowledge validity proofs,
 * homomorphic tallying, threshold decryption with proofs, and public
 * verification -- and prints what each party can and cannot see at each step.
 *
 * Usage:  node bench/demo-election.ts [voterCount] [modp2048|modp3072]
 */

import { MODP_2048, MODP_3072, groupExp } from "../src/elgamal/group.ts";
import { createBallot, verifyBallot, type ElectionParameters } from "../src/election/ballot.ts";
import { decryptTally, homomorphicTally } from "../src/election/tally.ts";
import { partialDecrypt, setupTrustees, verifyShare } from "../src/threshold/trustee.ts";
import { combinePartialDecryptions } from "../src/threshold/trustee.ts";
import { discreteLogSmall } from "../src/elgamal/dlog.ts";
import { toBase64Url } from "../src/util/bytes.ts";
import { encodeElement } from "../src/elgamal/group.ts";

const voterCount = Number(process.argv[2] ?? 25);
const group = (process.argv[3] ?? "modp3072") === "modp2048" ? MODP_2048 : MODP_3072;

const THRESHOLD = 3;
const TRUSTEES = 5;

const election: ElectionParameters = {
  electionId: "dvoting-demo-2026",
  candidates: ["Alice", "Bob", "Carol"],
  minSelections: 1,
  maxSelections: 1,
};

function heading(text: string): void {
  console.log(`\n${"=".repeat(70)}\n${text}\n${"=".repeat(70)}`);
}

function short(value: bigint): string {
  return `${toBase64Url(encodeElement(group, value)).slice(0, 20)}...`;
}

const started = performance.now();

// ---------------------------------------------------------------------------
heading("1. TRUSTEE SETUP");
console.log(`Group ${group.name} (${group.p.toString(2).length}-bit), ${THRESHOLD}-of-${TRUSTEES} threshold.\n`);

const setup = setupTrustees(group, THRESHOLD, TRUSTEES);

console.log(`Election public key : ${short(setup.publicKey.y)}`);
console.log("Each trustee verifies their share against the Feldman commitments:");
for (const keyShare of setup.keyShares) {
  const ok = verifyShare(group, keyShare.index, keyShare.share, setup.commitments);
  console.log(`  trustee ${keyShare.index}: share consistent = ${ok}`);
}
console.log(`\nThe election private key is NOT held by anyone. It exists only as`);
console.log(`${THRESHOLD} cooperating shares out of ${TRUSTEES}.`);

// ---------------------------------------------------------------------------
heading("2. VOTING (each ballot encrypted on the voter's own device)");

const trueCounts = [0, 0, 0];
const ballots = [];
const castStart = performance.now();

for (let voter = 0; voter < voterCount; voter++) {
  // A deterministic but uneven split, so the demo has a clear winner.
  const choice = voter % 7 === 0 ? 2 : voter % 3 === 0 ? 1 : 0;
  const selections = [0, 0, 0];
  selections[choice] = 1;
  trueCounts[choice]!++;

  ballots.push(await createBallot(election, setup.publicKey, selections));
}

const castMs = performance.now() - castStart;
console.log(`${voterCount} ballots cast in ${(castMs / 1000).toFixed(1)}s ` +
  `(${(castMs / voterCount).toFixed(0)}ms per ballot, on-device).`);

const sample = ballots[0]!;
console.log(`\nWhat the server receives for ballot ${sample.ballotId}:`);
for (const [i, ct] of sample.choices.entries()) {
  console.log(`  ${election.candidates[i]!.padEnd(6)} alpha=${short(ct.alpha)} beta=${short(ct.beta)}`);
}
console.log("  ...plus zero-knowledge proofs that each is 0 or 1 and exactly one is 1.");
console.log("  Nothing here reveals the vote -- not to the server, not to anyone.");

// ---------------------------------------------------------------------------
heading("3. PUBLIC VERIFICATION (anyone can run this)");

const verifyStart = performance.now();
let valid = 0;
for (const ballot of ballots) {
  if (await verifyBallot(election, setup.publicKey, ballot)) valid++;
}
const verifyMs = performance.now() - verifyStart;
console.log(`${valid}/${ballots.length} ballots verified in ${(verifyMs / 1000).toFixed(1)}s.`);
console.log("An observer can repeat this from the bulletin board with no secrets at all.");

// ---------------------------------------------------------------------------
heading("4. HOMOMORPHIC TALLY (no ballot is ever decrypted)");

const totals = homomorphicTally(group, election.candidates.length, ballots);
for (const [i, total] of totals.entries()) {
  console.log(`  ${election.candidates[i]!.padEnd(6)} encrypted total: ${short(total.beta)}`);
}
console.log("\nThese are the sums of every ballot, still encrypted.");

// ---------------------------------------------------------------------------
heading(`5. THRESHOLD DECRYPTION (${THRESHOLD} of ${TRUSTEES} trustees)`);

const participating = [0, 1, 2];
console.log(`Trustees ${participating.map((i) => i + 1).join(", ")} each produce a partial decryption + proof.\n`);

const partialsByCandidate = [];
for (const total of totals) {
  const partials = [];
  for (const i of participating) {
    partials.push(await partialDecrypt(group, election.electionId, setup.keyShares[i]!, total));
  }
  partialsByCandidate.push(partials);
}

// Demonstrate that a minority genuinely cannot decrypt.
const tooFew = partialsByCandidate[0]!.slice(0, THRESHOLD - 1);
const forced = combinePartialDecryptions(group, totals[0]!, tooFew, THRESHOLD - 1);
let minorityLearned: string;
try {
  minorityLearned = String(discreteLogSmall(group, forced, voterCount));
} catch {
  minorityLearned = "nothing (undecryptable garbage)";
}
console.log(`With only ${THRESHOLD - 1} trustees, the recovered value is: ${minorityLearned}`);

const result = await decryptTally(
  group,
  election.electionId,
  election.candidates,
  totals,
  partialsByCandidate,
  setup.publicShares,
  setup.threshold,
  ballots.length,
);

// ---------------------------------------------------------------------------
heading("6. RESULT");

const winner = [...result.results].sort((a, b) => b.votes - a.votes)[0]!;
for (const [i, entry] of result.results.entries()) {
  const bar = "#".repeat(Math.round((entry.votes / Math.max(voterCount, 1)) * 40));
  const check = entry.votes === trueCounts[i] ? "ok" : "MISMATCH";
  console.log(`  ${entry.candidate.padEnd(6)} ${String(entry.votes).padStart(4)}  ${bar} [${check}]`);
}
console.log(`\nWinner: ${winner.candidate} (${winner.votes} of ${result.ballotsCounted} votes)`);

const correct = result.results.every((entry, i) => entry.votes === trueCounts[i]);
console.log(`Tally matches the true counts: ${correct}`);

console.log(`
What just happened:
  * No individual ballot was ever decrypted -- only the aggregate.
  * No single trustee could have decrypted anything; ${THRESHOLD} had to cooperate.
  * Every ballot and every partial decryption carries a proof that anyone can
    re-check without any secret.
  * Total elapsed: ${((performance.now() - started) / 1000).toFixed(1)}s
`);

process.exitCode = correct ? 0 : 1;
