/**
 * Performance benchmark for the election crypto path.
 *
 * Ballot casting happens on a voter's device -- possibly a mid-range phone --
 * so the cost of createBallot is a real usability constraint, not a vanity
 * metric. Verification cost matters differently: every observer re-verifies
 * every ballot, so it bounds how cheaply the election can be audited.
 *
 * Usage:  node bench/election-bench.ts [modp2048|modp3072]
 */

import { MODP_2048, MODP_3072, groupExp, randomScalar } from "../src/elgamal/group.ts";
import { encrypt } from "../src/elgamal/cipher.ts";
import { createBallot, verifyBallot, type ElectionParameters } from "../src/election/ballot.ts";
import { homomorphicTally } from "../src/election/tally.ts";
import { partialDecrypt, setupTrustees } from "../src/threshold/trustee.ts";
import { decryptTally } from "../src/election/tally.ts";

const groupName = process.argv[2] ?? "modp3072";
const group = groupName === "modp2048" ? MODP_2048 : MODP_3072;

function time<T>(label: string, iterations: number, fn: () => T): T {
  const start = performance.now();
  let result!: T;
  for (let i = 0; i < iterations; i++) result = fn();
  const elapsed = performance.now() - start;
  console.log(`  ${label.padEnd(38)} ${(elapsed / iterations).toFixed(1).padStart(8)} ms`);
  return result;
}

async function timeAsync<T>(label: string, iterations: number, fn: () => Promise<T>): Promise<T> {
  const start = performance.now();
  let result!: T;
  for (let i = 0; i < iterations; i++) result = await fn();
  const elapsed = performance.now() - start;
  console.log(`  ${label.padEnd(38)} ${(elapsed / iterations).toFixed(1).padStart(8)} ms`);
  return result;
}

console.log(`\nGroup: ${group.name} (${group.p.toString(2).length}-bit)\n`);

console.log("Primitives");
const exponent = randomScalar(group);
time("modPow (random base)", 20, () => groupExp(group, group.g, exponent));

const setup = setupTrustees(group, 3, 5);
console.log("\nSetup");
time("setupTrustees(3-of-5)", 1, () => setupTrustees(group, 3, 5));

const election: ElectionParameters = {
  electionId: "bench-2026",
  candidates: ["Alice", "Bob", "Carol", "Dave"],
  minSelections: 1,
  maxSelections: 1,
};

console.log(`\nBallot (${election.candidates.length} candidates)`);
time("encrypt one choice", 20, () => encrypt(setup.publicKey, 1n));
const ballot = await timeAsync("createBallot  <- ON THE VOTER'S PHONE", 5, () =>
  createBallot(election, setup.publicKey, [1, 0, 0, 0]),
);
await timeAsync("verifyBallot  <- PER OBSERVER, PER BALLOT", 5, () =>
  verifyBallot(election, setup.publicKey, ballot),
);

console.log("\nTally (10 ballots)");
const ballots = [];
for (let i = 0; i < 10; i++) {
  ballots.push(await createBallot(election, setup.publicKey, [1, 0, 0, 0]));
}

const totals = time("homomorphicTally", 5, () =>
  homomorphicTally(group, election.candidates.length, ballots),
);

await timeAsync("partialDecrypt (one trustee, one race)", 5, () =>
  partialDecrypt(group, election.electionId, setup.keyShares[0]!, totals[0]!),
);

const partialsByCandidate = [];
for (const total of totals) {
  const partials = [];
  for (const i of [0, 1, 2]) {
    partials.push(await partialDecrypt(group, election.electionId, setup.keyShares[i]!, total));
  }
  partialsByCandidate.push(partials);
}

await timeAsync("decryptTally (verify + combine)", 3, () =>
  decryptTally(
    group,
    election.electionId,
    election.candidates,
    totals,
    partialsByCandidate,
    setup.publicShares,
    setup.threshold,
    ballots.length,
  ),
);

console.log("");
