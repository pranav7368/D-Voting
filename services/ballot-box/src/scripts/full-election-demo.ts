/**
 * THE FULL SYSTEM, END TO END.
 *
 * Registration -> blind-signed credential -> on-device ballot encryption ->
 * zero-knowledge validity proof -> ballot box -> permissioned ledger ->
 * public verification -> homomorphic tally -> threshold decryption -> result,
 * finishing with a demonstration that tampering with the record is detected.
 *
 * This is the viva demo. Every step prints what each party can and cannot see.
 *
 * Usage:  node src/scripts/full-election-demo.ts [voters] [modp2048|modp3072]
 */

import {
  LocalBlindSigner,
  MODP_2048,
  MODP_3072,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  auditAgainstCommitment,
  blind,
  cheatSurvivalProbability,
  computeKeyId,
  createBallot,
  decryptTally,
  describeSelections,
  encodeElement,
  finalize,
  generateCredential,
  partialDecrypt,
  prepareBallot,
  runDkg,
  toBase64Url,
  verify as verifyCredential,
  verifyBallot,
  type ElectionParameters,
  type PartialDecryption,
} from "@dvoting/crypto";
import { generateIssuerKeyPair } from "@dvoting/crypto/keygen";
import {
  DistributedSealer,
  InMemoryBlockStore,
  Ledger,
  LocalValidatorPeer,
  ValidatorNode,
  createValidatorSet,
  encodeEntry,
  generateValidatorKeyPair,
  verifyChain,
  verifyMerkleProof,
  type Block,
  type ValidatorKeyPair,
} from "@dvoting/ledger";

import { BallotBox, credentialFingerprint } from "../ballot-box.ts";
import { tallyFromChain } from "../chain-tally.ts";
import { buildPublishedTally, encodeTally, verifyPublishedTally } from "../tally-publication.ts";
import { ballotFromWire } from "../wire.ts";

const voterCount = Number(process.argv[2] ?? 12);
const group = (process.argv[3] ?? "modp2048") === "modp3072" ? MODP_3072 : MODP_2048;

const THRESHOLD = 3;
const TRUSTEES = 5;
const BALLOTS_PER_BLOCK = 4;

const election: ElectionParameters = {
  electionId: "dvoting-general-2026",
  candidates: ["Alice", "Bob", "Carol"],
  minSelections: 1,
  maxSelections: 1,
};

function heading(n: number, text: string): void {
  // ASCII rules only: box-drawing characters render inconsistently across
  // terminals and survive encoding round-trips badly.
  console.log(`\n${"-".repeat(72)}\n  STEP ${n}: ${text}\n${"-".repeat(72)}`);
}

const started = performance.now();

// ===========================================================================
heading(1, "ELECTION SETUP");

console.log(`Group: ${group.name} (${group.p.toString(2).length}-bit).`);
if (group === MODP_2048) {
  console.log("(Demo speed. Production default is modp3072 / 128-bit security.)");
}

// The Registration Authority's blind-signature key.
const issuerKeys = generateIssuerKeyPair(2048, RSABSSA_SHA384_PSS_DETERMINISTIC);
const issuerSigner = new LocalBlindSigner(issuerKeys.privateKey);
const issuerKeyId = await computeKeyId(issuerKeys.publicKey);

// The trustees jointly generate the election key with a Pedersen DKG.
// There is NO dealer: the key is never assembled anywhere, at any point.
const trustees = runDkg(group, THRESHOLD, TRUSTEES);

// The named authorities permitted to seal blocks.
const validatorKeys: ValidatorKeyPair[] = [];
for (const name of ["election-commission", "observer-press", "observer-university", "observer-ngo"]) {
  validatorKeys.push(await generateValidatorKeyPair(name));
}
const validatorSet = createValidatorSet(validatorKeys.map((k) => k.identity));

// Each validator is an independent node: one signing key, its own chain
// replica, and it re-validates every block itself before attesting.
//
// Crucially it re-verifies every BALLOT too. Without this a dishonest proposer
// could stuff invalid ballots into a block and the other validators would
// rubber-stamp it.
const validateBallotEntry = async (entry: { kind: string; data: Uint8Array }) => {
  if (entry.kind !== "ballot") return { ok: true };
  try {
    const wire = JSON.parse(new TextDecoder().decode(entry.data));
    const ballot = ballotFromWire(group, wire);
    const ok = await verifyBallot(election, trustees.publicKey, ballot);
    return ok ? { ok: true } : { ok: false, reason: "ballot failed zero-knowledge verification" };
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : "unparseable ballot" };
  }
};

const validatorNodes = validatorKeys.map(
  (keyPair) =>
    new ValidatorNode({
      identity: keyPair.identity,
      privateKey: keyPair.privateKey,
      ledger: new Ledger(new InMemoryBlockStore(), validatorSet, election.electionId),
      validateEntry: validateBallotEntry,
    }),
);
const peers = validatorNodes.map((node) => new LocalValidatorPeer(node));

// The ballot box holds NO signing keys.
const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, election.electionId);

console.log(`\nRegistration Authority key : ${issuerKeyId}`);
console.log(`Election public key        : ${toBase64Url(encodeElement(group, trustees.publicKey.y)).slice(0, 32)}...`);
console.log(`Trustees                   : ${THRESHOLD}-of-${TRUSTEES} threshold, key built by Pedersen DKG`);
console.log(`  qualified participants   : ${trustees.qualified.join(", ")} (complaints: ${trustees.complaints.length})`);
console.log("  NO dealer: the private key was never assembled anywhere, at any point.");
console.log(`Validators                 : ${validatorSet.validators.map((v) => v.id).join(", ")}`);
console.log(`Consensus quorum           : ${validatorSet.quorum}-of-${validatorSet.validators.length} (Proof-of-Authority)`);
console.log("  Each validator is a separate node holding ONLY its own key and its own");
console.log("  chain replica. Each re-verifies every ballot before attesting to a block.");

const ballotBox = new BallotBox({
  election,
  issuerPublicKey: issuerKeys.publicKey,
  electionPublicKey: trustees.publicKey,
  trustees: {
    threshold: THRESHOLD,
    total: TRUSTEES,
    publicShares: trustees.publicShares.map((share) => ({
      index: share.index,
      publicShare: toBase64Url(encodeElement(group, share.publicShare)),
    })),
  },
  ledger,
  sealer: new DistributedSealer(ledger, peers),
  maxPendingBeforeSeal: BALLOTS_PER_BLOCK,
});
await ballotBox.load();

// Opening the poll seals the whole configuration into the first block, so the
// issuer key, election key, trustee roster and validator set a voter relies on
// can all be checked against the chain itself rather than taken on trust.
const opened = await ballotBox.openPoll();
const genesisHeight = (await ledger.height()) - 1;
console.log(`\nElection sealed into block ${genesisHeight}: ${opened.candidates.join(", ")}.`);
console.log("It commits to the issuer key, election key, trustee roster and validator set.");
console.log("Nothing in it can change now without breaking the chain.");

// ===========================================================================
heading(2, "REGISTRATION (blind-signed anonymous credentials)");

interface Voter {
  label: string;
  credential: Uint8Array;
  signature: Uint8Array;
  fingerprint: string;
}

const voters: Voter[] = [];
for (let i = 0; i < voterCount; i++) {
  // --- on the voter's device ---
  const credential = generateCredential();
  const { blindedMessage, inverse } = await blind(issuerKeys.publicKey, credential);

  // --- at the Registration Authority (after KYC) ---
  const blindSignature = await issuerSigner.blindSign(blindedMessage);

  // --- back on the device ---
  const signature = await finalize(issuerKeys.publicKey, credential, blindSignature, inverse);

  voters.push({
    label: `voter-${i + 1}`,
    credential,
    signature,
    fingerprint: await credentialFingerprint(credential),
  });
}

console.log(`${voterCount} voters registered and issued credentials.`);
console.log(`\nExample -- what the RA saw vs what the voter holds:`);
console.log(`  RA saw (blinded)  : ${toBase64Url((await blind(issuerKeys.publicKey, voters[0]!.credential)).blindedMessage).slice(0, 32)}...`);
console.log(`  voter holds       : ${toBase64Url(voters[0]!.credential).slice(0, 32)}...`);
console.log(`  credential valid  : ${await verifyCredential(issuerKeys.publicKey, voters[0]!.credential, voters[0]!.signature)}`);
console.log("\nThe RA can confirm it signed this credential, but CANNOT tell which");
console.log("voter it issued it to -- the blinding is information-theoretic.");

// ===========================================================================
heading(3, "VOTING (ballots encrypted on each device)");

/** Each voter's EFFECTIVE choice, i.e. after any re-vote. */
const effectiveChoice = new Map<string, number>();
const castStart = performance.now();
let trackedBallotId = "";

for (const [index, voter] of voters.entries()) {
  const choice = index % 5 === 0 ? 2 : index % 3 === 0 ? 1 : 0;
  const selections = [0, 0, 0];
  selections[choice] = 1;
  effectiveChoice.set(voter.label, choice);

  const ballot = await createBallot(election, trustees.publicKey, selections, {
    credentialFingerprint: voter.fingerprint,
  });
  const result = await ballotBox.cast({
    credential: voter.credential,
    credentialSignature: voter.signature,
    ballot,
  });

  // Track the first voter's ballot: it lands in a full block, so its audit path
  // actually demonstrates a logarithmic inclusion proof.
  if (index === 0) {
    trackedBallotId = result.trackingCode;
    console.log(`First voter's tracking code: ${result.trackingCode}`);
  }
}

console.log(`\n${voterCount} ballots cast in ${((performance.now() - castStart) / 1000).toFixed(1)}s.`);

// --- coercion mitigation ---------------------------------------------------
// Pick a voter whose original vote was NOT Alice, so the re-vote visibly
// changes the outcome rather than being a no-op.
const coerced = voters.find((v) => effectiveChoice.get(v.label) !== 0) ?? voters[1]!;
const coercedInto = election.candidates[effectiveChoice.get(coerced.label)!];
console.log(`\n${coerced.label} was coerced into voting for ${coercedInto}, and re-votes in private for Alice.`);

const revoteBallot = await createBallot(election, trustees.publicKey, [1, 0, 0], {
  credentialFingerprint: coerced.fingerprint,
});
const revote = await ballotBox.cast({
  credential: coerced.credential,
  credentialSignature: coerced.signature,
  ballot: revoteBallot,
});
console.log(`Re-vote accepted; it supersedes ${revote.supersedes} earlier ballot(s).`);
effectiveChoice.set(coerced.label, 0);

await ballotBox.sealBlock();

const trueCounts = [0, 0, 0];
for (const choice of effectiveChoice.values()) trueCounts[choice]!++;

// ===========================================================================
heading(4, "CAST-OR-AUDIT (catching a malicious voting app)");

console.log("A compromised app can encrypt Bob when the voter picked Alice.");
console.log("Every ZK proof still verifies -- they prove well-formedness, not intent.\n");

const auditor = voters[2]!;
const voterIntended = [1, 0, 0]; // Alice

// The app misbehaves: it encrypts Bob instead.
const cheatingBallot = await prepareBallot(election, trustees.publicKey, [0, 1, 0], {
  credentialFingerprint: auditor.fingerprint,
});
console.log(`  ballot proofs valid?      ${await verifyBallot(election, trustees.publicKey, cheatingBallot.ballot)}  <- nothing objects`);
console.log(`  commitment shown to voter: ${cheatingBallot.commitment.slice(0, 24)}...`);
console.log("  (the app must commit BEFORE learning cast-or-audit)");

// --- Check 1: performed by the ballot box / any observer -------------------
// It can only establish WHAT the ballot encrypts. It is never told the voter's
// intent, because that would hand the server a plaintext vote.
const spoiled = await ballotBox.spoil({
  ballot: cheatingBallot.ballot,
  auditSecret: cheatingBallot.secret,
});
console.log(`\n  [check 1 - anyone] ciphertext matches revealed randomness: ${spoiled.encryptionConsistent}`);
console.log(`                     ballot provably encrypts: ${describeSelections(election, spoiled.encodedSelections ?? [])}`);
console.log("                     published on the bulletin board; any observer can re-run this.");

// --- Check 2: performed by the VOTER, on a device the app does not control --
const caught = await auditAgainstCommitment(
  election,
  trustees.publicKey,
  cheatingBallot.ballot,
  cheatingBallot.secret,
  cheatingBallot.commitment,
  voterIntended,
);
console.log(`\n  [check 2 - voter only] matches what I chose: ${caught.ok}`);
console.log(`                     ${caught.reason}`);
console.log("\n  Both checks are needed. The server can prove WHAT was encrypted but must");
console.log("  never learn the voter's intent; only the voter can compare the two.");

// An honest audit, for contrast.
const honest = await prepareBallot(election, trustees.publicKey, voterIntended, {
  credentialFingerprint: auditor.fingerprint,
});
const honestAudit = await auditAgainstCommitment(
  election,
  trustees.publicKey,
  honest.ballot,
  honest.secret,
  honest.commitment,
  voterIntended,
);
console.log(`\n  An HONEST app, audited the same way: passed = ${honestAudit.ok}`);
await ballotBox.spoil({ ballot: honest.ballot, auditSecret: honest.secret });

console.log(`\n  A client cheating on 10% of ballots survives 20 audits with`);
console.log(`  probability ${(cheatSurvivalProbability(0.1, 20) * 100).toFixed(1)}% -- systematic fraud is detected.`);

// ===========================================================================
heading(5, "REJECTING FRAUD (each of these is refused)");

const attacker = voters[0]!;
const attempts: [string, () => Promise<unknown>][] = [
  [
    "ballot with a forged credential signature",
    async () => {
      // A FRESH ballot, so this exercises the credential check rather than
      // tripping the duplicate-ballot-id check first.
      const ballot = await createBallot(election, trustees.publicKey, [1, 0, 0], {
        credentialFingerprint: attacker.fingerprint,
      });
      return ballotBox.cast({
        credential: attacker.credential,
        credentialSignature: new Uint8Array(256).fill(9),
        ballot,
      });
    },
  ],
  [
    "replaying another voter's ballot under my own credential",
    async () => {
      const victim = voters[2]!;
      const victimBallot = await createBallot(election, trustees.publicKey, [0, 1, 0], {
        credentialFingerprint: victim.fingerprint,
      });
      return ballotBox.cast({
        credential: attacker.credential,
        credentialSignature: attacker.signature,
        ballot: victimBallot,
      });
    },
  ],
  [
    "resubmitting a ballot already on the chain",
    () =>
      ballotBox.cast({
        credential: coerced.credential,
        credentialSignature: coerced.signature,
        ballot: revoteBallot,
      }),
  ],
];

for (const [description, attempt] of attempts) {
  try {
    await attempt();
    console.log(`  !! ACCEPTED (this is a bug): ${description}`);
  } catch (error) {
    const code = (error as { code?: string }).code ?? "error";
    console.log(`  refused [${code.padEnd(19)}] ${description}`);
  }
}

// ===========================================================================
heading(6, "PUBLIC VERIFICATION (no secrets required)");

const chainReport = await ledger.verify();
console.log(`Chain: ${chainReport.blockCount} blocks, ${chainReport.entryCount} entries, valid = ${chainReport.valid}`);

// A voter checks their own ballot is included, using only the signed header.
const tracked = await ledger.locateEntry("ballot", trackedBallotId);
if (tracked) {
  const included = await verifyMerkleProof(
    encodeEntry(tracked.entry),
    tracked.proof,
    tracked.merkleRoot,
  );
  console.log(`\nvoter-1 verifies tracking code ${trackedBallotId}:`);
  console.log(`  found in block   : ${tracked.blockHeight}, entry #${tracked.entryIndex} of ${tracked.proof.treeSize}`);
  console.log(`  audit path       : ${tracked.proof.path.length} hashes (${tracked.proof.path.length * 32} bytes)`);
  console.log(`  inclusion proof  : ${included ? "VALID" : "INVALID"}`);
  console.log("  ...checked against the Merkle root in the validator-signed header.");
}

// ===========================================================================
heading(7, "TALLY (from the chain, re-verifying every ballot)");

const tallyInput = await tallyFromChain(ledger, election, trustees.publicKey);
console.log(`counted    : ${tallyInput.counted.length}`);
console.log(`superseded : ${tallyInput.superseded.length}  (re-voting: only the last counts)`);
console.log(`rejected   : ${tallyInput.rejected.length}`);

const partialsByCandidate: PartialDecryption[][] = [];
for (const total of tallyInput.encryptedTotals) {
  const partials: PartialDecryption[] = [];
  for (const keyShare of trustees.keyShares.slice(0, THRESHOLD)) {
    partials.push(await partialDecrypt(group, election.electionId, keyShare, total));
  }
  partialsByCandidate.push(partials);
}

const result = await decryptTally(
  group,
  election.electionId,
  election.candidates,
  tallyInput.encryptedTotals,
  partialsByCandidate,
  trustees.publicShares,
  trustees.threshold,
  tallyInput.counted.length,
);

// ===========================================================================
heading(8, "RESULT");

for (const [i, entry] of result.results.entries()) {
  const bar = "#".repeat(Math.round((entry.votes / Math.max(tallyInput.counted.length, 1)) * 36));
  const ok = entry.votes === trueCounts[i] ? "ok" : `EXPECTED ${trueCounts[i]}`;
  console.log(`  ${entry.candidate.padEnd(7)} ${String(entry.votes).padStart(3)}  ${bar} [${ok}]`);
}
const correct = result.results.every((entry, i) => entry.votes === trueCounts[i]);
console.log(`\nTally matches the true counts: ${correct}`);

// ===========================================================================
heading(9, "PUBLISHING THE RESULT (so anyone can recount it)");

const closeRecord = await ballotBox.closePoll("administrator");
console.log(`Poll closed and recorded on the chain at block ${closeRecord.finalHeight}.`);
console.log("The close is an entry, not a flag: restarting the service cannot reopen it.\n");

const publishedTally = buildPublishedTally({
  election,
  publicKey: trustees.publicKey,
  threshold: THRESHOLD,
  countedBallotIds: tallyInput.counted.map((item) => item.ballot.ballotId),
  supersededBallotIds: tallyInput.superseded.map((item) => item.ballot.ballotId),
  encryptedTotals: tallyInput.encryptedTotals,
  partialsByCandidate,
  publicShares: trustees.publicShares,
  results: result.results,
});

const tallyBlock = await ballotBox.publishTally({
  encode: () => encodeTally(publishedTally),
});
console.log(`Result sealed on the chain at block ${tallyBlock.header.height}.`);
console.log("It carries the encrypted totals, every trustee's decryption proof,");
console.log("and the counted ballot ids -- everything needed to redo the count.\n");

const recount = await verifyPublishedTally(ledger, election, trustees.publicKey, publishedTally);
console.log("An independent observer recounts from the chain alone:");
for (const check of recount.checks) {
  console.log(`  ${check.ok ? "ok  " : "FAIL"} ${check.label}${check.detail ? ` -- ${check.detail}` : ""}`);
}

// And a rigged result is caught.
const rigged = {
  ...publishedTally,
  results: publishedTally.results.map((entry, i) => ({ ...entry, votes: i === 1 ? 99 : 0 })),
};
const riggedReport = await verifyPublishedTally(ledger, election, trustees.publicKey, rigged);
console.log(`\nIf the operator announced different numbers: valid = ${riggedReport.valid}`);
console.log(`  detected: ${riggedReport.checks.find((c) => !c.ok)?.detail}`);

// ===========================================================================
heading(10, "TAMPER DETECTION");

const blocks = [...(await ledger.blocks())] as Block[];
const target = blocks.findIndex((b) => b.entries.some((e) => e.kind === "ballot"));
console.log(`An insider with full database access edits one ballot in block ${target}...`);

blocks[target] = {
  ...blocks[target]!,
  entries: blocks[target]!.entries.map((entry, i) =>
    i === 0 ? { ...entry, data: new TextEncoder().encode("REWRITTEN") } : entry,
  ),
};

const tamperedReport = await verifyChain(blocks, validatorSet, {
  expectedElectionId: election.electionId,
});
console.log(`\nRe-verifying the chain: valid = ${tamperedReport.valid}`);
for (const error of tamperedReport.errors.slice(0, 3)) {
  console.log(`  detected: ${error}`);
}

console.log(`
${"=".repeat(72)}
  SUMMARY
${"=".repeat(72)}
  * The Registration Authority proved eligibility without learning any vote,
    and cannot link credentials to voters (information-theoretic blinding).
  * Ballots were encrypted on-device; the server never saw a plaintext vote.
  * Every ballot carries a zero-knowledge proof that it is well-formed.
  * The tally was computed homomorphically -- no individual ballot was decrypted.
  * ${THRESHOLD} of ${TRUSTEES} trustees were required to decrypt; no single party could.
  * Every voter can prove their ballot was included, from ${tracked?.proof.path.length ?? 0} hashes.
  * The RESULT is on the chain with every decryption proof, so anyone can
    recount it -- an announced number that does not match the ballots is caught.
  * Any tampering with the record is detected by any observer.

  Elapsed: ${((performance.now() - started) / 1000).toFixed(1)}s
`);

process.exitCode = correct && chainReport.valid && !tamperedReport.valid ? 0 : 1;
