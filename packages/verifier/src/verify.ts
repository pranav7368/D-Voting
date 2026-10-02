/**
 * Verify an election from its bulletin board alone.
 *
 * ===========================================================================
 * WHAT "STANDALONE" MEANS HERE.
 *
 * Every other check in D-Voting runs inside some D-Voting process: the portal's
 * recount is served by the ballot box, and a trustee checks the chain before it
 * decrypts. An observer should not have to trust any of them. This module takes
 * a list of blocks -- from anywhere -- and re-derives everything from those
 * blocks and nothing else:
 *
 *   1. the validator set it will trust (pinned out of band, or read from the
 *      sealed configuration with a loud warning that it was not pinned);
 *   2. every block's hash linkage, Merkle root and signature quorum;
 *   3. the election's sealed definition and whether voting closed;
 *   4. optionally, that a published electoral roll is the one committed to;
 *   5. optionally, that specific ballots are included, by Merkle proof;
 *   6. every ballot's zero-knowledge proofs, the re-voting rule, the
 *      homomorphic totals, every trustee's decryption proof, and the announced
 *      numbers.
 *
 * THE TRUST ANCHOR, STATED PLAINLY.
 *
 * Signatures prove that blocks were signed by a set of keys. They cannot prove
 * that those are the RIGHT keys: a forger who controls the whole file can sign
 * a whole fake chain with keys of their own and seal those keys into a fake
 * block 0. Only an out-of-band copy of the validator set closes that gap -- the
 * same way a TLS certificate is worthless without a trusted root. So the
 * verifier reports which anchor it used, prints the validator fingerprint for
 * comparison, and treats an unpinned run as a warning rather than a pass.
 * ===========================================================================
 */

import {
  MODP_2048,
  MODP_3072,
  fromBase64Url,
  os2ip,
  type ElGamalPublicKey,
  type ElectionParameters,
  type PrimeOrderGroup,
} from "@dvoting/crypto";
import {
  InMemoryBlockStore,
  Ledger,
  createValidatorSet,
  encodeEntry,
  validatorFingerprint,
  verifyMerkleProof,
  type Block,
  type ValidatorSet,
} from "@dvoting/ledger";
import {
  BALLOT_ENTRY_KIND,
  CLOSE_ENTRY_KIND,
  CONFIG_ENTRY_KIND,
  TALLY_ENTRY_KIND,
} from "@dvoting/ballot-box/src/ballot-box.ts";
import { tallyFromChain } from "@dvoting/ballot-box/src/chain-tally.ts";
import type {
  ElectionCloseRecord,
  ElectionRecord,
} from "@dvoting/ballot-box/src/election-record.ts";
import {
  verifyPublishedTally,
  type PublishedTally,
} from "@dvoting/ballot-box/src/tally-publication.ts";
import { rollCommitment } from "@dvoting/registration-authority/src/eligibility/roll-commitment.ts";

const CONFIG_KIND = CONFIG_ENTRY_KIND;
const CLOSE_KIND = CLOSE_ENTRY_KIND;
const BALLOT_KIND = BALLOT_ENTRY_KIND;
const TALLY_KIND = TALLY_ENTRY_KIND;

export interface PinnedValidators {
  readonly validators: readonly { id: string; publicKey: string }[];
  readonly quorum: number;
}

export interface VerifyOptions {
  /** The validator set obtained out of band. Strongly recommended. */
  readonly pinnedValidators?: PinnedValidators;
  /** The published electoral roll identifiers, to check the sealed commitment. */
  readonly rollIds?: readonly string[];
  /** Tracking codes (ballot ids) whose inclusion should be proven. */
  readonly ballotIds?: readonly string[];
}

export interface Check {
  readonly label: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export type ElectionPhase = "empty" | "open" | "closed" | "published";

export interface ElectionVerificationReport {
  /** True only if every check passed. A warning does not make this false. */
  readonly valid: boolean;
  readonly phase: ElectionPhase;
  readonly electionId: string | null;
  readonly name: string | null;
  readonly trustAnchor: "pinned" | "chain";
  readonly validatorFingerprint: string | null;
  readonly blockCount: number;
  readonly checks: readonly Check[];
  readonly warnings: readonly string[];
  readonly results: readonly { candidate: string; votes: number }[] | null;
}

export async function verifyElection(
  blocks: readonly Block[],
  options: VerifyOptions = {},
): Promise<ElectionVerificationReport> {
  const checks: Check[] = [];
  const warnings: string[] = [];
  let phase: ElectionPhase = "empty";
  let electionId: string | null = null;
  let name: string | null = null;
  let fingerprint: string | null = null;
  let results: { candidate: string; votes: number }[] | null = null;
  const trustAnchor = options.pinnedValidators ? "pinned" : "chain";

  const report = (): ElectionVerificationReport => ({
    valid: checks.length > 0 && checks.every((check) => check.ok),
    phase,
    electionId,
    name,
    trustAnchor,
    validatorFingerprint: fingerprint,
    blockCount: blocks.length,
    checks,
    warnings,
    results,
  });
  const fail = (label: string, detail: string): ElectionVerificationReport => {
    checks.push({ label, ok: false, detail });
    return report();
  };

  if (blocks.length === 0) {
    return fail("Bulletin board has blocks", "the chain is empty -- the election was never opened");
  }

  // --- The sealed definition, read before anything is trusted. -------------
  const genesis = blocks[0]!;
  electionId = genesis.header.electionId;
  const configEntry = genesis.entries.find((entry) => entry.kind === CONFIG_KIND);
  if (!configEntry) {
    return fail(
      "Election definition is sealed in block 0",
      "block 0 carries no election configuration",
    );
  }
  let record: ElectionRecord;
  try {
    record = JSON.parse(new TextDecoder().decode(configEntry.data)) as ElectionRecord;
  } catch {
    return fail("Election definition is sealed in block 0", "the configuration is not valid JSON");
  }
  if (record.recordVersion !== "dvoting/election-config/v1") {
    return fail(
      "Election definition is sealed in block 0",
      `unsupported record version "${String(record.recordVersion)}"`,
    );
  }
  if (record.electionId !== electionId || configEntry.id !== electionId) {
    return fail(
      "Election definition is sealed in block 0",
      "the configuration names a different election than the chain",
    );
  }
  name = record.name ?? null;

  // --- 1. The trust anchor. --------------------------------------------------
  let sealedSet: ValidatorSet;
  try {
    sealedSet = toValidatorSet(record);
  } catch (error) {
    return fail("Validator set is well formed", errorText(error));
  }
  fingerprint = validatorFingerprint(sealedSet);

  if (options.pinnedValidators) {
    let pinnedSet: ValidatorSet;
    try {
      pinnedSet = toValidatorSet(options.pinnedValidators);
    } catch (error) {
      return fail("Pinned validator set is well formed", errorText(error));
    }
    if (validatorFingerprint(pinnedSet) !== fingerprint) {
      // Either the pin is stale or this is not the chain the observer thinks
      // it is. Both mean: stop, and believe nothing the chain says.
      return fail(
        "Chain is signed by the pinned validators",
        `the chain seals ${fingerprint}, but the pinned set is ${validatorFingerprint(pinnedSet)}`,
      );
    }
    checks.push({
      label: "Chain is signed by the pinned validators",
      ok: true,
      detail: `${sealedSet.quorum}-of-${sealedSet.validators.length}`,
    });
  } else {
    warnings.push(
      "Validator set was NOT pinned: it was read from the chain itself, so a forger who " +
        "controls this whole file could have signed it with keys of their own. Compare the " +
        "fingerprint below with one obtained independently, or pass --validators.",
    );
  }

  // --- 2. Every block, re-validated on this machine. -------------------------
  const ledger = new Ledger(new InMemoryBlockStore(), sealedSet, electionId);
  for (const block of blocks) {
    try {
      await ledger.append(block);
    } catch (error) {
      return fail(
        "Every block is hash-linked, Merkle-committed and quorum-signed",
        `block ${block.header.height}: ${errorText(error)}`,
      );
    }
  }
  const entryCount = blocks.reduce((sum, block) => sum + block.entries.length, 0);
  checks.push({
    label: "Every block is hash-linked, Merkle-committed and quorum-signed",
    ok: true,
    detail: `${blocks.length} blocks, ${entryCount} entries`,
  });

  // --- 3. The election's definition and lifecycle. --------------------------
  const group = groupByName(record.group);
  if (!group) {
    return fail("Election parameters are usable", `unknown group "${record.group}"`);
  }
  let publicKey: ElGamalPublicKey;
  try {
    publicKey = { group, y: os2ip(fromBase64Url(record.electionPublicKey)) };
  } catch {
    return fail("Election parameters are usable", "the election public key does not decode");
  }
  const election: ElectionParameters = {
    electionId,
    candidates: record.candidates,
    minSelections: record.minSelections,
    maxSelections: record.maxSelections,
  };
  checks.push({
    label: "Election definition is sealed in block 0",
    ok: true,
    detail: `${record.candidates.length} candidates, ${record.trustees.threshold}-of-${record.trustees.total} trustees`,
  });

  const configBlocks = blocks.filter((block) =>
    block.entries.some((entry) => entry.kind === CONFIG_KIND),
  );
  if (configBlocks.length !== 1) {
    return fail("Election definition was sealed once", "more than one configuration on the chain");
  }

  const closeLocation = findEntry(blocks, CLOSE_KIND);
  let closeHeight: number | null = null;
  if (closeLocation) {
    let close: ElectionCloseRecord;
    try {
      close = JSON.parse(new TextDecoder().decode(closeLocation.data)) as ElectionCloseRecord;
    } catch {
      return fail("Voting closed on the chain", "the close record is not valid JSON");
    }
    closeHeight = closeLocation.height;
    // No ballot may be recorded after the poll closed.
    const late = blocks
      .filter((block) => block.header.height > closeLocation.height)
      .flatMap((block) => block.entries.filter((entry) => entry.kind === BALLOT_KIND));
    if (late.length > 0) {
      return fail(
        "No ballot was recorded after the close",
        `${late.length} ballot(s) appear after the close record`,
      );
    }
    checks.push({
      label: "Voting closed on the chain",
      ok: true,
      detail: `${close.reason} close at ${close.closedAt}, block ${closeLocation.height}`,
    });
    phase = "closed";
  } else {
    phase = "open";
    warnings.push("Voting has not closed yet, so there is no result to recount.");
  }

  // --- 4. The electoral roll. ------------------------------------------------
  if (options.rollIds) {
    if (!record.rollCommitment) {
      return fail("Published roll matches the sealed commitment", "no roll commitment was sealed");
    }
    const recomputed = await rollCommitment(electionId, options.rollIds);
    if (recomputed !== record.rollCommitment) {
      return fail(
        "Published roll matches the sealed commitment",
        `${options.rollIds.length} roll entries hash to ${recomputed}, the chain sealed ${record.rollCommitment}`,
      );
    }
    checks.push({
      label: "Published roll matches the sealed commitment",
      ok: true,
      detail: `${options.rollIds.length} roll entries`,
    });
  } else if (!record.rollCommitment) {
    warnings.push("No electoral-roll commitment was sealed, so roll additions are not detectable.");
  }

  // --- 5. Individual ballots. ------------------------------------------------
  for (const ballotId of options.ballotIds ?? []) {
    const located = await ledger.locateEntry(BALLOT_KIND, ballotId);
    const label = `Ballot ${ballotId} is on the chain`;
    if (!located) return fail(label, "no ballot with this tracking code was recorded");
    const proven = await verifyMerkleProof(
      encodeEntry(located.entry),
      located.proof,
      located.merkleRoot,
    );
    if (!proven) return fail(label, "the Merkle inclusion proof does not verify");
    checks.push({
      label,
      ok: true,
      detail: `block ${located.blockHeight}, Merkle path of ${located.proof.path.length}`,
    });
  }

  // --- 6. The count. ---------------------------------------------------------
  const tallyLocation = findEntry(blocks, TALLY_KIND);
  if (!tallyLocation) {
    // No result yet: still re-verify every ballot, which is useful mid-election.
    const recount = await tallyFromChain(ledger, election, publicKey);
    if (recount.rejected.length > 0) {
      return fail(
        "Every ballot on the chain verifies",
        `${recount.rejected.length} ballot(s) failed: ${recount.rejected
          .map((r) => `${r.ballotId} (${r.reason})`)
          .join(", ")}`,
      );
    }
    checks.push({
      label: "Every ballot on the chain verifies",
      ok: true,
      detail: `${recount.counted.length} counted, ${recount.superseded.length} superseded`,
    });
    if (phase === "closed") warnings.push("Voting is closed but no result has been published yet.");
    return report();
  }

  if (closeHeight === null || tallyLocation.height < closeHeight) {
    return fail("Result was published after the close", "a result appears before voting closed");
  }

  let published: PublishedTally;
  try {
    published = JSON.parse(new TextDecoder().decode(tallyLocation.data)) as PublishedTally;
  } catch {
    return fail("Published result is readable", "the result on the chain is not valid JSON");
  }

  // The tally's trustee roster must be the one sealed before voting -- a
  // result decrypted by keys nobody committed to proves nothing.
  const sealedShares = sharesKey(record.trustees.publicShares);
  const publishedShares = sharesKey(published.publicShares ?? []);
  if (sealedShares !== publishedShares || published.threshold !== record.trustees.threshold) {
    return fail(
      "Result uses the sealed trustee roster",
      "the trustee shares or threshold in the result differ from those sealed in block 0",
    );
  }
  checks.push({ label: "Result uses the sealed trustee roster", ok: true });

  const recount = await verifyPublishedTally(ledger, election, publicKey, published);
  checks.push(...recount.checks);
  if (recount.valid && recount.recomputedResults) {
    results = [...recount.recomputedResults];
    phase = "published";
  }
  return report();
}

function toValidatorSet(source: PinnedValidators): ValidatorSet {
  if (!Array.isArray(source.validators) || typeof source.quorum !== "number") {
    throw new Error("expected {validators: [{id, publicKey}], quorum}");
  }
  return createValidatorSet(
    source.validators.map((v) => ({ id: v.id, publicKey: fromBase64Url(v.publicKey) })),
    source.quorum,
  );
}

function groupByName(name: string): PrimeOrderGroup | null {
  if (name === MODP_2048.name) return MODP_2048;
  if (name === MODP_3072.name) return MODP_3072;
  return null;
}

function findEntry(
  blocks: readonly Block[],
  kind: string,
): { height: number; data: Uint8Array } | null {
  for (const block of blocks) {
    const entry = block.entries.find((candidate) => candidate.kind === kind);
    if (entry) return { height: block.header.height, data: entry.data };
  }
  return null;
}

function sharesKey(shares: readonly { index: number; publicShare: string }[]): string {
  return [...shares]
    .map((share) => `${share.index}:${share.publicShare}`)
    .sort()
    .join(",");
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
