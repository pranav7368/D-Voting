/**
 * Second-device checks: what a voter's phone verifies about a ballot that
 * another device prepared.
 *
 * ===========================================================================
 * THE GAP THIS CLOSES.
 *
 * The Benaloh cast-or-audit challenge only protects a voter if the audit is
 * checked somewhere the voting device does not control. Checked on the voting
 * device itself, a malicious app simply reports "test passed". So the voting
 * page shows a QR code carrying three values, the election id, the ballot id
 * and the ballot's commitment, BEFORE the voter decides to cast or test. A
 * second device scans it, then reads the PUBLIC bulletin board, not the voting
 * device, and checks:
 *
 *   tested ballot  the published randomness re-encrypts to exactly the
 *                  ciphertexts the commitment covers, and the phone shows the
 *                  voter which candidate that ballot really contained;
 *   cast ballot    the ballot sealed on the board is exactly the one the
 *                  commitment covers, included under a quorum of signatures.
 *
 * Because the device commits before learning which way the voter will go, it
 * cannot cheat on cast ballots only: a ballot it altered is caught if tested,
 * and a ballot it swapped is caught when cast.
 *
 * WHAT THIS STILL TRUSTS: the bulletin board served to the phone, and this
 * code as served to the phone. Phase 3 (witnessed checkpoints) removes the
 * first; publishing this page from an independent origin removes the second.
 * ===========================================================================
 *
 * Pure functions over public data, so the same file runs in a browser and in
 * the Node test suite.
 */

import {
  MODP_2048,
  MODP_3072,
  auditAgainstCommitment,
  ballotCommitment,
  fromBase64Url,
  os2ip,
} from "./dvoting-crypto.js";
import { verifyBallotReceipt } from "./verify-lib.js";

// --- the link carried by the QR code ------------------------------------------

/**
 * The URL the voting page encodes as a QR code. Values ride in the fragment,
 * which browsers never send to a server, so no web log ever records which
 * ballot a phone is watching.
 */
export function checkLink(origin, { electionId, ballotId, commitment }) {
  const params = new URLSearchParams({ e: electionId, b: ballotId, c: commitment });
  return `${origin}/check#${params.toString()}`;
}

export function parseCheckLink(hash) {
  const params = new URLSearchParams(String(hash).replace(/^#/, ""));
  const electionId = params.get("e");
  const ballotId = params.get("b");
  const commitment = params.get("c");
  if (!electionId || !ballotId || !commitment) return null;
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(ballotId) || !/^[A-Za-z0-9_-]{43}$/.test(commitment)) return null;
  return { electionId, ballotId, commitment };
}

/**
 * The 12-digit check code for a commitment: forty bits of the SHA-256
 * commitment, read as a number, in three groups. The voting page and the phone
 * both derive it from the same commitment, so a voter can compare them.
 */
export function checkCode(commitment) {
  const bytes = fromBase64Url(commitment);
  let value = 0n;
  for (let i = 0; i < 5; i++) value = (value << 8n) | BigInt(bytes[i]);
  const digits = (value % 1_000_000_000_000n).toString().padStart(12, "0");
  return `${digits.slice(0, 4)} ${digits.slice(4, 8)} ${digits.slice(8)}`;
}

// --- decoding public data -------------------------------------------------------

/** Decode a ledger leaf: three u32-length-prefixed fields, kind, id, data. */
export function decodeLeaf(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 0;
  const field = () => {
    if (offset + 4 > bytes.length) throw new Error("truncated ledger entry");
    const length = view.getUint32(offset, false);
    offset += 4;
    if (offset + length > bytes.length) throw new Error("truncated ledger entry");
    const value = bytes.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const kind = decoder.decode(field());
  const id = decoder.decode(field());
  const data = field();
  if (offset !== bytes.length) throw new Error("trailing bytes after ledger entry");
  return { kind, id, data };
}

export function groupFor(election) {
  if (election.group === "modp2048") return MODP_2048;
  if (election.group === "modp3072") return MODP_3072;
  throw new Error(`unknown group "${election.group}"`);
}

/** Parse a ballot from its public JSON form, with the same range checks as the server. */
export function ballotFromWire(group, wire) {
  const element = (text, label) => {
    const bytes = fromBase64Url(String(text));
    if (bytes.length !== group.pByteLength) throw new Error(`${label}: wrong length`);
    const value = os2ip(bytes);
    if (value <= 0n || value >= group.p) throw new Error(`${label}: out of range`);
    return value;
  };
  const scalar = (text, label) => {
    const bytes = fromBase64Url(String(text));
    if (bytes.length !== group.qByteLength) throw new Error(`${label}: wrong length`);
    const value = os2ip(bytes);
    if (value < 0n || value >= group.q) throw new Error(`${label}: out of range`);
    return value;
  };
  const proof = (input, label) => {
    if (!Array.isArray(input?.branches) || input.branches.length === 0) {
      throw new Error(`${label}: missing branches`);
    }
    return {
      branches: input.branches.map((b, i) => ({
        commitment1: element(b.commitment1, `${label}[${i}].commitment1`),
        commitment2: element(b.commitment2, `${label}[${i}].commitment2`),
        challenge: scalar(b.challenge, `${label}[${i}].challenge`),
        response: scalar(b.response, `${label}[${i}].response`),
      })),
    };
  };
  if (!Array.isArray(wire?.choices) || !Array.isArray(wire?.choiceProofs)) {
    throw new Error("ballot: choices and choiceProofs must be arrays");
  }
  if (wire.choices.length !== wire.choiceProofs.length) {
    throw new Error("ballot: choice and proof counts differ");
  }
  return {
    electionId: String(wire.electionId),
    ballotId: String(wire.ballotId),
    credentialFingerprint: String(wire.credentialFingerprint),
    choices: wire.choices.map((ct, i) => ({
      alpha: element(ct.alpha, `choices[${i}].alpha`),
      beta: element(ct.beta, `choices[${i}].beta`),
    })),
    choiceProofs: wire.choiceProofs.map((p, i) => proof(p, `choiceProofs[${i}]`)),
    aggregateProof: proof(wire.aggregateProof, "aggregateProof"),
  };
}

function auditSecretFromWire(group, wire) {
  if (!Array.isArray(wire?.selections) || !Array.isArray(wire?.randomness)) {
    throw new Error("audit data: selections and randomness must be arrays");
  }
  return {
    ballotId: String(wire.ballotId),
    selections: wire.selections.map((s) => {
      if (s !== 0 && s !== 1) throw new Error("audit data: selection must be 0 or 1");
      return s;
    }),
    randomness: wire.randomness.map((text, i) => {
      const bytes = fromBase64Url(String(text));
      if (bytes.length !== group.qByteLength) throw new Error(`audit data: randomness ${i} has the wrong length`);
      const value = os2ip(bytes);
      if (value <= 0n || value >= group.q) throw new Error(`audit data: randomness ${i} is out of range`);
      return value;
    }),
  };
}

function electionParameters(election) {
  return {
    electionId: election.electionId,
    candidates: election.candidates,
    minSelections: election.minSelections,
    maxSelections: election.maxSelections,
  };
}

// --- the two checks -------------------------------------------------------------

/**
 * Shared first half: the receipt is a real inclusion under a validator quorum,
 * and the entry it proves is the one this link is about.
 */
async function locate(receipt, election, link, expectedKind) {
  const result = await verifyBallotReceipt(receipt, election);
  const steps = result.steps.map((step) => ({ id: "record", ok: step.ok, detail: `${step.label}: ${step.detail ?? ""}` }));
  const recorded = { id: "recorded", ok: result.ok, detail: `block ${receipt.blockHeight}` };
  if (!result.ok) return { fail: { ok: false, steps: [...steps, recorded] } };

  let entry;
  try {
    entry = decodeLeaf(fromBase64Url(receipt.leaf));
  } catch (error) {
    return { fail: { ok: false, steps: [recorded, { id: "entry", ok: false, detail: error.message }] } };
  }
  if (entry.kind !== expectedKind || entry.id !== link.ballotId) {
    return {
      fail: {
        ok: false,
        steps: [recorded, { id: "entry", ok: false, detail: `the proven entry is ${entry.kind}/${entry.id}` }],
      },
    };
  }
  if (election.electionId !== link.electionId) {
    return { fail: { ok: false, steps: [recorded, { id: "election", ok: false, detail: election.electionId }] } };
  }
  return { entry, recorded };
}

/**
 * A CAST ballot: is the ballot sealed on the board exactly the one whose
 * commitment the voter's screen showed before casting?
 *
 * Detects a voting device that showed one ballot and cast another.
 */
export async function checkCast(receipt, election, link) {
  const located = await locate(receipt, election, link, "ballot");
  if (located.fail) return located.fail;

  const group = groupFor(election);
  let ballot;
  try {
    ballot = ballotFromWire(group, JSON.parse(new TextDecoder().decode(located.entry.data)));
  } catch (error) {
    return { ok: false, steps: [located.recorded, { id: "matches", ok: false, detail: error.message }] };
  }
  const publicKey = { group, y: os2ip(fromBase64Url(election.electionPublicKey)) };
  const actual = await ballotCommitment(publicKey, ballot);
  const matches = actual === link.commitment;
  return {
    ok: matches,
    steps: [
      located.recorded,
      {
        id: "matches",
        ok: matches,
        detail: matches ? checkCode(actual) : `sealed ${checkCode(actual)}, shown ${checkCode(link.commitment)}`,
      },
    ],
  };
}

/**
 * A TESTED ballot: does the ballot the voter's screen committed to really
 * contain what the voting device later claimed? Returns the selections the
 * ballot provably encodes, for the voter to compare with what they chose.
 *
 * Detects a voting device that encrypted a different choice.
 */
export async function checkTested(receipt, election, link) {
  const located = await locate(receipt, election, link, "spoiled-ballot");
  if (located.fail) return located.fail;

  const group = groupFor(election);
  let ballot;
  let secret;
  try {
    const record = JSON.parse(new TextDecoder().decode(located.entry.data));
    ballot = ballotFromWire(group, record.ballot);
    secret = auditSecretFromWire(group, record.audit);
  } catch (error) {
    return { ok: false, steps: [located.recorded, { id: "opened", ok: false, detail: error.message }] };
  }

  const publicKey = { group, y: os2ip(fromBase64Url(election.electionPublicKey)) };
  // No expectedSelections: the phone does not know what the voter chose, and
  // must not be told by the voting device. It shows what the ballot contains;
  // the voter is the only one who can say whether that is what they chose.
  const audit = await auditAgainstCommitment(
    electionParameters(election), publicKey, ballot, secret, link.commitment,
  );
  return {
    ok: audit.ok,
    encodedSelections: audit.ok ? [...audit.encodedSelections] : null,
    steps: [located.recorded, { id: "opened", ok: audit.ok, detail: audit.reason ?? checkCode(link.commitment) }],
  };
}
