/**
 * What a validator checks inside a block, beyond its structure.
 *
 * A validator that attests blocks without looking at the ballots in them is a
 * notary for whatever the ballot box hands it. So before attesting, every
 * validator re-verifies each cast ballot's zero-knowledge proofs against the
 * election definition sealed on ITS OWN replica, not against anything the
 * proposer says. A ballot box that slipped an invalid ballot past its own
 * checks still cannot get it sealed.
 *
 * Tested (spoiled) ballots are checked for shape only: a failed audit is
 * recorded on purpose, as evidence that a voting client misbehaved, so its
 * proofs may legitimately be invalid.
 *
 * Credentials are not re-checked here: the sealed record carries the issuer
 * key's fingerprint, not the key. The ballot box checks the blind signature;
 * the binding between credential and ballot is inside the proofs checked here.
 */

import {
  MODP_2048,
  MODP_3072,
  fromBase64Url,
  os2ip,
  verifyBallot,
  type ElGamalPublicKey,
  type ElectionParameters,
} from "@dvoting/crypto";
import type { EntryValidator, Ledger, LedgerEntry } from "@dvoting/ledger";

import { CONFIG_ENTRY_KIND, readElectionRecord } from "./election-record.ts";
import { ballotFromWire, type WireBallot } from "./wire.ts";

export function createBallotEntryValidator(ledger: Ledger, electionId: string): EntryValidator {
  // The sealed definition never changes, so it is read once and kept.
  let sealed: { election: ElectionParameters; publicKey: ElGamalPublicKey } | null = null;

  const definition = async () => {
    if (sealed) return sealed;
    const record = await readElectionRecord(ledger, electionId);
    if (!record) return null;
    const group = record.group === MODP_2048.name ? MODP_2048 : record.group === MODP_3072.name ? MODP_3072 : null;
    if (!group) throw new Error(`unknown group "${record.group}"`);
    sealed = {
      election: {
        electionId: record.electionId,
        candidates: record.candidates,
        minSelections: record.minSelections,
        maxSelections: record.maxSelections,
      },
      publicKey: { group, y: os2ip(fromBase64Url(record.electionPublicKey)) },
    };
    return sealed;
  };

  return async (entry: LedgerEntry) => {
    if (entry.kind === CONFIG_ENTRY_KIND) return { ok: true };
    if (entry.kind !== "ballot" && entry.kind !== "spoiled-ballot") return { ok: true };

    const def = await definition();
    if (!def) return { ok: false, reason: "a ballot cannot be sealed before the election definition" };

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(entry.data));
    } catch {
      return { ok: false, reason: "ballot entry is not valid JSON" };
    }
    const wire = (entry.kind === "spoiled-ballot" ? (parsed as { ballot?: WireBallot }).ballot : parsed) as WireBallot | undefined;
    let ballot;
    try {
      ballot = ballotFromWire(def.publicKey.group, wire as WireBallot);
    } catch (error) {
      return { ok: false, reason: `ballot is malformed: ${error instanceof Error ? error.message : String(error)}` };
    }
    if (ballot.ballotId !== entry.id) return { ok: false, reason: "ballot id does not match its entry" };
    if (ballot.electionId !== electionId) return { ok: false, reason: "ballot is for a different election" };
    if (entry.kind === "spoiled-ballot") return { ok: true };

    return (await verifyBallot(def.election, def.publicKey, ballot))
      ? { ok: true }
      : { ok: false, reason: "ballot failed zero-knowledge verification" };
  };
}
