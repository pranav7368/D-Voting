import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  checkpointFromWire,
  checkpointToWire,
  encodeCheckpoint,
  generateValidatorKeyPair,
  signCheckpoint,
  verifyCheckpoint,
  type Checkpoint,
} from "../src/index.ts";

const base: Checkpoint = {
  electionId: "e-2026",
  height: 7,
  headHash: new Uint8Array(32).fill(7),
  genesisHash: new Uint8Array(32).fill(1),
  witnessedAt: "2026-10-16T10:00:00.000Z",
};

describe("witness checkpoints", () => {
  it("verifies a checkpoint signed by the named witness", async () => {
    const witness = await generateValidatorKeyPair("agent-a");
    const signed = await signCheckpoint(base, "agent-a", witness.privateKey);
    assert.equal(await verifyCheckpoint(signed, witness.identity), true);
  });

  it("REJECTS any change to what was signed", async () => {
    const witness = await generateValidatorKeyPair("agent-a");
    const signed = await signCheckpoint(base, "agent-a", witness.privateKey);
    const variants: Checkpoint[] = [
      { ...base, height: 8 },
      { ...base, headHash: new Uint8Array(32).fill(9) },
      { ...base, genesisHash: new Uint8Array(32).fill(2) },
      { ...base, electionId: "e-2027" },
      { ...base, witnessedAt: "2026-10-16T10:00:01.000Z" },
    ];
    for (const checkpoint of variants) {
      assert.equal(await verifyCheckpoint({ ...signed, checkpoint }, witness.identity), false);
    }
  });

  it("REJECTS a signature re-attributed to another witness", async () => {
    // The witness id is inside the signed bytes, so claiming someone else
    // signed it fails even if both use the same key.
    const witness = await generateValidatorKeyPair("agent-a");
    const signed = await signCheckpoint(base, "agent-a", witness.privateKey);
    const borrowed = { id: "agent-b", publicKey: witness.identity.publicKey };
    assert.equal(await verifyCheckpoint({ ...signed, witness: "agent-b" }, borrowed), false);
  });

  it("REJECTS a checkpoint signed by a different key", async () => {
    const real = await generateValidatorKeyPair("agent-a");
    const impostor = await generateValidatorKeyPair("agent-a");
    const signed = await signCheckpoint(base, "agent-a", impostor.privateKey);
    assert.equal(await verifyCheckpoint(signed, real.identity), false);
  });

  it("round-trips through the wire format", async () => {
    const witness = await generateValidatorKeyPair("agent-a");
    const signed = await signCheckpoint(base, "agent-a", witness.privateKey);
    const back = checkpointFromWire(JSON.parse(JSON.stringify(checkpointToWire(signed))));
    assert.equal(await verifyCheckpoint(back, witness.identity), true);
    assert.deepEqual(back.checkpoint, base);
  });

  it("refuses malformed input instead of guessing", () => {
    assert.throws(() => checkpointFromWire(null));
    assert.throws(() => checkpointFromWire({ ...checkpointToWireLike(), height: 0 }));
    assert.throws(() => checkpointFromWire({ ...checkpointToWireLike(), headHash: "AAAA" }));
    assert.throws(() => encodeCheckpoint({ ...base, height: 0 }, "agent-a"));
  });
});

function checkpointToWireLike() {
  return {
    witness: "agent-a",
    electionId: "e-2026",
    height: 1,
    headHash: "B".repeat(43),
    genesisHash: "C".repeat(43),
    witnessedAt: "2026-10-16T10:00:00.000Z",
    signature: "D".repeat(86),
  };
}
