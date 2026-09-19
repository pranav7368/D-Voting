/**
 * What a trustee checks before it lends its share.
 *
 * A trustee that decrypts whatever it is handed is a rubber stamp, and five
 * rubber stamps are worth no more than one. So the interesting tests here are
 * the refusals: a ballot box that inflates a total, one that drops a ballot,
 * one serving a different election, and a share that does not match the roster
 * sealed on the chain.
 *
 * The ballot box is a stub. That is deliberate -- these tests are about what the
 * trustee does when the ballot box LIES, which a real one will not do on
 * request.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  MODP_2048,
  addCiphertexts,
  encodeElement,
  encrypt,
  groupExp,
  os2ip,
  randomScalar,
  setupTrustees,
  toBase64Url,
  type Ciphertext,
} from "@dvoting/crypto";
import {
  DistributedSealer,
  InMemoryBlockStore,
  Ledger,
  LocalValidatorPeer,
  ValidatorNode,
  blockToWire,
  createValidatorSet,
  generateValidatorKeyPair,
  nextSealRequest,
  type LedgerEntry,
} from "@dvoting/ledger";

import { Trustee, TrusteeServiceError } from "../src/trustee.ts";

const GROUP = MODP_2048;
const ELECTION_ID = "trustee-test";
const CANDIDATES = ["Alice", "Bob"];
const THRESHOLD = 2;
const TOTAL = 3;

const trustees = setupTrustees(GROUP, THRESHOLD, TOTAL);

const element = (value: bigint): string => toBase64Url(encodeElement(GROUP, value));
const wireCiphertext = (ct: Ciphertext) => ({ alpha: element(ct.alpha), beta: element(ct.beta) });

interface Fixture {
  /** Blocks as the bulletin board serves them. */
  blocks: unknown[];
  validators: { id: string; publicKey: string }[];
  quorum: number;
  totals: Ciphertext[];
  ballotCount: number;
}

/**
 * Build a real, quorum-signed chain: config block, one block of ballots, and a
 * close record. Nothing here is faked -- the trustee has to be able to verify
 * it, so it has to be genuine.
 */
async function buildChain(votes: number[][]): Promise<Fixture> {
  const keyPairs = [];
  for (const id of ["commission", "press", "university"]) {
    keyPairs.push(await generateValidatorKeyPair(id));
  }
  const validatorSet = createValidatorSet(keyPairs.map((k) => k.identity));

  const nodes = keyPairs.map(
    (keyPair) =>
      new ValidatorNode({
        identity: keyPair.identity,
        privateKey: keyPair.privateKey,
        ledger: new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION_ID),
      }),
  );
  const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION_ID);
  const sealer = new DistributedSealer(ledger, nodes.map((node) => new LocalValidatorPeer(node)));

  const seal = async (entries: LedgerEntry[]) => {
    const block = await sealer.seal(await nextSealRequest(ledger, ELECTION_ID, entries));
    await ledger.append(block);
    await sealer.broadcastCommit?.(block);
  };

  const encoded = (value: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(value));

  await seal([
    {
      kind: "election-config",
      id: ELECTION_ID,
      data: encoded({
        recordVersion: "dvoting/election-config/v1",
        electionId: ELECTION_ID,
        candidates: CANDIDATES,
        trustees: {
          threshold: THRESHOLD,
          total: TOTAL,
          publicShares: trustees.publicShares.map((share) => ({
            index: share.index,
            publicShare: element(share.publicShare),
          })),
        },
      }),
    },
  ]);

  // One ballot per voter, each a column of ciphertexts.
  const ballots: Ciphertext[][] = [];
  const entries: LedgerEntry[] = [];
  for (const [index, selections] of votes.entries()) {
    const choices = selections.map(
      (selection) => encrypt(trustees.publicKey, BigInt(selection)).ciphertext,
    );
    ballots.push(choices);
    entries.push({
      kind: "ballot",
      id: `ballot-${index}`,
      data: encoded({
        credentialFingerprint: `voter-${index}`,
        choices: choices.map(wireCiphertext),
      }),
    });
  }
  await seal(entries);
  await seal([
    { kind: "election-closed", id: ELECTION_ID, data: encoded({ closedAt: new Date().toISOString() }) },
  ]);

  const totals = CANDIDATES.map((_, candidate) =>
    addCiphertexts(GROUP, ballots.map((choices) => choices[candidate]!)),
  );

  return {
    blocks: (await ledger.blocks()).map(blockToWire),
    validators: validatorSet.validators.map((v) => ({ id: v.id, publicKey: toBase64Url(v.publicKey) })),
    quorum: validatorSet.quorum,
    totals,
    ballotCount: votes.length,
  };
}

/** A ballot box that answers whatever the test tells it to. */
function stubBox(
  fixture: Fixture,
  overrides: {
    totals?: Ciphertext[];
    ballotsCounted?: number;
    electionId?: string;
    submitted?: number[];
    blocks?: unknown[];
  } = {},
): { fetchImpl: typeof fetch; submissions: unknown[] } {
  const submissions: unknown[] = [];
  const blocks = overrides.blocks ?? fixture.blocks;

  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;

    if (path === "/v1/ceremony") {
      return json({
        phase: "awaiting-trustees",
        threshold: THRESHOLD,
        total: TOTAL,
        submitted: overrides.submitted ?? [],
        candidates: CANDIDATES,
        ballotsCounted: overrides.ballotsCounted ?? fixture.ballotCount,
        encryptedTotals: (overrides.totals ?? fixture.totals).map(wireCiphertext),
        message: "",
      });
    }
    if (path === "/v1/election") {
      return json({
        electionId: overrides.electionId ?? ELECTION_ID,
        validators: fixture.validators,
        quorum: fixture.quorum,
      });
    }
    if (path === "/v1/bulletin/head") return json({ height: blocks.length });
    if (path.startsWith("/v1/bulletin/blocks/")) {
      const height = Number(path.split("/").pop());
      const block = blocks[height];
      return block ? json(block) : json({ error: "not_found" }, 404);
    }
    if (path === "/v1/ceremony/shares") {
      submissions.push(JSON.parse(String(init?.body)));
      return json({ accepted: true, submitted: [1], outstanding: 1, published: false }, 201);
    }
    return json({ error: "not_found" }, 404);
  }) as unknown as typeof fetch;

  return { fetchImpl, submissions };
}

function trusteeFor(index: number, fetchImpl: typeof fetch, share?: bigint): Trustee {
  return new Trustee({
    electionId: ELECTION_ID,
    group: GROUP,
    index,
    share: share ?? trustees.keyShares.find((s) => s.index === index)!.share,
    ballotBoxUrl: "http://ballot-box.test",
    fetchImpl,
  });
}

describe("a trustee verifies before it decrypts", () => {
  it("contributes when everything checks out, and says what it checked", async () => {
    const fixture = await buildChain([[1, 0], [1, 0], [0, 1]]);
    const box = stubBox(fixture);

    const result = await trusteeFor(1, box.fetchImpl).participate();

    assert.equal(result.index, 1);
    assert.equal(result.candidates, 2);
    assert.equal(box.submissions.length, 1);
    assert.deepEqual(result.verified, [
      "Re-verified 3 blocks against a 3-signature quorum",
      "Confirmed this share matches trustee 1 in the sealed roster",
      "Confirmed voting is closed on the chain",
      "Recomputed all 2 encrypted totals from 3 counted ballots",
    ]);
  });

  it("REFUSES a total that is not the sum of the ballots on the chain", async () => {
    // The attack: a ballot box that inflates one candidate's total and hopes
    // the trustees decrypt whatever they are handed.
    const fixture = await buildChain([[1, 0], [0, 1]]);
    const inflated = [...fixture.totals];
    inflated[0] = addCiphertexts(GROUP, [
      inflated[0]!,
      encrypt(trustees.publicKey, 5n).ciphertext,
    ]);

    const box = stubBox(fixture, { totals: inflated });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      (error: TrusteeServiceError) => error.code === "totals_mismatch",
    );
    assert.equal(box.submissions.length, 0, "the trustee submitted despite the mismatch");
  });

  it("REFUSES when the ballot box misreports how many ballots were counted", async () => {
    const fixture = await buildChain([[1, 0], [0, 1]]);
    const box = stubBox(fixture, { ballotsCounted: 7 });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      (error: TrusteeServiceError) => error.code === "totals_mismatch",
    );
  });

  it("REFUSES a chain whose blocks do not carry a quorum", async () => {
    // Stripping attestations is the cheapest way to slip an extra ballot in.
    const fixture = await buildChain([[1, 0], [0, 1]]);
    const tampered = fixture.blocks.map((block, index) =>
      index === 1 ? { ...(block as Record<string, unknown>), attestations: [] } : block,
    );
    const box = stubBox(fixture, { blocks: tampered });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      (error: TrusteeServiceError) => error.code === "chain_invalid",
    );
  });

  it("REFUSES an election it does not hold a share for", async () => {
    const fixture = await buildChain([[1, 0]]);
    const box = stubBox(fixture, { electionId: "some-other-election" });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      (error: TrusteeServiceError) => error.code === "wrong_election",
    );
  });

  it("REFUSES when its own share does not match the sealed roster", async () => {
    // Catches a misconfigured trustee before it produces partials that cannot
    // combine -- a failure that would otherwise surface only at the very end.
    const fixture = await buildChain([[1, 0]]);
    const box = stubBox(fixture);

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl, randomScalar(GROUP)).participate(),
      (error: TrusteeServiceError) => error.code === "share_mismatch",
    );
  });

  it("REFUSES a chain with no sealed election configuration", async () => {
    const fixture = await buildChain([[1, 0]]);
    const box = stubBox(fixture, { blocks: fixture.blocks.slice(1) });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      // The chain no longer starts at genesis, so linkage fails first -- either
      // refusal is correct, and both stop the decryption.
      (error: TrusteeServiceError) =>
        error.code === "no_config" || error.code === "chain_invalid",
    );
  });

  it("does not submit twice", async () => {
    const fixture = await buildChain([[1, 0]]);
    const box = stubBox(fixture, { submitted: [1] });

    await assert.rejects(
      () => trusteeFor(1, box.fetchImpl).participate(),
      (error: TrusteeServiceError) => error.code === "already_submitted",
    );
  });
});

describe("what a trustee exposes", () => {
  it("publishes its public share and never its private one", async () => {
    const fixture = await buildChain([[1, 0]]);
    const box = stubBox(fixture);
    const trustee = trusteeFor(2, box.fetchImpl);

    const expected = element(groupExp(GROUP, GROUP.g, trustees.keyShares[1]!.share));
    assert.equal(trustee.publicShare, expected);

    // The private share is not recoverable from anything the object offers.
    const surface = JSON.stringify(Object.entries(trustee));
    assert.ok(!surface.includes(trustees.keyShares[1]!.share.toString(16)));
  });

  it("sends only the factor and its proof, never the share", async () => {
    const fixture = await buildChain([[1, 0], [0, 1]]);
    const box = stubBox(fixture);
    await trusteeFor(1, box.fetchImpl).participate();

    const body = JSON.stringify(box.submissions[0]);
    assert.ok(!body.includes(trustees.keyShares[0]!.share.toString(16)));
    assert.match(body, /"factor"/);
    assert.match(body, /"proof"/);

    // And what it did send is a real group element, not a placeholder.
    const submitted = box.submissions[0] as { partials: { factor: string }[] };
    const factor = os2ip(
      Uint8Array.from(atob(submitted.partials[0]!.factor.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
        c.charCodeAt(0),
      ),
    );
    assert.ok(factor > 1n && factor < GROUP.p);
  });
});
