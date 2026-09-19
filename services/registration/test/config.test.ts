import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { loadConfig, redactedSummary } from "../src/config.ts";
import { deriveIdentityHash } from "../src/identity.ts";
import {
  ElectoralRollVerifier,
  InMemoryElectoralRollStore,
} from "../src/eligibility/electoral-roll.ts";
import {
  generateEnrolmentCode,
  hashEnrolmentCode,
  isWellFormedEnrolmentCode,
  normaliseEnrolmentCode,
} from "../src/eligibility/enrolment-code.ts";
import { BASE_ENV, testConfig } from "./helpers.ts";

describe("configuration", () => {
  it("rejects a short identity pepper", () => {
    assert.throws(
      () => loadConfig({ ...BASE_ENV, IDENTITY_PEPPER: "too-short" } as NodeJS.ProcessEnv),
      /IDENTITY_PEPPER/,
    );
  });

  it("requires a database url when using postgres", () => {
    assert.throws(
      () =>
        loadConfig({
          ...BASE_ENV,
          STORAGE_DRIVER: "postgres",
          DATABASE_URL: undefined,
        } as NodeJS.ProcessEnv),
      /DATABASE_URL is required/,
    );
  });

  it("refuses in-memory storage in production", () => {
    assert.throws(
      () =>
        loadConfig({
          ...BASE_ENV,
          NODE_ENV: "production",
          STORAGE_DRIVER: "memory",
        } as NodeJS.ProcessEnv),
      /loses every issued credential/,
    );
  });

  it("does not trust X-Forwarded-For by default", () => {
    assert.equal(testConfig().TRUST_PROXY, false);
  });

  it("redacts every secret in the loggable summary", () => {
    const summary = JSON.stringify(redactedSummary(testConfig()));
    assert.ok(!summary.includes(BASE_ENV.IDENTITY_PEPPER));
    assert.ok(!summary.includes(BASE_ENV.REGISTRATION_TOKEN_SECRET));
    assert.ok(summary.includes("[redacted]"));
  });
});

describe("identity hashing", () => {
  const PEPPER = "a-pepper-that-is-long-enough-for-testing";

  it("is deterministic for the same person and election", async () => {
    const a = await deriveIdentityHash(PEPPER, "e1", "123456789012");
    const b = await deriveIdentityHash(PEPPER, "e1", "123456789012");
    assert.deepEqual(Array.from(a), Array.from(b));
  });

  it("separates elections so participation cannot be cross-referenced", async () => {
    const a = await deriveIdentityHash(PEPPER, "e1", "123456789012");
    const b = await deriveIdentityHash(PEPPER, "e2", "123456789012");
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it("changes completely when the pepper changes", async () => {
    const a = await deriveIdentityHash(PEPPER, "e1", "123456789012");
    const b = await deriveIdentityHash(`${PEPPER}-rotated`, "e1", "123456789012");
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it("is not vulnerable to boundary ambiguity between election and subject", async () => {
    // Without length-prefixing, ("ab","c") and ("a","bc") would concatenate to
    // the same input and collide -- silently blocking a legitimate voter.
    const a = await deriveIdentityHash(PEPPER, "ab", "c");
    const b = await deriveIdentityHash(PEPPER, "a", "bc");
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it("does not contain the raw subject id", async () => {
    const hash = await deriveIdentityHash(PEPPER, "e1", "123456789012");
    assert.ok(!Buffer.from(hash).toString("utf8").includes("123456789012"));
    assert.equal(hash.length, 32);
  });
});

describe("enrolment codes", () => {
  const PEPPER = "a-pepper-that-is-long-enough-for-testing";

  it("generates well-formed, grouped codes", () => {
    for (let i = 0; i < 20; i++) {
      const code = generateEnrolmentCode();
      assert.ok(isWellFormedEnrolmentCode(code), `malformed: ${code}`);
      assert.equal(normaliseEnrolmentCode(code).length, 32);
      assert.match(code, /^[0-9A-Z-]+$/);
    }
  });

  it("never emits the ambiguous characters I, L, O or U", () => {
    // These get misread as 1, 1, 0 and V on a printed polling card.
    for (let i = 0; i < 50; i++) {
      assert.ok(!/[ILOU]/.test(generateEnrolmentCode()));
    }
  });

  it("is unpredictable", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(generateEnrolmentCode());
    assert.equal(seen.size, 200);
  });

  it("forgives the substitutions people actually make", () => {
    // A voter who types lowercase l for 1 must not be told they cannot vote.
    const canonical = normaliseEnrolmentCode("0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ");
    assert.equal(normaliseEnrolmentCode("0123 4567 89ab cdef ghjk mnpq rstv wxyz"), canonical);
    assert.equal(
      normaliseEnrolmentCode("O123-4567-89AB-CDEF-GHJK-MNPQ-RSTU-WXYZ"),
      normaliseEnrolmentCode("0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ"),
    );
  });

  it("binds the code to its roll id", async () => {
    // A code lifted from one polling card must not work on another.
    const code = generateEnrolmentCode();
    const forRollA = await hashEnrolmentCode(PEPPER, "R-1", code);
    const forRollB = await hashEnrolmentCode(PEPPER, "R-2", code);
    assert.notDeepEqual(Array.from(forRollA), Array.from(forRollB));
  });

  it("changes completely with the pepper", async () => {
    const code = generateEnrolmentCode();
    const a = await hashEnrolmentCode(PEPPER, "R-1", code);
    const b = await hashEnrolmentCode(`${PEPPER}-rotated`, "R-1", code);
    assert.notDeepEqual(Array.from(a), Array.from(b));
  });

  it("does not store the code itself", async () => {
    const code = generateEnrolmentCode();
    const hash = await hashEnrolmentCode(PEPPER, "R-1", code);
    assert.ok(!Buffer.from(hash).toString("utf8").includes(normaliseEnrolmentCode(code)));
    assert.equal(hash.length, 32);
  });
});

describe("electoral roll verifier", () => {
  const PEPPER = "a-pepper-that-is-long-enough-for-testing";
  const ELECTION = "roll-test";

  async function setup() {
    const store = new InMemoryElectoralRollStore();
    const verifier = new ElectoralRollVerifier({ store, pepper: PEPPER, electionId: ELECTION });
    const enrol = async (rollId: string) => {
      const enrolmentCode = generateEnrolmentCode();
      await store.addEntry({
        rollId,
        electionId: ELECTION,
        enrolmentCodeHash: await hashEnrolmentCode(PEPPER, rollId, enrolmentCode),
      });
      return { rollId, enrolmentCode };
    };
    return { store, verifier, enrol };
  }

  it("accepts a voter on the roll", async () => {
    const { verifier, enrol } = await setup();
    const card = await enrol("R-1");
    const result = await verifier.verify(card);
    assert.ok(result.ok);
    assert.equal(result.subjectId, "R-1");
  });

  it("accepts a code typed with spaces and lowercase", async () => {
    const { verifier, enrol } = await setup();
    const card = await enrol("R-1");
    const result = await verifier.verify({
      rollId: "R-1",
      enrolmentCode: card.enrolmentCode.toLowerCase().replace(/-/g, " "),
    });
    assert.ok(result.ok);
  });

  it("REJECTS a voter not on the roll", async () => {
    const { verifier } = await setup();
    const result = await verifier.verify({
      rollId: "R-nobody",
      enrolmentCode: generateEnrolmentCode(),
    });
    assert.ok(!result.ok);
  });

  it("REJECTS the wrong code for a real roll entry", async () => {
    const { verifier, enrol } = await setup();
    await enrol("R-1");
    const result = await verifier.verify({
      rollId: "R-1",
      enrolmentCode: generateEnrolmentCode(),
    });
    assert.ok(!result.ok);
  });

  it("REJECTS a code replayed against a different roll number", async () => {
    const { verifier, enrol } = await setup();
    const cardA = await enrol("R-1");
    await enrol("R-2");
    const result = await verifier.verify({
      rollId: "R-2",
      enrolmentCode: cardA.enrolmentCode,
    });
    assert.ok(!result.ok);
  });

  it("REJECTS a revoked entry", async () => {
    const { store, verifier, enrol } = await setup();
    const card = await enrol("R-1");
    assert.ok((await verifier.verify(card)).ok);

    assert.equal(await store.revokeEntry(ELECTION, "R-1"), true);
    assert.ok(!(await verifier.verify(card)).ok);
  });

  it("gives an IDENTICAL failure for every rejection reason", async () => {
    // The endpoint must not become an oracle for enumerating the electoral roll.
    const { store, verifier, enrol } = await setup();
    const good = await enrol("R-1");
    await enrol("R-2");
    await store.revokeEntry(ELECTION, "R-2");

    const unknown = await verifier.verify({ rollId: "R-nobody", enrolmentCode: good.enrolmentCode });
    const wrongCode = await verifier.verify({ rollId: "R-1", enrolmentCode: generateEnrolmentCode() });
    const revoked = await verifier.verify({ rollId: "R-2", enrolmentCode: good.enrolmentCode });

    assert.deepEqual(unknown, wrongCode);
    assert.deepEqual(unknown, revoked);
  });

  it("scopes the roll to its election", async () => {
    const { store, verifier } = await setup();
    const code = generateEnrolmentCode();
    await store.addEntry({
      rollId: "R-1",
      electionId: "a-different-election",
      enrolmentCodeHash: await hashEnrolmentCode(PEPPER, "R-1", code),
    });
    assert.ok(!(await verifier.verify({ rollId: "R-1", enrolmentCode: code })).ok);
  });

  it("refuses a weak pepper", () => {
    assert.throws(
      () =>
        new ElectoralRollVerifier({
          store: new InMemoryElectoralRollStore(),
          pepper: "short",
          electionId: ELECTION,
        }),
      /at least 32/,
    );
  });

  it("refuses to enrol the same roll number twice", async () => {
    // A duplicate would mean one person receives two credentials.
    const { enrol } = await setup();
    await enrol("R-1");
    await assert.rejects(() => enrol("R-1"), /already exists/);
  });
});
