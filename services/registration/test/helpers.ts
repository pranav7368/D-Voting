import { LocalBlindSigner, RSABSSA_SHA384_PSS_DETERMINISTIC } from "@dvoting/crypto";
import { generateIssuerKeyPair } from "@dvoting/crypto/keygen";

import { createApp, type AppDependencies } from "../src/app.ts";
import { loadConfig, type Config } from "../src/config.ts";
import {
  ElectoralRollVerifier,
  InMemoryElectoralRollStore,
} from "../src/eligibility/electoral-roll.ts";
import { generateEnrolmentCode, hashEnrolmentCode } from "../src/eligibility/enrolment-code.ts";
import { InMemoryVoterRepository } from "../src/repo/memory.ts";

export const TEST_SUITE = RSABSSA_SHA384_PSS_DETERMINISTIC;

/** 2048-bit keys keep the test suite fast; production defaults to 3072. */
export const issuerKeys = generateIssuerKeyPair(2048, TEST_SUITE);

export const BASE_ENV = {
  NODE_ENV: "test",
  ELECTION_ID: "election-2026-demo",
  ISSUER_PRIVATE_KEY_JWK: "{}",
  IDENTITY_PEPPER: "test-pepper-that-is-long-enough-to-pass-validation",
  REGISTRATION_TOKEN_SECRET: "test-token-secret-that-is-long-enough-ok",
  STORAGE_DRIVER: "memory",
  RATE_LIMIT_MAX_REQUESTS: "1000",
} as const;

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({ ...BASE_ENV, ...overrides } as NodeJS.ProcessEnv);
}

export interface TestHarness {
  app: ReturnType<typeof createApp>;
  repository: InMemoryVoterRepository;
  roll: InMemoryElectoralRollStore;
  config: Config;
  deps: AppDependencies;
  /** Add a voter to the roll and return their polling-card details. */
  enrol(rollId?: string): Promise<{ rollId: string; enrolmentCode: string }>;
}

export function createHarness(overrides: Record<string, string> = {}): TestHarness {
  const config = testConfig(overrides);
  const repository = new InMemoryVoterRepository();
  const roll = new InMemoryElectoralRollStore();

  const deps: AppDependencies = {
    config,
    repository,
    eligibilityVerifier: new ElectoralRollVerifier({
      store: roll,
      pepper: config.IDENTITY_PEPPER,
      electionId: config.ELECTION_ID,
    }),
    signer: new LocalBlindSigner(issuerKeys.privateKey),
    // Roll administration is only wired up when a token is also configured, so
    // supplying the store here is harmless for tests that do not use it.
    rollStore: roll,
  };

  return {
    app: createApp(deps),
    repository,
    roll,
    config,
    deps,
    async enrol(rollId = nextRollId()) {
      const enrolmentCode = generateEnrolmentCode();
      await roll.addEntry({
        rollId,
        electionId: config.ELECTION_ID,
        enrolmentCodeHash: await hashEnrolmentCode(config.IDENTITY_PEPPER, rollId, enrolmentCode),
      });
      return { rollId, enrolmentCode };
    },
  };
}

export async function postJson(
  app: TestHarness["app"],
  path: string,
  body: unknown,
): Promise<Response> {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Enrol a fresh voter on the roll and register them in one step. */
export async function registerNewVoter(harness: TestHarness): Promise<Response> {
  const card = await harness.enrol();
  return postJson(harness.app, "/v1/register", card);
}

/** A distinct roll number per test. */
let rollCounter = 100_000;
export function nextRollId(): string {
  rollCounter += 1;
  return `R-${rollCounter}`;
}
