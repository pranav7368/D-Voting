/**
 * Registration Authority entry point.
 *
 * TLS: this process speaks plain HTTP and expects TLS 1.3 to be terminated at
 * the load balancer / reverse proxy, with mTLS between internal services. Do not
 * expose this port directly to the internet.
 */

import { serve } from "@hono/node-server";
import pg from "pg";
import { LocalBlindSigner, computeKeyId, fromBase64Url } from "@dvoting/crypto";
import { RSABSSA_SHA384_PSS_DETERMINISTIC } from "@dvoting/crypto";
import { privateKeyFromJwk, type RsaPrivateJwk } from "@dvoting/crypto/keygen";

import { createApp } from "./app.ts";
import { loadConfig, redactedSummary } from "./config.ts";
import {
  ElectoralRollVerifier,
  InMemoryElectoralRollStore,
  type ElectoralRollStore,
} from "./eligibility/electoral-roll.ts";
import { PostgresElectoralRollStore } from "./eligibility/postgres-roll.ts";
import { InMemoryVoterRepository } from "./repo/memory.ts";
import { PostgresVoterRepository } from "./repo/postgres.ts";
import type { VoterRepository } from "./repo/types.ts";

async function main(): Promise<void> {
  const config = loadConfig();

  let jwk: RsaPrivateJwk;
  try {
    jwk = JSON.parse(config.ISSUER_PRIVATE_KEY_JWK) as RsaPrivateJwk;
  } catch {
    throw new Error("ISSUER_PRIVATE_KEY_JWK is not valid JSON. Generate one with `npm run keygen`.");
  }

  // privateKeyFromJwk runs a full consistency check on the CRT parameters and
  // throws if anything is off -- we never serve traffic with a suspect key.
  const privateKey = privateKeyFromJwk(jwk, RSABSSA_SHA384_PSS_DETERMINISTIC);
  const signer = new LocalBlindSigner(privateKey);

  const repository: VoterRepository =
    config.STORAGE_DRIVER === "postgres"
      ? new PostgresVoterRepository(config.DATABASE_URL!)
      : new InMemoryVoterRepository();

  // The electoral roll shares the RA's pepper; the two uses are domain-separated
  // inside their respective HMAC inputs, so one cannot be used to attack the other.
  let rollPool: pg.Pool | undefined;
  let rollStore: ElectoralRollStore;
  if (config.STORAGE_DRIVER === "postgres") {
    rollPool = new pg.Pool({ connectionString: config.DATABASE_URL!, max: 5 });
    rollStore = new PostgresElectoralRollStore(rollPool);
  } else {
    rollStore = new InMemoryElectoralRollStore();

    // Local development: seed the in-memory roll from a file, since a separate
    // import process cannot reach this one's memory. Only HMACs are stored.
    if (config.ROLL_SEED_FILE) {
      const { readFile } = await import("node:fs/promises");
      const seed = JSON.parse(await readFile(config.ROLL_SEED_FILE, "utf8")) as {
        entries: { rollId: string; enrolmentCodeHash: string }[];
      };
      for (const entry of seed.entries) {
        await rollStore.addEntry({
          rollId: entry.rollId,
          electionId: config.ELECTION_ID,
          enrolmentCodeHash: fromBase64Url(entry.enrolmentCodeHash),
        });
      }
    }
  }

  const eligibilityVerifier = new ElectoralRollVerifier({
    store: rollStore,
    pepper: config.IDENTITY_PEPPER,
    electionId: config.ELECTION_ID,
  });

  const app = createApp({ config, repository, eligibilityVerifier, signer, rollStore });

  console.log("[registration] starting", redactedSummary(config));
  console.log("[registration] issuer keyId", await computeKeyId(signer.publicKey));
  console.log(
    `[registration] electoral roll: ${await rollStore.countEntries(config.ELECTION_ID)} entries`,
  );

  const server = serve({ fetch: app.fetch, port: config.PORT }, (info) => {
    console.log(`[registration] listening on http://localhost:${info.port}`);
  });

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`[registration] ${signal} received, shutting down`);
    server.close();
    await repository.close();
    await rollPool?.end();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error: unknown) => {
  console.error("[registration] failed to start:", error instanceof Error ? error.message : error);
  process.exit(1);
});
