/**
 * Witness entry point.
 *
 * Holds one secret, this witness's Ed25519 signing key (`WITNESS_PRIVATE_KEY`,
 * PKCS#8 base64url, generated with `npm run keygen --workspace
 * @dvoting/validator-node -- <id>`). Its public half is what the commission
 * seals into the election so devices know whose checkpoints to trust.
 *
 * In deployment a witness belongs to whoever is watching (a party, a
 * newspaper, a university) and runs on their own machine. `npm run dev` runs
 * three on one laptop, which proves the protocol and provides no independence.
 */

import { serve } from "@hono/node-server";
import { z } from "zod";
import { fromBase64Url } from "@dvoting/crypto";
import { InMemoryBlockStore, importPrivateKey, type BlockStore } from "@dvoting/ledger";
import { FileBlockStore } from "@dvoting/ledger/file-store";

import { createApp } from "./app.ts";
import { Witness } from "./witness.ts";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8110),
  WITNESS_ID: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/),
  WITNESS_PRIVATE_KEY: z.string().min(40),
  ELECTION_ID: z.string().min(1),
  BALLOT_BOX_URL: z.string().url(),
  /** Durable replica. Without it a restarted witness forgets what it saw. */
  CHAIN_PATH: z.string().optional(),
  /** Block 0's hash as published by the commission, if known. */
  GENESIS_HASH: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
  SYNC_INTERVAL_SECONDS: z.coerce.number().int().min(1).max(3600).default(5),
});

async function main(): Promise<void> {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  const config = parsed.data;
  if (config.NODE_ENV === "production" && !config.CHAIN_PATH) {
    // A witness that forgets on restart can be shown a rewritten history and
    // will not notice. Durability is the whole point.
    throw new Error("CHAIN_PATH is required in production");
  }

  const store: BlockStore = config.CHAIN_PATH
    ? await FileBlockStore.open(config.CHAIN_PATH)
    : new InMemoryBlockStore();

  const witness = await Witness.open({
    id: config.WITNESS_ID,
    privateKey: await importPrivateKey(fromBase64Url(config.WITNESS_PRIVATE_KEY)),
    electionId: config.ELECTION_ID,
    ballotBoxUrl: config.BALLOT_BOX_URL.replace(/\/$/, ""),
    store,
    ...(config.GENESIS_HASH ? { genesisPin: fromBase64Url(config.GENESIS_HASH) } : {}),
  });

  const tick = () =>
    witness.sync().catch((error: unknown) => {
      // Unreachable board: not an alarm. Try again next tick.
      console.warn(`[witness ${config.WITNESS_ID}] sync failed: ${error instanceof Error ? error.message : error}`);
    });
  await tick();
  setInterval(tick, config.SYNC_INTERVAL_SECONDS * 1000).unref();

  const app = createApp({ witness, store });
  console.log("[witness] starting", {
    id: config.WITNESS_ID,
    electionId: config.ELECTION_ID,
    ballotBox: config.BALLOT_BOX_URL,
    durable: Boolean(config.CHAIN_PATH),
    pinned: Boolean(config.GENESIS_HASH),
    privateKey: "[redacted]",
  });
  const server = serve({ fetch: app.fetch, port: config.PORT }, (info) => {
    console.log(`[witness] ${config.WITNESS_ID} on http://localhost:${info.port}/v1/checkpoint`);
  });
  const shutdown = () => server.close();
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  console.error("[witness] failed to start:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
