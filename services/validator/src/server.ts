/**
 * Validator authority entry point.
 *
 * Run one of these per authority, on infrastructure that authority controls.
 * Running several on one machine is a demo convenience and gives you none of
 * the independence the quorum rule assumes.
 *
 * TLS terminates at the proxy; validator traffic crosses organisational
 * boundaries and must not run in clear text.
 */

import { serve } from "@hono/node-server";
import { fromBase64Url } from "@dvoting/crypto";
import {
  InMemoryBlockStore,
  Ledger,
  ValidatorNode,
  createValidatorSet,
  importPrivateKey,
  type BlockStore,
  type ValidatorIdentity,
} from "@dvoting/ledger";
import { FileBlockStore } from "@dvoting/ledger/file-store";

import { createValidatorApp } from "./app.ts";

interface ValidatorSetFile {
  quorum?: number;
  validators: { id: string; publicKey: string }[];
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main(): Promise<void> {
  const validatorId = required("VALIDATOR_ID");
  const electionId = required("ELECTION_ID");
  const proposeToken = required("PROPOSE_TOKEN");
  if (proposeToken.length < 32) {
    throw new Error("PROPOSE_TOKEN must be at least 32 characters");
  }

  const privateKey = await importPrivateKey(fromBase64Url(required("VALIDATOR_PRIVATE_KEY")));

  const parsed = JSON.parse(required("VALIDATOR_SET")) as ValidatorSetFile;
  const identities: ValidatorIdentity[] = parsed.validators.map((entry) => ({
    id: entry.id,
    publicKey: fromBase64Url(entry.publicKey),
  }));
  const validatorSet = createValidatorSet(identities, parsed.quorum);

  const identity = identities.find((entry) => entry.id === validatorId);
  if (!identity) {
    throw new Error(`VALIDATOR_ID "${validatorId}" is not in the configured validator set`);
  }

  // Durable by default. In-memory storage loses the entire election record on
  // restart, so it is opt-in and refused outright in production.
  const chainPath = process.env.CHAIN_PATH;
  if (!chainPath && process.env.NODE_ENV === "production") {
    throw new Error("CHAIN_PATH is required in production: in-memory storage loses the chain");
  }

  let store: BlockStore;
  let fileStore: FileBlockStore | undefined;
  if (chainPath) {
    fileStore = await FileBlockStore.open(chainPath);
    store = fileStore;
  } else {
    console.warn("[validator] CHAIN_PATH not set -- using in-memory storage, data will be lost");
    store = new InMemoryBlockStore();
  }

  const ledger = new Ledger(store, validatorSet, electionId);

  // Verify whatever was loaded from disk BEFORE serving. A node that starts up
  // on a corrupted or tampered chain and begins attesting would launder that
  // damage into the quorum.
  if (fileStore) {
    const report = await ledger.verify();
    if (!report.valid) {
      throw new Error(
        `refusing to start: chain at ${chainPath} failed verification: ` +
          report.errors.slice(0, 3).join("; "),
      );
    }
    console.log(`[validator:${validatorId}] loaded ${report.blockCount} block(s) from ${chainPath}`);
  }

  const node = new ValidatorNode({ identity, privateKey, ledger });

  const port = Number(process.env.PORT ?? 8090);
  const app = createValidatorApp({ node, proposeToken });

  console.log(`[validator:${validatorId}] starting`, {
    electionId,
    port,
    quorum: `${validatorSet.quorum}-of-${validatorSet.validators.length}`,
    proposeToken: "[redacted]",
    privateKey: "[redacted]",
  });

  const server = serve({ fetch: app.fetch, port }, (info) => {
    console.log(`[validator:${validatorId}] listening on http://localhost:${info.port}`);
  });

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`[validator:${validatorId}] ${signal} received, shutting down`);
    server.close();
    // Close the chain file so the handle is released cleanly; every append was
    // already fsynced, so nothing is lost either way.
    await fileStore?.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error: unknown) => {
  console.error(
    "[validator] failed to start:",
    error instanceof Error ? error.message : error,
  );
  process.exit(1);
});
