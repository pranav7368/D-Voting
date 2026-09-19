/**
 * Ballot box + public bulletin board entry point.
 *
 * Holds NO signing keys of any kind: not the trustees' key shares, not the
 * validators' block-signing keys, not the Registration Authority's issuer key.
 * It can accept and record ballots, and nothing else.
 *
 * TLS terminates at the load balancer; do not expose this port directly.
 */

import { serve } from "@hono/node-server";
import { z } from "zod";
import {
  MODP_2048,
  MODP_3072,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  fromBase64Url,
  os2ip,
  type ElGamalPublicKey,
  type ElectionParameters,
  type PrimeOrderGroup,
} from "@dvoting/crypto";
import { publicKeyFromJwk, type RsaPublicJwk } from "@dvoting/crypto/keygen";
import {
  DistributedSealer,
  HttpValidatorPeer,
  Ledger,
  createValidatorSet,
  type ValidatorIdentity,
} from "@dvoting/ledger";
import { FileBlockStore } from "@dvoting/ledger/file-store";

import { createApp } from "./app.ts";
import { BallotBox } from "./ballot-box.ts";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8082),

  ELECTION_ID: z.string().min(1),
  /** Comma-separated candidate names, in ballot order. */
  CANDIDATES: z.string().min(1),
  MIN_SELECTIONS: z.coerce.number().int().min(0).default(1),
  MAX_SELECTIONS: z.coerce.number().int().min(1).default(1),

  /** Registration Authority's PUBLIC issuer key (JWK), for checking credentials. */
  ISSUER_PUBLIC_KEY_JWK: z.string().min(1),

  /** Joint trustee public key: base64url of the group element. */
  ELECTION_PUBLIC_KEY: z.string().min(1),
  GROUP: z.enum(["modp2048", "modp3072"]).default("modp3072"),

  /**
   * The trustee roster: how many must cooperate, and each one's PUBLIC share.
   *
   * Public halves only. This service verifies decryption proofs against them
   * during the ceremony and never holds a private share -- there is no
   * environment variable here that could carry one.
   *
   * JSON: [{"index":1,"publicShare":"..."}, ...]
   */
  TRUSTEE_PUBLIC_SHARES: z.string().min(1),
  TRUSTEE_THRESHOLD: z.coerce.number().int().min(1).max(1024),

  /** JSON: {"quorum":3,"validators":[{"id":"...","publicKey":"...","url":"http://..."}]} */
  VALIDATOR_SET: z.string().min(1),
  /** Shared secret for asking a validator to propose. */
  PROPOSE_TOKEN: z.string().min(32),

  /** Durable chain file. Required in production. */
  CHAIN_PATH: z.string().optional(),
  /** Seal a block once this many ballots are pending. */
  BALLOTS_PER_BLOCK: z.coerce.number().int().min(1).default(25),

  /** Enables /admin and /v1/admin/*. Omit to disable the admin surface entirely. */
  ADMIN_TOKEN: z.string().min(32).optional(),

  /**
   * Write-path throttling. Casting runs a full zero-knowledge verification, so
   * an unthrottled endpoint is a CPU exhaustion primitive.
   */
  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().min(1).default(60),
  /** Trust X-Forwarded-For. Only enable when actually behind a trusted proxy. */
  TRUST_PROXY: z.enum(["true", "false"]).default("false"),

  /**
   * Public URL of the Registration Authority.
   *
   * Published to the voter's browser, which calls it DIRECTLY. It is never
   * proxied through this service — doing so would let one party see both the
   * voter's identity and their ballot.
   */
  REGISTRATION_URL: z.string().url().optional(),
});

interface ValidatorSetFile {
  quorum?: number;
  validators: { id: string; publicKey: string; url: string }[];
}

async function main(): Promise<void> {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  const config = parsed.data;

  if (config.NODE_ENV === "production" && !config.CHAIN_PATH) {
    throw new Error("CHAIN_PATH is required in production: in-memory storage loses the chain");
  }

  const group: PrimeOrderGroup = config.GROUP === "modp2048" ? MODP_2048 : MODP_3072;

  const election: ElectionParameters = {
    electionId: config.ELECTION_ID,
    candidates: config.CANDIDATES.split(",").map((c) => c.trim()).filter(Boolean),
    minSelections: config.MIN_SELECTIONS,
    maxSelections: config.MAX_SELECTIONS,
  };
  if (election.candidates.length === 0) throw new Error("CANDIDATES must list at least one name");

  const issuerPublicKey = publicKeyFromJwk(
    JSON.parse(config.ISSUER_PUBLIC_KEY_JWK) as RsaPublicJwk,
    RSABSSA_SHA384_PSS_DETERMINISTIC,
  );

  const electionPublicKey: ElGamalPublicKey = {
    group,
    y: os2ip(fromBase64Url(config.ELECTION_PUBLIC_KEY)),
  };

  const publicShares = JSON.parse(config.TRUSTEE_PUBLIC_SHARES) as {
    index: number;
    publicShare: string;
  }[];
  if (!Array.isArray(publicShares) || publicShares.length === 0) {
    throw new Error("TRUSTEE_PUBLIC_SHARES must be a non-empty JSON array");
  }
  if (config.TRUSTEE_THRESHOLD > publicShares.length) {
    // A threshold nobody can reach would leave the election permanently
    // undecryptable, and only discoverably so after polling had closed.
    throw new Error(
      `TRUSTEE_THRESHOLD (${config.TRUSTEE_THRESHOLD}) exceeds the number of trustees (${publicShares.length})`,
    );
  }
  const trustees = {
    threshold: config.TRUSTEE_THRESHOLD,
    total: publicShares.length,
    publicShares,
  };

  const validatorFile = JSON.parse(config.VALIDATOR_SET) as ValidatorSetFile;
  const identities: ValidatorIdentity[] = validatorFile.validators.map((v) => ({
    id: v.id,
    publicKey: fromBase64Url(v.publicKey),
  }));
  const validatorSet = createValidatorSet(identities, validatorFile.quorum);

  const peers = validatorFile.validators.map(
    (v) =>
      new HttpValidatorPeer({
        id: v.id,
        baseUrl: v.url,
        proposeToken: config.PROPOSE_TOKEN,
      }),
  );

  let store;
  if (config.CHAIN_PATH) {
    store = await FileBlockStore.open(config.CHAIN_PATH);
  } else {
    console.warn("[ballot-box] CHAIN_PATH not set -- using in-memory storage, data will be lost");
    const { InMemoryBlockStore } = await import("@dvoting/ledger");
    store = new InMemoryBlockStore();
  }

  const ledger = new Ledger(store, validatorSet, election.electionId);

  // Never serve from a chain that does not verify: a corrupted replica would
  // otherwise be laundered into the bulletin board as if it were authentic.
  const report = await ledger.verify();
  if (!report.valid) {
    throw new Error(`refusing to start: chain failed verification: ${report.errors.slice(0, 3).join("; ")}`);
  }

  const ballotBox = new BallotBox({
    election,
    issuerPublicKey,
    electionPublicKey,
    trustees,
    ledger,
    sealer: new DistributedSealer(ledger, peers),
    maxPendingBeforeSeal: config.BALLOTS_PER_BLOCK,
    ...(config.REGISTRATION_URL ? { registrationUrl: config.REGISTRATION_URL } : {}),
  });

  // Adopt whatever the chain already says about this election: whether it was
  // opened, what it was sealed as, and whether voting has ended. This throws
  // rather than starting if the sealed identity disagrees with this process.
  await ballotBox.load();

  const app = createApp({
    ballotBox,
    rateLimit: {
      windowSeconds: config.RATE_LIMIT_WINDOW_SECONDS,
      maxRequests: config.RATE_LIMIT_MAX_REQUESTS,
    },
    trustProxy: config.TRUST_PROXY === "true",
    ...(config.ADMIN_TOKEN ? { adminToken: config.ADMIN_TOKEN } : {}),
  });

  console.log("[ballot-box] starting", {
    electionId: ballotBox.election.electionId,
    phase: ballotBox.phase,
    candidates: ballotBox.election.candidates,
    group: group.name,
    validators: identities.map((v) => v.id),
    quorum: validatorSet.quorum,
    trustees: `${trustees.threshold} of ${trustees.total}`,
    blockHeight: await ledger.height(),
    adminConsole: config.ADMIN_TOKEN ? "enabled at /admin" : "disabled",
    proposeToken: "[redacted]",
    adminToken: "[redacted]",
  });

  const server = serve({ fetch: app.fetch, port: config.PORT }, (info) => {
    console.log(`[ballot-box] verification portal  http://localhost:${info.port}/`);
    if (config.ADMIN_TOKEN) {
      console.log(`[ballot-box] admin console       http://localhost:${info.port}/admin`);
    }
  });

  const shutdown = async (signal: string): Promise<void> => {
    console.log(`[ballot-box] ${signal} received, shutting down`);
    server.close();
    if (config.CHAIN_PATH) await (store as FileBlockStore).close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error: unknown) => {
  console.error("[ballot-box] failed to start:", error instanceof Error ? error.message : error);
  process.exit(1);
});
