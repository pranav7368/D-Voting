/**
 * Trustee entry point.
 *
 * Holds exactly one thing of value: this trustee's key share, supplied as
 * `TRUSTEE_SHARE`. It is read once at start-up and never written anywhere --
 * not to the chain, not to a log line, not into an HTTP response.
 *
 * In deployment this process belongs to the trustee organisation, not to the
 * election commission, and runs on their hardware. Running five of them on one
 * laptop (as `npm run dev` does) is convenient and proves the protocol works;
 * it does not provide the guarantee, and nothing here pretends otherwise.
 */

import { serve } from "@hono/node-server";
import { z } from "zod";
import { MODP_2048, MODP_3072, type PrimeOrderGroup } from "@dvoting/crypto";

import { createApp } from "./app.ts";
import { Trustee } from "./trustee.ts";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8100),

  ELECTION_ID: z.string().min(1),
  GROUP: z.enum(["modp2048", "modp3072"]).default("modp3072"),

  /** 1-based position in the trustee roster, matching the sealed public share. */
  TRUSTEE_INDEX: z.coerce.number().int().min(1).max(1024),
  /** Human name for the console, e.g. "Supreme Court observer". */
  TRUSTEE_LABEL: z.string().min(1).default("Trustee"),
  /** The private Shamir share, hex. The one secret this process holds. */
  TRUSTEE_SHARE: z.string().regex(/^[0-9a-fA-F]+$/, "TRUSTEE_SHARE must be hex"),
  /** This trustee's operator token. Never shared with the commission. */
  TRUSTEE_TOKEN: z.string().min(32),

  BALLOT_BOX_URL: z.string().url(),
});

async function main(): Promise<number> {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid configuration:\n${issues}`);
  }
  const config = parsed.data;

  const group: PrimeOrderGroup = config.GROUP === "modp2048" ? MODP_2048 : MODP_3072;
  const share = BigInt(`0x${config.TRUSTEE_SHARE}`);
  if (share <= 0n || share >= group.q) {
    throw new Error("TRUSTEE_SHARE is not a valid scalar for this group");
  }

  const trustee = new Trustee({
    electionId: config.ELECTION_ID,
    group,
    index: config.TRUSTEE_INDEX,
    share,
    ballotBoxUrl: config.BALLOT_BOX_URL.replace(/\/$/, ""),
  });

  const app = createApp({
    trustee,
    operatorToken: config.TRUSTEE_TOKEN,
    label: config.TRUSTEE_LABEL,
    ballotBoxUrl: config.BALLOT_BOX_URL,
  });

  console.log("[trustee] starting", {
    label: config.TRUSTEE_LABEL,
    index: config.TRUSTEE_INDEX,
    electionId: config.ELECTION_ID,
    group: group.name,
    ballotBox: config.BALLOT_BOX_URL,
    // Never the share, and never the token.
    share: "[redacted]",
    token: "[redacted]",
  });

  const server = serve({ fetch: app.fetch, port: config.PORT }, (info) => {
    console.log(`[trustee] console  http://localhost:${info.port}/`);
  });

  const shutdown = (signal: string): void => {
    console.log(`[trustee] ${signal} received, shutting down`);
    server.close();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  return 0;
}

main().catch((error: unknown) => {
  console.error("[trustee] failed to start:", error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
