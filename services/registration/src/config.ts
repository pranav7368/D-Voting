/**
 * Configuration, loaded from the environment and validated at startup.
 *
 * Two rules this file enforces, both of which are on the security checklist:
 *   1. No secret has a default value. A missing secret is a hard startup
 *      failure, never a silent fallback to a guessable dev value -- that is how
 *      demo credentials end up in production.
 *   2. Nothing here is ever logged. See `redactedSummary()` for what may be.
 */

import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().min(1).max(65535).default(8081),

  /** The election this Registration Authority issues credentials for. */
  ELECTION_ID: z.string().min(1),

  /**
   * Issuer RSA private key as a JSON Web Key. Generate with `npm run keygen`.
   * In production this must come from a secrets manager, and better still the
   * signing operation should move into KMS so the key is never in process
   * memory at all (see BlindSigner in @dvoting/crypto).
   */
  ISSUER_PRIVATE_KEY_JWK: z.string().min(1),

  /**
   * HMAC key used to derive identity hashes from national ID numbers.
   *
   * Why a keyed hash and not a plain SHA-256: national ID numbers come from a
   * small, enumerable space. A plain hash of an Aadhaar-style number is
   * reversible by brute force in seconds. An HMAC under a secret pepper is not,
   * so a database dump alone does not reveal who registered. The pepper must
   * live outside the database.
   */
  IDENTITY_PEPPER: z.string().min(32, "IDENTITY_PEPPER must be at least 32 characters"),

  /** HMAC key for short-lived registration tokens. */
  REGISTRATION_TOKEN_SECRET: z
    .string()
    .min(32, "REGISTRATION_TOKEN_SECRET must be at least 32 characters"),

  /** Registration token lifetime. Short by design: it is a bearer credential. */
  REGISTRATION_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),

  DATABASE_URL: z.string().url().optional(),


  /** "memory" is for tests and the offline demo; "postgres" is the real path. */
  STORAGE_DRIVER: z.enum(["postgres", "memory"]).default("postgres"),

  /**
   * Path to a JSON electoral roll to load at startup, for in-memory runs.
   *
   * Local development only: with `STORAGE_DRIVER=memory` the roll cannot be
   * imported by a separate process, so it is seeded from a file instead. It
   * holds only enrolment-code HMACs, never the codes themselves.
   */
  ROLL_SEED_FILE: z.string().optional(),

  /**
   * Enables the electoral roll administration routes. Omit to disable them
   * entirely — a Registration Authority whose roll is imported offline should
   * not expose a route that can add voters.
   */
  ADMIN_TOKEN: z.string().min(32).optional(),

  /** Comma-separated list of allowed browser origins. Empty means same-origin only. */
  CORS_ALLOWED_ORIGINS: z.string().default(""),

  RATE_LIMIT_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().min(1).default(20),

  /** Trust X-Forwarded-For. Only enable when actually behind a trusted proxy. */
  TRUST_PROXY: z
    .enum(["true", "false"])
    .default("false")
    .transform((v) => v === "true"),
});

export type Config = z.infer<typeof schema> & { corsAllowedOrigins: string[] };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Invalid configuration:\n${issues}`);
  }

  const config = parsed.data;

  if (config.STORAGE_DRIVER === "postgres" && !config.DATABASE_URL) {
    throw new Error("Invalid configuration:\n  - DATABASE_URL is required when STORAGE_DRIVER=postgres");
  }
  if (config.NODE_ENV === "production" && config.STORAGE_DRIVER === "memory") {
    throw new Error("Refusing to start: STORAGE_DRIVER=memory loses every issued credential on restart");
  }

  return {
    ...config,
    corsAllowedOrigins: config.CORS_ALLOWED_ORIGINS.split(",")
      .map((o) => o.trim())
      .filter(Boolean),
  };
}

/** The ONLY representation of config that is safe to log. */
export function redactedSummary(config: Config): Record<string, unknown> {
  return {
    nodeEnv: config.NODE_ENV,
    port: config.PORT,
    electionId: config.ELECTION_ID,
    storageDriver: config.STORAGE_DRIVER,
    eligibility: "electoral-roll",
    rollAdmin: config.ADMIN_TOKEN ? "enabled at /v1/admin/roll" : "disabled",
    corsAllowedOrigins: config.corsAllowedOrigins,
    rateLimit: `${config.RATE_LIMIT_MAX_REQUESTS}/${config.RATE_LIMIT_WINDOW_SECONDS}s`,
    trustProxy: config.TRUST_PROXY,
    issuerKey: "[redacted]",
    identityPepper: "[redacted]",
    registrationTokenSecret: "[redacted]",
  };
}
