/**
 * Registration Authority HTTP API.
 *
 * Two-step flow, and the split is deliberate:
 *
 *   POST /v1/register          identity in  -> short-lived registration token out
 *   POST /v1/credential/issue  token + blinded message -> blind signature out
 *
 * Separating them keeps the expensive, identity-bearing KYC step away from the
 * signing step, and means the blinded message is submitted under a bearer token
 * rather than alongside identity documents. It also gives the voter a clean
 * retry path if their device fails mid-issuance.
 *
 * WHAT THIS SERVICE NEVER SEES: the voter's credential, their ballot, or their
 * candidate choice. It sees a blinded value that is statistically independent of
 * all three.
 */

import { Hono } from "hono";
import { z } from "zod";
import {
  computeKeyId,
  digest,
  fromBase64Url,
  toBase64Url,
  bitLength,
  type BlindSigner,
} from "@dvoting/crypto";
import { publicKeyToJwk } from "@dvoting/crypto/keygen";

import { registerRollAdminRoutes } from "./admin.ts";
import type { Config } from "./config.ts";
import { deriveIdentityHash } from "./identity.ts";
import type { ElectoralRollStore } from "./eligibility/electoral-roll.ts";
import type { EligibilityVerifier } from "./eligibility/types.ts";
import { createRateLimiter } from "./middleware/rate-limit.ts";
import { bodyLimit, clientIp, cors, securityHeaders } from "./middleware/security.ts";
import type { VoterRepository } from "./repo/types.ts";
import { TokenError, issueRegistrationToken, verifyRegistrationToken } from "./tokens.ts";

export interface AppDependencies {
  config: Config;
  repository: VoterRepository;
  eligibilityVerifier: EligibilityVerifier;
  signer: BlindSigner;
  /** Supply together with config.ADMIN_TOKEN to enable roll administration. */
  rollStore?: ElectoralRollStore;
}

type Variables = { clientIp: string };

const registerSchema = z
  .object({
    /** Roll number from the voter's polling card. */
    rollId: z.string().min(1).max(128),
    /** Enrolment secret from the same card. */
    enrolmentCode: z.string().min(1).max(128),
  })
  .strict();

const issueSchema = z
  .object({
    registrationToken: z.string().min(1).max(4096),
    // base64url, no padding. Length is checked against the modulus separately.
    blindedMessage: z
      .string()
      .min(1)
      .max(2048)
      .regex(/^[A-Za-z0-9_-]+$/, "blindedMessage must be base64url"),
  })
  .strict();

export function createApp(deps: AppDependencies): Hono<{ Variables: Variables }> {
  const { config, repository, eligibilityVerifier, signer } = deps;
  const app = new Hono<{ Variables: Variables }>();

  const modulusBits = bitLength(signer.publicKey.n);
  const modulusBytes = Math.ceil(modulusBits / 8);

  app.use("*", clientIp(config.TRUST_PROXY));
  app.use("*", securityHeaders(config.NODE_ENV === "production"));
  app.use("*", cors(config.corsAllowedOrigins));
  app.use("*", bodyLimit(16 * 1024));

  const limiter = createRateLimiter({
    windowSeconds: config.RATE_LIMIT_WINDOW_SECONDS,
    maxRequests: config.RATE_LIMIT_MAX_REQUESTS,
  });
  app.use("/v1/register", limiter);
  app.use("/v1/credential/*", limiter);

  app.get("/health", (c) => c.json({ status: "ok", service: "registration-authority" }));

  /**
   * Publish the issuer's public key.
   *
   * Public and cacheable ON PURPOSE. Every voter must be able to fetch this and
   * confirm they were given the same key as everyone else -- if the RA could
   * hand out per-voter keys it could tag ballots and break unlinkability
   * without breaking any cryptography. The `keyId` should be pinned in the
   * client and mirrored on the bulletin board / chain genesis block.
   */
  app.get("/v1/issuer", async (c) => {
    const keyId = await computeKeyId(signer.publicKey);
    c.header("Cache-Control", "public, max-age=300");
    return c.json({
      electionId: config.ELECTION_ID,
      keyId,
      suite: signer.publicKey.suite.name,
      hash: signer.publicKey.suite.hash,
      saltLength: signer.publicKey.suite.saltLength,
      modulusBits,
      publicKey: publicKeyToJwk(signer.publicKey),
    });
  });

  /** Step 1: verify identity, return a short-lived token. */
  app.post("/v1/register", async (c) => {
    const body = await readJson(c.req.raw);
    const parsed = registerSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_request", message: "Malformed registration payload." }, 400);
    }

    const eligibility = await eligibilityVerifier.verify({
      rollId: parsed.data.rollId,
      enrolmentCode: parsed.data.enrolmentCode,
    });

    if (!eligibility.ok) {
      await repository.recordAudit({
        electionId: config.ELECTION_ID,
        action: "eligibility.rejected",
        detail: eligibility.reason,
      });
      // Deliberately identical for an unknown roll number, a wrong code and a
      // revoked entry: distinguishing them would let anyone enumerate the roll.
      return c.json(
        {
          error: "not_eligible",
          message: "That roll number and enrolment code are not valid for this election.",
        },
        403,
      );
    }

    const identityHash = await deriveIdentityHash(
      config.IDENTITY_PEPPER,
      config.ELECTION_ID,
      eligibility.subjectId,
    );

    const voter = await repository.findOrCreateVoter({
      electionId: config.ELECTION_ID,
      identityHash,
      kycProvider: eligibility.source,
    });

    // Tell the caller up front rather than letting them blind a credential and
    // discover the refusal only at the issuance step.
    if (voter.credentialIssuedAt !== null) {
      await repository.recordAudit({
        electionId: config.ELECTION_ID,
        action: "register.already_issued",
        subjectRef: voter.id,
      });
      return c.json(
        {
          error: "credential_already_issued",
          message: "A voting credential has already been issued for this identity.",
        },
        409,
      );
    }

    const expiresAt = Math.floor(Date.now() / 1000) + config.REGISTRATION_TOKEN_TTL_SECONDS;
    const { token, jti } = await issueRegistrationToken(config.REGISTRATION_TOKEN_SECRET, {
      sub: voter.id,
      el: config.ELECTION_ID,
      exp: expiresAt,
    });

    await repository.recordAudit({
      electionId: config.ELECTION_ID,
      action: "register.token_issued",
      subjectRef: voter.id,
      detail: jti,
    });

    return c.json({
      registrationToken: token,
      expiresAt: new Date(expiresAt * 1000).toISOString(),
      issuer: { keyId: await computeKeyId(signer.publicKey) },
    });
  });

  /** Step 2: blind-sign the voter's credential. */
  app.post("/v1/credential/issue", async (c) => {
    const body = await readJson(c.req.raw);
    const parsed = issueSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_request", message: "Malformed issuance payload." }, 400);
    }

    let payload;
    try {
      payload = await verifyRegistrationToken(
        config.REGISTRATION_TOKEN_SECRET,
        parsed.data.registrationToken,
        config.ELECTION_ID,
      );
    } catch (error) {
      if (error instanceof TokenError) {
        return c.json({ error: "invalid_token", message: error.message }, 401);
      }
      throw error;
    }

    let blindedMessage: Uint8Array;
    try {
      blindedMessage = fromBase64Url(parsed.data.blindedMessage);
    } catch {
      return c.json({ error: "invalid_request", message: "blindedMessage is not base64url." }, 400);
    }

    // The blinded message must be exactly one modulus wide. Rejecting here keeps
    // malformed input away from the signing key entirely.
    if (blindedMessage.length !== modulusBytes) {
      return c.json(
        {
          error: "invalid_blinded_message",
          message: `blindedMessage must be exactly ${modulusBytes} bytes for this issuer key.`,
        },
        400,
      );
    }

    const voter = await repository.findVoterById(payload.sub);
    if (!voter || voter.electionId !== config.ELECTION_ID) {
      return c.json({ error: "invalid_token", message: "Unknown voter." }, 401);
    }

    const blindedMessageHash = await digest("SHA-256", blindedMessage);

    const outcome = await repository.issueCredential(voter.id, blindedMessageHash, () =>
      signer.blindSign(blindedMessage),
    );

    if (outcome.status === "already_issued") {
      await repository.recordAudit({
        electionId: config.ELECTION_ID,
        action: "issue.refused_second_credential",
        subjectRef: voter.id,
      });
      return c.json(
        {
          error: "credential_already_issued",
          message:
            "A credential has already been issued for this voter with a different blinded message.",
        },
        409,
      );
    }

    await repository.recordAudit({
      electionId: config.ELECTION_ID,
      action: outcome.status === "issued" ? "issue.succeeded" : "issue.replayed",
      subjectRef: voter.id,
    });

    return c.json({
      blindSignature: toBase64Url(outcome.blindSignature),
      keyId: await computeKeyId(signer.publicKey),
      replayed: outcome.status === "replayed",
    });
  });

  // Roll administration, only when a token AND a store are both supplied. A
  // route that can add voters should not exist unless it was asked for.
  if (config.ADMIN_TOKEN && deps.rollStore) {
    registerRollAdminRoutes(app as unknown as Hono, {
      rollStore: deps.rollStore,
      repository,
      electionId: config.ELECTION_ID,
      pepper: config.IDENTITY_PEPPER,
      adminToken: config.ADMIN_TOKEN,
    });
  }

  app.notFound((c) => c.json({ error: "not_found" }, 404));

  app.onError((error, c) => {
    // Log server-side with detail; return an opaque message to the client.
    // Echoing internal errors would leak schema and key details to an attacker.
    console.error("[registration] unhandled error", {
      path: c.req.path,
      message: error instanceof Error ? error.message : String(error),
    });
    return c.json({ error: "internal_error", message: "An unexpected error occurred." }, 500);
  });

  return app;
}

/** Parse JSON without letting a malformed body produce a 500. */
async function readJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}
