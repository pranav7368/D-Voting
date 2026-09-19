/**
 * Ballot box + public bulletin board HTTP API.
 *
 * The bulletin board routes are deliberately unauthenticated and cacheable:
 * public verifiability means ANY observer -- voter, journalist, opposition
 * party, auditor -- can download the chain and re-verify the whole election
 * without permission from the operator. Requiring credentials to read the board
 * would defeat the point.
 *
 * In deployment the read routes belong on a separate, horizontally scaled
 * service (they are pure reads), leaving the write path isolated.
 */

import { Hono } from "hono";
import { z } from "zod";
import { fromBase64Url, toBase64Url } from "@dvoting/crypto";
import { blockHash, encodeEntry, type Block } from "@dvoting/ledger";

import { registerAdminRoutes } from "./admin.ts";
import { BallotBox, BallotBoxError } from "./ballot-box.ts";
import { CeremonyError, DecryptionCeremony } from "./ceremony.ts";
import { clientIp, createRateLimiter } from "./middleware.ts";
import { readPublishedTally, verifyPublishedTally } from "./tally-publication.ts";
import {
  auditSecretFromWire,
  ballotFromWire,
  WireError,
  type WireAuditSecret,
  type WireBallot,
} from "./wire.ts";

const castSchema = z
  .object({
    credential: z.string().min(1).max(512),
    credentialSignature: z.string().min(1).max(2048),
    ballot: z.object({}).passthrough(),
  })
  .strict();

const shareSchema = z
  .object({
    index: z.number().int().min(1).max(1024),
    partials: z.array(z.object({}).passthrough()).min(1).max(64),
  })
  .strict();

export interface AppOptions {
  ballotBox: BallotBox;
  /** Requests per window, per IP, on the write path. */
  rateLimit?: { windowSeconds: number; maxRequests: number };
  /** Honour X-Forwarded-For. Only enable behind a proxy you control. */
  trustProxy?: boolean;
  /**
   * Bearer token for the admin dashboard. Omit to disable admin routes
   * entirely — a deployment that does not need them should not expose them.
   */
  adminToken?: string;
}

export function createApp(options: AppOptions): Hono {
  const { ballotBox } = options;
  const ceremony = new DecryptionCeremony(ballotBox);
  const app = new Hono();

  app.use("*", clientIp(options.trustProxy ?? false));

  // Registered before the limiter so that a throttled request still comes back
  // with the security headers -- a 429 is a response like any other.
  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    // Default to the strictest policy, but never clobber one a route already
    // set: the API wants "deny everything", the portal needs its own script.
    if (!c.res.headers.has("Content-Security-Policy")) {
      c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    }
  });

  // Throttle the write path only. The bulletin board stays wide open: public
  // verifiability means anyone must be able to download and re-check the whole
  // chain, and rate-limiting an auditor is the opposite of the point.
  if (options.rateLimit) {
    const limiter = createRateLimiter(options.rateLimit);
    app.use("/v1/ballots", limiter);
    app.use("/v1/ballots/*", limiter);
    app.use("/v1/ceremony/*", limiter);
  }

  app.get("/health", (c) => c.json({ status: "ok", service: "ballot-box" }));

  /**
   * Public verification portal.
   *
   * An explicit two-file allow-list rather than a static file server: path
   * traversal is the classic way a "just serve ./public" helper turns into
   * arbitrary file disclosure, and this service has an issuer key and a chain
   * on disk. Two named files cannot traverse anywhere.
   */
  const HTML = "text/html; charset=utf-8";
  const JS = "text/javascript; charset=utf-8";

  const PORTAL_FILES: Record<string, { file: string; type: string }> = {
    "/": { file: "vote.html", type: HTML },
    "/vote": { file: "vote.html", type: HTML },
    "/verify": { file: "index.html", type: HTML },
    "/results": { file: "results.html", type: HTML },
    "/chain": { file: "chain.html", type: HTML },
    "/app.css": { file: "app.css", type: "text/css; charset=utf-8" },
    "/verify-lib.js": { file: "verify-lib.js", type: JS },
    "/verify-page.js": { file: "verify-page.js", type: JS },
    "/voter.js": { file: "voter.js", type: JS },
    "/vote-page.js": { file: "vote-page.js", type: JS },
    "/results-page.js": { file: "results-page.js", type: JS },
    "/chain-lib.js": { file: "chain-lib.js", type: JS },
    "/chain-page.js": { file: "chain-page.js", type: JS },
    "/dvoting-crypto.js": { file: "dvoting-crypto.js", type: JS },
    ...(options.adminToken
      ? {
          "/admin": { file: "admin.html", type: HTML },
          "/admin-page.js": { file: "admin-page.js", type: JS },
        }
      : {}),
  };

  for (const [route, asset] of Object.entries(PORTAL_FILES)) {
    app.get(route, async (c) => {
      try {
        const { readFile } = await import("node:fs/promises");
        const { dirname, join } = await import("node:path");
        const { fileURLToPath } = await import("node:url");
        const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
        const body = await readFile(join(publicDir, asset.file), "utf8");
        // The portal is static and identical for everyone; the CSP is tight
        // because the page's whole job is to be trustworthy.
        c.header("Content-Type", asset.type);
        c.header("Cache-Control", "public, max-age=300");
        // connect-src must allow the Registration Authority's origin: the
        // voter's browser talks to it DIRECTLY, so that neither service sees
        // both the voter's identity and their ballot.
        const raOrigin = safeOrigin(ballotBox.registrationUrl);
        c.header(
          "Content-Security-Policy",
          [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            `connect-src 'self'${raOrigin ? ` ${raOrigin}` : ""}`,
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
          ].join("; "),
        );
        return c.body(body);
      } catch {
        return c.json({ error: "not_found" }, 404);
      }
    });
  }

  /** Everything a voter needs to build a ballot, and an auditor to check one. */
  app.get("/v1/election", async (c) => {
    // Deliberately NOT cached. This descriptor carries the issuer key id that a
    // voter's browser pins, so a stale copy surfaces as a key-mismatch alarm --
    // indistinguishable, to the voter, from the substitution attack the pinning
    // exists to catch. A false alarm that tells someone not to vote is worse
    // than re-fetching a few hundred bytes.
    c.header("Cache-Control", "no-store");
    return c.json(await ballotBox.describe());
  });

  app.post("/v1/ballots", async (c) => {
    const body = await readJson(c.req.raw);
    const parsed = castSchema.safeParse(body);
    if (!parsed.success) {
      return c.json({ error: "invalid_request", message: "Malformed submission." }, 400);
    }

    let submission;
    try {
      submission = {
        credential: fromBase64Url(parsed.data.credential),
        credentialSignature: fromBase64Url(parsed.data.credentialSignature),
        ballot: ballotFromWire(
          ballotBox.electionPublicKeyGroup,
          parsed.data.ballot as unknown as WireBallot,
        ),
      };
    } catch (error) {
      return c.json(
        {
          error: "invalid_request",
          message: error instanceof WireError ? error.message : "Malformed ballot encoding.",
        },
        400,
      );
    }

    try {
      const result = await ballotBox.cast(submission);
      return c.json(result, 201);
    } catch (error) {
      if (error instanceof BallotBoxError) {
        const status = error.code === "duplicate_ballot" ? 409 : 400;
        return c.json({ error: error.code, message: error.message }, status);
      }
      throw error;
    }
  });

  /**
   * Spoil a ballot the voter chose to audit (Benaloh cast-or-audit).
   *
   * Publishing the revealed randomness is the point: it lets any observer
   * re-run the audit from the chain. The ballot id is burned permanently.
   */
  app.post("/v1/ballots/audit", async (c) => {
    const body = await readJson(c.req.raw);
    if (body === null || typeof body !== "object") {
      return c.json({ error: "invalid_request" }, 400);
    }

    const payload = body as { ballot?: unknown; auditSecret?: unknown };
    let ballot;
    let auditSecret;
    try {
      ballot = ballotFromWire(ballotBox.electionPublicKeyGroup, payload.ballot as WireBallot);
      auditSecret = auditSecretFromWire(
        ballotBox.electionPublicKeyGroup,
        payload.auditSecret as WireAuditSecret,
      );
    } catch (error) {
      return c.json(
        {
          error: "invalid_request",
          message: error instanceof WireError ? error.message : "Malformed audit payload.",
        },
        400,
      );
    }

    try {
      const result = await ballotBox.spoil({ ballot, auditSecret });
      return c.json(result, 201);
    } catch (error) {
      if (error instanceof BallotBoxError) {
        return c.json({ error: error.code, message: error.message }, 409);
      }
      throw error;
    }
  });

  // --- Public bulletin board -----------------------------------------------

  app.get("/v1/bulletin/head", async (c) => {
    const head = await ballotBox.ledger.head();
    if (!head) return c.json({ height: 0, head: null });
    return c.json({
      height: await ballotBox.ledger.height(),
      head: {
        ...headerToWire(head),
        hash: toBase64Url(await blockHash(head.header)),
      },
    });
  });

  app.get("/v1/bulletin/blocks/:height", async (c) => {
    const height = Number(c.req.param("height"));
    if (!Number.isInteger(height) || height < 0) {
      return c.json({ error: "invalid_height" }, 400);
    }
    const block = await ballotBox.ledger.getBlock(height);
    if (!block) return c.json({ error: "not_found" }, 404);

    c.header("Cache-Control", "public, max-age=31536000, immutable");
    return c.json({
      header: headerToWire(block),
      hash: toBase64Url(await blockHash(block.header)),
      attestations: block.attestations.map((a) => ({
        validator: a.validator,
        signature: toBase64Url(a.signature),
      })),
      entries: block.entries.map((entry) => ({
        kind: entry.kind,
        id: entry.id,
        data: toBase64Url(entry.data),
      })),
    });
  });

  /**
   * "Was my ballot recorded?"
   *
   * Returns the Merkle inclusion proof plus the signed header that commits to
   * the root, so the voter can verify locally without trusting this response.
   */
  app.get("/v1/bulletin/ballots/:ballotId", async (c) => {
    const ballotId = c.req.param("ballotId");
    const located = await ballotBox.ledger.locateEntry("ballot", ballotId);
    if (!located) {
      return c.json({ error: "not_found", message: "No such ballot on the chain." }, 404);
    }

    const block = await ballotBox.ledger.getBlock(located.blockHeight);
    return c.json({
      ballotId,
      blockHeight: located.blockHeight,
      entryIndex: located.entryIndex,
      leaf: toBase64Url(encodeEntry(located.entry)),
      merkleRoot: toBase64Url(located.merkleRoot),
      proof: {
        leafIndex: located.proof.leafIndex,
        treeSize: located.proof.treeSize,
        path: located.proof.path.map((node) => toBase64Url(node)),
      },
      blockHeader: block ? headerToWire(block) : null,
      attestations: block
        ? block.attestations.map((a) => ({
            validator: a.validator,
            signature: toBase64Url(a.signature),
          }))
        : [],
    });
  });

  // --- Trustee decryption ceremony ------------------------------------------

  /**
   * What the trustees have to decrypt, and who has done it so far.
   *
   * Public, because the encrypted totals are public: they are a deterministic
   * function of ballots that anyone can already read off the chain. Publishing
   * them here saves each trustee from recomputing the tally, but a trustee that
   * does not trust this endpoint can derive the same ciphertexts itself and
   * will get the same answer.
   */
  app.get("/v1/ceremony", async (c) => {
    c.header("Cache-Control", "no-store");
    try {
      return c.json(await ceremony.status());
    } catch (error) {
      if (error instanceof CeremonyError) {
        return c.json({ error: error.code, message: error.message }, 409);
      }
      throw error;
    }
  });

  /**
   * Submit one trustee's partial decryptions.
   *
   * Unauthenticated on purpose. The Chaum-Pedersen proof inside the submission
   * is the authentication: it verifies only against the public share sealed
   * into the election record, and only the holder of the matching private share
   * can produce one. A bearer token here would be a secret to steal that
   * guaranteed nothing.
   */
  app.post("/v1/ceremony/shares", async (c) => {
    const parsed = shareSchema.safeParse(await readJson(c.req.raw));
    if (!parsed.success) {
      return c.json(
        { error: "invalid_request", message: "Send {index, partials[]}." },
        400,
      );
    }

    try {
      const result = await ceremony.submit({
        index: parsed.data.index,
        partials: parsed.data.partials as never[],
      });
      return c.json(result, 201);
    } catch (error) {
      if (error instanceof CeremonyError) {
        const conflict =
          error.code === "already_submitted" ||
          error.code === "already_published" ||
          error.code === "election_open";
        return conflict
          ? c.json({ error: error.code, message: error.message }, 409)
          : c.json({ error: error.code, message: error.message }, 400);
      }
      throw error;
    }
  });

  /** Full independent re-verification of the chain. */
  app.get("/v1/bulletin/verify", async (c) => {
    const report = await ballotBox.ledger.verify();
    return c.json(report);
  });

  /**
   * The published result, plus an independent recount.
   *
   * The recount is run server-side here for convenience, but it uses only data
   * that is on the chain — an observer with the chain file reaches the same
   * verdict without asking this server anything.
   */
  app.get("/v1/bulletin/result", async (c) => {
    const published = await readPublishedTally(ballotBox.ledger, ballotBox.election.electionId);
    if (!published) {
      return c.json({ error: "not_published", message: "No result has been published yet." }, 404);
    }

    const verification = await verifyPublishedTally(
      ballotBox.ledger,
      ballotBox.election,
      ballotBox.electionPublicKey,
      published,
    );

    return c.json({
      electionId: published.electionId,
      results: published.results,
      ballotsCounted: published.countedBallotIds.length,
      ballotsSuperseded: published.supersededBallotIds.length,
      threshold: published.threshold,
      verification,
    });
  });

  if (options.adminToken) {
    registerAdminRoutes(app, { ballotBox, ceremony, adminToken: options.adminToken });
  }

  app.notFound((c) => c.json({ error: "not_found" }, 404));

  app.onError((error, c) => {
    console.error("[ballot-box] unhandled error", {
      path: c.req.path,
      message: error instanceof Error ? error.message : String(error),
    });
    return c.json({ error: "internal_error", message: "An unexpected error occurred." }, 500);
  });

  return app;
}

function headerToWire(block: Block) {
  return {
    height: block.header.height,
    electionId: block.header.electionId,
    previousHash: toBase64Url(block.header.previousHash),
    merkleRoot: toBase64Url(block.header.merkleRoot),
    entryCount: block.header.entryCount,
    timestamp: block.header.timestamp,
    proposer: block.header.proposer,
    // Required for a client to recompute the header hash independently.
    view: block.header.view,
  };
}

/** Origin of a configured URL, or null. Never echo an unparseable value into a CSP. */
function safeOrigin(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

async function readJson(request: Request): Promise<unknown> {
  const contentType = request.headers.get("Content-Type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    return await request.json();
  } catch {
    return null;
  }
}
