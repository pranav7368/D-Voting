/**
 * Validator authority HTTP API.
 *
 * One process = one authority = one signing key. This service never sees
 * another validator's key, and it decides for itself whether to attest.
 *
 * Endpoint risk profiles (see http-peer.ts for the full reasoning):
 *
 *   POST /v1/propose  AUTHENTICATED. Makes this node sign a block and commit to
 *                     a height; an attacker with access could lock it out of the
 *                     legitimate block at that height via its own
 *                     anti-equivocation rule.
 *   POST /v1/attest   Open. Only signs blocks already signed by the scheduled
 *                     proposer, so nothing new can be induced.
 *   POST /v1/commit   Open. A block must already carry a valid quorum.
 *   GET  /v1/status   Open, public.
 */

import { Hono } from "hono";
import { constantTimeEqual, utf8 } from "@dvoting/crypto";
import {
  ValidatorNodeError,
  blockFromWire,
  blockToWire,
  proposeRequestFromWire,
  WireFormatError,
  type ValidatorNode,
} from "@dvoting/ledger";
import { toBase64Url } from "@dvoting/crypto";

export interface ValidatorAppOptions {
  node: ValidatorNode;
  /** Bearer token required for /v1/propose. */
  proposeToken: string;
  /** Max request body size. Blocks carry ballots, so this is generous. */
  maxBodyBytes?: number;
  rateLimit?: { windowSeconds: number; maxRequests: number };
}

export function createValidatorApp(options: ValidatorAppOptions): Hono {
  const { node, proposeToken } = options;
  const maxBodyBytes = options.maxBodyBytes ?? 8 * 1024 * 1024;

  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  });

  // Attestation re-verifies every ballot, so it is deliberately expensive.
  // Without a limit, an unauthenticated caller could exhaust the node's CPU.
  const limiter = createRateLimiter(
    options.rateLimit ?? { windowSeconds: 60, maxRequests: 120 },
  );
  app.use("/v1/attest", limiter);
  app.use("/v1/commit", limiter);

  app.use("/v1/*", async (c, next) => {
    const declared = c.req.header("Content-Length");
    if (declared && Number(declared) > maxBodyBytes) {
      return c.json({ error: "payload_too_large" }, 413);
    }
    await next();
  });

  app.get("/health", (c) => c.json({ status: "ok", service: "validator-node" }));

  app.get("/v1/status", async (c) =>
    c.json({
      validator: node.identity.id,
      publicKey: toBase64Url(node.identity.publicKey),
      height: await node.height(),
      electionId: node.ledger.electionId,
    }),
  );

  app.post("/v1/propose", async (c) => {
    const supplied = (c.req.header("Authorization") ?? "").replace(/^Bearer\s+/i, "");
    // Constant-time comparison: a short-circuiting check would leak the token
    // one byte at a time to anyone able to measure response latency.
    if (!constantTimeEqual(utf8(supplied), utf8(proposeToken))) {
      return c.json({ error: "unauthorized" }, 401);
    }

    const body = await readJson(c.req.raw);
    if (body === null) return c.json({ error: "invalid_request" }, 400);

    let request;
    try {
      request = proposeRequestFromWire(body);
    } catch (error) {
      return c.json(
        { error: "invalid_request", message: error instanceof WireFormatError ? error.message : "bad request" },
        400,
      );
    }

    try {
      const block = await node.propose(request);
      return c.json({ block: blockToWire(block) }, 201);
    } catch (error) {
      if (error instanceof ValidatorNodeError) {
        return c.json({ error: "cannot_propose", message: error.message }, 409);
      }
      throw error;
    }
  });

  app.post("/v1/attest", async (c) => {
    const body = await readJson(c.req.raw);
    if (body === null) return c.json({ error: "invalid_request" }, 400);

    let block;
    try {
      block = blockFromWire((body as { block: unknown }).block);
    } catch (error) {
      return c.json(
        { error: "invalid_block", message: error instanceof WireFormatError ? error.message : "bad block" },
        400,
      );
    }

    const response = await node.attest(block);
    if (response.refused) {
      // 409, not 4xx-generic: refusing is a normal protocol outcome and the
      // caller needs to distinguish it from a transport failure. `behindAt`
      // tells the caller this node is merely lagging and can be caught up.
      return c.json(
        {
          refused: true,
          validator: response.validator,
          reason: response.reason,
          ...(response.behindAt !== undefined ? { behindAt: response.behindAt } : {}),
        },
        409,
      );
    }

    return c.json({
      attestation: {
        validator: response.attestation.validator,
        signature: toBase64Url(response.attestation.signature),
      },
    });
  });

  app.post("/v1/commit", async (c) => {
    const body = await readJson(c.req.raw);
    if (body === null) return c.json({ error: "invalid_request" }, 400);

    let block;
    try {
      block = blockFromWire((body as { block: unknown }).block);
    } catch (error) {
      return c.json(
        { error: "invalid_block", message: error instanceof WireFormatError ? error.message : "bad block" },
        400,
      );
    }

    try {
      await node.commit(block);
      return c.json({ committed: true, height: await node.height() });
    } catch (error) {
      return c.json(
        {
          error: "commit_rejected",
          message: error instanceof Error ? error.message : "rejected",
        },
        409,
      );
    }
  });

  app.get("/v1/blocks/:height", async (c) => {
    const height = Number(c.req.param("height"));
    if (!Number.isInteger(height) || height < 0) return c.json({ error: "invalid_height" }, 400);
    const block = await node.ledger.getBlock(height);
    if (!block) return c.json({ error: "not_found" }, 404);
    return c.json({ block: blockToWire(block) });
  });

  app.get("/v1/verify", async (c) => c.json(await node.ledger.verify()));

  app.notFound((c) => c.json({ error: "not_found" }, 404));

  app.onError((error, c) => {
    console.error(`[validator:${node.identity.id}] unhandled error`, {
      path: c.req.path,
      message: error instanceof Error ? error.message : String(error),
    });
    return c.json({ error: "internal_error" }, 500);
  });

  return app;
}

function createRateLimiter(options: { windowSeconds: number; maxRequests: number }) {
  const windows = new Map<string, { count: number; resetAt: number }>();
  const windowMs = options.windowSeconds * 1000;

  return async (c: { req: { header: (name: string) => string | undefined }; json: (body: unknown, status?: 429) => Response }, next: () => Promise<void>) => {
    const key = c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() ?? "default";
    const now = Date.now();

    if (windows.size > 10_000) {
      for (const [existing, window] of windows) {
        if (window.resetAt <= now) windows.delete(existing);
      }
    }

    let window = windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + windowMs };
      windows.set(key, window);
    }
    window.count++;

    if (window.count > options.maxRequests) {
      return c.json({ error: "rate_limited" }, 429);
    }
    await next();
    return undefined;
  };
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
