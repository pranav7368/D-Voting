/**
 * Trustee HTTP surface.
 *
 * Two things only: show this trustee's operator what is going on, and let them
 * decide to contribute their share. Both are behind this trustee's own token,
 * which nobody else in the system holds -- not the election commission, not the
 * ballot box, not the other trustees.
 *
 * Note what is absent. There is no endpoint that decrypts a supplied
 * ciphertext, no endpoint that exports the share, and no way to make this
 * process act automatically on someone else's schedule. A trustee's whole value
 * is that it is a deliberate, human decision by an independent party.
 */

import { Hono } from "hono";
import { constantTimeEqual, utf8 } from "@dvoting/crypto";

import { Trustee, TrusteeServiceError } from "./trustee.ts";

export interface AppOptions {
  trustee: Trustee;
  /** This trustee's own operator token. Not shared with any other party. */
  operatorToken: string;
  label: string;
  ballotBoxUrl: string;
}

export function createApp(options: AppOptions): Hono {
  const { trustee, operatorToken, label } = options;

  if (!operatorToken || operatorToken.length < 32) {
    throw new Error("createApp: operatorToken must be at least 32 characters");
  }

  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    if (!c.res.headers.has("Content-Security-Policy")) {
      c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    }
  });

  const authorised = (header: string | undefined): boolean =>
    constantTimeEqual(utf8((header ?? "").replace(/^Bearer\s+/i, "")), utf8(operatorToken));

  app.get("/health", (c) => c.json({ status: "ok", service: "trustee", index: trustee.index }));

  // The console. Static, no inline script or style, so the CSP can stay strict.
  const PAGES: Record<string, { file: string; type: string }> = {
    "/": { file: "trustee.html", type: "text/html; charset=utf-8" },
    "/trustee.css": { file: "trustee.css", type: "text/css; charset=utf-8" },
    "/trustee-page.js": { file: "trustee-page.js", type: "text/javascript; charset=utf-8" },
  };

  for (const [route, asset] of Object.entries(PAGES)) {
    app.get(route, async (c) => {
      try {
        const { readFile } = await import("node:fs/promises");
        const { dirname, join } = await import("node:path");
        const { fileURLToPath } = await import("node:url");
        const publicDir = join(dirname(fileURLToPath(import.meta.url)), "..", "public");
        const body = await readFile(join(publicDir, asset.file), "utf8");
        c.header("Content-Type", asset.type);
        c.header("Cache-Control", "no-store");
        c.header(
          "Content-Security-Policy",
          [
            "default-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
            "connect-src 'self'",
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

  app.use("/v1/*", async (c, next) => {
    if (!authorised(c.req.header("Authorization"))) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.header("Cache-Control", "no-store");
    await next();
    return undefined;
  });

  /** Who this trustee is, and where the ceremony stands. */
  app.get("/v1/status", async (c) => {
    const base = {
      label,
      index: trustee.index,
      publicShare: trustee.publicShare,
      ballotBoxUrl: options.ballotBoxUrl,
    };
    try {
      const ceremony = await trustee.ceremony();
      return c.json({
        ...base,
        reachable: true,
        ceremony,
        hasSubmitted: ceremony.submitted.includes(trustee.index),
      });
    } catch (error) {
      return c.json({
        ...base,
        reachable: false,
        message: error instanceof Error ? error.message : "The ballot box is unreachable.",
      });
    }
  });

  /**
   * Contribute this trustee's share.
   *
   * Everything expensive and everything that matters happens inside
   * `participate`: the chain is re-verified, the totals are re-derived, and only
   * then is the share applied. A refusal here is a finding, not an error -- it
   * means this trustee's own machine disagreed with the ballot box.
   */
  app.post("/v1/participate", async (c) => {
    try {
      return c.json(await trustee.participate(), 201);
    } catch (error) {
      if (error instanceof TrusteeServiceError) {
        const conflict = error.code === "already_submitted" || error.code === "already_published";
        const body = { error: error.code, message: error.message };
        return conflict ? c.json(body, 409) : c.json(body, 400);
      }
      throw error;
    }
  });

  app.notFound((c) => c.json({ error: "not_found" }, 404));

  app.onError((error, c) => {
    console.error("[trustee] unhandled error", {
      path: c.req.path,
      message: error instanceof Error ? error.message : String(error),
    });
    return c.json({ error: "internal_error", message: "An unexpected error occurred." }, 500);
  });

  return app;
}
