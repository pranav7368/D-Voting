/**
 * Write-path throttling for the ballot box.
 *
 * ===========================================================================
 * WHY THIS MATTERS MORE HERE THAN ON A NORMAL API.
 *
 * Casting a ballot is expensive ON PURPOSE: every submission runs a full set of
 * disjunctive zero-knowledge proofs, which is tens to hundreds of milliseconds
 * of pure CPU. That is the price of accepting nothing an attacker could forge.
 *
 * It also means an unthrottled cast endpoint is a CPU exhaustion primitive. A
 * single machine spraying malformed-but-well-shaped ballots can starve the
 * service of the cycles real voters need, and a ballot box that is unreachable
 * during polling hours disenfranchises people just as effectively as one that
 * rejects their ballots.
 *
 * The order of checks inside `cast` is the first defence -- cheap structural
 * checks reject junk before the expensive path. This is the second.
 *
 * SCOPE, stated honestly: single-process and in-memory. It protects one
 * instance from casual abuse. It does not survive a restart and does not
 * coordinate across instances, so a real deployment terminates this at the WAF
 * or API gateway, where a distributed attack is actually visible.
 * ===========================================================================
 */

import type { MiddlewareHandler } from "hono";

export interface RateLimitOptions {
  windowSeconds: number;
  maxRequests: number;
}

interface Window {
  count: number;
  resetAt: number;
}

/**
 * Resolve the client IP once.
 *
 * `X-Forwarded-For` is honoured only when a proxy is explicitly trusted:
 * trusting it unconditionally would let any client forge its own address and
 * walk straight through the limiter below.
 */
export function clientIp(trustProxy: boolean): MiddlewareHandler {
  return async (c, next) => {
    let ip = "unknown";
    if (trustProxy) {
      const forwarded = c.req.header("X-Forwarded-For");
      if (forwarded) ip = forwarded.split(",")[0]!.trim();
    }
    if (ip === "unknown") {
      const info = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
      ip = info?.incoming?.socket?.remoteAddress ?? "unknown";
    }
    c.set("clientIp", ip);
    await next();
  };
}

export function createRateLimiter(options: RateLimitOptions): MiddlewareHandler {
  const windows = new Map<string, Window>();
  const windowMs = options.windowSeconds * 1000;

  // Bound memory: an attacker rotating source addresses must not be able to
  // grow this map without limit.
  const MAX_TRACKED_KEYS = 100_000;

  function sweep(now: number): void {
    for (const [key, window] of windows) {
      if (window.resetAt <= now) windows.delete(key);
    }
  }

  return async (c, next) => {
    const key = (c.get("clientIp") as string | undefined) ?? "unknown";
    const now = Date.now();

    if (windows.size > MAX_TRACKED_KEYS) sweep(now);

    let window = windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + windowMs };
      windows.set(key, window);
    }
    window.count++;

    const retryAfter = Math.ceil((window.resetAt - now) / 1000);
    c.header("RateLimit-Limit", String(options.maxRequests));
    c.header("RateLimit-Remaining", String(Math.max(0, options.maxRequests - window.count)));
    c.header("RateLimit-Reset", String(retryAfter));

    if (window.count > options.maxRequests) {
      c.header("Retry-After", String(retryAfter));
      return c.json(
        {
          error: "rate_limited",
          message: "Too many requests from this address. Wait a moment and try again.",
        },
        429,
      );
    }

    await next();
    return undefined;
  };
}
