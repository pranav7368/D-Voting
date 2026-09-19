/**
 * Fixed-window rate limiter.
 *
 * SCOPE: single-process, in-memory. That is honest about what it is -- it
 * protects one instance from casual abuse and scripted enumeration. It does NOT
 * survive a restart and does NOT coordinate across instances, so a horizontally
 * scaled deployment must move this to Redis (or terminate it at the WAF/API
 * gateway, which is the better place for it anyway).
 */

import type { MiddlewareHandler } from "hono";

interface Window {
  count: number;
  resetAt: number;
}

export interface RateLimitOptions {
  windowSeconds: number;
  maxRequests: number;
  /** Derives the bucket key. Defaults to client IP. */
  keyFor?: (clientIp: string) => string;
}

export function createRateLimiter(options: RateLimitOptions): MiddlewareHandler {
  const windows = new Map<string, Window>();
  const windowMs = options.windowSeconds * 1000;

  // Bound memory: an attacker rotating source IPs must not be able to grow this
  // map without limit. Sweeping expired windows on each request is O(1)
  // amortised because we only sweep when the map gets large.
  const MAX_TRACKED_KEYS = 100_000;

  function sweep(now: number): void {
    for (const [key, window] of windows) {
      if (window.resetAt <= now) windows.delete(key);
    }
  }

  return async (c, next) => {
    const clientIp = c.get("clientIp") ?? "unknown";
    const key = options.keyFor ? options.keyFor(clientIp) : clientIp;
    const now = Date.now();

    if (windows.size > MAX_TRACKED_KEYS) sweep(now);

    let window = windows.get(key);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + windowMs };
      windows.set(key, window);
    }

    window.count++;

    const remaining = Math.max(0, options.maxRequests - window.count);
    c.header("RateLimit-Limit", String(options.maxRequests));
    c.header("RateLimit-Remaining", String(remaining));
    c.header("RateLimit-Reset", String(Math.ceil((window.resetAt - now) / 1000)));

    if (window.count > options.maxRequests) {
      c.header("Retry-After", String(Math.ceil((window.resetAt - now) / 1000)));
      return c.json({ error: "rate_limited", message: "Too many requests." }, 429);
    }

    await next();
  };
}
