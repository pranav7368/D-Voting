/**
 * Baseline HTTP hardening: security headers, strict CORS, body size limit, and
 * client IP resolution.
 */

import type { MiddlewareHandler } from "hono";

export function securityHeaders(isProduction: boolean): MiddlewareHandler {
  return async (c, next) => {
    await next();
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Cross-Origin-Opener-Policy", "same-origin");
    c.header("Cross-Origin-Resource-Policy", "same-site");
    c.header("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
    // This is a JSON API and serves no markup, so everything can be denied.
    c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    // Only meaningful over HTTPS; TLS termination is expected at the load balancer.
    if (isProduction) {
      c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
    }
    // Registration responses are per-voter secrets. Never let a proxy cache them.
    if (!c.res.headers.has("Cache-Control")) {
      c.header("Cache-Control", "no-store");
    }
  };
}

/**
 * Strict allow-list CORS. Deliberately does NOT reflect arbitrary origins and
 * does not enable credentials, so a hostile page cannot ride a voter's session.
 */
export function cors(allowedOrigins: string[]): MiddlewareHandler {
  const allowed = new Set(allowedOrigins);
  return async (c, next) => {
    const origin = c.req.header("Origin");
    if (origin && allowed.has(origin)) {
      c.header("Access-Control-Allow-Origin", origin);
      c.header("Vary", "Origin");
      c.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      // Authorization is needed by the roll administration routes, which the
      // commission's console calls directly rather than through the ballot box.
      // Still no `Access-Control-Allow-Credentials`: nothing here rides on a
      // cookie, so a hostile page cannot borrow an operator's session.
      c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
      c.header("Access-Control-Max-Age", "600");
    }
    if (c.req.method === "OPTIONS") {
      return c.body(null, 204);
    }
    await next();
  };
}

/**
 * Resolve the client IP once, honouring X-Forwarded-For only when explicitly
 * configured to trust a proxy. Trusting that header unconditionally would let
 * any client forge its own IP and walk straight through the rate limiter.
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

/** Reject oversized bodies before they are buffered or parsed. */
export function bodyLimit(maxBytes: number): MiddlewareHandler {
  return async (c, next) => {
    const declared = c.req.header("Content-Length");
    if (declared && Number(declared) > maxBytes) {
      return c.json({ error: "payload_too_large" }, 413);
    }
    await next();
  };
}
