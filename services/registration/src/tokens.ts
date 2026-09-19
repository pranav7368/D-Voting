/**
 * Short-lived registration tokens (HMAC-SHA256, JWT-shaped but deliberately not JWT).
 *
 * Why not a JWT library: JWT's `alg` header field is a well-known footgun --
 * "alg": "none" and RS256/HS256 confusion have both produced real
 * authentication bypasses. This token format has no algorithm negotiation at
 * all. There is exactly one algorithm, fixed in code, so there is nothing for
 * an attacker to negotiate. For a single-issuer single-verifier token that is
 * strictly better than importing a general-purpose library.
 *
 * Format:  base64url(payloadJson) "." base64url(HMAC-SHA256(payloadB64))
 */

import { constantTimeEqual, fromBase64Url, toBase64Url, utf8 } from "@dvoting/crypto";

export interface RegistrationTokenPayload {
  /** Format version, so the token can be changed without ambiguity later. */
  v: 1;
  /** Voter row id. */
  sub: string;
  /** Election id, bound in so a token cannot be replayed against another election. */
  el: string;
  /** Expiry, seconds since epoch. */
  exp: number;
  /** Unique token id, for audit correlation. */
  jti: string;
}

export class TokenError extends Error {
  override name = "TokenError";
}

// Return type is inferred: `CryptoKey` is a DOM-lib type and this package
// compiles without the DOM lib so it stays runnable on Node and React Native.
async function importKey(secret: string) {
  return globalThis.crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

export async function issueRegistrationToken(
  secret: string,
  payload: Omit<RegistrationTokenPayload, "v" | "jti">,
): Promise<{ token: string; jti: string }> {
  const jti = globalThis.crypto.randomUUID();
  const full: RegistrationTokenPayload = { v: 1, jti, ...payload };

  const body = toBase64Url(utf8(JSON.stringify(full)));
  const key = await importKey(secret);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, utf8(body)));

  return { token: `${body}.${toBase64Url(mac)}`, jti };
}

export async function verifyRegistrationToken(
  secret: string,
  token: string,
  expectedElectionId: string,
  now: Date = new Date(),
): Promise<RegistrationTokenPayload> {
  const parts = token.split(".");
  if (parts.length !== 2) throw new TokenError("malformed token");
  const [body, providedMac] = parts as [string, string];

  const key = await importKey(secret);
  const expectedMac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, utf8(body)));

  let providedMacBytes: Uint8Array;
  try {
    providedMacBytes = fromBase64Url(providedMac);
  } catch {
    throw new TokenError("malformed token");
  }

  // Verify the MAC BEFORE parsing the payload. Parsing attacker-controlled JSON
  // from an unauthenticated token would expose the parser to untrusted input
  // and can leak information through differential error messages.
  if (!constantTimeEqual(expectedMac, providedMacBytes)) {
    throw new TokenError("invalid token signature");
  }

  let payload: RegistrationTokenPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(fromBase64Url(body))) as RegistrationTokenPayload;
  } catch {
    throw new TokenError("malformed token payload");
  }

  if (payload.v !== 1) throw new TokenError("unsupported token version");
  if (typeof payload.sub !== "string" || typeof payload.el !== "string") {
    throw new TokenError("malformed token payload");
  }
  if (payload.el !== expectedElectionId) throw new TokenError("token is for a different election");
  if (typeof payload.exp !== "number" || payload.exp * 1000 <= now.getTime()) {
    throw new TokenError("token has expired");
  }

  return payload;
}
