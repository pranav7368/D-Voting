import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { toBase64Url, utf8 } from "@dvoting/crypto";

import { TokenError, issueRegistrationToken, verifyRegistrationToken } from "../src/tokens.ts";

const SECRET = "a-token-secret-long-enough-for-tests-ok";
const ELECTION = "election-2026-demo";

function futureExp(seconds = 600): number {
  return Math.floor(Date.now() / 1000) + seconds;
}

describe("registration tokens", () => {
  it("round-trips a valid token", async () => {
    const sub = globalThis.crypto.randomUUID();
    const { token, jti } = await issueRegistrationToken(SECRET, {
      sub,
      el: ELECTION,
      exp: futureExp(),
    });

    const payload = await verifyRegistrationToken(SECRET, token, ELECTION);
    assert.equal(payload.sub, sub);
    assert.equal(payload.el, ELECTION);
    assert.equal(payload.jti, jti);
  });

  it("issues a unique jti per token", async () => {
    const a = await issueRegistrationToken(SECRET, { sub: "s", el: ELECTION, exp: futureExp() });
    const b = await issueRegistrationToken(SECRET, { sub: "s", el: ELECTION, exp: futureExp() });
    assert.notEqual(a.jti, b.jti);
    assert.notEqual(a.token, b.token);
  });

  it("rejects a wrong secret", async () => {
    const { token } = await issueRegistrationToken(SECRET, {
      sub: "s",
      el: ELECTION,
      exp: futureExp(),
    });
    await assert.rejects(
      () => verifyRegistrationToken("a-different-secret-also-long-enough", token, ELECTION),
      TokenError,
    );
  });

  it("rejects a tampered payload", async () => {
    const { token } = await issueRegistrationToken(SECRET, {
      sub: "voter-a",
      el: ELECTION,
      exp: futureExp(),
    });

    // Swap the payload for one naming a different voter, keeping the old MAC.
    const forgedPayload = toBase64Url(
      utf8(JSON.stringify({ v: 1, sub: "voter-b", el: ELECTION, exp: futureExp(), jti: "x" })),
    );
    const forged = `${forgedPayload}.${token.split(".")[1]}`;

    await assert.rejects(() => verifyRegistrationToken(SECRET, forged, ELECTION), TokenError);
  });

  it("rejects an expired token", async () => {
    const { token } = await issueRegistrationToken(SECRET, {
      sub: "s",
      el: ELECTION,
      exp: Math.floor(Date.now() / 1000) - 1,
    });
    await assert.rejects(() => verifyRegistrationToken(SECRET, token, ELECTION), /expired/);
  });

  it("binds the token to its election", async () => {
    const { token } = await issueRegistrationToken(SECRET, {
      sub: "s",
      el: ELECTION,
      exp: futureExp(),
    });
    await assert.rejects(
      () => verifyRegistrationToken(SECRET, token, "another-election"),
      /different election/,
    );
  });

  it("rejects structurally malformed tokens", async () => {
    for (const bad of ["", "no-dot", "a.b.c", ".", "abc.!!!"]) {
      await assert.rejects(
        () => verifyRegistrationToken(SECRET, bad, ELECTION),
        TokenError,
        `accepted malformed token: ${JSON.stringify(bad)}`,
      );
    }
  });

  it("has no algorithm field to confuse", async () => {
    // Unlike JWT there is no `alg` header, so the "alg: none" class of
    // authentication bypass is structurally impossible here.
    const { token } = await issueRegistrationToken(SECRET, {
      sub: "s",
      el: ELECTION,
      exp: futureExp(),
    });
    const decoded = Buffer.from(token.split(".")[0]!, "base64url").toString();
    assert.ok(!decoded.includes("alg"));
  });
});
