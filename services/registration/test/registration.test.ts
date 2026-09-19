import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { blind, finalize, generateCredential, toBase64Url, verify } from "@dvoting/crypto";

import { createHarness, issuerKeys, postJson, registerNewVoter } from "./helpers.ts";
import { issueRegistrationToken } from "../src/tokens.ts";

describe("GET /v1/issuer", () => {
  it("publishes the public key and a stable key id", async () => {
    const harness = createHarness();
    const { app } = harness;
    const res = await app.request("/v1/issuer");
    assert.equal(res.status, 200);

    const body = (await res.json()) as Record<string, unknown>;
    assert.equal(body.suite, "RSABSSA-SHA384-PSS-Deterministic");
    assert.equal(body.modulusBits, 2048);
    assert.equal(body.electionId, "election-2026-demo");
    assert.ok(typeof body.keyId === "string" && body.keyId.length > 0);

    const jwk = body.publicKey as { kty: string; n: string; e: string };
    assert.equal(jwk.kty, "RSA");
    assert.ok(jwk.n.length > 0);

    // Must be cacheable: every voter needs to see the same key.
    assert.match(res.headers.get("Cache-Control") ?? "", /public/);
  });

  it("never exposes private key material", async () => {
    const harness = createHarness();
    const { app } = harness;
    const text = await (await app.request("/v1/issuer")).text();
    for (const field of ['"d"', '"p"', '"q"', '"dp"', '"dq"', '"qi"']) {
      assert.ok(!text.includes(field), `issuer endpoint leaked private field ${field}`);
    }
  });
});

describe("the full issuance flow", () => {
  it("registers a voter and issues a verifiable anonymous credential", async () => {
    const harness = createHarness();
    const { app } = harness;

    const registerRes = await registerNewVoter(harness);
    assert.equal(registerRes.status, 200);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    // Everything from here happens on the voter's device.
    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(issuerKeys.publicKey, credential);

    const issueRes = await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(blindedMessage),
    });
    assert.equal(issueRes.status, 200);

    const { blindSignature, replayed } = (await issueRes.json()) as {
      blindSignature: string;
      replayed: boolean;
    };
    assert.equal(replayed, false);

    const signature = await finalize(
      issuerKeys.publicKey,
      credential,
      Buffer.from(blindSignature, "base64url"),
      inverse,
    );

    assert.ok(await verify(issuerKeys.publicKey, credential, signature));
  });

  it("never receives the credential itself", async () => {
    // Asserts the core privacy claim structurally: the only voter-supplied
    // value the service stores is the blinded message hash, and the credential
    // is not recoverable from it.
    const harness = createHarness();
    const { app, repository } = harness;

    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const credential = generateCredential();
    const { blindedMessage } = await blind(issuerKeys.publicKey, credential);
    await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(blindedMessage),
    });

    const voter = await repository.findVoterById(await firstVoterId(repository));
    assert.ok(voter, "voter should exist");

    // The stored row holds a hash of the BLINDED message and the BLIND
    // signature -- neither of which contains the credential in any encoding.
    const stored = JSON.stringify({
      ...voter,
      identityHash: toBase64Url(voter.identityHash),
      blindedMessageHash: voter.blindedMessageHash && toBase64Url(voter.blindedMessageHash),
      blindSignature: voter.blindSignature && toBase64Url(voter.blindSignature),
    });

    assert.ok(!stored.includes(toBase64Url(credential)), "credential leaked into storage");
    assert.ok(
      !stored.includes(Buffer.from(credential).toString("hex")),
      "credential leaked into storage",
    );
    assert.ok(voter.blindedMessageHash !== null, "blinded message hash should be recorded");
  });
});

describe("one person, one credential", () => {
  it("refuses a second registration once a credential is issued", async () => {
    const harness = createHarness();
    const { app } = harness;
    // The SAME polling card is presented both times.
    const card = await harness.enrol();

    const first = await postJson(app, "/v1/register", card);
    const { registrationToken } = (await first.json()) as { registrationToken: string };

    const credential = generateCredential();
    const { blindedMessage } = await blind(issuerKeys.publicKey, credential);
    await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(blindedMessage),
    });

    const second = await postJson(app, "/v1/register", card);
    assert.equal(second.status, 409);
    assert.equal(((await second.json()) as { error: string }).error, "credential_already_issued");
  });

  it("refuses a second DIFFERENT blinded message under the same token", async () => {
    // The attack: register once, then try to harvest two valid credentials by
    // reusing the still-valid registration token. This is ballot stuffing.
    const harness = createHarness();
    const { app } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const first = await blind(issuerKeys.publicKey, generateCredential());
    const second = await blind(issuerKeys.publicKey, generateCredential());

    const ok = await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(first.blindedMessage),
    });
    assert.equal(ok.status, 200);

    const refused = await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(second.blindedMessage),
    });
    assert.equal(refused.status, 409);
    assert.equal(((await refused.json()) as { error: string }).error, "credential_already_issued");
  });

  it("serves an identical retry idempotently so a crashed client is not disenfranchised", async () => {
    const harness = createHarness();
    const { app } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(issuerKeys.publicKey, credential);
    const payload = { registrationToken, blindedMessage: toBase64Url(blindedMessage) };

    const first = (await (await postJson(app, "/v1/credential/issue", payload)).json()) as {
      blindSignature: string;
      replayed: boolean;
    };
    const retry = (await (await postJson(app, "/v1/credential/issue", payload)).json()) as {
      blindSignature: string;
      replayed: boolean;
    };

    assert.equal(first.replayed, false);
    assert.equal(retry.replayed, true);
    assert.equal(first.blindSignature, retry.blindSignature);

    // And the replayed signature is still a working credential.
    const signature = await finalize(
      issuerKeys.publicKey,
      credential,
      Buffer.from(retry.blindSignature, "base64url"),
      inverse,
    );
    assert.ok(await verify(issuerKeys.publicKey, credential, signature));
  });

  it("survives a concurrent double-issuance race", async () => {
    // Fire two DIFFERENT blinded messages simultaneously. Exactly one must win.
    const harness = createHarness();
    const { app } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const a = await blind(issuerKeys.publicKey, generateCredential());
    const b = await blind(issuerKeys.publicKey, generateCredential());

    const [resA, resB] = await Promise.all([
      postJson(app, "/v1/credential/issue", {
        registrationToken,
        blindedMessage: toBase64Url(a.blindedMessage),
      }),
      postJson(app, "/v1/credential/issue", {
        registrationToken,
        blindedMessage: toBase64Url(b.blindedMessage),
      }),
    ]);

    const statuses = [resA.status, resB.status].sort();
    assert.deepEqual(statuses, [200, 409], "exactly one concurrent issuance must succeed");
  });

  it("does not spend the issuance when signing fails", async () => {
    // A transient signer fault must leave the voter able to retry, not
    // permanently locked out.
    const harness = createHarness();
    const { app, repository, deps } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const credential = generateCredential();
    const { blindedMessage, inverse } = await blind(issuerKeys.publicKey, credential);
    const payload = { registrationToken, blindedMessage: toBase64Url(blindedMessage) };

    const realSign = deps.signer.blindSign.bind(deps.signer);
    let failNext = true;
    deps.signer.blindSign = async (message: Uint8Array) => {
      if (failNext) {
        failNext = false;
        throw new Error("simulated HSM outage");
      }
      return realSign(message);
    };

    const failed = await postJson(app, "/v1/credential/issue", payload);
    assert.equal(failed.status, 500);

    const voterId = await firstVoterId(repository);
    const voter = await repository.findVoterById(voterId);
    assert.equal(voter?.credentialIssuedAt, null, "issuance was spent despite the signing failure");

    // The retry must now succeed and yield a working credential.
    const recovered = await postJson(app, "/v1/credential/issue", payload);
    assert.equal(recovered.status, 200);
    const { blindSignature } = (await recovered.json()) as { blindSignature: string };
    const signature = await finalize(
      issuerKeys.publicKey,
      credential,
      Buffer.from(blindSignature, "base64url"),
      inverse,
    );
    assert.ok(await verify(issuerKeys.publicKey, credential, signature));
  });
});

describe("authentication and input validation", () => {
  it("rejects a forged registration token", async () => {
    const harness = createHarness();
    const { app } = harness;
    const { token } = await issueRegistrationToken("the-wrong-secret-but-long-enough-x", {
      sub: globalThis.crypto.randomUUID(),
      el: "election-2026-demo",
      exp: Math.floor(Date.now() / 1000) + 600,
    });

    const { blindedMessage } = await blind(issuerKeys.publicKey, generateCredential());
    const res = await postJson(app, "/v1/credential/issue", {
      registrationToken: token,
      blindedMessage: toBase64Url(blindedMessage),
    });
    assert.equal(res.status, 401);
  });

  it("rejects an expired token", async () => {
    const harness = createHarness();
    const { app, config } = harness;
    const { token } = await issueRegistrationToken(config.REGISTRATION_TOKEN_SECRET, {
      sub: globalThis.crypto.randomUUID(),
      el: config.ELECTION_ID,
      exp: Math.floor(Date.now() / 1000) - 1,
    });

    const { blindedMessage } = await blind(issuerKeys.publicKey, generateCredential());
    const res = await postJson(app, "/v1/credential/issue", {
      registrationToken: token,
      blindedMessage: toBase64Url(blindedMessage),
    });
    assert.equal(res.status, 401);
    assert.match(((await res.json()) as { message: string }).message, /expired/);
  });

  it("rejects a token minted for a different election", async () => {
    const harness = createHarness();
    const { app, config } = harness;
    const { token } = await issueRegistrationToken(config.REGISTRATION_TOKEN_SECRET, {
      sub: globalThis.crypto.randomUUID(),
      el: "some-other-election",
      exp: Math.floor(Date.now() / 1000) + 600,
    });

    const { blindedMessage } = await blind(issuerKeys.publicKey, generateCredential());
    const res = await postJson(app, "/v1/credential/issue", {
      registrationToken: token,
      blindedMessage: toBase64Url(blindedMessage),
    });
    assert.equal(res.status, 401);
  });

  it("rejects a blinded message of the wrong size", async () => {
    const harness = createHarness();
    const { app } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const res = await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: toBase64Url(new Uint8Array(64)),
    });
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as { error: string }).error, "invalid_blinded_message");
  });

  it("rejects a voter who is not on the electoral roll", async () => {
    const harness = createHarness();
    const { app } = harness;
    const res = await postJson(app, "/v1/register", {
      rollId: "R-999999",
      enrolmentCode: "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZ",
    });
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as { error: string }).error, "not_eligible");
  });

  it("rejects a valid roll number with the wrong enrolment code", async () => {
    const harness = createHarness();
    const card = await harness.enrol();

    const res = await postJson(harness.app, "/v1/register", {
      rollId: card.rollId,
      enrolmentCode: "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZ",
    });
    assert.equal(res.status, 403);
  });

  it("gives an IDENTICAL response for an unknown roll id and a wrong code", async () => {
    // Otherwise the endpoint is an oracle for enumerating who is registered to
    // vote, which for an electoral roll is a privacy breach in itself.
    const harness = createHarness();
    const card = await harness.enrol();
    const wrongCode = "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZ";

    const unknown = await postJson(harness.app, "/v1/register", {
      rollId: "R-does-not-exist",
      enrolmentCode: wrongCode,
    });
    const wrong = await postJson(harness.app, "/v1/register", {
      rollId: card.rollId,
      enrolmentCode: wrongCode,
    });

    assert.equal(unknown.status, wrong.status);
    assert.deepEqual(await unknown.json(), await wrong.json());
  });

  it("rejects unknown fields and malformed bodies", async () => {
    const harness = createHarness();
    const { app } = harness;

    const extra = await postJson(app, "/v1/register", {
      ...(await harness.enrol()),
      isAdmin: true,
    });
    assert.equal(extra.status, 400);

    const malformed = await app.request("/v1/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{ not json",
    });
    assert.equal(malformed.status, 400);
  });

  it("rejects non-base64url blinded messages", async () => {
    const harness = createHarness();
    const { app } = harness;
    const registerRes = await registerNewVoter(harness);
    const { registrationToken } = (await registerRes.json()) as { registrationToken: string };

    const res = await postJson(app, "/v1/credential/issue", {
      registrationToken,
      blindedMessage: "!!!! not base64url !!!!",
    });
    assert.equal(res.status, 400);
  });
});

describe("hardening", () => {
  it("sets security headers and no-store on sensitive responses", async () => {
    const harness = createHarness();
    const { app } = harness;
    const res = await registerNewVoter(harness);

    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(res.headers.get("X-Frame-Options"), "DENY");
    assert.equal(res.headers.get("Referrer-Policy"), "no-referrer");
    assert.equal(res.headers.get("Cache-Control"), "no-store");
  });

  it("rate limits repeated requests", async () => {
    const harness = createHarness({
      RATE_LIMIT_MAX_REQUESTS: "3",
      RATE_LIMIT_WINDOW_SECONDS: "60",
    });

    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const res = await registerNewVoter(harness);
      statuses.push(res.status);
    }
    assert.ok(statuses.includes(429), `expected a 429, got ${statuses.join(", ")}`);
  });

  it("does not reflect arbitrary CORS origins", async () => {
    const harness = createHarness();
    const { app } = harness;
    const res = await app.request("/v1/issuer", { headers: { Origin: "https://evil.example" } });
    assert.equal(res.headers.get("Access-Control-Allow-Origin"), null);
  });
});

/** The in-memory repo has no list API; walk the audit log for the voter id. */
async function firstVoterId(repository: { audit: { subjectRef?: string }[] }): Promise<string> {
  const entry = repository.audit.find((e) => e.subjectRef);
  if (!entry?.subjectRef) throw new Error("no voter recorded in audit log");
  return entry.subjectRef;
}


