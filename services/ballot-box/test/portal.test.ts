import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createApp } from "../src/app.ts";
import { createHarness } from "./helpers.ts";

async function app() {
  const harness = await createHarness();
  return { app: createApp({ ballotBox: harness.ballotBox }), harness };
}

describe("public verification portal", () => {
  it("serves the voter interface at / and /vote", async () => {
    const { app: server } = await app();
    for (const path of ["/", "/vote"]) {
      const response = await server.request(path);
      assert.equal(response.status, 200, path);
      assert.match(response.headers.get("Content-Type") ?? "", /text\/html/);
      const body = await response.text();
      assert.match(body, /Prove you are on the electoral roll/);
      assert.match(body, /vote-page\.js/);
    }
  });

  it("offers a way to re-vote after casting, without re-registering", async () => {
    // Found by manual testing: the backend has always allowed a credential to
    // cast a superseding ballot (last vote counts -- the coercion-mitigation
    // story the docs describe), but the voter-facing page had no button to do
    // it after a successful cast, and reloading the tab to start over is
    // refused ("credential_already_issued"). Losing this button silently would
    // mean the re-voting feature exists in the protocol but not for a voter.
    const { app: server } = await app();
    const body = await (await server.request("/vote")).text();
    assert.match(body, /id="revote"/, "no re-vote affordance on the receipt step");
    assert.match(body, /Vote again with this credential/);

    // And the client-side piece it depends on: casting must never clear the
    // credential, and there must be a way to reset just the ballot state.
    const voterJs = await (await server.request("/voter.js")).text();
    assert.match(voterJs, /function resetForRevote/);
  });

  it("keeps all page scripts external, so the strict CSP holds", async () => {
    // An inline <script> or style="..." would force 'unsafe-inline', which
    // removes the main protection CSP offers on pages handling a credential.
    const harness = await createHarness();
    const server = createApp({
      ballotBox: harness.ballotBox,
      adminToken: "an-admin-token-long-enough-to-be-ok",
    });
    for (const path of ["/", "/verify", "/results", "/admin", "/chain"]) {
      const body = await (await server.request(path)).text();
      assert.ok(!/<script(?![^>]*\bsrc=)/i.test(body), `${path} has an inline script`);
      assert.ok(!/\sstyle="/i.test(body), `${path} has an inline style attribute`);
      assert.ok(!/\son[a-z]+="/i.test(body), `${path} has an inline event handler`);
    }
  });

  it("serves the verification page at /verify", async () => {
    const { app: server } = await app();
    const response = await server.request("/verify");
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.match(body, /Verify your ballot/);
    assert.match(body, /verify-page\.js/);
  });

  it("every page script's $(\"id\") lookups resolve to a real element", async () => {
    // The general form of a bug found by hand while renaming an element for
    // the display-name feature: a $("stale-id") lookup returns null and throws
    // the moment its handler runs, with nothing in the test suite noticing,
    // because rendering the HTML never executes the page's JavaScript. This
    // checks the two artefacts agree, for every page that has both.
    const { app: server } = await app();
    const pairs: [string, string, string[]][] = [
      ["/vote", "/vote-page.js", ["/voter.js"]],
      ["/verify", "/verify-page.js", []],
      ["/results", "/results-page.js", []],
      ["/chain", "/chain-page.js", []],
    ];

    for (const [htmlPath, scriptPath, extraScripts] of pairs) {
      const html = await (await server.request(htmlPath)).text();
      const declaredIds = new Set([...html.matchAll(/\sid="([\w-]+)"/g)].map((m) => m[1]));

      const scripts = [scriptPath, ...extraScripts];
      const referencedIds = new Set<string>();
      for (const path of scripts) {
        const text = await (await server.request(path)).text();
        for (const m of text.matchAll(/\$\("([\w-]+)"\)/g)) referencedIds.add(m[1]!);
      }

      for (const id of referencedIds) {
        assert.ok(
          declaredIds.has(id),
          `${scripts.join(" + ")} references #${id}, which ${htmlPath} does not declare`,
        );
      }
    }
  });

  it("serves the Chain Explorer, publicly and without an admin token", async () => {
    // Transparency is the point: an observer should not need a token to watch
    // the chain be independently re-verified.
    const { app: server } = await app();
    const page = await server.request("/chain");
    assert.equal(page.status, 200);
    const body = await page.text();
    assert.match(body, /chain-page\.js/);
    assert.match(body, /re-checked/);

    for (const script of ["/chain-page.js", "/chain-lib.js"]) {
      const response = await server.request(script);
      assert.equal(response.status, 200, script);
      assert.match(response.headers.get("Content-Type") ?? "", /javascript/);
    }
  });

  it("never caches the election descriptor", async () => {
    // It carries the issuer key id a voter's browser pins. A stale copy would
    // surface as a key-mismatch alarm indistinguishable from a real attack.
    const { app: server } = await app();
    const response = await server.request("/v1/election");
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  });

  it("serves the results page and the stylesheet", async () => {
    const { app: server } = await app();
    assert.match(await (await server.request("/results")).text(), /Independent recount|No result yet|Result/);
    const css = await server.request("/app.css");
    assert.equal(css.status, 200);
    assert.match(css.headers.get("Content-Type") ?? "", /text\/css/);
  });

  it("serves the browser crypto bundle, without server-only key material", async () => {
    // The bundle is what lets a ballot be encrypted on the voter's device. It
    // must not carry issuer key generation into a browser.
    const { app: server } = await app();
    const response = await server.request("/dvoting-crypto.js");
    assert.equal(response.status, 200);
    assert.match(response.headers.get("Content-Type") ?? "", /javascript/);

    const body = await response.text();
    assert.match(body, /prepareBallot|createBallot/);
    for (const forbidden of ["node:crypto", "generateIssuerKeyPair", "privateKeyToJwk"]) {
      assert.ok(!body.includes(forbidden), `bundle leaked server-only "${forbidden}"`);
    }
  });

  it("serves the verification library as JavaScript", async () => {
    const { app: server } = await app();
    const response = await server.request("/verify-lib.js");
    assert.equal(response.status, 200);
    assert.match(response.headers.get("Content-Type") ?? "", /javascript/);
    assert.match(await response.text(), /verifyBallotReceipt/);
  });

  it("allows the portal's own script but nothing external", async () => {
    // The page's whole job is to be trustworthy, so its CSP has to be tight --
    // and the API's deny-everything policy must not clobber it.
    const { app: server } = await app();
    const csp = (await server.request("/")).headers.get("Content-Security-Policy") ?? "";
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /connect-src 'self'/);
    assert.ok(!csp.includes("unsafe-eval"));
    assert.ok(!csp.includes("unsafe-inline"));
    assert.match(csp, /frame-ancestors 'none'/);
  });

  it("keeps the API's strict policy on JSON endpoints", async () => {
    const { app: server } = await app();
    const csp = (await server.request("/v1/election")).headers.get("Content-Security-Policy") ?? "";
    assert.match(csp, /default-src 'none'/);
    assert.ok(!csp.includes("script-src 'self'"));
  });

  it("does NOT expose a general file server", async () => {
    // Path traversal is how a "just serve ./public" helper becomes arbitrary
    // file disclosure -- and this service has an issuer key and a chain on disk.
    const { app: server } = await app();
    for (const path of [
      "/../src/ballot-box.ts",
      "/%2e%2e/package.json",
      "/../../package.json",
      "/verify-lib.js/../../src/app.ts",
    ]) {
      const response = await server.request(path);
      assert.notEqual(response.status, 200, `traversal succeeded for ${path}`);
    }
  });

  it("publishes what a verifier needs, and nothing secret", async () => {
    const { app: server } = await app();
    const body = (await (await server.request("/v1/election")).json()) as Record<string, unknown>;

    assert.ok(Array.isArray(body.validators));
    assert.equal(typeof body.quorum, "number");
    assert.ok(body.electionPublicKey);

    // No private material anywhere in the public descriptor.
    const text = JSON.stringify(body);
    for (const forbidden of ["privateKey", "keyShare", '"d"', "secret"]) {
      assert.ok(!text.includes(forbidden), `election descriptor leaked ${forbidden}`);
    }
  });

  it("throttles the write path but never the bulletin board", async () => {
    // Casting runs a full zero-knowledge verification, so an unthrottled
    // endpoint is a CPU exhaustion primitive. The read path stays open:
    // rate-limiting an auditor downloading the chain is the opposite of the
    // point of publishing it.
    const harness = await createHarness();
    const server = createApp({
      ballotBox: harness.ballotBox,
      rateLimit: { windowSeconds: 60, maxRequests: 3 },
    });

    const cast = () =>
      server.request("/v1/ballots", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

    // Four attempts against a limit of three: the last one is refused before it
    // ever reaches the verification path.
    let lastStatus = 0;
    for (let i = 0; i < 4; i++) lastStatus = (await cast()).status;
    assert.equal(lastStatus, 429);

    const board = await server.request("/v1/bulletin/head");
    assert.equal(board.status, 200, "the bulletin board must never be throttled");
  });

  it("includes the view so a client can recompute the block hash", async () => {
    // Block 0 is the sealed election configuration, written when the poll opens.
    const { app: server } = await app();

    const body = (await (await server.request("/v1/bulletin/blocks/0")).json()) as {
      header: Record<string, unknown>;
    };
    assert.equal(typeof body.header.view, "number");
    assert.equal(typeof body.header.previousHash, "string");
    assert.equal(typeof body.header.merkleRoot, "string");
  });
});
