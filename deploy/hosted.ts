/**
 * Hosted demo: the whole election on one public URL.
 *
 * ===========================================================================
 * WHY THIS EXISTS, AND WHAT IT IS NOT.
 *
 * `npm run dev` runs fourteen separate processes, which is the honest shape of
 * the system but does not fit a free hosting tier (512 MB of memory, one public
 * port). This entry point runs every party inside ONE Node process and fronts
 * them with a path-routing gateway, so the full system is reachable at a
 * single HTTPS address:
 *
 *   /                 ballot box: voting, verification, results, public record
 *   /admin            commission console
 *   /ra/...           Registration Authority
 *   /w/<id>/...       witnesses (each with its own key and replica)
 *   /trustee/<n>/     trustee consoles (each holding one key share)
 *   /demo             how to try it, with public demo polling cards
 *
 * Each party still holds only its own key and keeps its own replica, and every
 * check runs exactly as in the multi-process system. What a single process
 * cannot give is INDEPENDENCE: whoever runs this host could read every key.
 * That is acceptable for a demonstration and for nothing else. The hosted
 * election is in memory: it starts fresh, with an automatically opened demo
 * election, every time the service starts.
 * ===========================================================================
 */

import { serve } from "@hono/node-server";
import {
  LocalBlindSigner,
  MODP_2048,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  encodeElement,
  randomBytes,
  runDkg,
  toBase64Url,
} from "@dvoting/crypto";
import { generateIssuerKeyPair, privateKeyToJwk } from "@dvoting/crypto/keygen";
import {
  DistributedSealer,
  InMemoryBlockStore,
  Ledger,
  LocalValidatorPeer,
  ValidatorNode,
  createValidatorSet,
  generateValidatorKeyPair,
} from "@dvoting/ledger";

import { createApp as createBallotBoxApp } from "../services/ballot-box/src/app.ts";
import { BallotBox } from "../services/ballot-box/src/ballot-box.ts";
import { createBallotEntryValidator } from "../services/ballot-box/src/entry-validator.ts";
import { validateWitnessRoster } from "../services/ballot-box/src/election-record.ts";
import { createApp as createRegistrationApp } from "../services/registration/src/app.ts";
import { loadConfig } from "../services/registration/src/config.ts";
import { ElectoralRollVerifier, InMemoryElectoralRollStore } from "../services/registration/src/eligibility/electoral-roll.ts";
import { generateEnrolmentCode, hashEnrolmentCode } from "../services/registration/src/eligibility/enrolment-code.ts";
import { InMemoryVoterRepository } from "../services/registration/src/repo/memory.ts";
import { createApp as createTrusteeApp } from "../services/trustee/src/app.ts";
import { Trustee } from "../services/trustee/src/trustee.ts";
import { createApp as createWitnessApp } from "../services/witness/src/app.ts";
import { Witness } from "../services/witness/src/witness.ts";

// --- configuration --------------------------------------------------------------

const PORT = Number(process.env.PORT ?? 10000);
const BASE = (process.env.PUBLIC_URL ?? process.env.RENDER_EXTERNAL_URL ?? `http://localhost:${PORT}`).replace(/\/+$/, "");
const ELECTION_ID = process.env.ELECTION_ID ?? "dvoting-demo";
const VOTERS = Number(process.env.DEMO_VOTERS ?? 200);
const AUTO_OPEN = process.env.DEMO_AUTO_OPEN !== "off";
const PUBLIC_CARDS = process.env.DEMO_PUBLIC_CARDS !== "off";
const STUDY = process.env.STUDY_MODE === "on";
const GROUP = MODP_2048; // fast on shared hosting; production default is 3072-bit
const secret = () => toBase64Url(randomBytes(32));
const ADMIN_TOKEN = process.env.ADMIN_TOKEN && process.env.ADMIN_TOKEN.length >= 32 ? process.env.ADMIN_TOKEN : secret();
const ROLL_ADMIN_TOKEN = process.env.ROLL_ADMIN_TOKEN && process.env.ROLL_ADMIN_TOKEN.length >= 32 ? process.env.ROLL_ADMIN_TOKEN : secret();

const VALIDATORS = ["election-commission", "observer-press", "observer-university", "observer-ngo"];
const TRUSTEE_LABELS = ["Election Commission", "Supreme Court observer", "Governing party agent", "Opposition party agent", "University observer"];
const WITNESSES = [
  { id: "agent-psf", label: "Polling agent, Progressive Students Front" },
  { id: "agent-cua", label: "Polling agent, Campus Unity Alliance" },
  { id: "civil-observer", label: "Independent civil-society observer" },
];

const log = (text: string) => console.log(`[hosted] ${text}`);

// --- keys and parties -----------------------------------------------------------

log("generating keys…");
const issuer = generateIssuerKeyPair(2048, RSABSSA_SHA384_PSS_DETERMINISTIC);
const dkg = runDkg(GROUP, 3, 5);
const validatorKeys = await Promise.all(VALIDATORS.map((id) => generateValidatorKeyPair(id)));
const witnessKeys = await Promise.all(WITNESSES.map((w) => generateValidatorKeyPair(w.id)));
const validatorSet = createValidatorSet(validatorKeys.map((k) => k.identity));

// Validators: one key and one replica each, re-verifying every ballot.
const peers = validatorKeys.map((k) => {
  const replica = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION_ID);
  return new LocalValidatorPeer(new ValidatorNode({
    identity: k.identity,
    privateKey: k.privateKey,
    ledger: replica,
    validateEntry: createBallotEntryValidator(replica, ELECTION_ID),
  }));
});

// Ballot box: its own replica, no signing keys.
const ledger = new Ledger(new InMemoryBlockStore(), validatorSet, ELECTION_ID);
const ballotBox = new BallotBox({
  election: { electionId: ELECTION_ID, candidates: ["Asha Verma", "Rohit Nair", "Meera Iyer"], minSelections: 1, maxSelections: 1 },
  issuerPublicKey: issuer.publicKey,
  electionPublicKey: dkg.publicKey,
  trustees: {
    threshold: 3,
    total: 5,
    publicShares: dkg.publicShares.map((s) => ({ index: s.index, publicShare: toBase64Url(encodeElement(GROUP, s.publicShare)) })),
  },
  ledger,
  sealer: new DistributedSealer(ledger, peers),
  maxPendingBeforeSeal: 1,
  registrationUrl: `${BASE}/ra`,
  witnesses: validateWitnessRoster({
    quorum: 2,
    witnesses: witnessKeys.map((k) => ({ id: k.identity.id, publicKey: toBase64Url(k.identity.publicKey), url: `${BASE}/w/${k.identity.id}` })),
  }),
  ...(STUDY ? { studyMode: true } : {}),
});
await ballotBox.load();
setInterval(() => {
  if (ballotBox.pendingCount > 0) ballotBox.sealBlock().catch((e: unknown) => console.error("[hosted] timed seal failed", e));
}, 3000).unref();
const ballotBoxApp = createBallotBoxApp({ ballotBox, trustProxy: true, adminToken: ADMIN_TOKEN });

/** A fetch that reaches the ballot box inside this process (for trustees and witnesses). */
const toBallotBox = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(String(input instanceof Request ? input.url : input), "http://internal");
  return ballotBoxApp.fetch(new Request(`http://internal${url.pathname}${url.search}`, init));
}) as typeof fetch;

// Registration Authority, with a demo electoral roll.
const pepper = secret();
const raConfig = loadConfig({
  NODE_ENV: "development",
  PORT: String(PORT),
  ELECTION_ID,
  ISSUER_PRIVATE_KEY_JWK: JSON.stringify(privateKeyToJwk(issuer.privateKey)),
  IDENTITY_PEPPER: pepper,
  REGISTRATION_TOKEN_SECRET: secret(),
  STORAGE_DRIVER: "memory",
  ADMIN_TOKEN: ROLL_ADMIN_TOKEN,
  CORS_ALLOWED_ORIGINS: new URL(BASE).origin,
  TRUST_PROXY: "true",
});
const rollStore = new InMemoryElectoralRollStore();
const cards: { rollId: string; code: string }[] = [];
for (let i = 0; i < VOTERS; i++) {
  const rollId = `R-${100001 + i}`;
  const code = generateEnrolmentCode();
  await rollStore.addEntry({ rollId, electionId: ELECTION_ID, enrolmentCodeHash: await hashEnrolmentCode(pepper, rollId, code) });
  cards.push({ rollId, code });
}
const registrationApp = createRegistrationApp({
  config: raConfig,
  repository: new InMemoryVoterRepository(),
  eligibilityVerifier: new ElectoralRollVerifier({ store: rollStore, pepper, electionId: ELECTION_ID }),
  signer: new LocalBlindSigner(issuer.privateKey),
  rollStore,
});

// Witnesses: own key, own replica, watching the board.
const witnessApps = new Map<string, ReturnType<typeof createWitnessApp>>();
const witnesses: Witness[] = [];
for (const k of witnessKeys) {
  const store = new InMemoryBlockStore();
  const witness = await Witness.open({
    id: k.identity.id, privateKey: k.privateKey, electionId: ELECTION_ID,
    ballotBoxUrl: "http://internal", store, fetchImpl: toBallotBox,
  });
  witnesses.push(witness);
  witnessApps.set(k.identity.id, createWitnessApp({ witness, store }));
}
setInterval(() => {
  for (const w of witnesses) w.sync().catch(() => undefined);
}, 3000).unref();

// Trustees: one share each, each behind its own token.
const trustees = dkg.keyShares.map((share, index) => {
  const token = secret();
  const trustee = new Trustee({
    electionId: ELECTION_ID, group: GROUP, index: share.index, share: share.share,
    ballotBoxUrl: "http://internal", fetchImpl: toBallotBox,
  });
  const label = TRUSTEE_LABELS[index] ?? `Trustee ${share.index}`;
  return { index: share.index, label, token, app: createTrusteeApp({ trustee, operatorToken: token, label, ballotBoxUrl: BASE }) };
});

// --- the demo election ---------------------------------------------------------

async function openDemoElection() {
  const admin = { "Content-Type": "application/json", Authorization: `Bearer ${ADMIN_TOKEN}` };
  const draft = await ballotBoxApp.request("/v1/admin/election/draft", {
    method: "POST",
    headers: admin,
    body: JSON.stringify({
      name: "SRM Student Council Election (demo)",
      candidates: ["Asha Verma", "Rohit Nair", "Meera Iyer", "None of the Above"],
      candidateDetails: [
        { party: "Progressive Students Front", symbol: "lamp" },
        { party: "Campus Unity Alliance", symbol: "tree" },
        { party: "Independent", symbol: "book" },
        { nota: true },
      ],
      minSelections: 1,
      maxSelections: 1,
    }),
  });
  if (!draft.ok) throw new Error(`draft failed: ${await draft.text()}`);
  const frozen = await registrationApp.request("/v1/admin/roll/freeze", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${ROLL_ADMIN_TOKEN}` },
    body: "{}",
  });
  const { commitment } = (await frozen.json()) as { commitment: string };
  const opened = await ballotBoxApp.request("/v1/admin/election/open", {
    method: "POST",
    headers: admin,
    body: JSON.stringify({ confirmElectionId: ELECTION_ID, rollCommitment: commitment }),
  });
  if (!opened.ok) throw new Error(`open failed: ${await opened.text()}`);
  for (const w of witnesses) await w.sync();
}
if (AUTO_OPEN) {
  await openDemoElection();
  log("demo election opened and sealed in block 0");
}

// --- the demo page ---------------------------------------------------------------

function demoPage(): string {
  const esc = (s: string) => s.replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
  const cardRows = PUBLIC_CARDS
    ? cards.slice(0, 40).map((c) => `<tr><td>${esc(c.rollId)}</td><td><code>${esc(c.code)}</code></td></tr>`).join("")
    : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Try D-Voting</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/app.css?v=5">
<style>body{padding:0 16px 48px}main{max-width:860px;margin:0 auto}h1{margin:28px 0 6px}table{border-collapse:collapse;width:100%;font-size:14px}td{padding:6px 10px;border-top:1px solid #e3e9f2}.warn{background:#fff8e8;border:1px solid #f3dfab;border-radius:10px;padding:12px 14px;color:#6b4b00}ul.links li{margin:6px 0}</style></head>
<body><main>
<h1>Try D-Voting</h1>
<p class="lede">An end-to-end verifiable election you can vote in, check on your phone, and recount yourself.</p>
<p class="warn"><strong>Demonstration only.</strong> Every party runs inside this one server so the whole system fits on one address; the real deployment runs each party on its own machine. The election resets when the server restarts. The polling cards below are public on purpose.</p>
<h2>1. Vote</h2>
<p>Open <a href="/vote">the voting page</a>, enter a roll number and enrolment code from the table, choose a candidate, and scan the QR code with your phone before you cast or test the ballot.</p>
<h2>2. Check</h2>
<ul class="links">
<li><a href="/verify">Verify a ballot</a> with its tracking code: validator signatures, Merkle proof and independent witnesses.</li>
<li><a href="/chain">Public record</a>: every block, re-verified in your browser.</li>
<li><a href="/results">Results</a>: published after the commission closes the poll and three of five trustees unlock the totals.</li>
<li>Witnesses: ${WITNESSES.map((w) => `<a href="/w/${w.id}/v1/status">${esc(w.label)}</a>`).join(" · ")}</li>
</ul>
<h2>3. Count (presenter)</h2>
<p>The commission console is at <a href="/admin">/admin</a>; trustee consoles are at <code>/trustee/1/</code> to <code>/trustee/5/</code>. Their tokens are printed in the server log, not here.</p>
${PUBLIC_CARDS ? `<h2>Demo polling cards</h2><table><thead><tr><td><strong>Roll number</strong></td><td><strong>Enrolment code</strong></td></tr></thead><tbody>${cardRows}</tbody></table>` : ""}
</main></body></html>`;
}

// --- gateway -----------------------------------------------------------------------

type App = { fetch: (request: Request, env?: unknown) => Response | Promise<Response> };

async function forward(app: App, request: Request, path: string, env: unknown): Promise<Response> {
  const url = new URL(request.url);
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const body = hasBody ? await request.arrayBuffer() : undefined;
  return app.fetch(new Request(`${url.origin}${path}${url.search}`, {
    method: request.method,
    headers: request.headers,
    ...(body ? { body } : {}),
  }), env);
}

serve({
  port: PORT,
  fetch: async (request: Request, env: unknown) => {
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return Response.json({ status: "ok" });
    if (pathname === "/demo" || pathname === "/demo/") {
      return new Response(demoPage(), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Security-Policy": "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
    if (pathname === "/ra" || pathname.startsWith("/ra/")) {
      return forward(registrationApp, request, pathname.slice(3) || "/", env);
    }
    const witness = /^\/w\/([A-Za-z0-9_.-]+)(\/.*)?$/.exec(pathname);
    if (witness) {
      const app = witnessApps.get(witness[1]!);
      return app ? forward(app, request, witness[2] ?? "/", env) : Response.json({ error: "not_found" }, { status: 404 });
    }
    const trustee = /^\/trustee\/(\d+)(\/.*)?$/.exec(pathname);
    if (trustee) {
      if (!trustee[2]) return Response.redirect(`${BASE}${pathname}/`, 301);
      const found = trustees.find((t) => t.index === Number(trustee[1]));
      return found ? forward(found.app, request, trustee[2], env) : Response.json({ error: "not_found" }, { status: 404 });
    }
    return forward(ballotBoxApp, request, pathname, env);
  },
}, () => {
  console.log(`
D-Voting hosted demo is running at ${BASE}
  Try it                ${BASE}/demo
  Vote                  ${BASE}/vote
  Commission console    ${BASE}/admin
    commission token    ${ADMIN_TOKEN}
    roll token          ${ROLL_ADMIN_TOKEN}
${trustees.map((t) => `  Trustee ${t.index} (${t.label})`.padEnd(48) + `${BASE}/trustee/${t.index}/\n    token               ${t.token}`).join("\n")}
  Witnesses             ${WITNESSES.map((w) => `${BASE}/w/${w.id}/v1/checkpoint`).join("\n                        ")}
  First polling card    ${cards[0]!.rollId}  ${cards[0]!.code}
${STUDY ? "  STUDY MODE IS ON: ?manipulate=1 links make the voting page misbehave on purpose.\n" : ""}`);
});
