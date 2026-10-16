/**
 * Page controller for ballot verification.
 *
 * External rather than inline so the page runs under `script-src 'self'`.
 * Every check happens in verify-lib.js, in this browser.
 */

import {
  electionFingerprint, ed25519Available, gatherWitnessEvidence, verifyBallotReceipt,
} from "/verify-lib.js?v=2";

const $ = (id) => document.getElementById(id);
const esc = (v) =>
  String(v).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

let election = null;
let retry = null;

/**
 * The witness step. Everything else on this page trusts the board as the
 * ballot box serves it; this asks independent observers, directly, whether
 * they saw the same board.
 */
function witnessStep(w) {
  const names = w.vouched.join(", ");
  let ok = w.ok;
  let label;
  let detail;
  if (w.total === 0) {
    label = "No independent witnesses";
    detail = "This election names no witnesses, so a private copy of the record shown only to you could not be detected.";
  } else if (w.ok) {
    label = `Witnessed by ${w.vouched.length} of ${w.total} independent observers`;
    detail = `${names}: their own copies of the record contain this block, and they fetched nothing through the ballot box.`;
  } else if (w.pending) {
    label = "Waiting for the independent observers";
    detail = `${w.vouched.length} of ${w.quorum} needed have confirmed this block so far. This page checks again automatically.`;
  } else {
    label = "The independent observers did NOT see this record";
    detail = w.rejected.map((r) => `${r.witness}: ${r.reason}`).join("; ") ||
      `only ${w.vouched.length} of the required ${w.quorum} could be reached.`;
  }
  const alarms = w.alarms
    .map((a) => `<div class="msg bad">Observer ${esc(a.witness)} has raised an alarm: ${esc(a.alarm)}</div>`)
    .join("");
  return {
    ok,
    pending: w.pending,
    html: `
      <div class="step ${ok ? "ok" : "bad"}">
        <span class="mark">${ok ? "&#10003;" : w.pending ? "&hellip;" : "&#10007;"}</span>
        <span><span class="label">${esc(label)}</span><br /><span class="detail">${esc(detail)}</span></span>
      </div>${alarms}
      <div class="step ok">
        <span class="mark">#</span>
        <span><span class="label">Election fingerprint ${esc(electionFingerprint(w.genesisHash))}</span><br />
        <span class="detail">Must match the fingerprint published by the election commission and its observers.</span></span>
      </div>`,
  };
}

for (const link of document.querySelectorAll("nav button[data-href]")) {
  link.addEventListener("click", () => {
    location.href = link.dataset.href;
  });
}

async function loadElection() {
  try {
    const response = await fetch("/v1/election");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    election = await response.json();

    $("election-card").innerHTML = `
      <dl class="facts">
        <dt>Election</dt><dd>${esc(election.name || election.electionId)}</dd>
        ${election.name ? `<dt>Election id</dt><dd>${esc(election.electionId)}</dd>` : ""}
        <dt>Candidates</dt><dd>${election.candidates.map(esc).join(", ")}</dd>
        <dt>Authorities</dt><dd>${election.validators.map((v) => esc(v.id)).join(", ")}</dd>
        <dt>Quorum</dt><dd>${election.quorum} of ${election.validators.length}</dd>
        <dt>Blocks</dt><dd>${election.blockHeight}</dd>
      </dl>`;

    if (!(await ed25519Available())) {
      $("election-card").insertAdjacentHTML(
        "beforeend",
        `<div class="msg warn">This browser cannot check Ed25519 signatures. Inclusion
         will still be verified, but signatures will not. Use a current Chrome,
         Safari or Firefox.</div>`,
      );
    }
  } catch (error) {
    $("election-card").innerHTML =
      `<div class="msg bad">Could not load the election. ${esc(String(error))}</div>`;
  }
}

async function verify() {
  const code = $("tracking").value.trim();
  if (!code) return;

  $("check").disabled = true;
  $("result").innerHTML = `<div class="card"><span class="spinner"></span>Verifying...</div>`;

  try {
    const response = await fetch(`/v1/bulletin/ballots/${encodeURIComponent(code)}`);
    if (response.status === 404) {
      $("result").innerHTML = `
        <div class="card">
          <div class="verdict bad">Not found</div>
          <p class="detail">No ballot with this tracking code is on the chain. If you
          have just voted, it may not be sealed into a block yet.</p>
        </div>`;
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const receipt = await response.json();
    const result = await verifyBallotReceipt(receipt, election);
    let witnessed;
    try {
      witnessed = witnessStep(await gatherWitnessEvidence(receipt));
    } catch (error) {
      witnessed = {
        ok: false, pending: false,
        html: `<div class="step bad"><span class="mark">&#10007;</span><span><span class="label">Could not reach the independent observers</span><br /><span class="detail">${esc(String(error.message ?? error))}</span></span></div>`,
      };
    }
    clearTimeout(retry);
    if (witnessed.pending) retry = setTimeout(verify, 5000);

    const steps = result.steps
      .map(
        (step) => `
        <div class="step ${step.ok ? "ok" : "bad"}">
          <span class="mark">${step.ok ? "&#10003;" : "&#10007;"}</span>
          <span>
            <span class="label">${esc(step.label)}</span><br />
            <span class="detail">${esc(step.detail ?? "")}</span>
          </span>
        </div>`,
      )
      .join("");

    $("result").innerHTML = `
      <div class="card">
        <div class="verdict ${result.ok && witnessed.ok ? "ok" : result.ok && witnessed.pending ? "warn" : "bad"}">
          ${
            !result.ok
              ? "Verification FAILED."
              : witnessed.ok
                ? "Your ballot is recorded, and independent observers see the same record."
                : witnessed.pending
                  ? "Your ballot is recorded. Waiting for independent observers to confirm it."
                  : "Your ballot is in the record this site showed you, but independent observers did NOT confirm that record."
          }
        </div>
        ${steps}
        ${witnessed.html}
        <dl class="facts mt-3">
          <dt>Block</dt><dd>${receipt.blockHeight}</dd>
          <dt>Proposed by</dt><dd>${esc(receipt.blockHeader?.proposer ?? "-")}</dd>
          <dt>Sealed at</dt><dd>${new Date(receipt.blockHeader?.timestamp ?? 0).toISOString()}</dd>
        </dl>
      </div>`;
  } catch (error) {
    $("result").innerHTML = `
      <div class="card">
        <div class="verdict bad">Could not verify</div>
        <p class="detail">${esc(String(error.message ?? error))}</p>
      </div>`;
  } finally {
    $("check").disabled = false;
  }
}

$("check").addEventListener("click", verify);
$("tracking").addEventListener("keydown", (event) => {
  if (event.key === "Enter") verify();
});

await loadElection();

// Deep link from the voting flow: /verify?code=...
const preset = new URLSearchParams(location.search).get("code");
if (preset) {
  $("tracking").value = preset;
  await verify();
}
