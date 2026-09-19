/**
 * Page controller for ballot verification.
 *
 * External rather than inline so the page runs under `script-src 'self'`.
 * Every check happens in verify-lib.js, in this browser.
 */

import { verifyBallotReceipt, ed25519Available } from "/verify-lib.js";

const $ = (id) => document.getElementById(id);
const esc = (v) =>
  String(v).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

let election = null;

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
        <div class="verdict ${result.ok ? "ok" : "bad"}">
          ${
            result.ok
              ? "Your ballot is recorded and the record is authentic."
              : "Verification FAILED."
          }
        </div>
        ${steps}
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
