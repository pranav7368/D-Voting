/**
 * Page controller for the published result.
 *
 * External rather than inline so the page runs under `script-src 'self'`.
 */

const $ = (id) => document.getElementById(id);
const esc = (v) =>
  String(v).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

for (const link of document.querySelectorAll("nav button[data-href]")) {
  link.addEventListener("click", () => {
    location.href = link.dataset.href;
  });
}

try {
  const election = await (await fetch("/v1/election")).json();
  $("election-name").textContent = election.name || election.electionId;

  const response = await fetch("/v1/bulletin/result");

  if (response.status === 404) {
    // The ceremony is public: anyone can watch the count being unlocked, and
    // see that it takes several independent parties to do it.
    const ceremony = await (await fetch("/v1/ceremony")).json();

    let progress = "";
    if (ceremony.phase === "awaiting-trustees") {
      const pills = Array.from({ length: ceremony.total }, (_, i) => {
        const done = ceremony.submitted.includes(i + 1);
        return `<span class="pill" data-state="${done ? "done" : "waiting"}">Trustee ${i + 1}${
          done ? " &#10003;" : ""
        }</span>`;
      }).join("");
      progress = `
        <div class="pills">${pills}</div>
        <p class="note mt-2">
          ${ceremony.submitted.length} of ${ceremony.threshold} required trustees have
          contributed. ${ceremony.ballotsCounted} ballots are waiting to be counted.
          No single party -- including the election commission -- can complete this alone.
        </p>`;
    }

    $("content").innerHTML = `
      <div class="card">
        <h2>No result yet</h2>
        <p class="lede flush">
          ${
            election.open
              ? "Voting is still open. The result is published after the poll closes and the trustees decrypt the totals together."
              : "Voting has closed. The result appears once a quorum of trustees has completed the decryption ceremony."
          }
        </p>
        ${progress}
      </div>`;
  } else if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  } else {
    const body = await response.json();
    const max = Math.max(...body.results.map((r) => r.votes), 1);
    const winner = [...body.results].sort((a, b) => b.votes - a.votes)[0];

    const rows = body.results
      .map(
        (r) => `
        <div class="result-row">
          <span class="name">${esc(r.candidate)}</span>
          <span class="votes">${r.votes}</span>
          <span><span class="bar" data-width="${(r.votes / max) * 100}"></span></span>
        </div>`,
      )
      .join("");

    const checks = body.verification.checks
      .map(
        (c) => `
        <div class="step ${c.ok ? "ok" : "bad"}">
          <span class="mark">${c.ok ? "&#10003;" : "&#10007;"}</span>
          <span>
            <span class="label">${esc(c.label)}</span><br />
            <span class="detail">${esc(c.detail ?? "")}</span>
          </span>
        </div>`,
      )
      .join("");

    $("content").innerHTML = `
      <div class="card">
        <div class="verdict ${body.verification.valid ? "ok" : "bad"}">
          ${
            body.verification.valid
              ? `Recount verified &mdash; ${esc(winner.candidate)} leads with ${winner.votes}`
              : "RECOUNT FAILED &mdash; this result does not match the ballots on the chain"
          }
        </div>
        ${rows}
        <dl class="facts mt-3">
          <dt>Ballots counted</dt><dd>${body.ballotsCounted}</dd>
          <dt>Superseded by a re-vote</dt><dd>${body.ballotsSuperseded}</dd>
          <dt>Trustee threshold</dt><dd>${body.threshold}</dd>
        </dl>
      </div>

      <div class="card raised">
        <h3 class="mt-0">Independent recount</h3>
        ${checks}
      </div>`;

    // Bar widths are set here rather than in a style attribute, which the
    // Content-Security-Policy forbids.
    for (const bar of document.querySelectorAll(".bar[data-width]")) {
      bar.style.width = `${bar.dataset.width}%`;
    }
  }
} catch (error) {
  $("content").innerHTML = `
    <div class="card">
      <div class="verdict bad">Could not load the result</div>
      <p class="detail">${esc(String(error.message ?? error))}</p>
    </div>`;
}
