/**
 * Chain Explorer.
 *
 * Every fact shown here is downloaded from this server and then re-derived by
 * this browser using `chain-lib.js` -- the hash of each block, the link to the
 * block before it, and the validator signatures. The page renders what that
 * independent recomputation found, not what any endpoint merely asserts.
 *
 * External script, so the page runs under `script-src 'self'`.
 */

import { decodeEntryJson, summariseChainVerification, verifyChain } from "/chain-lib.js";

const $ = (id) => document.getElementById(id);
const esc = (v) =>
  String(v).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const MAX_BLOCKS = 500;

for (const link of document.querySelectorAll("nav button[data-href]")) {
  link.addEventListener("click", () => {
    location.href = link.dataset.href;
  });
}

function fmt(ts) {
  return new Date(ts).toLocaleString();
}

function step(ok, label, detail) {
  return `
    <div class="step ${ok ? "ok" : "bad"}">
      <span class="mark">${ok ? "&#10003;" : "&#10007;"}</span>
      <span>
        <span class="label">${esc(label)}</span><br />
        <span class="detail">${esc(detail)}</span>
      </span>
    </div>`;
}

function kindPill(kind, count) {
  const labels = {
    "election-config": "config",
    ballot: count === 1 ? "ballot" : "ballots",
    "spoiled-ballot": "audited",
    "election-closed": "closed",
    "tally-result": "result",
  };
  return `<span class="pill" data-kind="${esc(kind)}">${count}&nbsp;${esc(labels[kind] ?? kind)}</span>`;
}

/** What each entry kind means, and -- for cast ballots -- why it stays unopened here. */
function renderEntry(entry, election) {
  if (entry.kind === "election-config") {
    const config = decodeEntryJson(entry);
    if (!config) return `<p class="note">Could not decode this entry.</p>`;
    return `
      <dl class="facts">
        <dt>Name</dt><dd>${esc(config.name || "(none set)")}</dd>
        <dt>Candidates</dt><dd>${config.candidates.map(esc).join(", ")}</dd>
        <dt>Choose</dt><dd>${config.minSelections} to ${config.maxSelections}</dd>
        <dt>Trustees</dt><dd>${config.trustees.threshold} of ${config.trustees.total} required to decrypt</dd>
        <dt>Validators</dt><dd>${config.validators.map((v) => esc(v.id)).join(", ")} (quorum ${config.quorum})</dd>
        <dt>Roll commitment</dt><dd>${esc(config.rollCommitment ?? "none sealed")}</dd>
        <dt>Opens at</dt><dd>${config.opensAt ? fmt(config.opensAt) : "immediately"}</dd>
        <dt>Closes at</dt><dd>${config.closesAt ? fmt(config.closesAt) : "no fixed time"}</dd>
        <dt>Sealed at</dt><dd>${fmt(config.sealedAt)}</dd>
      </dl>
      <p class="note mt-2">
        This is the whole election, committed before a single ballot was accepted.
        Nothing in it could be changed after this block was sealed.
      </p>`;
  }

  if (entry.kind === "election-closed") {
    const closed = decodeEntryJson(entry);
    if (!closed) return `<p class="note">Could not decode this entry.</p>`;
    return `
      <dl class="facts">
        <dt>Closed at</dt><dd>${fmt(closed.closedAt)}</dd>
        <dt>Reason</dt><dd>${esc(closed.reason)}</dd>
        <dt>Final height</dt><dd>${closed.finalHeight}</dd>
      </dl>
      <p class="note mt-2">
        Written to the chain, not held in memory -- this is what makes "voting
        has ended" survive a restart of the service.
      </p>`;
  }

  if (entry.kind === "tally-result") {
    const tally = decodeEntryJson(entry);
    if (!tally) return `<p class="note">Could not decode this entry.</p>`;
    const max = Math.max(...tally.results.map((r) => r.votes), 1);
    const rows = tally.results
      .map(
        (r) => `
        <div class="result-row">
          <span class="name">${esc(r.candidate)}</span>
          <span class="votes">${r.votes}</span>
          <span><span class="bar" data-width="${(r.votes / max) * 100}"></span></span>
        </div>`,
      )
      .join("");
    return `
      ${rows}
      <dl class="facts mt-2">
        <dt>Counted ballots</dt><dd>${tally.countedBallotIds.length}</dd>
        <dt>Superseded by a re-vote</dt><dd>${tally.supersededBallotIds.length}</dd>
        <dt>Trustee threshold</dt><dd>${tally.threshold}</dd>
      </dl>
      <p class="note mt-2">
        Sealed with every trustee's decryption proof. <a href="/results">Open the
        results page</a> for the full independent recount, redone from this
        chain rather than taken on trust.
      </p>`;
  }

  if (entry.kind === "spoiled-ballot") {
    const audit = decodeEntryJson(entry);
    if (!audit) return `<p class="note">Could not decode this entry.</p>`;
    const candidateNames =
      audit.encodedSelections
        ?.map((v, i) => (v > 0 ? (election?.candidates?.[i] ?? `candidate ${i}`) : null))
        .filter(Boolean) ?? [];
    return `
      <p class="note flush">
        A voter chose to <strong>audit</strong> this ballot instead of casting it:
        the app had to reveal the randomness that unlocks it, proving what it
        really encrypted. That is why this one entry is publicly decryptable
        while every cast ballot stays secret.
      </p>
      <dl class="facts mt-2">
        <dt>Consistent with the app's claim</dt>
        <dd>${audit.encryptionConsistent ? "yes -- the app was honest" : "NO -- the app was caught lying"}</dd>
        ${candidateNames.length ? `<dt>Revealed to encrypt</dt><dd>${candidateNames.map(esc).join(", ")}</dd>` : ""}
      </dl>
      <p class="note mt-2">Ballot id: ${esc(entry.id)}. It can never be cast now.</p>`;
  }

  if (entry.kind === "ballot") {
    let choiceCount = "unknown";
    const wire = decodeEntryJson(entry);
    if (wire?.choices) choiceCount = wire.choices.length;
    return `
      <p class="note flush">
        A cast ballot. It is on the chain as ${choiceCount} ElGamal ciphertexts
        (one per candidate) plus a zero-knowledge proof that each one encrypts 0
        or 1 -- and that is all this page will show, because that is all anyone
        can see. Decrypting even one of them would need a threshold of trustees
        to cooperate, and the protocol only ever decrypts the SUM across every
        ballot, never a single one.
      </p>
      <dl class="facts mt-2">
        <dt>Tracking code</dt><dd>${esc(entry.id)}</dd>
      </dl>
      <p class="note mt-2"><a href="/verify?code=${encodeURIComponent(entry.id)}">Verify this specific ballot</a></p>`;
  }

  return `<p class="note">Unrecognised entry kind "${esc(entry.kind)}".</p>`;
}

function renderBlock(block, result, election, isLast) {
  const kinds = new Map();
  for (const entry of block.entries) kinds.set(entry.kind, (kinds.get(entry.kind) ?? 0) + 1);

  const linkStep = result.isGenesis
    ? step(result.linked, "Genesis block", result.linked ? "links to the all-zero hash, as every chain must start" : "does NOT link to the all-zero hash")
    : step(
        result.linked,
        "Linked to the block before it",
        result.linked
          ? "this block's previousHash matches the ACTUAL hash of the block below it"
          : "this block's previousHash does not match -- the chain is broken here",
      );

  const checks = [
    step(
      result.hashOk,
      "Hash recomputed locally",
      result.hashOk
        ? `${result.computedHash.slice(0, 28)}…`
        : `claimed ${result.claimedHash.slice(0, 16)}… but this browser computed ${result.computedHash.slice(0, 16)}…`,
    ),
    linkStep,
    result.hasEd25519
      ? step(
          result.quorumOk,
          "Validator quorum",
          `${result.verifiedSignatures.length} verified: ${result.verifiedSignatures.join(", ") || "none"}${
            result.rejectedSignatures.length
              ? ` (rejected: ${result.rejectedSignatures.map((r) => r.validator).join(", ")})`
              : ""
          }`,
        )
      : step(false, "Validator quorum", "this browser does not support Ed25519 in WebCrypto"),
  ].join("");

  const entryDetail = block.entries
    .map(
      (entry) => `
      <div class="card mt-2">
        <div class="row">
          <strong>${esc(entry.kind)}</strong>
          <span class="hint mono">${esc(entry.id.length > 40 ? `${entry.id.slice(0, 40)}…` : entry.id)}</span>
        </div>
        <div class="mt-1">${renderEntry(entry, election)}</div>
      </div>`,
    )
    .join("");

  const id = `block-${block.header.height}`;
  return `
    <div class="block-card" data-ok="${result.ok}">
      <button class="block-head" data-target="${id}" aria-expanded="false">
        <span class="block-height">#${block.header.height}</span>
        <span class="block-kinds">${[...kinds.entries()].map(([k, c]) => kindPill(k, c)).join("")}</span>
        <span class="block-meta">${fmt(block.header.timestamp)} &middot; ${esc(block.header.proposer)}</span>
        <span class="block-caret">&#9662;</span>
      </button>
      <div class="block-checks">${checks}</div>
      <div class="block-detail" id="${id}" hidden>${entryDetail}</div>
    </div>
    ${isLast ? "" : `<div class="chain-connector" data-linked="${result.linked}"></div>`}`;
}

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
  return response.json();
}

async function load() {
  $("loading").hidden = false;
  $("error").hidden = true;
  $("content").hidden = true;

  try {
    const election = await api("/v1/election");
    $("election-name").textContent = `${election.name || election.electionId} — Chain Explorer`;

    const head = await api("/v1/bulletin/head");
    const total = head.height ?? 0;
    const truncated = total > MAX_BLOCKS;
    const fromHeight = truncated ? total - MAX_BLOCKS : 0;

    const blocks = [];
    for (let h = fromHeight; h < total; h++) {
      blocks.push(await api(`/v1/bulletin/blocks/${h}`));
    }

    const results = blocks.length > 0 ? await verifyChain(blocks, election) : [];
    const summary = summariseChainVerification(results);

    let ballotsAccepted = 0;
    let ballotsSpoiled = 0;
    for (const block of blocks) {
      for (const entry of block.entries) {
        if (entry.kind === "ballot") ballotsAccepted++;
        if (entry.kind === "spoiled-ballot") ballotsSpoiled++;
      }
    }

    $("verdict").className = `verdict ${summary.ok ? "ok" : "bad"}`;
    $("verdict").textContent = truncated
      ? `${summary.message} (showing the most recent ${MAX_BLOCKS} of ${total} blocks)`
      : summary.message;

    $("summary-facts").innerHTML = `
      <dt>Election</dt><dd>${esc(election.name || election.electionId)}</dd>
      ${election.name ? `<dt>Election id</dt><dd>${esc(election.electionId)}</dd>` : ""}
      <dt>Phase</dt><dd>${esc(election.phase)}</dd>
      <dt>Blocks</dt><dd>${total}</dd>
      <dt>Ballots cast (from the public chain)</dt><dd>${ballotsAccepted}</dd>
      <dt>Ballots audited and spoiled</dt><dd>${ballotsSpoiled}</dd>
      <dt>Validators</dt><dd>${election.validators.map((v) => esc(v.id)).join(", ")} (quorum ${election.quorum})</dd>
      <dt>Trustees</dt><dd>${election.trustees.threshold} of ${election.trustees.total} required to decrypt</dd>
      ${election.rollCommitment ? `<dt>Roll commitment</dt><dd>${esc(election.rollCommitment)}</dd>` : ""}`;

    // The ceremony is public precisely so this page can show it happening.
    try {
      const ceremony = await api("/v1/ceremony");
      if (ceremony.phase === "awaiting-trustees") {
        $("ceremony-card").hidden = false;
        $("ceremony-text").textContent = ceremony.message;
        $("ceremony-pills").innerHTML = Array.from({ length: ceremony.total }, (_, i) => {
          const done = ceremony.submitted.includes(i + 1);
          return `<span class="pill" data-state="${done ? "done" : "waiting"}">Trustee ${i + 1}${done ? " &#10003;" : ""}</span>`;
        }).join("");
      } else {
        $("ceremony-card").hidden = true;
      }
    } catch {
      $("ceremony-card").hidden = true;
    }

    if (blocks.length === 0) {
      $("chain-track").innerHTML = `<p class="note">No blocks yet. The election has not been opened.</p>`;
    } else {
      $("chain-track").innerHTML = blocks
        .map((block, i) => renderBlock(block, results[i], election, i === blocks.length - 1))
        .join("");

      for (const button of document.querySelectorAll(".block-head")) {
        button.addEventListener("click", () => {
          const panel = document.getElementById(button.dataset.target);
          const expanded = button.getAttribute("aria-expanded") === "true";
          button.setAttribute("aria-expanded", String(!expanded));
          panel.hidden = expanded;
        });
      }
    }

    $("download").onclick = () => {
      const blob = new Blob([JSON.stringify({ election, blocks }, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${election.electionId}-chain.json`;
      link.click();
      URL.revokeObjectURL(url);
    };

    $("loading").hidden = true;
    $("content").hidden = false;
  } catch (error) {
    $("loading").hidden = true;
    $("error").hidden = false;
    $("error").innerHTML = `<div class="msg bad">Could not load the chain: ${esc(error.message ?? String(error))}</div>`;
  }
}

$("refresh")?.addEventListener("click", load);
await load();
