/**
 * Election administration console.
 *
 * TWO TOKENS, ON PURPOSE. The commission token authorises the ballot box; the
 * roll token authorises the Registration Authority. They are separate
 * authorities holding separate halves of the picture, and this page talks to
 * each one directly rather than proxying either through the other. Neither
 * token is written to storage: they authorise irreversible acts, and a token in
 * localStorage outlives the person who typed it.
 *
 * WHAT THIS PAGE CANNOT MAKE HAPPEN. There is no decrypt button, no running
 * total, and no ballot in any response it receives. Those are not hidden
 * features -- the endpoints do not exist.
 */

const $ = (id) => document.getElementById(id);

let token = null;
let rollToken = null;
let registrationUrl = null;
let timer = null;
// The real identifier, tracked separately from the header: that element shows
// the human-facing name when one is set, and the two must never be confused --
// close/open confirmations are checked against the electionId on the server.
let currentElectionId = null;

// --- plumbing --------------------------------------------------------------

function message(node, text, kind = "info") {
  node.replaceChildren();
  if (!text) return;
  const div = document.createElement("div");
  div.className = `msg ${kind}`;
  div.textContent = text;
  node.append(div);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers ?? {}),
      Authorization: `Bearer ${token}`,
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.message ?? `Request failed (${response.status})`);
    error.code = body.error;
    throw error;
  }
  return body;
}

async function rollApi(path, options = {}) {
  if (!rollToken) throw new Error("No Registration Authority token was supplied.");
  if (!registrationUrl) throw new Error("This ballot box does not publish a Registration Authority URL.");
  const response = await fetch(`${registrationUrl}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers ?? {}),
      Authorization: `Bearer ${rollToken}`,
    },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.message ?? `The Registration Authority refused (${response.status})`);
    error.code = body.error;
    throw error;
  }
  return body;
}

function definitions(pairs) {
  return pairs.flatMap(([term, value]) => {
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    return [dt, dd];
  });
}

/** A datetime-local value is local wall-clock time; the API wants an instant. */
function toInstant(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

// --- rendering -------------------------------------------------------------

function render(status) {
  currentElectionId = status.electionId;
  $("election-title").textContent = status.name || status.electionId;
  $("election-id-sub").textContent = status.name ? `id: ${status.electionId}` : "";
  $("phase").textContent = status.phase;
  $("phase").dataset.phase = status.phase;
  $("next-step").textContent = status.nextStep;

  const facts = [
    ["Ballots accepted", String(status.ballotsAccepted)],
    ["Ballots audited and spoiled", String(status.ballotsSpoiled)],
    ["Awaiting seal", String(status.pendingUnsealed)],
    ["Chain height", String(status.blockHeight)],
    ["Chain verifies", status.chainValid ? "yes" : `NO - ${status.chainErrors.join("; ")}`],
    ["Validators", `${status.validators.join(", ")} (quorum ${status.quorum})`],
    ["Trustees", `${status.ceremony.threshold} of ${status.ceremony.total} required to decrypt`],
  ];
  if (status.sealed) {
    facts.push(["Candidates", status.candidates.join(", ")]);
    facts.push(["Roll commitment", status.rollCommitment ?? "none sealed"]);
    if (status.opensAt) facts.push(["Opens at", new Date(status.opensAt).toLocaleString()]);
    if (status.closesAt) facts.push(["Closes at", new Date(status.closesAt).toLocaleString()]);
    if (status.closedAt) facts.push(["Closed at", new Date(status.closedAt).toLocaleString()]);
  }
  $("status").replaceChildren(...definitions(facts));

  $("setup").hidden = status.phase !== "setup";
  $("voting").hidden = status.phase !== "voting" && status.phase !== "scheduled";
  $("ceremony").hidden = status.phase !== "closed";
  $("published").hidden = status.phase !== "published";

  if (status.phase === "setup") {
    if (document.activeElement !== $("election-name")) {
      $("election-name").value = status.name ?? "";
    }
    if (document.activeElement !== $("candidates")) {
      $("candidates").value = status.candidates.join("\n");
    }
    if (document.activeElement !== $("min-selections")) {
      $("min-selections").value = String(status.minSelections);
    }
    if (document.activeElement !== $("max-selections")) {
      $("max-selections").value = String(status.maxSelections);
    }
    $("confirm-open").placeholder = status.electionId;
  }

  if (status.phase === "closed") {
    const pills = [];
    for (let index = 1; index <= status.ceremony.total; index++) {
      const pill = document.createElement("span");
      pill.className = "pill";
      const done = status.ceremony.submitted.includes(index);
      pill.dataset.state = done ? "done" : "waiting";
      pill.textContent = done ? `Trustee ${index} - contributed` : `Trustee ${index} - waiting`;
      pills.push(pill);
    }
    $("trustee-pills").replaceChildren(...pills);
    $("ceremony-note").textContent =
      status.ceremony.outstanding > 0
        ? `${status.ceremony.outstanding} more trustee(s) must contribute before the result can be decrypted. Nothing this console can do will speed that up.`
        : "The threshold has been reached; the result is being sealed.";
  }
}

async function renderRoll() {
  if (!rollToken) {
    $("roll-status").replaceChildren(
      ...definitions([["Roll administration", "no Registration Authority token supplied"]]),
    );
    for (const id of ["add-voters", "freeze-roll", "export-roll"]) $(id).disabled = true;
    return;
  }
  try {
    const roll = await rollApi("/v1/admin/roll");
    $("roll-status").replaceChildren(
      ...definitions([
        ["Entries on the roll", String(roll.entries)],
        ["Frozen", roll.frozen ? "yes - no further additions" : "no"],
        ["Commitment", roll.commitment],
      ]),
    );
    $("add-voters").disabled = roll.frozen;
    $("freeze-roll").disabled = roll.frozen;
  } catch (error) {
    message($("roll-msg"), error.message, "bad");
  }
}

async function refresh() {
  try {
    const status = await api("/v1/admin/status");
    render(status);
    const audit = await api("/v1/admin/audit?limit=15");
    $("audit-log").replaceChildren(
      ...audit.entries.map((entry) => {
        const tr = document.createElement("tr");
        const when = document.createElement("td");
        when.textContent = new Date(entry.at).toLocaleTimeString();
        const what = document.createElement("td");
        what.textContent = `${entry.action}${entry.detail ? ` - ${entry.detail}` : ""}`;
        tr.append(when, what);
        return tr;
      }),
    );
    if (status.phase === "setup") await renderRoll();
  } catch (error) {
    message($("auth-msg"), error.message, "bad");
  }
}

// --- actions ---------------------------------------------------------------

$("connect").addEventListener("click", async () => {
  const value = $("token").value.trim();
  if (!value) {
    message($("auth-msg"), "Enter the election commission token.", "bad");
    return;
  }
  token = value;
  rollToken = $("roll-token").value.trim() || null;

  try {
    const election = await fetch("/v1/election").then((r) => r.json());
    registrationUrl = election.registrationUrl;
    await api("/v1/admin/status");
    $("auth-card").hidden = true;
    $("console").hidden = false;
    await refresh();
    timer = setInterval(refresh, 5000);
  } catch (error) {
    token = null;
    message(
      $("auth-msg"),
      error.code === "unauthorized" ? "That token was not accepted." : error.message,
      "bad",
    );
  }
});

$("token").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("connect").click();
});

$("save-draft").addEventListener("click", async () => {
  const candidates = $("candidates").value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const name = $("election-name").value.trim();
  try {
    await api("/v1/admin/election/draft", {
      method: "POST",
      body: JSON.stringify({
        name: name || null,
        candidates,
        minSelections: Number($("min-selections").value),
        maxSelections: Number($("max-selections").value),
      }),
    });
    message($("draft-msg"), `Ballot saved: ${candidates.length} candidates.`, "ok");
    await refresh();
  } catch (error) {
    message($("draft-msg"), error.message, "bad");
  }
});

$("add-voters").addEventListener("click", async () => {
  message($("roll-msg"), "Enrolling voters...", "info");
  try {
    const result = await rollApi("/v1/admin/roll", {
      method: "POST",
      body: JSON.stringify({ count: 20 }),
    });
    // Shown once, and never again: the service stores only an HMAC of each code.
    $("cards-field").hidden = false;
    $("cards").value = ["roll_id,enrolment_code"]
      .concat(result.cards.map((card) => `${card.rollId},${card.enrolmentCode}`))
      .join("\n");
    message(
      $("roll-msg"),
      `${result.added} voters enrolled. Copy these polling cards now - they cannot be shown again.`,
      "warn",
    );
    await renderRoll();
  } catch (error) {
    message($("roll-msg"), error.message, "bad");
  }
});

$("freeze-roll").addEventListener("click", async () => {
  try {
    const result = await rollApi("/v1/admin/roll/freeze", { method: "POST" });
    message(
      $("roll-msg"),
      `Roll frozen at ${result.entries} entries. The commitment will be sealed when you open the poll.`,
      "ok",
    );
    await renderRoll();
  } catch (error) {
    message($("roll-msg"), error.message, "bad");
  }
});

$("export-roll").addEventListener("click", async () => {
  try {
    const result = await rollApi("/v1/admin/roll/export");
    $("cards-field").hidden = false;
    $("cards").value = result.rollIds.join("\n");
    message(
      $("roll-msg"),
      `${result.entries} roll identifiers. Publish this list so anyone can recompute the commitment.`,
      "info",
    );
  } catch (error) {
    message($("roll-msg"), error.message, "bad");
  }
});

$("open-poll").addEventListener("click", async () => {
  const button = $("open-poll");
  button.disabled = true;
  message($("open-msg"), "Sealing the election onto the chain...", "info");

  let rollCommitment = null;
  if (rollToken) {
    try {
      const roll = await rollApi("/v1/admin/roll");
      if (!roll.frozen) {
        message(
          $("open-msg"),
          "Freeze the electoral roll first. An unfrozen roll can still change, so committing to it would prove nothing.",
          "bad",
        );
        button.disabled = false;
        return;
      }
      rollCommitment = roll.commitment;
    } catch (error) {
      message($("open-msg"), error.message, "bad");
      button.disabled = false;
      return;
    }
  }

  try {
    await api("/v1/admin/election/open", {
      method: "POST",
      body: JSON.stringify({
        confirmElectionId: $("confirm-open").value.trim(),
        rollCommitment,
        opensAt: toInstant($("opens-at").value),
        closesAt: toInstant($("closes-at").value),
      }),
    });
    message($("open-msg"), "The election is sealed. Polling is open.", "ok");
    await refresh();
  } catch (error) {
    message($("open-msg"), error.message, "bad");
    button.disabled = false;
  }
});

$("seal").addEventListener("click", async () => {
  try {
    const result = await api("/v1/admin/seal", { method: "POST" });
    message(
      $("action-msg"),
      result.sealed ? `Sealed block ${result.height}.` : "Nothing was pending.",
      result.sealed ? "ok" : "info",
    );
    await refresh();
  } catch (error) {
    message($("action-msg"), error.message, "bad");
  }
});

$("close").addEventListener("click", async () => {
  const id = currentElectionId;
  if (!window.confirm(`Close "${id}" permanently? Anyone who has not voted loses the chance.`)) {
    return;
  }
  try {
    await api("/v1/admin/close", {
      method: "POST",
      body: JSON.stringify({ confirmElectionId: id }),
    });
    message($("action-msg"), "The poll is closed. The trustees can now decrypt.", "ok");
    await refresh();
  } catch (error) {
    message($("action-msg"), error.message, "bad");
  }
});

$("refresh").addEventListener("click", refresh);
$("refresh-closed").addEventListener("click", refresh);
$("go-results").addEventListener("click", () => {
  window.location.href = "/results";
});

for (const button of document.querySelectorAll("nav button[data-href]")) {
  button.addEventListener("click", () => {
    window.location.href = button.dataset.href;
  });
}

window.addEventListener("beforeunload", () => {
  if (timer) clearInterval(timer);
});
