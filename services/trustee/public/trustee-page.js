/**
 * Trustee console.
 *
 * The token stays in this tab, in memory. It is not written to localStorage or
 * a cookie: it authorises the one action that moves an election to its result,
 * and a token sitting in browser storage is a token that outlives the person
 * who typed it.
 */

const $ = (id) => document.getElementById(id);

let token = null;
let timer = null;

function setMessage(node, text, kind) {
  node.textContent = text;
  node.className = `msg${kind ? ` ${kind}` : ""}`;
}

async function call(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...(options.headers ?? {}), Authorization: `Bearer ${token}` },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.message ?? `Request failed (${response.status})`);
    error.code = body.error;
    throw error;
  }
  return body;
}

function render(status) {
  $("label").textContent = status.label;
  $("title").textContent = status.label;
  $("index-tag").textContent = `Trustee ${status.index}`;

  const facts = [];
  facts.push(["Ballot box", status.ballotBoxUrl]);
  facts.push(["My public share", `${status.publicShare.slice(0, 16)}...`]);

  const phaseNode = $("phase");
  const participate = $("participate");

  if (!status.reachable) {
    phaseNode.textContent = "ballot box unreachable";
    phaseNode.className = "phase";
    $("message").textContent = status.message ?? "";
    participate.disabled = true;
    $("status").replaceChildren(...facts.flatMap(definition));
    return;
  }

  const ceremony = status.ceremony;
  facts.push(["Election phase", labelForPhase(ceremony.phase)]);
  facts.push(["Threshold", `${ceremony.threshold} of ${ceremony.total} trustees`]);
  facts.push(["Submitted so far", ceremony.submitted.length ? ceremony.submitted.join(", ") : "none"]);
  if (ceremony.phase !== "not-ready") {
    facts.push(["Ballots counted", String(ceremony.ballotsCounted)]);
  }

  phaseNode.textContent = labelForPhase(ceremony.phase);
  phaseNode.className =
    ceremony.phase === "published" ? "phase done" : ceremony.phase === "awaiting-trustees" ? "phase ready" : "phase";

  $("message").textContent = ceremony.message;
  $("status").replaceChildren(...facts.flatMap(definition));

  participate.disabled = ceremony.phase !== "awaiting-trustees" || status.hasSubmitted;
  participate.textContent = status.hasSubmitted
    ? "Your share has been contributed"
    : "Verify and contribute my share";
}

function labelForPhase(phase) {
  if (phase === "published") return "result published";
  if (phase === "awaiting-trustees") return "awaiting trustees";
  return "voting still open";
}

function definition([term, value]) {
  const dt = document.createElement("dt");
  dt.textContent = term;
  const dd = document.createElement("dd");
  dd.textContent = value;
  return [dt, dd];
}

async function refresh() {
  try {
    render(await call("/v1/status"));
  } catch (error) {
    setMessage($("action-msg"), error.message, "bad");
  }
}

$("connect").addEventListener("click", async () => {
  const value = $("token").value.trim();
  if (!value) {
    setMessage($("auth-msg"), "Enter this trustee's operator token.", "bad");
    return;
  }
  token = value;
  try {
    const status = await call("/v1/status");
    $("auth-card").hidden = true;
    $("console").hidden = false;
    render(status);
    // The ceremony moves when OTHER trustees act, so this page has to watch.
    timer = setInterval(refresh, 5000);
  } catch (error) {
    token = null;
    setMessage($("auth-msg"), error.code === "unauthorized" ? "That token was not accepted." : error.message, "bad");
  }
});

$("token").addEventListener("keydown", (event) => {
  if (event.key === "Enter") $("connect").click();
});

$("participate").addEventListener("click", async () => {
  const button = $("participate");
  button.disabled = true;
  $("checks").replaceChildren();
  setMessage($("action-msg"), "Downloading the chain and re-verifying it...", "busy");

  try {
    const result = await call("/v1/participate", { method: "POST" });
    for (const check of result.verified ?? []) {
      const li = document.createElement("li");
      li.textContent = check;
      $("checks").append(li);
    }
    setMessage(
      $("action-msg"),
      result.published
        ? "Threshold reached. The result has been sealed on the chain."
        : `Share accepted. ${result.outstanding} more trustee(s) needed.`,
      "ok",
    );
  } catch (error) {
    // A refusal here is a finding: this machine disagreed with the ballot box.
    setMessage($("action-msg"), error.message, "bad");
    button.disabled = false;
  }
  await refresh();
});

window.addEventListener("beforeunload", () => {
  if (timer) clearInterval(timer);
});
