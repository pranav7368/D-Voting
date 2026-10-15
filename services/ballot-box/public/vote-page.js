/**
 * Page controller for the voter interface.
 *
 * Kept in its own file rather than inline in the HTML so the page can run under
 * a strict `script-src 'self'` Content-Security-Policy. Inline scripts would
 * require 'unsafe-inline', which removes the main protection CSP offers on a
 * page that handles a voting credential.
 *
 * voter.js owns the protocol; this file owns what the voter sees. Every string
 * comes from i18n.js so the page can switch language without a reload, which
 * would destroy the in-memory credential.
 */

import {
  loadElection, registerAndGetCredential, prepareSelection, auditPrepared, castPrepared,
  resetForRevote, discardPrepared, checkCode, session, esc, $,
} from "/voter.js?v=5";
import { apply, lang, onLangChange, setLang, t } from "/i18n.js?v=1";
import { symbolSvg } from "/symbols.js?v=1";

const STAGES = ["identify", "choose", "confirm", "done"];
let stage = "identify";
let sealPoll = null;

// --- small helpers -----------------------------------------------------------

function show(target, kind, text) {
  const box = document.createElement("div");
  box.className = `msg ${kind}`;
  box.textContent = text;
  $(target).replaceChildren(box);
}

function clear(target) {
  $(target).replaceChildren();
}

/** Disable a button and show progress text, restoring its label afterwards. */
async function withBusy(button, key, work) {
  const original = [...button.childNodes].map((node) => node.cloneNode(true));
  button.disabled = true;
  const spinner = document.createElement("span");
  spinner.className = "spinner";
  spinner.setAttribute("aria-hidden", "true");
  button.replaceChildren(spinner, document.createTextNode(t(key)));
  try {
    return await work();
  } finally {
    button.replaceChildren(...original);
    apply(button);
    button.disabled = false;
  }
}

function when(iso) {
  return new Date(iso).toLocaleString(lang() === "hi" ? "hi-IN" : "en-IN", {
    dateStyle: "medium", timeStyle: "short",
  });
}

function setStage(next, focus = false) {
  stage = next;
  document.body.dataset.stage = next;
  const current = STAGES.indexOf(next);
  for (const [index, name] of STAGES.entries()) {
    const rail = $(`rail-${name}`);
    rail.dataset.state = index < current ? "done" : index === current ? "active" : "";
    if (index === current) rail.setAttribute("aria-current", "step");
    else rail.removeAttribute("aria-current");
    $(`stage-${name}`).hidden = name !== next;
  }
  renderKnows();
  if (focus) {
    const heading = $(`stage-${next}`).querySelector("h2");
    heading.setAttribute("tabindex", "-1");
    heading.focus();
  }
}

// --- election header, facts and ballot --------------------------------------

function ruleText(election) {
  const { minSelections: min, maxSelections: max } = election;
  if (min === max) return t("rule.exactly", { n: max });
  if (min === 0) return t("rule.upTo", { n: max });
  return t("rule.range", { min, max });
}

function candidateLabel(index) {
  const detail = session.election.candidateDetails?.[index];
  return detail?.nota ? t("ch.nota") : session.election.candidates[index];
}

function renderElection() {
  const election = session.election;
  if (!election) return;

  $("election-name").textContent = election.name || election.electionId;
  $("election-name").removeAttribute("data-i18n");
  const status = $("election-status");
  status.textContent = t(`status.${election.phase}`);
  status.dataset.phase = election.phase;
  $("ballot-rule").textContent = ruleText(election);
  $("ballot-sheet-rule").textContent = `· ${ruleText(election)}`;
  $("election-deadline").textContent =
    election.phase === "voting" && election.closesAt ? t("closes", { when: when(election.closesAt) }) : "";

  const facts = [
    t("facts.authorities", { q: election.quorum, n: election.validators.length }),
    t("facts.trustees", { k: election.trustees.threshold, n: election.trustees.total }),
  ];
  $("election-facts").replaceChildren(
    ...facts.map((text) => Object.assign(document.createElement("li"), { textContent: text })),
  );
  if (election.rollCommitment) {
    const li = document.createElement("li");
    li.append(`${t("facts.roll")}: `);
    const code = Object.assign(document.createElement("code"), { textContent: election.rollCommitment.slice(0, 16) + "…" });
    code.title = election.rollCommitment;
    li.append(code);
    $("election-facts").append(li);
  }

  if (!election.open) {
    const key = election.phase === "scheduled" ? "phase.scheduled" : election.phase === "setup" ? "phase.setup" : "phase.closed";
    show("identify-msg", "warn", t(key, { when: election.opensAt ? when(election.opensAt) : "" }));
    $("register").disabled = true;
  }
}

/**
 * The ballot, laid out like a ballot unit: serial number, candidate, party,
 * symbol, and one large target to select. Real radio/checkbox inputs carry the
 * state, so keyboard and screen-reader behaviour is the browser's own.
 */
function renderBallot() {
  const election = session.election;
  const type = election.minSelections === 1 && election.maxSelections === 1 ? "radio" : "checkbox";
  const checked = new Set(
    [...document.querySelectorAll('input[name="candidate"]:checked')].map((input) => Number(input.value)),
  );

  const rows = election.candidates.map((_, index) => {
    const detail = election.candidateDetails?.[index] ?? null;
    const label = candidateLabel(index);
    const row = document.createElement("label");
    row.className = "ballot-row";
    row.dataset.nota = String(Boolean(detail?.nota));
    row.innerHTML = `
      <span class="ballot-serial" aria-hidden="true">${index + 1}</span>
      <span class="ballot-who">
        <span class="ballot-name">${esc(label)}</span>
        ${detail?.party ? `<span class="ballot-party">${esc(detail.party)}</span>` : ""}
      </span>
      <span class="ballot-symbol">${symbolSvg(detail)}</span>
      <input type="${type}" name="candidate" value="${index}" class="ballot-input" />
      <span class="ballot-target" aria-hidden="true"><span class="ballot-target-dot"></span><span class="ballot-target-text">${esc(t("ch.select"))}</span></span>`;
    const input = row.querySelector("input");
    input.checked = checked.has(index);
    input.setAttribute("aria-label", `${index + 1}. ${label}${detail?.party ? `, ${detail.party}` : ""}`);
    return row;
  });
  $("choices").replaceChildren(...rows);
  syncSelected();
}

function syncSelected() {
  for (const row of document.querySelectorAll(".ballot-row")) {
    const on = row.querySelector("input").checked;
    row.dataset.selected = String(on);
    row.querySelector(".ballot-target-text").textContent = on ? t("ch.selected") : t("ch.select");
  }
}

// --- "who knows what" --------------------------------------------------------

/**
 * The separation of knowledge, shown as it happens. This is the system's
 * central claim, so it is stated per party, per step, in plain words, rather
 * than once in a footer.
 */
function renderKnows() {
  const election = session.election;
  const at = STAGES.indexOf(stage);
  const parties = [
    ["kn.device", at === 0 ? "kn.nothing" : at === 1 ? "kn.device.choose" : at === 2 ? "kn.device.confirm" : "kn.device.done", at > 0],
    ["kn.ra", at === 0 ? "kn.ra.before" : "kn.ra.after", at > 0],
    ["kn.box", at === 3 ? "kn.box.done" : "kn.box.before", at === 3],
    ["kn.validators", at === 3 ? "kn.val.done" : "kn.val.before", at === 3],
    ["kn.trustees", "kn.tr", false],
  ];
  $("knows").replaceChildren(
    ...parties.map(([party, text, active]) => {
      const li = document.createElement("li");
      li.dataset.active = String(active);
      const name = Object.assign(document.createElement("strong"), { textContent: t(party) });
      const body = Object.assign(document.createElement("span"), {
        textContent: t(text, {
          k: election?.trustees.threshold ?? "k", n: election?.trustees.total ?? "n",
        }),
      });
      li.append(name, body);
      return li;
    }),
  );
}

// --- receipt timeline --------------------------------------------------------

function setStep(step, state, text) {
  const li = $("timeline").querySelector(`[data-step="${step}"]`);
  li.dataset.state = state;
  $(`t-${step}`).textContent = text;
}

/**
 * Follow the ballot from accepted, to sealed by the authorities, to counted.
 * Read from the public bulletin board, the same place any observer reads.
 */
async function followReceipt(trackingCode) {
  clearInterval(sealPoll);
  setStep("received", "done", t("dn.t.receivedDetail"));
  setStep("sealed", "wait", t("dn.t.sealedWait"));
  setStep("counted", "todo", t("dn.t.countedWait"));

  // Sealing takes seconds, so poll for it often. Counting cannot start until
  // the poll closes, which may be days away, so after sealing only look at the
  // election's phase now and then, and ask for the result once it has closed.
  let sealed = false;
  let ticks = 0;
  const check = async () => {
    ticks++;
    try {
      if (!sealed) {
        const response = await fetch(`/v1/bulletin/ballots/${encodeURIComponent(trackingCode)}`);
        if (!response.ok) return;
        const located = await response.json();
        sealed = true;
        setStep("sealed", "done", t("dn.t.sealedDetail", {
          block: located.blockHeight,
          sigs: located.attestations.length,
          total: session.election.validators.length,
        }));
      }
      if (ticks % 8 !== 1) return; // about every 30 seconds
      const election = await (await fetch("/v1/election")).json();
      if (election.phase !== "closed") return;
      const result = await fetch("/v1/bulletin/result");
      if (result.ok) {
        setStep("counted", "done", t("dn.t.countedDetail"));
        clearInterval(sealPoll);
      }
    } catch {
      /* transient; the next poll retries */
    }
  };
  await check();
  sealPoll = setInterval(check, 4000);
}

// --- wiring ------------------------------------------------------------------

function renderAll() {
  apply();
  renderElection();
  if (session.election) renderBallot();
  renderKnows();
  if (session.trackingCode && stage === "done") followReceipt(session.trackingCode);
}

$("lang-toggle").addEventListener("click", () => setLang(lang() === "hi" ? "en" : "hi"));
onLangChange(renderAll);

apply();
setStage("identify");

try {
  await loadElection();
  renderAll();
} catch (error) {
  show("identify-msg", "bad", t("err.load", { reason: error.message }));
}

$("choices").addEventListener("change", syncSelected);

$("register").addEventListener("click", async () => {
  const rollId = $("rollId").value.trim();
  const code = $("code").value.trim();
  if (!rollId || !code) {
    show("identify-msg", "bad", t("id.missing"));
    return;
  }
  try {
    await withBusy($("register"), "id.busy", () => registerAndGetCredential(rollId, code));
    // The polling-card details are not needed again; take them off the page.
    $("rollId").value = "";
    $("code").value = "";
    clear("identify-msg");
    setStage("choose", true);
  } catch (error) {
    show("identify-msg", "bad", error.message);
  }
});

$("prepare").addEventListener("click", async () => {
  const selected = [...document.querySelectorAll('input[name="candidate"]:checked')].map((input) => Number(input.value));
  const { minSelections: min, maxSelections: max } = session.election;
  if (selected.length < min || selected.length > max) {
    const rule = min === max
      ? (max === 1 ? t("ch.ruleOne") : t("ch.ruleExact", { n: max }))
      : t("ch.ruleRange", { min, max });
    show("choose-msg", "bad", rule);
    return;
  }

  try {
    const commitment = await withBusy($("prepare"), "ch.busy", () => prepareSelection(selected));
    $("commitment").textContent = commitment;
    $("check-code").textContent = checkCode(commitment);
    const items = selected.length
      ? selected.map((index) => {
          const detail = session.election.candidateDetails?.[index];
          const li = document.createElement("li");
          li.innerHTML = `<span class="chosen-symbol">${symbolSvg(detail)}</span><span><strong>${esc(candidateLabel(index))}</strong>${detail?.party ? `<small>${esc(detail.party)}</small>` : ""}</span>`;
          return li;
        })
      : [Object.assign(document.createElement("li"), { textContent: t("rv.noChoice") })];
    $("chosen-summary").replaceChildren(...items);
    clear("choose-msg");
    clear("confirm-msg");
    setStage("confirm", true);
  } catch (error) {
    show("choose-msg", "bad", error.message);
  }
});

$("cast").addEventListener("click", async () => {
  $("audit").disabled = true;
  try {
    const result = await withBusy($("cast"), "rv.casting", () => castPrepared());
    $("tracking").textContent = result.trackingCode;
    $("receipt-meta").textContent =
      `${session.election.name || session.election.electionId} · ${when(new Date().toISOString())} · ` +
      t("dn.receiptNote", { url: `${location.origin}/verify` });
    setStage("done", true);
    followReceipt(result.trackingCode);
  } catch (error) {
    show("confirm-msg", "bad", error.message);
  } finally {
    $("audit").disabled = false;
  }
});

$("audit").addEventListener("click", async () => {
  $("cast").disabled = true;
  try {
    const result = await withBusy($("audit"), "rv.auditing", () => auditPrepared());
    if (result.ok) {
      show("confirm-msg", "ok", t("rv.auditOk"));
      setTimeout(() => setStage("choose", true), 3500);
    } else {
      show("confirm-msg", "bad", t("rv.auditBad", { reason: result.reason ?? "" }));
    }
  } catch (error) {
    show("confirm-msg", "bad", error.message);
  } finally {
    $("cast").disabled = false;
  }
});

$("change-choice").addEventListener("click", () => {
  discardPrepared();
  clear("confirm-msg");
  setStage("choose", true);
});

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("tracking").textContent);
    show("done-msg", "ok", t("dn.copied"));
  } catch {
    show("done-msg", "warn", t("dn.copyFail"));
  }
});

$("print").addEventListener("click", () => window.print());

$("goverify").addEventListener("click", () => {
  location.href = `/verify?code=${encodeURIComponent($("tracking").textContent)}`;
});

$("revote").addEventListener("click", () => {
  clearInterval(sealPoll);
  resetForRevote();
  syncSelected();
  clear("choose-msg");
  setStage("choose", true);
});

