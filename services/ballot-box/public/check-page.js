/**
 * The second-device page: opened on a phone by scanning the QR code on the
 * voting screen.
 *
 * It holds the ballot id and commitment from the link (which the voting device
 * produced BEFORE the voter chose to cast or test), then watches the public
 * bulletin board until that ballot is sealed one way or the other, and runs
 * the matching check from check-lib.js. It never talks to the voting device.
 */

import { checkCast, checkCode, checkTested, parseCheckLink } from "/check-lib.js?v=1";
import { apply, lang, onLangChange, setLang, t } from "/i18n.js?v=3";
import { symbolSvg } from "/symbols.js?v=1";

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value).replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);

const link = parseCheckLink(location.hash);
let election = null;
let outcome = null; // the last rendered result, re-rendered on language change
const startedAt = Date.now();
let timer = null;

function render() {
  apply();
  if (!link) return setStatus("bad", t("ck.badLink"), "");
  if (!election) return;

  if (!outcome) {
    const waitedLong = Date.now() - startedAt > 90_000;
    setStatus(
      waitedLong ? "warn" : "waiting",
      t("ck.waiting"),
      `<p>${esc(t("ck.waitingBody"))}</p>${waitedLong ? `<p class="check-warn">${esc(t("ck.waitingLong"))}</p>` : ""}`,
    );
    return;
  }

  const { kind, result } = outcome;
  if (kind === "tested") {
    if (!result.ok) {
      setStatus("bad", t("ck.testFail"), `<p>${esc(t("ck.testFailBody"))}</p>`);
    } else {
      const chosen = result.encodedSelections
        .map((value, index) => (value === 1 ? index : null))
        .filter((index) => index !== null);
      const items = chosen.length
        ? chosen.map((index) => {
            const detail = election.candidateDetails?.[index];
            const name = detail?.nota ? t("ch.nota") : election.candidates[index];
            return `<li><span class="chosen-symbol">${symbolSvg(detail)}</span><span><strong>${esc(name)}</strong>${detail?.party ? `<small>${esc(detail.party)}</small>` : ""}</span></li>`;
          })
        : [`<li><strong>${esc(t("ck.testedNothing"))}</strong></li>`];
      setStatus(
        "ask",
        t("ck.tested"),
        `<ul class="chosen-list">${items.join("")}</ul>` +
          `<p class="check-ask">${esc(t("ck.testedAsk"))}</p>` +
          `<p class="check-yes">${esc(t("ck.testedYes"))}</p>` +
          `<p class="check-no">${esc(t("ck.testedNo"))}</p>`,
      );
    }
  } else if (result.ok) {
    setStatus("ok", t("ck.cast"), `<p>${esc(t("ck.castBody", {
      block: outcome.receipt.blockHeight,
      sigs: outcome.receipt.attestations.length,
      total: election.validators.length,
    }))}</p>`);
  } else {
    setStatus("bad", t("ck.castFail"), `<p>${esc(t("ck.castFailBody"))}</p>`);
  }

  $("details").hidden = false;
  $("steps").replaceChildren(
    ...result.steps.map((step) => {
      const li = document.createElement("li");
      li.dataset.ok = String(step.ok);
      li.textContent = `${step.ok ? "✓" : "✗"} ${step.id}: ${step.detail ?? ""}`;
      return li;
    }),
  );
}

function setStatus(state, title, bodyHtml) {
  $("status").dataset.state = state;
  $("status-title").textContent = title;
  $("status-body").innerHTML = bodyHtml;
}

async function getJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

/** Poll until the ballot is sealed, as cast or as tested, then check it once. */
async function poll() {
  try {
    const { sealedAs } = await getJson(`/v1/bulletin/lookup/${encodeURIComponent(link.ballotId)}`);
    if (sealedAs === "ballot") {
      const receipt = await getJson(`/v1/bulletin/ballots/${encodeURIComponent(link.ballotId)}`);
      outcome = { kind: "cast", receipt, result: await checkCast(receipt, election, link) };
    } else if (sealedAs === "spoiled-ballot") {
      const receipt = await getJson(`/v1/bulletin/audits/${encodeURIComponent(link.ballotId)}`);
      outcome = { kind: "tested", receipt, result: await checkTested(receipt, election, link) };
    }
  } catch (error) {
    setStatus("warn", t("ck.loadErr", { reason: error.message }), "");
    return;
  }
  render();
  if (outcome) clearInterval(timer);
}

$("lang-toggle").addEventListener("click", () => setLang(lang() === "hi" ? "en" : "hi"));
onLangChange(render);

// Scanning the next ballot's code while this page is open changes only the
// fragment, which browsers treat as the same page. Start over, so the phone
// can never keep showing the previous ballot's verdict under a new code.
addEventListener("hashchange", () => location.reload());

render();
if (link && !globalThis.crypto?.subtle) {
  // Browsers expose WebCrypto only on secure origins. Without it nothing here
  // can be verified, and a page that cannot verify must not look like it did.
  setStatus("bad", t("ck.insecure"), "");
} else if (link) {
  $("code-card").hidden = false;
  $("code").textContent = checkCode(link.commitment);
  try {
    election = await getJson("/v1/election");
    $("election").textContent = election.name || election.electionId;
    if (election.electionId !== link.electionId) {
      setStatus("bad", t("ck.wrongElection"), "");
    } else {
      render();
      await poll();
      if (!outcome) timer = setInterval(poll, 3000);
    }
  } catch (error) {
    setStatus("warn", t("ck.loadErr", { reason: error.message }), "");
  }
}
