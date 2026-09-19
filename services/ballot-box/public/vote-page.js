/**
 * Page controller for the voter interface.
 *
 * Kept in its own file rather than inline in the HTML so the page can run under
 * a strict `script-src 'self'` Content-Security-Policy. Inline scripts would
 * require 'unsafe-inline', which removes the main protection CSP offers on a
 * page that handles a voting credential.
 */

import {
  loadElection, registerAndGetCredential, prepareSelection, auditPrepared, castPrepared,
  resetForRevote, session, setStage, show, busy, esc, $,
} from "/voter.js";

for (const button of document.querySelectorAll("button.action")) {
  button.dataset.label = button.textContent.trim();
}
for (const link of document.querySelectorAll("nav button[data-href]")) {
  link.addEventListener("click", () => {
    location.href = link.dataset.href;
  });
}

setStage("identify");

try {
  await loadElection();
} catch (error) {
  show("identify-msg", "bad", `Could not load the election: ${esc(error.message)}`);
}

$("register").addEventListener("click", async () => {
  const rollId = $("rollId").value.trim();
  const code = $("code").value.trim();
  if (!rollId || !code) {
    show("identify-msg", "bad", "Enter both your roll number and enrolment code.");
    return;
  }

  busy($("register"), true, "Obtaining your credential…");
  try {
    await registerAndGetCredential(rollId, code);
    // Clear the polling-card details from the DOM once they have been used.
    $("rollId").value = "";
    $("code").value = "";
    $("identify-msg").innerHTML = "";
    setStage("choose");
  } catch (error) {
    show("identify-msg", "bad", esc(error.message));
  } finally {
    busy($("register"), false);
  }
});

$("prepare").addEventListener("click", async () => {
  const selected = document.querySelector('input[name="candidate"]:checked');
  if (!selected) {
    show("choose-msg", "bad", "Select a candidate first.");
    return;
  }

  busy($("prepare"), true, "Encrypting on this device…");
  try {
    const commitment = await prepareSelection(Number(selected.value));
    $("commitment").textContent = commitment;
    $("chosen-summary").textContent =
      `You chose: ${session.election.candidates[session.prepared.selectedIndex]}`;
    $("choose-msg").innerHTML = "";
    setStage("confirm");
  } catch (error) {
    show("choose-msg", "bad", esc(error.message));
  } finally {
    busy($("prepare"), false);
  }
});

$("cast").addEventListener("click", async () => {
  busy($("cast"), true, "Casting…");
  $("audit").disabled = true;
  try {
    const result = await castPrepared();
    $("tracking").textContent = result.trackingCode;
    setStage("done");
  } catch (error) {
    show("confirm-msg", "bad", esc(error.message));
  } finally {
    busy($("cast"), false);
    $("audit").disabled = false;
  }
});

$("audit").addEventListener("click", async () => {
  busy($("audit"), true, "Checking…");
  $("cast").disabled = true;
  try {
    const result = await auditPrepared();
    if (result.ok) {
      show(
        "confirm-msg", "ok",
        "<strong>Verified.</strong> This ballot really did encrypt your choice. " +
          "It is now spoiled and cannot be counted — choose again to cast a fresh one.",
      );
      setTimeout(() => setStage("choose"), 2500);
    } else {
      show(
        "confirm-msg", "bad",
        `<strong>WARNING — do not use this device.</strong> ${esc(result.reason ?? "The check failed.")}`,
      );
    }
  } catch (error) {
    show("confirm-msg", "bad", esc(error.message));
  } finally {
    busy($("audit"), false);
    $("cast").disabled = false;
  }
});

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("tracking").textContent);
    show("done-msg", "ok", "Copied to the clipboard.");
  } catch {
    show("done-msg", "warn", "Copy failed — select the code and copy it manually.");
  }
});

$("goverify").addEventListener("click", () => {
  location.href = `/verify?code=${encodeURIComponent($("tracking").textContent)}`;
});

$("revote").addEventListener("click", () => {
  resetForRevote();
  $("choose-msg").innerHTML = "";
  setStage("choose");
});
