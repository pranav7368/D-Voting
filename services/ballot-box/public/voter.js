/**
 * The voter application. Runs entirely in the browser.
 *
 * ===========================================================================
 * WHAT NEVER LEAVES THIS PAGE.
 *
 *   - the selected candidate, in plaintext;
 *   - the anonymous credential;
 *   - the blinding factor used to obtain it;
 *   - the randomness used to encrypt the ballot.
 *
 * All four exist only in this tab's memory. Nothing is written to
 * localStorage or sessionStorage: a voting credential on disk outlives the
 * election and outlives the voter's attention. The cost is that a page reload
 * loses an in-progress session, which is the right trade.
 *
 * The server sees a blinded credential request, then an encrypted ballot with
 * zero-knowledge proofs. It cannot decrypt either.
 * ===========================================================================
 */

import {
  RSABSSA_SHA384_PSS_DETERMINISTIC,
  MODP_2048,
  MODP_3072,
  blind,
  computeKeyId,
  digest,
  finalize,
  fromBase64Url,
  generateCredential,
  os2ip,
  prepareBallot,
  auditAgainstCommitment,
  toBase64Url,
  verify as verifyCredentialSignature,
} from "./dvoting-crypto.js";

// --- session state, in memory only -----------------------------------------

const session = {
  election: null,
  issuer: null,       // { publicKey, keyId }
  electionKey: null,  // ElGamal public key
  credential: null,   // Uint8Array — never persisted
  signature: null,    // Uint8Array — never persisted
  fingerprint: null,
  prepared: null,     // { ballot, commitment, secret }
  trackingCode: null,
};

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}

function show(target, kind, html) {
  $(target).innerHTML = `<div class="msg ${kind}">${html}</div>`;
}

function busy(button, on, label) {
  button.disabled = on;
  button.innerHTML = on ? `<span class="spinner"></span>${esc(label)}` : button.dataset.label;
}

function setStage(stage) {
  const order = ["identify", "choose", "confirm", "done"];
  for (const [index, name] of order.entries()) {
    const element = $(`rail-${name}`);
    const current = order.indexOf(stage);
    element.dataset.state = index < current ? "done" : index === current ? "active" : "";
  }
  for (const name of order) $(`stage-${name}`).hidden = name !== stage;
}

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.message ?? body.error ?? `HTTP ${response.status}`);
  return body;
}

/** Fingerprint of the anonymous credential; must match the server's derivation. */
async function credentialFingerprint(credential) {
  const tag = new TextEncoder().encode("dvoting/credential-fingerprint/v1");
  const combined = new Uint8Array(tag.length + credential.length);
  combined.set(tag);
  combined.set(credential, tag.length);
  return toBase64Url(await digest("SHA-256", combined));
}

// --- 1. Load the election ---------------------------------------------------

export async function loadElection() {
  const election = await api("/v1/election");
  session.election = election;

  const group = election.group === "modp2048" ? MODP_2048 : MODP_3072;
  session.electionKey = { group, y: os2ip(fromBase64Url(election.electionPublicKey)) };

  $("election-name").textContent = election.name || election.electionId;
  $("election-facts").innerHTML = `
    ${election.name ? `<dt>Election id</dt><dd>${esc(election.electionId)}</dd>` : ""}
    <dt>Candidates</dt><dd>${election.candidates.map(esc).join(", ")}</dd>
    <dt>Choose</dt><dd>${election.minSelections === election.maxSelections
      ? `exactly ${election.maxSelections}`
      : `${election.minSelections} to ${election.maxSelections}`}</dd>
    <dt>Authorities</dt><dd>${election.validators.map((v) => esc(v.id)).join(", ")} (quorum ${election.quorum})</dd>
    <dt>Trustees</dt><dd>${election.trustees.threshold} of ${election.trustees.total} required to decrypt the result</dd>
    ${election.rollCommitment
      ? `<dt>Roll commitment</dt><dd>${esc(election.rollCommitment)}</dd>`
      : ""}
    <dt>Status</dt><dd>${esc(phaseLabel(election))}</dd>`;

  $("choices").innerHTML = election.candidates
    .map(
      (candidate, index) => `
      <label class="choice" data-index="${index}">
        <input type="radio" name="candidate" value="${index}" />
        <span>${esc(candidate)}</span>
      </label>`,
    )
    .join("");

  for (const label of document.querySelectorAll(".choice")) {
    label.addEventListener("change", () => {
      for (const other of document.querySelectorAll(".choice")) other.dataset.selected = "false";
      label.dataset.selected = "true";
    });
  }

  if (!election.open) {
    show("identify-msg", "warn", phaseExplanation(election));
    $("register").disabled = true;
  }
  return election;
}

/** Human wording for each phase, so a voter is never left guessing. */
function phaseLabel(election) {
  switch (election.phase) {
    case "setup":
      return "not yet opened";
    case "scheduled":
      return `opens ${new Date(election.opensAt).toLocaleString()}`;
    case "voting":
      return election.closesAt
        ? `open until ${new Date(election.closesAt).toLocaleString()}`
        : "open for voting";
    case "closed":
      return "closed";
    default:
      return String(election.phase);
  }
}

function phaseExplanation(election) {
  switch (election.phase) {
    case "setup":
      return "This election has not opened yet. The commission has not sealed the ballot to the chain.";
    case "scheduled":
      return `Voting opens at ${new Date(election.opensAt).toLocaleString()}. Come back then.`;
    default:
      return "This election is closed. You can still verify a ballot you cast earlier.";
  }
}

// --- 2. Prove eligibility and obtain an anonymous credential ---------------

export async function registerAndGetCredential(rollId, enrolmentCode) {
  // The browser talks to the Registration Authority DIRECTLY, never through the
  // ballot box. The RA learns which roll entry is registering; the ballot box
  // learns which ballot is cast. Routing the first through the second would let
  // one party correlate them by session or timing — precisely the link blind
  // signatures exist to destroy.
  const ra = session.election.registrationUrl;
  if (!ra) throw new Error("This election does not publish a registration service URL.");

  // (a) Fetch the issuer key and PIN it. Recomputing the key id locally is what
  //     stops a malicious RA handing this voter a unique key in order to tag
  //     their ballot later. Cross-checking it against the ballot box's copy
  //     means both services must agree.
  const issuerInfo = await api(`${ra}/v1/issuer`);
  const issuerPublicKey = {
    n: os2ip(fromBase64Url(issuerInfo.publicKey.n)),
    e: os2ip(fromBase64Url(issuerInfo.publicKey.e)),
    suite: RSABSSA_SHA384_PSS_DETERMINISTIC,
  };
  const localKeyId = await computeKeyId(issuerPublicKey);
  if (localKeyId !== issuerInfo.keyId || localKeyId !== session.election.issuerKeyId) {
    throw new Error(
      "Issuer key mismatch. The registration service and the ballot box disagree about " +
        "the election key — do not proceed.",
    );
  }
  session.issuer = { publicKey: issuerPublicKey, keyId: localKeyId };

  // (b) Prove eligibility against the electoral roll.
  const registration = await api(`${ra}/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rollId, enrolmentCode }),
  });

  // (c) Everything below happens ONLY here. The blinding factor never leaves.
  const credential = generateCredential();
  const { blindedMessage, inverse } = await blind(issuerPublicKey, credential);

  const issued = await api(`${ra}/v1/credential/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      registrationToken: registration.registrationToken,
      blindedMessage: toBase64Url(blindedMessage),
    }),
  });

  const signature = await finalize(
    issuerPublicKey,
    credential,
    fromBase64Url(issued.blindSignature),
    inverse,
  );

  if (!(await verifyCredentialSignature(issuerPublicKey, credential, signature))) {
    throw new Error("The Registration Authority returned an invalid credential.");
  }

  session.credential = credential;
  session.signature = signature;
  session.fingerprint = await credentialFingerprint(credential);
  return session.fingerprint;
}

// --- 3. Encrypt the ballot on this device ----------------------------------

export async function prepareSelection(selectedIndex) {
  const selections = session.election.candidates.map((_, i) => (i === selectedIndex ? 1 : 0));

  const prepared = await prepareBallot(
    {
      electionId: session.election.electionId,
      candidates: session.election.candidates,
      minSelections: session.election.minSelections,
      maxSelections: session.election.maxSelections,
    },
    session.electionKey,
    selections,
    { credentialFingerprint: session.fingerprint },
  );

  session.prepared = { ...prepared, selections, selectedIndex };
  return prepared.commitment;
}

/**
 * Audit the prepared ballot: does it encrypt what the voter chose?
 *
 * Spoils the ballot — its randomness becomes public, so it can never be cast.
 * The voter then starts over with a fresh one. That is the point: the client
 * had to commit before learning which way this would go.
 */
export async function auditPrepared() {
  const { ballot, secret, commitment, selections } = session.prepared;

  const result = await auditAgainstCommitment(
    {
      electionId: session.election.electionId,
      candidates: session.election.candidates,
      minSelections: session.election.minSelections,
      maxSelections: session.election.maxSelections,
    },
    session.electionKey,
    ballot,
    secret,
    commitment,
    selections,
  );

  // Publish the spoiled ballot so anyone can re-run the audit from the chain.
  await api("/v1/ballots/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ballot: serialiseBallot(ballot),
      auditSecret: {
        ballotId: secret.ballotId,
        selections: [...secret.selections],
        randomness: secret.randomness.map((r) => toBase64Url(scalarBytes(r))),
      },
    }),
  }).catch(() => {
    /* Publication is best-effort; the local audit result is what protects the voter. */
  });

  session.prepared = null;
  return result;
}

/**
 * Start a fresh ballot with the SAME credential already held in this tab.
 *
 * This is what makes re-voting possible: casting never destroys the
 * credential or signature, only the spent encryption randomness. A voter who
 * cast under duress can use this, right here, without registering again --
 * which matters, because registering again would fail outright (one
 * credential is ever issued per identity) and would in any case be a second,
 * detectable act. Re-preparing and re-casting is invisible to anyone but the
 * ballot box, which will simply record it as this credential's newest ballot.
 */
export function resetForRevote() {
  session.prepared = null;
  session.trackingCode = null;
  for (const label of document.querySelectorAll(".choice")) label.dataset.selected = "false";
  for (const input of document.querySelectorAll('input[name="candidate"]')) input.checked = false;
}

export async function castPrepared() {
  const { ballot } = session.prepared;

  const result = await api("/v1/ballots", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      credential: toBase64Url(session.credential),
      credentialSignature: toBase64Url(session.signature),
      ballot: serialiseBallot(ballot),
    }),
  });

  // Destroy the encryption randomness: from here the ballot is not decryptable
  // by this device either.
  session.prepared = null;
  session.trackingCode = result.trackingCode;
  return result;
}

// --- serialisation ----------------------------------------------------------

function elementBytes(value) {
  return toFixedBytes(value, session.electionKey.group.pByteLength);
}
function scalarBytes(value) {
  return toFixedBytes(value, session.electionKey.group.qByteLength);
}
function toFixedBytes(value, length) {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function serialiseProof(proof) {
  return {
    branches: proof.branches.map((branch) => ({
      commitment1: toBase64Url(elementBytes(branch.commitment1)),
      commitment2: toBase64Url(elementBytes(branch.commitment2)),
      challenge: toBase64Url(scalarBytes(branch.challenge)),
      response: toBase64Url(scalarBytes(branch.response)),
    })),
  };
}

function serialiseBallot(ballot) {
  return {
    electionId: ballot.electionId,
    ballotId: ballot.ballotId,
    credentialFingerprint: ballot.credentialFingerprint,
    choices: ballot.choices.map((ct) => ({
      alpha: toBase64Url(elementBytes(ct.alpha)),
      beta: toBase64Url(elementBytes(ct.beta)),
    })),
    choiceProofs: ballot.choiceProofs.map(serialiseProof),
    aggregateProof: serialiseProof(ballot.aggregateProof),
  };
}

export { session, setStage, show, busy, esc, api, $ };
