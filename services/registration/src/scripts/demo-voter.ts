/**
 * End-to-end demo of the voter's side of registration, against a running RA.
 *
 * Everything in this script is what happens ON THE VOTER'S DEVICE. Read it as
 * the reference implementation the React Native app will mirror.
 *
 * Usage:
 *   node src/scripts/demo-voter.ts [baseUrl] [rollId] [enrolmentCode]
 */

import {
  blind,
  computeKeyId,
  finalize,
  fromBase64Url,
  generateCredential,
  toBase64Url,
  verify,
  RSABSSA_SHA384_PSS_DETERMINISTIC,
} from "@dvoting/crypto";
import { publicKeyFromJwk, type RsaPublicJwk } from "@dvoting/crypto/keygen";

const baseUrl = process.argv[2] ?? "http://localhost:8081";
const rollId = process.argv[3] ?? "R-100001";
const enrolmentCode = process.argv[4] ?? "";

function step(n: number, text: string): void {
  console.log(`\n[${n}] ${text}`);
}

interface IssuerInfo {
  electionId: string;
  keyId: string;
  suite: string;
  modulusBits: number;
  publicKey: RsaPublicJwk;
}

/**
 * Returns a process exit status instead of calling process.exit().
 *
 * Calling process.exit() while an HTTP socket is still open aborts Node with a
 * libuv assertion on Windows, which would bury the real error message behind a
 * crash dump in the middle of a live demo.
 */
async function main(): Promise<number> {
  // --- 1. Fetch and pin the issuer key ---------------------------------------
  step(1, "Fetching the issuer's public key");

  const issuerRes = await fetch(`${baseUrl}/v1/issuer`);
  if (!issuerRes.ok) {
    console.error(`    issuer lookup failed: HTTP ${issuerRes.status}`);
    return 1;
  }
  const issuer = (await issuerRes.json()) as IssuerInfo;
  const publicKey = publicKeyFromJwk(issuer.publicKey, RSABSSA_SHA384_PSS_DETERMINISTIC);

  // Recompute the key id locally rather than trusting the one we were handed.
  // This is the client half of the key-consistency defence: a malicious RA that
  // tried to hand this voter a unique key would have to publish a key id that
  // differs from the one on the bulletin board, which is detectable.
  const localKeyId = await computeKeyId(publicKey);
  if (localKeyId !== issuer.keyId) {
    console.error(`    KEY ID MISMATCH: server said ${issuer.keyId}, we computed ${localKeyId}`);
    return 1;
  }
  console.log(`    election    : ${issuer.electionId}`);
  console.log(`    suite       : ${issuer.suite} (${issuer.modulusBits}-bit)`);
  console.log(`    keyId       : ${localKeyId}`);
  console.log(`                  ^ pin this and compare against the bulletin board`);

  // --- 2. Prove identity -----------------------------------------------------
  step(2, "Proving eligibility against the electoral roll");

  const registerRes = await fetch(`${baseUrl}/v1/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rollId, enrolmentCode }),
  });
  const registerBody = (await registerRes.json()) as Record<string, string>;
  if (!registerRes.ok) {
    console.error(
      `    refused (${registerRes.status}): ${registerBody.error} - ${registerBody.message}`,
    );
    return 1;
  }
  console.log(`    token expires at ${registerBody.expiresAt}`);

  // --- 3. Create and blind a credential --------------------------------------
  step(3, "Generating an anonymous credential and blinding it LOCALLY");

  const credential = generateCredential();
  const { blindedMessage, inverse } = await blind(publicKey, credential);

  console.log(`    credential  : ${toBase64Url(credential).slice(0, 24)}...`);
  console.log(`                  ^ NEVER leaves this device`);
  console.log(`    blinded     : ${toBase64Url(blindedMessage).slice(0, 24)}...`);
  console.log(`                  ^ all the Registration Authority ever sees`);

  // --- 4. Get it blind-signed ------------------------------------------------
  step(4, "Asking the Registration Authority to blind-sign it");

  const issueRes = await fetch(`${baseUrl}/v1/credential/issue`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      registrationToken: registerBody.registrationToken,
      blindedMessage: toBase64Url(blindedMessage),
    }),
  });
  const issueBody = (await issueRes.json()) as Record<string, string>;
  if (!issueRes.ok) {
    console.error(`    refused (${issueRes.status}): ${issueBody.error} - ${issueBody.message}`);
    return 1;
  }
  console.log(`    blind signature received (replayed: ${issueBody.replayed})`);

  // --- 5. Unblind and verify -------------------------------------------------
  step(5, "Unblinding and verifying the credential");

  // fromBase64Url rather than Buffer: this script is the reference the React
  // Native app mirrors, and Buffer does not exist outside Node.
  const signature = await finalize(
    publicKey,
    credential,
    fromBase64Url(issueBody.blindSignature!),
    inverse,
  );
  const valid = await verify(publicKey, credential, signature);
  console.log(`    signature valid: ${valid}`);

  console.log(`
=== Result ===
The voter now holds (credential, signature) -- an anonymous voting credential.

  * The RA can verify this signature is genuinely its own.
  * The RA CANNOT tell which voter it issued it to: it only ever saw the blinded
    form, which is statistically independent of the credential above.
  * The credential can be spent exactly once at the ballot box (Phase 1 next
    steps: ElGamal ballot encryption, validity ZKP, and the chain write).
`);

  return valid ? 0 : 1;
}

// Set exitCode rather than calling exit(): Node drains open handles and exits
// cleanly on its own.
try {
  process.exitCode = await main();
} catch (error) {
  console.error(`\nDemo failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
