/**
 * Generate an Ed25519 key pair for a validator authority.
 *
 * Usage:  node src/scripts/generate-validator-key.ts <validator-id>
 *
 * Prints the PRIVATE key to stdout (for VALIDATOR_PRIVATE_KEY) and the public
 * entry to stderr (for the shared VALIDATOR_SET). Each authority runs this on
 * its own machine and publishes only the public half — a validator set assembled
 * by one party from keys it generated is not a validator set, it is one party
 * wearing four hats.
 */

import { toBase64Url } from "@dvoting/crypto";
import { exportPrivateKey, generateValidatorKeyPair } from "@dvoting/ledger";

const validatorId = process.argv[2];
if (!validatorId) {
  console.error("usage: generate-validator-key.ts <validator-id>");
  process.exit(1);
}

const keyPair = await generateValidatorKeyPair(validatorId);
const privateKey = toBase64Url(await exportPrivateKey(keyPair.privateKey));

process.stdout.write(`${privateKey}\n`);

process.stderr.write(`
Validator key generated for "${validatorId}".

  VALIDATOR_PRIVATE_KEY was written to stdout. Keep it on this machine only.

Publish this entry to the shared validator set:
${JSON.stringify({ id: validatorId, publicKey: toBase64Url(keyPair.identity.publicKey) }, null, 2)}
`);
