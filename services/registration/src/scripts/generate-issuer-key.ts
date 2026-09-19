/**
 * Generate an issuer key pair for an election.
 *
 * Usage:  node src/scripts/generate-issuer-key.ts [modulusBits]
 *
 * Prints the private JWK to stdout and the public material to stderr, so the
 * secret can be piped into a secrets manager while the human-readable summary
 * stays on the terminal:
 *
 *   node src/scripts/generate-issuer-key.ts > issuer.key.json
 *
 * The printed private key is the crown jewel of the registration layer: anyone
 * holding it can mint unlimited valid voting credentials. Never commit it,
 * never log it, and in production generate it inside KMS/HSM instead so it has
 * no plaintext form at all.
 */

import { computeKeyId } from "@dvoting/crypto";
import { RSABSSA_SHA384_PSS_DETERMINISTIC } from "@dvoting/crypto";
import { generateIssuerKeyPair, privateKeyToJwk, publicKeyToJwk } from "@dvoting/crypto/keygen";

const modulusBits = Number(process.argv[2] ?? 3072);
if (!Number.isInteger(modulusBits) || modulusBits < 2048) {
  console.error("modulusBits must be an integer >= 2048");
  process.exit(1);
}

process.stderr.write(`Generating a ${modulusBits}-bit issuer key (this takes a few seconds)...\n`);

const { privateKey, publicKey } = generateIssuerKeyPair(modulusBits, RSABSSA_SHA384_PSS_DETERMINISTIC);
const keyId = await computeKeyId(publicKey);

process.stdout.write(`${JSON.stringify(privateKeyToJwk(privateKey))}\n`);

process.stderr.write(`
Issuer key generated.
  suite      : ${RSABSSA_SHA384_PSS_DETERMINISTIC.name}
  modulusBits: ${modulusBits}
  keyId      : ${keyId}

Public JWK (publish this on the bulletin board so voters can pin it):
${JSON.stringify(publicKeyToJwk(publicKey), null, 2)}

The PRIVATE key was written to stdout. Store it as ISSUER_PRIVATE_KEY_JWK in a
secrets manager. Do not commit it.
`);
