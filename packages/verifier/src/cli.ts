#!/usr/bin/env node
/**
 * dvoting-verify -- recount an election on your own machine.
 *
 *   node packages/verifier/src/cli.ts --url http://localhost:8080
 *   node packages/verifier/src/cli.ts --file board.json --validators validators.json
 *
 * Exit code 0 means every check passed, 1 means something did not verify, and 2
 * means the verifier could not run (bad arguments, unreachable server).
 */

import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";

import { fetchBlocks, readExport, writeExport } from "./source.ts";
import { verifyElection, type ElectionVerificationReport, type PinnedValidators } from "./verify.ts";

const USAGE = `dvoting-verify -- independently verify a D-Voting election

Source (exactly one):
  --url <base>          download the bulletin board from a ballot box
  --file <path>         read a previously exported bulletin board

Trust anchor:
  --validators <path>   JSON {"validators":[{"id","publicKey"}],"quorum":n}
                        obtained out of band. Without it, the validator set is
                        read from the chain itself and the run warns.

Optional checks:
  --roll <path>         published electoral roll, one identifier per line
  --ballot <code>       prove a tracking code is on the chain (repeatable)

Output:
  --save <path>         also write the downloaded board to a file for later
  --json                print the report as JSON
  --help                show this message
`;

async function main(): Promise<number> {
  let args;
  try {
    args = parseArgs({
      options: {
        url: { type: "string" },
        file: { type: "string" },
        validators: { type: "string" },
        roll: { type: "string" },
        ballot: { type: "string", multiple: true },
        save: { type: "string" },
        json: { type: "boolean", default: false },
        help: { type: "boolean", default: false },
      },
      strict: true,
    }).values;
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n\n${USAGE}`);
    return 2;
  }

  if (args.help) {
    process.stdout.write(USAGE);
    return 0;
  }
  if (Boolean(args.url) === Boolean(args.file)) {
    process.stderr.write(`Give exactly one of --url or --file.\n\n${USAGE}`);
    return 2;
  }

  try {
    const blocks = args.url ? await fetchBlocks(args.url) : await readExport(args.file!);
    if (args.save) await writeExport(args.save, blocks, args.url ?? null);

    const pinnedValidators = args.validators
      ? (JSON.parse(await readFile(args.validators, "utf8")) as PinnedValidators)
      : undefined;
    const rollIds = args.roll
      ? (await readFile(args.roll, "utf8"))
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line.length > 0)
      : undefined;

    const report = await verifyElection(blocks, {
      ...(pinnedValidators ? { pinnedValidators } : {}),
      ...(rollIds ? { rollIds } : {}),
      ...(args.ballot ? { ballotIds: args.ballot } : {}),
    });

    process.stdout.write(args.json ? `${JSON.stringify(report, null, 2)}\n` : render(report));
    return report.valid ? 0 : 1;
  } catch (error) {
    process.stderr.write(`dvoting-verify: ${error instanceof Error ? error.message : String(error)}\n`);
    return 2;
  }
}

function render(report: ElectionVerificationReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  Election   ${report.name ? `${report.name} (${report.electionId})` : report.electionId ?? "unknown"}`);
  lines.push(`  Phase      ${report.phase}`);
  lines.push(`  Blocks     ${report.blockCount}`);
  lines.push(`  Anchor     ${report.trustAnchor === "pinned" ? "pinned validator set" : "chain (NOT pinned)"}`);
  if (report.validatorFingerprint) lines.push(`  Validators ${report.validatorFingerprint}`);
  lines.push("");

  for (const check of report.checks) {
    lines.push(`  ${check.ok ? "PASS" : "FAIL"}  ${check.label}${check.detail ? ` -- ${check.detail}` : ""}`);
  }
  for (const warning of report.warnings) {
    lines.push(`  WARN  ${warning}`);
  }

  if (report.results) {
    lines.push("");
    lines.push("  Recounted result");
    const width = Math.max(...report.results.map((entry) => entry.candidate.length));
    for (const entry of report.results) {
      lines.push(`    ${entry.candidate.padEnd(width)}  ${entry.votes}`);
    }
  }

  lines.push("");
  lines.push(
    report.valid
      ? "  VERIFIED -- every check passed on this machine."
      : "  NOT VERIFIED -- see the failing check above.",
  );
  lines.push("");
  return lines.join("\n");
}

process.exitCode = await main();
