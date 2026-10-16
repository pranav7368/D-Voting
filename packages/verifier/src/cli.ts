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

import { checkpointFromWire, type Block, type SignedCheckpoint } from "@dvoting/ledger";

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

Independent witnesses:
  --witnesses           fetch a checkpoint from every witness sealed in block 0
                        and require the board to contain what they saw
  --checkpoint <path>   a saved checkpoint file instead (repeatable)

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
        witnesses: { type: "boolean", default: false },
        checkpoint: { type: "string", multiple: true },
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

    const checkpoints = args.witnesses || args.checkpoint
      ? await collectCheckpoints(blocks, args.witnesses ?? false, args.checkpoint ?? [])
      : undefined;

    const report = await verifyElection(blocks, {
      ...(checkpoints ? { checkpoints } : {}),
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

/**
 * Checkpoints from the witnesses sealed in block 0, fetched from each
 * witness's own address, plus any saved checkpoint files.
 */
async function collectCheckpoints(blocks: readonly Block[], live: boolean, files: readonly string[]): Promise<SignedCheckpoint[]> {
  const out: SignedCheckpoint[] = [];
  for (const path of files) {
    const body = JSON.parse(await readFile(path, "utf8")) as { checkpoint?: unknown };
    out.push(checkpointFromWire(body.checkpoint ?? body));
  }
  if (live) {
    const config = blocks[0]?.entries.find((e) => e.kind === "election-config");
    const record = config ? (JSON.parse(new TextDecoder().decode(config.data)) as { witnesses?: { witnesses: { id: string; url: string }[] } }) : null;
    for (const witness of record?.witnesses?.witnesses ?? []) {
      try {
        const response = await fetch(`${witness.url}/v1/checkpoint`, { signal: AbortSignal.timeout(15_000) });
        const body = (await response.json()) as { checkpoint?: unknown; alarm?: string | null };
        if (body.alarm) process.stderr.write(`dvoting-verify: witness ${witness.id} reports an ALARM: ${body.alarm}\n`);
        if (body.checkpoint) out.push(checkpointFromWire(body.checkpoint));
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        process.stderr.write(`dvoting-verify: witness ${witness.id} unreachable: ${reason}\n`);
      }
    }
  }
  return out;
}

function render(report: ElectionVerificationReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`  Election   ${report.name ? `${report.name} (${report.electionId})` : report.electionId ?? "unknown"}`);
  lines.push(`  Phase      ${report.phase}`);
  lines.push(`  Blocks     ${report.blockCount}`);
  lines.push(`  Anchor     ${report.trustAnchor === "pinned" ? "pinned validator set" : "chain (NOT pinned)"}`);
  if (report.validatorFingerprint) lines.push(`  Validators ${report.validatorFingerprint}`);
  if (report.electionFingerprint) lines.push(`  Fingerprint ${report.electionFingerprint}  (compare with the published value)`);
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
