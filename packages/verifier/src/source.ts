/**
 * Where the bulletin board comes from.
 *
 * Two sources, deliberately interchangeable: a live ballot box over HTTP, or a
 * file somebody exported earlier. The verifier does not care which -- a block
 * is checked against the validator quorum either way, so a file handed over by
 * a stranger is exactly as trustworthy as one downloaded from the commission.
 * That is what lets an observer verify an election years later, after every
 * D-Voting server has been switched off.
 */

import { readFile, writeFile } from "node:fs/promises";

import { blockFromWire, blockToWire, type Block, type WireBlock } from "@dvoting/ledger";

export const EXPORT_FORMAT = "dvoting/bulletin-export/v1";

export interface BulletinExport {
  readonly format: typeof EXPORT_FORMAT;
  /** Where it was downloaded from. Informational only; nothing trusts it. */
  readonly source: string | null;
  readonly exportedAt: string;
  readonly blocks: readonly WireBlock[];
}

export class SourceError extends Error {
  override name = "SourceError";
}

/** Download every block from a ballot box's public bulletin board. */
export async function fetchBlocks(
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Block[]> {
  const base = baseUrl.replace(/\/+$/, "");
  const getJson = async (path: string): Promise<unknown> => {
    let response: Response;
    try {
      response = await fetchImpl(`${base}${path}`, { signal: AbortSignal.timeout(30_000) });
    } catch (error) {
      throw new SourceError(
        `could not reach ${base}${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (!response.ok) throw new SourceError(`${base}${path} returned HTTP ${response.status}`);
    return response.json();
  };

  const head = (await getJson("/v1/bulletin/head")) as { height?: unknown };
  if (typeof head.height !== "number" || !Number.isInteger(head.height) || head.height < 0) {
    throw new SourceError("the bulletin board head did not report a valid height");
  }

  const blocks: Block[] = [];
  for (let height = 0; height < head.height; height++) {
    blocks.push(parseBlock(await getJson(`/v1/bulletin/blocks/${height}`), height));
  }
  return blocks;
}

export async function readExport(path: string): Promise<Block[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new SourceError(
      `could not read ${path}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const value = parsed as Partial<BulletinExport>;
  if (value.format !== EXPORT_FORMAT || !Array.isArray(value.blocks)) {
    throw new SourceError(`${path} is not a ${EXPORT_FORMAT} file`);
  }
  return value.blocks.map((wire, height) => parseBlock(wire, height));
}

export function toExport(blocks: readonly Block[], source: string | null): BulletinExport {
  return {
    format: EXPORT_FORMAT,
    source,
    exportedAt: new Date().toISOString(),
    blocks: blocks.map(blockToWire),
  };
}

export async function writeExport(
  path: string,
  blocks: readonly Block[],
  source: string | null,
): Promise<void> {
  await writeFile(path, `${JSON.stringify(toExport(blocks, source), null, 2)}\n`, "utf8");
}

function parseBlock(wire: unknown, height: number): Block {
  try {
    return blockFromWire(wire);
  } catch (error) {
    throw new SourceError(
      `block ${height} is malformed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
