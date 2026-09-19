/**
 * Durable, append-only block store backed by a single file. SERVER-ONLY.
 *
 * Separate entry point (`@dvoting/ledger/file-store`) because it imports
 * node:fs; the main entry point stays isomorphic.
 *
 * ===========================================================================
 * WHY A FILE RATHER THAN A DATABASE.
 *
 * The storage shape should match the data. A chain is an append-only sequence
 * that is never updated and never deleted, so a relational store buys indexing
 * and transactions we barely use while adding an operational dependency. A flat
 * file gives three things that matter here:
 *
 *   - The append-only property is structural, not merely a convention. There is
 *     no UPDATE to accidentally grant.
 *   - The whole chain is one artefact. An observer can copy it, walk away, and
 *     re-verify the entire election offline -- which is exactly what public
 *     verifiability is supposed to mean.
 *   - Crash behaviour is simple enough to reason about (see below).
 *
 * The `BlockStore` interface is unchanged, so a Postgres implementation remains
 * a drop-in for deployments that want one.
 *
 * ===========================================================================
 * CRASH SAFETY.
 *
 * Each block is one JSON line. Appending is: write the line, then fsync, THEN
 * acknowledge. So at any crash point:
 *
 *   - the line was fully written and synced  -> the block is present, correct;
 *   - the write was torn mid-line            -> the final line fails to parse.
 *
 * A torn final line is discarded on load, because it can only correspond to an
 * append that was never acknowledged to the caller. A malformed line ANYWHERE
 * ELSE is corruption or tampering and is a hard error -- silently skipping it
 * would let an attacker delete a ballot by scribbling on the file.
 */

import { open, type FileHandle } from "node:fs/promises";

import type { Block, LedgerEntry } from "./block.ts";
import type { BlockStore } from "./chain.ts";
import { blockFromWire, blockToWire } from "./wire.ts";

export class FileStoreError extends Error {
  override name = "FileStoreError";
}

export interface FileBlockStoreOptions {
  /**
   * fsync after every append.
   *
   * Default true. Turning it off makes appends much faster and makes durability
   * a lie: the OS may buffer a "committed" block that a power cut then loses.
   * Only acceptable for tests and throwaway demos.
   */
  readonly fsync?: boolean;
}

export class FileBlockStore implements BlockStore {
  readonly #handle: FileHandle;
  readonly #blocks: Block[];
  readonly #index: Map<string, [number, number]>;
  readonly #fsync: boolean;
  /** Byte offset for the next append. Tracked explicitly; see open(). */
  #writeOffset: number;
  #closed = false;

  private constructor(
    handle: FileHandle,
    blocks: Block[],
    index: Map<string, [number, number]>,
    fsync: boolean,
    writeOffset: number,
  ) {
    this.#handle = handle;
    this.#blocks = blocks;
    this.#index = index;
    this.#fsync = fsync;
    this.#writeOffset = writeOffset;
  }

  /** Open (creating if absent) and load the chain into memory. */
  static async open(path: string, options: FileBlockStoreOptions = {}): Promise<FileBlockStore> {
    // "r+" rather than append mode: Windows refuses ftruncate on a handle opened
    // with O_APPEND (EPERM), and truncation is required to clean up a torn tail.
    // Write positions are therefore tracked explicitly instead of relying on the
    // append cursor.
    let handle: FileHandle;
    try {
      handle = await open(path, "r+");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      handle = await open(path, "w+");
    }

    let text: string;
    try {
      text = await handle.readFile({ encoding: "utf8" });
    } catch (error) {
      await handle.close();
      throw new FileStoreError(
        `could not read ${path}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    const blocks: Block[] = [];
    const index = new Map<string, [number, number]>();
    const encoder = new TextEncoder();

    // A record is complete only if it is newline-terminated. Splitting on "\n"
    // leaves everything after the final newline in `tail`: either "" for a clean
    // file, or an unterminated fragment from an append that never finished. A
    // caller was never told such an append succeeded, so discarding it is
    // correct -- and it is the ONLY line that may be incomplete.
    const segments = text.split("\n");
    const tail = segments.pop() ?? "";
    let validBytes = 0;

    for (const [lineNumber, line] of segments.entries()) {
      if (line.length === 0) {
        await handle.close();
        throw new FileStoreError(`${path}: blank line at line ${lineNumber + 1}`);
      }

      let block: Block;
      try {
        block = blockFromWire(JSON.parse(line));
      } catch (error) {
        await handle.close();
        throw new FileStoreError(
          `${path}: corrupt block at line ${lineNumber + 1}: ` +
            (error instanceof Error ? error.message : String(error)),
        );
      }

      if (block.header.height !== blocks.length) {
        await handle.close();
        throw new FileStoreError(
          `${path}: block at line ${lineNumber + 1} has height ${block.header.height}, ` +
            `expected ${blocks.length}`,
        );
      }

      const blockIndex = blocks.length;
      blocks.push(block);
      for (const [entryIndex, entry] of block.entries.entries()) {
        const key = entryKey(entry);
        if (index.has(key)) {
          await handle.close();
          throw new FileStoreError(`${path}: duplicate entry "${key}" at line ${lineNumber + 1}`);
        }
        index.set(key, [blockIndex, entryIndex]);
      }

      validBytes += encoder.encode(line).length + 1;
    }

    if (tail.length > 0) {
      // TRUNCATE, do not merely skip. Appending past an unterminated fragment
      // would splice the next block onto it and corrupt the chain permanently.
      console.warn(
        `[ledger] discarding ${tail.length} unterminated byte(s) at the end of ${path} ` +
          "(interrupted append; the block was never acknowledged)",
      );
      await handle.truncate(validBytes);
      if (options.fsync ?? true) await handle.sync();
    }

    return new FileBlockStore(handle, blocks, index, options.fsync ?? true, validBytes);
  }

  async append(block: Block): Promise<void> {
    this.#assertOpen();

    if (block.header.height !== this.#blocks.length) {
      throw new FileStoreError(
        `append: block height ${block.header.height} does not follow ${this.#blocks.length - 1}`,
      );
    }

    const line = `${JSON.stringify(blockToWire(block))}\n`;
    await this.#handle.write(line, this.#writeOffset, "utf8");
    // Durable BEFORE the in-memory view changes: a caller that sees the append
    // succeed must be able to rely on it having survived.
    if (this.#fsync) await this.#handle.sync();
    this.#writeOffset += new TextEncoder().encode(line).length;

    const blockIndex = this.#blocks.length;
    this.#blocks.push(block);
    for (const [entryIndex, entry] of block.entries.entries()) {
      this.#index.set(entryKey(entry), [blockIndex, entryIndex]);
    }
  }

  async height(): Promise<number> {
    return this.#blocks.length;
  }

  async head(): Promise<Block | null> {
    return this.#blocks.at(-1) ?? null;
  }

  async getByHeight(height: number): Promise<Block | null> {
    return this.#blocks[height] ?? null;
  }

  async all(): Promise<readonly Block[]> {
    return this.#blocks;
  }

  async findEntry(kind: string, id: string): Promise<{ block: Block; entryIndex: number } | null> {
    const location = this.#index.get(`${kind}/${id}`);
    if (!location) return null;
    const [blockIndex, entryIndex] = location;
    return { block: this.#blocks[blockIndex]!, entryIndex };
  }

  async hasEntry(kind: string, id: string): Promise<boolean> {
    return this.#index.has(`${kind}/${id}`);
  }

  async entriesOfKind(kind: string): Promise<LedgerEntry[]> {
    const out: LedgerEntry[] = [];
    for (const block of this.#blocks) {
      for (const entry of block.entries) {
        if (entry.kind === kind) out.push(entry);
      }
    }
    return out;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#handle.close();
  }

  #assertOpen(): void {
    if (this.#closed) throw new FileStoreError("store is closed");
  }
}

function entryKey(entry: LedgerEntry): string {
  return `${entry.kind}/${entry.id}`;
}
