/**
 * In-memory block store.
 *
 * Deliberately simple and append-only: there is no method to mutate or remove a
 * block, so the type system itself refuses to express a rewrite. A persistent
 * implementation (Postgres, or one file per block) satisfies the same interface;
 * the validation rules live in the Ledger, not the store, so swapping storage
 * cannot weaken them.
 */

import type { Block, LedgerEntry } from "./block.ts";
import type { BlockStore } from "./chain.ts";

export class InMemoryBlockStore implements BlockStore {
  readonly #blocks: Block[] = [];
  /** "kind/id" -> [blockIndex, entryIndex], so lookups stay O(1). */
  readonly #index = new Map<string, [number, number]>();

  async append(block: Block): Promise<void> {
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

  async findEntry(
    kind: string,
    id: string,
  ): Promise<{ block: Block; entryIndex: number } | null> {
    const location = this.#index.get(`${kind}/${id}`);
    if (!location) return null;
    const [blockIndex, entryIndex] = location;
    return { block: this.#blocks[blockIndex]!, entryIndex };
  }

  async hasEntry(kind: string, id: string): Promise<boolean> {
    return this.#index.has(`${kind}/${id}`);
  }

  /** All entries of a kind, in chain order. Used by the tally. */
  async entriesOfKind(kind: string): Promise<LedgerEntry[]> {
    const out: LedgerEntry[] = [];
    for (const block of this.#blocks) {
      for (const entry of block.entries) {
        if (entry.kind === kind) out.push(entry);
      }
    }
    return out;
  }
}

function entryKey(entry: LedgerEntry): string {
  return `${entry.kind}/${entry.id}`;
}
