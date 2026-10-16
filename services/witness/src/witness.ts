/**
 * One witness.
 *
 * ===========================================================================
 * WHAT A WITNESS IS FOR.
 *
 * The digital counterpart of a polling agent signing the account of votes at a
 * booth: an observer independent of the commission, who keeps their own copy
 * of the record and puts their name only to what they have seen with their own
 * eyes. Anyone can run one; it holds no election secret, only its own signing
 * key, and it needs no cooperation from the ballot box beyond the public board.
 *
 * WHAT IT REFUSES.
 *
 * Every block it accepts must extend the chain it already holds, carry a
 * validator quorum, and pass the same validation every replica applies. If the
 * board ever shrinks, rewrites a block it has seen, or presents a head that
 * does not extend its own, the witness raises an alarm and STOPS signing. The
 * alarm is sticky by design: deciding that a fork was benign is a human
 * judgement, not something a process should talk itself into.
 *
 * WHAT IT DOES NOT PROVE.
 *
 * That the board is CORRECT. Validators and the recount establish that. A
 * witness establishes that the board is ONE board: that every voter who asks
 * enough witnesses is looking at the same history.
 * ===========================================================================
 */

import { fromBase64Url, toBase64Url } from "@dvoting/crypto";
import {
  Ledger,
  blockFromWire,
  blockHash,
  createValidatorSet,
  signCheckpoint,
  verifyChain,
  type Block,
  type BlockStore,
  type CryptoKeyLike,
  type SignedCheckpoint,
  type ValidatorSet,
} from "@dvoting/ledger";

const CONFIG_KIND = "election-config";

export interface WitnessConfig {
  readonly id: string;
  readonly privateKey: CryptoKeyLike;
  readonly electionId: string;
  readonly ballotBoxUrl: string;
  /** This witness's own replica. Must be durable in production. */
  readonly store: BlockStore;
  /**
   * The election's genesis hash, if the operator obtained it out of band.
   * Without it the witness trusts the first block 0 it sees.
   */
  readonly genesisPin?: Uint8Array;
  readonly fetchImpl?: typeof fetch;
  readonly now?: () => Date;
}

export type WitnessState = "waiting" | "ok" | "alarm";

export interface WitnessStatus {
  readonly id: string;
  readonly electionId: string;
  readonly state: WitnessState;
  readonly height: number;
  readonly genesisHash: string | null;
  readonly headHash: string | null;
  readonly alarm: string | null;
  readonly lastSyncAt: string | null;
}

export class Witness {
  readonly #config: WitnessConfig;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  #ledger: Ledger | null = null;
  #genesisHash: Uint8Array | null = null;
  #latest: SignedCheckpoint | null = null;
  #alarm: string | null = null;
  #lastSyncAt: string | null = null;
  #syncing: Promise<void> | null = null;

  private constructor(config: WitnessConfig) {
    this.#config = config;
    this.#fetch = config.fetchImpl ?? fetch;
    this.#now = config.now ?? (() => new Date());
  }

  /**
   * Open a witness over its replica. A replica that already holds blocks is
   * re-verified from genesis before anything is signed, so a witness that
   * restarts on a tampered file cannot vouch for it.
   */
  static async open(config: WitnessConfig): Promise<Witness> {
    const witness = new Witness(config);
    const blocks = await config.store.all();
    if (blocks.length > 0) {
      const genesis = blocks[0]!;
      const set = validatorSetFrom(genesis);
      const report = await verifyChain(blocks, set, { expectedElectionId: config.electionId });
      if (!report.valid) {
        throw new Error(`refusing to start: this witness's replica fails verification: ${report.errors.slice(0, 3).join("; ")}`);
      }
      const hash = await blockHash(genesis.header);
      if (config.genesisPin && toBase64Url(hash) !== toBase64Url(config.genesisPin)) {
        throw new Error("refusing to start: the replica's block 0 differs from the configured genesis pin");
      }
      witness.#ledger = new Ledger(config.store, set, config.electionId);
      witness.#genesisHash = hash;
    }
    return witness;
  }

  get id(): string {
    return this.#config.id;
  }

  get latest(): SignedCheckpoint | null {
    return this.#latest;
  }

  async status(): Promise<WitnessStatus> {
    const head = await this.#config.store.head();
    return {
      id: this.#config.id,
      electionId: this.#config.electionId,
      state: this.#alarm ? "alarm" : head ? "ok" : "waiting",
      height: await this.#config.store.height(),
      genesisHash: this.#genesisHash ? toBase64Url(this.#genesisHash) : null,
      headHash: head ? toBase64Url(await blockHash(head.header)) : null,
      alarm: this.#alarm,
      lastSyncAt: this.#lastSyncAt,
    };
  }

  /** Pull new blocks from the board, check them, and sign a fresh checkpoint. */
  sync(): Promise<void> {
    // One sync at a time: two concurrent syncs would race to append.
    this.#syncing ??= this.#sync().finally(() => {
      this.#syncing = null;
    });
    return this.#syncing;
  }

  async #sync(): Promise<void> {
    if (this.#alarm) return; // sticky: a human decides what a fork means

    const remote = (await this.#getJson("/v1/bulletin/head")) as {
      height: number;
      head: { hash: string } | null;
    };
    const store = this.#config.store;
    const local = await store.height();

    if (remote.height < local) {
      return this.#raise(`the board shrank: this witness holds ${local} blocks, the board now shows ${remote.height}`);
    }
    if (remote.height === local && local > 0) {
      const ours = toBase64Url(await blockHash((await store.head())!.header));
      if (remote.head?.hash !== ours) {
        return this.#raise(`fork at height ${local - 1}: the board's head is not the block this witness holds`);
      }
    }

    for (let height = local; height < remote.height; height++) {
      let block: Block;
      try {
        block = blockFromWire(await this.#getJson(`/v1/bulletin/blocks/${height}`));
      } catch (error) {
        return this.#raise(`block ${height} is malformed: ${message(error)}`);
      }

      if (height === 0) {
        const verdict = await this.#adoptGenesis(block);
        if (verdict) return this.#raise(verdict);
        continue;
      }
      try {
        await this.#ledger!.append(block);
      } catch (error) {
        // Either history was rewritten under us (the block does not link to
        // our head) or the block is invalid. Neither may be vouched for.
        return this.#raise(`block ${height} does not extend the board this witness saw: ${message(error)}`);
      }
    }

    this.#lastSyncAt = this.#now().toISOString();
    const head = await store.head();
    if (!head || !this.#genesisHash) return;
    this.#latest = await signCheckpoint(
      {
        electionId: this.#config.electionId,
        height: await store.height(),
        headHash: await blockHash(head.header),
        genesisHash: this.#genesisHash,
        witnessedAt: this.#lastSyncAt,
      },
      this.#config.id,
      this.#config.privateKey,
    );
  }

  /** Accept block 0, which defines the validators every later block is checked against. */
  async #adoptGenesis(block: Block): Promise<string | null> {
    if (block.header.electionId !== this.#config.electionId) {
      return `block 0 is for election "${block.header.electionId}", not "${this.#config.electionId}"`;
    }
    const hash = await blockHash(block.header);
    if (this.#config.genesisPin && toBase64Url(hash) !== toBase64Url(this.#config.genesisPin)) {
      return "block 0 is not the election this witness was told to watch (genesis hash differs from the pin)";
    }
    let ledger: Ledger;
    try {
      ledger = new Ledger(this.#config.store, validatorSetFrom(block), this.#config.electionId);
      await ledger.append(block);
    } catch (error) {
      return `block 0 does not verify: ${message(error)}`;
    }
    this.#ledger = ledger;
    this.#genesisHash = hash;
    return null;
  }

  #raise(reason: string): void {
    this.#alarm = reason;
    console.error(`[witness ${this.#config.id}] ALARM: ${reason}. No further checkpoints will be signed.`);
  }

  async #getJson(path: string): Promise<unknown> {
    const response = await this.#fetch(`${this.#config.ballotBoxUrl}${path}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok) throw new Error(`${path} returned HTTP ${response.status}`);
    return response.json();
  }
}

/** The validator set block 0 seals; every later block is checked against it. */
function validatorSetFrom(genesis: Block): ValidatorSet {
  const entry = genesis.entries.find((e) => e.kind === CONFIG_KIND);
  if (!entry) throw new Error("block 0 carries no election configuration");
  const record = JSON.parse(new TextDecoder().decode(entry.data)) as {
    validators: { id: string; publicKey: string }[];
    quorum: number;
  };
  return createValidatorSet(
    record.validators.map((v) => ({ id: v.id, publicKey: fromBase64Url(v.publicKey) })),
    record.quorum,
  );
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
