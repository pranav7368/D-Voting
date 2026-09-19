/**
 * One trustee.
 *
 * ===========================================================================
 * WHY THIS IS A SEPARATE PROCESS.
 *
 * A 3-of-5 threshold means nothing if all five shares sit inside one service.
 * The guarantee is not "the code splits the key"; it is "no single machine can
 * decrypt", and that is only true when the shares are genuinely apart. So a
 * trustee is its own process holding exactly one share, driven by one operator
 * -- and in deployment, on hardware the election commission does not administer.
 *
 * WHAT IT WILL AND WILL NOT DECRYPT.
 *
 * A trustee contributes to decrypting the TOTALS, never a ballot. There is no
 * route here that accepts a ciphertext of the caller's choosing: this process
 * derives the totals itself, from the chain, and decrypts those. That
 * restriction is what stops a trustee -- or someone who has compromised one --
 * from being talked into decrypting a single voter's ballot.
 *
 * IT VERIFIES BEFORE IT SIGNS.
 *
 * Before applying its share it downloads the bulletin board, re-checks every
 * block against the validator quorum, re-derives the encrypted totals from the
 * ballots, and compares them to what the ballot box asked it to decrypt. A
 * trustee that decrypts whatever it is handed is a rubber stamp; the reason
 * there are several is that each one checks independently.
 *
 * KNOWN LIMITATION, stated plainly: this re-derivation checks the chain's
 * integrity and the homomorphic arithmetic. It does not re-run every ballot's
 * zero-knowledge proofs -- the validators did that on admission, and
 * `verifyPublishedTally` does it again over the published result, where any
 * observer can repeat it.
 * ===========================================================================
 */

import {
  addCiphertexts,
  encodeElement,
  encodeScalar,
  fromBase64Url,
  groupExp,
  os2ip,
  partialDecrypt,
  toBase64Url,
  type Ciphertext,
  type PrimeOrderGroup,
} from "@dvoting/crypto";
import {
  InMemoryBlockStore,
  Ledger,
  blockFromWire,
  createValidatorSet,
  type Block,
  type ValidatorIdentity,
} from "@dvoting/ledger";

export class TrusteeServiceError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
  override name = "TrusteeServiceError";
}

const BALLOT_ENTRY_KIND = "ballot";
const CONFIG_ENTRY_KIND = "election-config";

export interface WireCiphertext {
  readonly alpha: string;
  readonly beta: string;
}

export interface CeremonyView {
  readonly phase: "not-ready" | "awaiting-trustees" | "published";
  readonly threshold: number;
  readonly total: number;
  readonly submitted: readonly number[];
  readonly candidates: readonly string[];
  readonly ballotsCounted: number;
  readonly encryptedTotals: readonly WireCiphertext[];
  readonly message: string;
}

export interface TrusteeConfig {
  readonly electionId: string;
  readonly group: PrimeOrderGroup;
  readonly index: number;
  /** This trustee's private Shamir share. Never leaves this process. */
  readonly share: bigint;
  readonly ballotBoxUrl: string;
  readonly fetchImpl?: typeof fetch;
}

export interface ParticipationResult {
  readonly index: number;
  readonly candidates: number;
  readonly submitted: readonly number[];
  readonly outstanding: number;
  readonly published: boolean;
  readonly ballotsCounted: number;
  /** What this trustee checked for itself before applying its share. */
  readonly verified: readonly string[];
}

export class Trustee {
  readonly #config: TrusteeConfig;
  readonly #fetch: typeof fetch;

  constructor(config: TrusteeConfig) {
    this.#config = config;
    this.#fetch = config.fetchImpl ?? fetch;
  }

  get index(): number {
    return this.#config.index;
  }

  /** g^{x_i} -- this trustee's public commitment, safe to publish anywhere. */
  get publicShare(): string {
    return toBase64Url(
      encodeElement(
        this.#config.group,
        groupExp(this.#config.group, this.#config.group.g, this.#config.share),
      ),
    );
  }

  async ceremony(): Promise<CeremonyView> {
    return this.#getJson<CeremonyView>("/v1/ceremony");
  }

  /**
   * Do this trustee's part: verify, decrypt, prove, submit.
   *
   * Everything before `partialDecrypt` is a check. The share is applied only
   * once this process is satisfied that the ciphertexts really are the totals
   * the chain implies.
   */
  async participate(): Promise<ParticipationResult> {
    const view = await this.ceremony();

    if (view.phase === "published") {
      throw new TrusteeServiceError("already_published", "The result is already published.");
    }
    if (view.phase !== "awaiting-trustees") {
      throw new TrusteeServiceError(
        "not_ready",
        "Voting has not closed yet, so there is nothing to decrypt.",
      );
    }
    if (view.submitted.includes(this.#config.index)) {
      throw new TrusteeServiceError(
        "already_submitted",
        `Trustee ${this.#config.index} has already contributed to this ceremony.`,
      );
    }
    if (view.encryptedTotals.length !== view.candidates.length) {
      throw new TrusteeServiceError(
        "malformed_ceremony",
        "The ballot box offered a different number of totals than candidates.",
      );
    }

    const offered = view.encryptedTotals.map((ct, index) => this.#decode(ct, `total ${index}`));
    const verified = await this.#verifyAgainstChain(offered, view);

    const partials = [];
    for (const total of offered) {
      const partial = await partialDecrypt(
        this.#config.group,
        this.#config.electionId,
        { index: this.#config.index, share: this.#config.share },
        total,
      );
      partials.push({
        index: partial.index,
        factor: toBase64Url(encodeElement(this.#config.group, partial.factor)),
        proof: {
          commitment1: toBase64Url(encodeElement(this.#config.group, partial.proof.commitment1)),
          commitment2: toBase64Url(encodeElement(this.#config.group, partial.proof.commitment2)),
          challenge: toBase64Url(encodeScalar(this.#config.group, partial.proof.challenge)),
          response: toBase64Url(encodeScalar(this.#config.group, partial.proof.response)),
        },
      });
    }

    const response = await this.#fetch(`${this.#config.ballotBoxUrl}/v1/ceremony/shares`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ index: this.#config.index, partials }),
      signal: AbortSignal.timeout(120_000),
    });

    const body = (await response.json()) as Record<string, unknown>;
    if (!response.ok) {
      throw new TrusteeServiceError(
        String(body.error ?? "submission_rejected"),
        String(body.message ?? `The ballot box rejected the submission (${response.status}).`),
      );
    }

    return {
      index: this.#config.index,
      candidates: offered.length,
      submitted: (body.submitted as number[]) ?? [],
      outstanding: Number(body.outstanding ?? 0),
      published: body.published === true,
      ballotsCounted: view.ballotsCounted,
      verified,
    };
  }

  /**
   * Download the bulletin board and satisfy this trustee, independently, that
   * the totals it has been asked to decrypt are the right ones.
   *
   * Returns the list of checks that passed, so the operator sees what their
   * machine established rather than being told "ok".
   */
  async #verifyAgainstChain(
    offered: readonly Ciphertext[],
    view: CeremonyView,
  ): Promise<string[]> {
    const passed: string[] = [];

    const election = await this.#getJson<{
      electionId: string;
      validators: { id: string; publicKey: string }[];
      quorum: number;
    }>("/v1/election");

    if (election.electionId !== this.#config.electionId) {
      throw new TrusteeServiceError(
        "wrong_election",
        `This trustee holds a share for "${this.#config.electionId}" but the ballot box is serving "${election.electionId}".`,
      );
    }

    // Rebuild the chain locally. `Ledger.append` re-validates every block --
    // hash linkage, Merkle root, and a signature quorum -- so a forged or
    // altered block is rejected here, on this machine, using this trustee's own
    // copy of the validator set.
    const identities: ValidatorIdentity[] = election.validators.map((v) => ({
      id: v.id,
      publicKey: fromBase64Url(v.publicKey),
    }));
    const ledger = new Ledger(
      new InMemoryBlockStore(),
      createValidatorSet(identities, election.quorum),
      election.electionId,
    );

    const head = await this.#getJson<{ height: number }>("/v1/bulletin/head");
    const blocks: Block[] = [];
    for (let height = 0; height < head.height; height++) {
      const wire = await this.#getJson<unknown>(`/v1/bulletin/blocks/${height}`);
      let block: Block;
      try {
        block = blockFromWire(wire);
      } catch (error) {
        throw new TrusteeServiceError(
          "chain_invalid",
          `Block ${height} is malformed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      try {
        await ledger.append(block);
      } catch (error) {
        throw new TrusteeServiceError(
          "chain_invalid",
          `Block ${height} does not verify: ${error instanceof Error ? error.message : String(error)}. Refusing to decrypt.`,
        );
      }
      blocks.push(block);
    }
    passed.push(`Re-verified ${head.height} blocks against a ${election.quorum}-signature quorum`);

    // The election's own definition, as sealed before voting opened.
    const config = this.#readConfig(blocks);
    if (config.candidates.length !== view.candidates.length) {
      throw new TrusteeServiceError(
        "config_mismatch",
        "The candidate list offered for decryption is not the one sealed on the chain.",
      );
    }
    for (const [index, candidate] of config.candidates.entries()) {
      if (candidate !== view.candidates[index]) {
        throw new TrusteeServiceError(
          "config_mismatch",
          `Candidate ${index} is "${view.candidates[index]}" but the chain sealed "${candidate}".`,
        );
      }
    }
    const mine = config.trustees.publicShares.find((s) => s.index === this.#config.index);
    if (!mine) {
      throw new TrusteeServiceError(
        "not_a_trustee",
        `Trustee ${this.#config.index} is not in the roster sealed on the chain.`,
      );
    }
    if (mine.publicShare !== this.publicShare) {
      // The share this process holds is not the one this election committed to.
      throw new TrusteeServiceError(
        "share_mismatch",
        "The share held by this process does not match the public share sealed on the chain. Refusing to decrypt.",
      );
    }
    passed.push(`Confirmed this share matches trustee ${this.#config.index} in the sealed roster`);

    if (!blocks.some((block) => block.entries.some((e) => e.kind === "election-closed"))) {
      throw new TrusteeServiceError(
        "not_closed",
        "The chain carries no close record, so voting has not verifiably ended.",
      );
    }
    passed.push("Confirmed voting is closed on the chain");

    // Re-derive the totals: last ballot per credential, summed homomorphically.
    const latest = new Map<string, Ciphertext[]>();
    for (const block of blocks) {
      for (const entry of block.entries) {
        if (entry.kind !== BALLOT_ENTRY_KIND) continue;
        const ballot = JSON.parse(new TextDecoder().decode(entry.data)) as {
          credentialFingerprint?: string;
          choices?: WireCiphertext[];
        };
        if (typeof ballot.credentialFingerprint !== "string" || !Array.isArray(ballot.choices)) {
          throw new TrusteeServiceError("chain_invalid", `Ballot "${entry.id}" is malformed.`);
        }
        latest.set(
          ballot.credentialFingerprint,
          ballot.choices.map((ct, index) => this.#decode(ct, `${entry.id} choice ${index}`)),
        );
      }
    }

    if (latest.size !== view.ballotsCounted) {
      throw new TrusteeServiceError(
        "totals_mismatch",
        `The ballot box says ${view.ballotsCounted} ballots counted; the chain yields ${latest.size}.`,
      );
    }

    for (const [candidate, total] of offered.entries()) {
      const column: Ciphertext[] = [];
      for (const choices of latest.values()) {
        const ct = choices[candidate];
        if (!ct) {
          throw new TrusteeServiceError(
            "chain_invalid",
            `A counted ballot has no ciphertext for candidate ${candidate}.`,
          );
        }
        column.push(ct);
      }
      const recomputed = addCiphertexts(this.#config.group, column);
      if (recomputed.alpha !== total.alpha || recomputed.beta !== total.beta) {
        throw new TrusteeServiceError(
          "totals_mismatch",
          `The total offered for "${view.candidates[candidate]}" is not the sum of the ballots on the chain. Refusing to decrypt.`,
        );
      }
    }
    passed.push(
      `Recomputed all ${offered.length} encrypted totals from ${latest.size} counted ballots`,
    );

    return passed;
  }

  #readConfig(blocks: readonly Block[]): {
    candidates: string[];
    trustees: { publicShares: { index: number; publicShare: string }[] };
  } {
    for (const block of blocks) {
      for (const entry of block.entries) {
        if (entry.kind !== CONFIG_ENTRY_KIND) continue;
        return JSON.parse(new TextDecoder().decode(entry.data)) as {
          candidates: string[];
          trustees: { publicShares: { index: number; publicShare: string }[] };
        };
      }
    }
    throw new TrusteeServiceError(
      "no_config",
      "The chain carries no sealed election configuration. Refusing to decrypt.",
    );
  }

  #decode(ct: WireCiphertext, label: string): Ciphertext {
    try {
      return { alpha: os2ip(fromBase64Url(ct.alpha)), beta: os2ip(fromBase64Url(ct.beta)) };
    } catch {
      throw new TrusteeServiceError("malformed_ceremony", `${label} is not a decodable ciphertext.`);
    }
  }

  async #getJson<T>(path: string): Promise<T> {
    const response = await this.#fetch(`${this.#config.ballotBoxUrl}${path}`, {
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) {
      throw new TrusteeServiceError(
        "ballot_box_unreachable",
        `The ballot box returned ${response.status} for ${path}.`,
      );
    }
    return (await response.json()) as T;
  }
}
