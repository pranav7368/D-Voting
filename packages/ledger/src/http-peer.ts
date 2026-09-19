/**
 * HTTP transport for validator peers.
 *
 * ===========================================================================
 * WHY `propose` IS AUTHENTICATED AND `attest` IS NOT.
 *
 * These endpoints have genuinely different risk profiles, and it is worth being
 * able to explain why.
 *
 * `attest` is safe to leave open. A node only signs a block that is
 * structurally valid AND already signed by the scheduled proposer, so an
 * attacker cannot fabricate something new to get attested — at worst they replay
 * a block the proposer really did produce, and the response is identical to the
 * legitimate one. Signing a valid block harms nobody.
 *
 * `propose` is NOT safe to leave open, for a reason that is easy to miss.
 * Proposing makes the node sign a block AND record that height as attested. An
 * attacker who can call it therefore makes the validator commit to a block of
 * the attacker's choosing at height H — after which the node's own
 * anti-equivocation rule makes it refuse the LEGITIMATE block at that height.
 * The safety mechanism becomes a liveness attack. So `propose` requires a
 * bearer token shared with the block-assembly coordinator.
 *
 * `commit` is open: a block must already carry a valid quorum to be accepted,
 * which is exactly the property that makes it legitimate.
 * ===========================================================================
 *
 * TLS: this client speaks plain HTTP to the configured base URL. Validator
 * traffic crosses organisational boundaries and MUST run over TLS (ideally mTLS)
 * in deployment — terminate it at the proxy and point `baseUrl` at https://.
 */

import type { Block } from "./block.ts";
import { ValidatorNodeError, type AttestationResponse, type ProposeRequest, type ValidatorPeer } from "./node.ts";
import { blockFromWire, blockToWire, proposeRequestToWire } from "./wire.ts";

export interface HttpValidatorPeerOptions {
  readonly id: string;
  readonly baseUrl: string;
  /** Bearer token for `propose`. Required; see the note above. */
  readonly proposeToken?: string;
  readonly timeoutMs?: number;
  /** Injectable for tests. Defaults to global fetch. */
  readonly fetchImpl?: typeof fetch;
}

export class HttpValidatorPeer implements ValidatorPeer {
  readonly id: string;
  readonly #baseUrl: string;
  readonly #proposeToken: string | undefined;
  readonly #timeoutMs: number;
  readonly #fetch: typeof fetch;

  constructor(options: HttpValidatorPeerOptions) {
    this.id = options.id;
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#proposeToken = options.proposeToken;
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#fetch = options.fetchImpl ?? globalThis.fetch;
  }

  async propose(request: ProposeRequest): Promise<Block> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.#proposeToken) headers.Authorization = `Bearer ${this.#proposeToken}`;

    const response = await this.#post("/v1/propose", proposeRequestToWire(request), headers);
    if (!response.ok) {
      throw new ValidatorNodeError(
        `${this.id} refused to propose (HTTP ${response.status}): ${await safeText(response)}`,
      );
    }
    const body = (await response.json()) as { block: unknown };
    return blockFromWire(body.block);
  }

  async requestAttestation(block: Block): Promise<AttestationResponse> {
    const response = await this.#post("/v1/attest", { block: blockToWire(block) });

    if (response.status === 409) {
      // The node validated and declined — a normal protocol outcome, not an error.
      const body = (await response.json()) as { reason?: string; behindAt?: number };
      return {
        refused: true,
        validator: this.id,
        reason: body.reason ?? "refused",
        // Preserved so the sealer can replay missing blocks instead of writing
        // this validator off.
        ...(typeof body.behindAt === "number" ? { behindAt: body.behindAt } : {}),
      };
    }
    if (!response.ok) {
      throw new ValidatorNodeError(
        `${this.id} attestation failed (HTTP ${response.status}): ${await safeText(response)}`,
      );
    }

    const body = (await response.json()) as {
      attestation?: { validator: string; signature: string };
    };
    if (!body.attestation) {
      throw new ValidatorNodeError(`${this.id} returned no attestation`);
    }

    const { fromBase64Url } = await import("@dvoting/crypto");
    return {
      refused: false,
      attestation: {
        validator: body.attestation.validator,
        signature: fromBase64Url(body.attestation.signature),
      },
    };
  }

  async commit(block: Block): Promise<void> {
    const response = await this.#post("/v1/commit", { block: blockToWire(block) });
    if (!response.ok) {
      throw new ValidatorNodeError(
        `${this.id} rejected commit (HTTP ${response.status}): ${await safeText(response)}`,
      );
    }
  }

  async height(): Promise<number> {
    return (await this.status()).height;
  }

  async status(): Promise<{ validator: string; height: number }> {
    const response = await this.#fetch(`${this.#baseUrl}/v1/status`, {
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
    if (!response.ok) throw new ValidatorNodeError(`${this.id} status failed`);
    return (await response.json()) as { validator: string; height: number };
  }

  async #post(
    path: string,
    body: unknown,
    headers: Record<string, string> = { "Content-Type": "application/json" },
  ): Promise<Response> {
    return this.#fetch(`${this.#baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      // Bounded: a hung peer must not stall block production indefinitely. The
      // quorum rule already tolerates a slow minority.
      signal: AbortSignal.timeout(this.#timeoutMs),
    });
  }
}

async function safeText(response: Response): Promise<string> {
  try {
    return (await response.text()).slice(0, 200);
  } catch {
    return "<no body>";
  }
}
