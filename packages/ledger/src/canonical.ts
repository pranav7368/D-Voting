/**
 * Deterministic binary encoding.
 *
 * WHY NOT JSON. Everything in this ledger is identified by its hash, so the
 * bytes that get hashed must be reproducible by every independent verifier,
 * forever. `JSON.stringify` is not a specification: key order follows insertion
 * order, number formatting is implementation-defined at the edges, and unicode
 * escaping varies. Two verifiers serialising the "same" block could therefore
 * compute two different hashes and disagree about whether the chain is valid.
 *
 * This encoder is fully specified instead: fixed-width big-endian integers,
 * every variable-length field preceded by its u32 length. Length prefixing also
 * removes concatenation ambiguity -- without it, the fields ("ab", "c") and
 * ("a", "bc") would encode identically, letting an attacker shift bytes between
 * fields to forge a colliding block.
 */

export class EncodingError extends Error {
  override name = "EncodingError";
}

export class Encoder {
  readonly #parts: Uint8Array[] = [];

  u8(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xff) {
      throw new EncodingError("u8: value out of range");
    }
    this.#parts.push(Uint8Array.of(value));
    return this;
  }

  u32(value: number): this {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new EncodingError("u32: value out of range");
    }
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    this.#parts.push(out);
    return this;
  }

  u64(value: number | bigint): this {
    const big = BigInt(value);
    if (big < 0n || big > 0xffffffffffffffffn) {
      throw new EncodingError("u64: value out of range");
    }
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, big, false);
    this.#parts.push(out);
    return this;
  }

  /** Length-prefixed byte string. */
  bytes(value: Uint8Array): this {
    this.u32(value.length);
    this.#parts.push(value);
    return this;
  }

  /** Length-prefixed UTF-8 string. */
  string(value: string): this {
    return this.bytes(new TextEncoder().encode(value));
  }

  /** Raw bytes with no length prefix. Only for fixed-width fields. */
  fixed(value: Uint8Array, expectedLength: number): this {
    if (value.length !== expectedLength) {
      throw new EncodingError(
        `fixed: expected ${expectedLength} bytes, received ${value.length}`,
      );
    }
    this.#parts.push(value);
    return this;
  }

  finish(): Uint8Array {
    let total = 0;
    for (const part of this.#parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of this.#parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }
}

export function encode(build: (encoder: Encoder) => void): Uint8Array {
  const encoder = new Encoder();
  build(encoder);
  return encoder.finish();
}
