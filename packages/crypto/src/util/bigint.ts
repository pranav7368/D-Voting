/**
 * Modular arithmetic over native BigInt.
 *
 * SECURITY NOTE (state this in the viva -- it is a real limitation, not a bug):
 * JavaScript's BigInt is *not* constant-time. Its operations branch and allocate
 * based on operand magnitude, so any secret-dependent computation here is
 * theoretically vulnerable to timing/microarchitectural side channels. For
 * D-Voting this is an accepted risk in two different postures:
 *
 *   - Client side (blinding): the secret is the blinding factor r, used once and
 *     discarded, on the voter's own device. There is no remote timing oracle.
 *   - Server side (issuing): the secret is the long-lived issuer key d. This is
 *     the one that matters. The production posture is to move the private-key
 *     operation into AWS KMS / an HSM, which is exactly why `BlindSigner` is an
 *     interface with a swappable implementation (see blind-rsa/issuer.ts).
 */

export function bitLength(value: bigint): number {
  if (value < 0n) throw new RangeError("bitLength: value must be non-negative");
  if (value === 0n) return 0;
  const hex = value.toString(16);
  // Every hex digit after the first contributes exactly 4 bits; the leading
  // digit contributes only as many bits as it actually uses (1..4).
  const leadingDigit = Number.parseInt(hex[0]!, 16);
  let leadingBits = 0;
  for (let d = leadingDigit; d > 0; d >>= 1) leadingBits++;
  return (hex.length - 1) * 4 + leadingBits;
}

/** Number of bytes needed to hold `value`'s modulus, i.e. ceil(bitLength / 8). */
export function byteLength(value: bigint): number {
  return Math.ceil(bitLength(value) / 8);
}

/** Least non-negative residue. JS `%` keeps the sign of the dividend; we don't want that. */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/**
 * Modular exponentiation by left-to-right sliding window.
 *
 * The textbook square-and-multiply does one multiply per set bit -- about n/2
 * for an n-bit exponent. A sliding window of w bits processes w bits per
 * multiply by pre-computing the odd powers b^1, b^3, ... b^(2^w - 1), cutting
 * multiplies to roughly n/(w+1). At w=5 that is a ~25% reduction in total work
 * across the whole system, since every protocol here is exponentiation-bound.
 *
 * Only ODD powers are tabulated: any window can be normalised to end in a 1 bit
 * by shifting, so the even entries would never be used.
 */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new RangeError("modPow: modulus must be positive");
  if (exponent < 0n) throw new RangeError("modPow: negative exponent requires an inverse");
  if (modulus === 1n) return 0n;
  if (exponent === 0n) return 1n;

  const b = mod(base, modulus);
  if (b === 0n) return 0n;

  // Read the exponent's bits from a string once. Indexing bits out of a BigInt
  // with shifts would cost O(n) per access and make the whole routine O(n^2).
  const bits = exponent.toString(2);
  const bitCount = bits.length;

  // Small exponents (e.g. the RSA public exponent 65537) are not worth a table.
  if (bitCount <= 8) {
    let result = 1n;
    for (const bit of bits) {
      result = (result * result) % modulus;
      if (bit === "1") result = (result * b) % modulus;
    }
    return result;
  }

  const windowBits = bitCount >= 512 ? 5 : bitCount >= 128 ? 4 : 3;
  const tableSize = 1 << (windowBits - 1);

  // odd[i] = b^(2i + 1)
  const odd = new Array<bigint>(tableSize);
  odd[0] = b;
  const bSquared = (b * b) % modulus;
  for (let i = 1; i < tableSize; i++) {
    odd[i] = (odd[i - 1]! * bSquared) % modulus;
  }

  let result = 1n;
  let i = 0;
  while (i < bitCount) {
    if (bits[i] === "0") {
      result = (result * result) % modulus;
      i++;
      continue;
    }

    // Take the longest window (<= windowBits) that ends on a set bit.
    let end = Math.min(i + windowBits, bitCount) - 1;
    while (bits[end] === "0") end--;

    const length = end - i + 1;
    for (let k = 0; k < length; k++) result = (result * result) % modulus;

    const value = Number.parseInt(bits.slice(i, end + 1), 2);
    result = (result * odd[(value - 1) >> 1]!) % modulus;
    i = end + 1;
  }
  return result;
}

/**
 * Precomputed table for repeated exponentiation of a FIXED base.
 *
 * When the base is known in advance -- and in this system the generator g and
 * the election public key y account for roughly half of all exponentiations --
 * the squarings can be precomputed away entirely. With a 4-bit window the
 * exponent is read as hex digits and each digit costs a single multiply:
 * about 768 multiplies for a 3072-bit exponent, versus ~4600 operations for the
 * generic path. Roughly a 6x speedup on those calls.
 *
 * The table costs ~9000 multiplies to build, so it only pays off after a few
 * uses -- callers should build it via the adaptive cache in group.ts rather
 * than eagerly.
 */
export class FixedBaseExponentiator {
  readonly #modulus: bigint;
  /** #table[block][digit - 1] = base^(digit * 16^block) */
  readonly #table: bigint[][];

  constructor(base: bigint, modulus: bigint, maxExponentBits: number) {
    if (modulus <= 0n) throw new RangeError("FixedBaseExponentiator: modulus must be positive");
    this.#modulus = modulus;

    const blocks = Math.ceil(maxExponentBits / 4);
    this.#table = new Array<bigint[]>(blocks);

    let blockBase = mod(base, modulus);
    for (let block = 0; block < blocks; block++) {
      const row = new Array<bigint>(15);
      row[0] = blockBase;
      for (let digit = 1; digit < 15; digit++) {
        row[digit] = (row[digit - 1]! * blockBase) % modulus;
      }
      this.#table[block] = row;

      // Next block's base is this one raised to the 16th power.
      let next = blockBase;
      for (let k = 0; k < 4; k++) next = (next * next) % modulus;
      blockBase = next;
    }
  }

  get blocks(): number {
    return this.#table.length;
  }

  pow(exponent: bigint): bigint {
    if (exponent < 0n) throw new RangeError("FixedBaseExponentiator: negative exponent");
    if (exponent === 0n) return 1n;

    const hex = exponent.toString(16);
    if (hex.length > this.#table.length) {
      throw new RangeError("FixedBaseExponentiator: exponent exceeds the precomputed range");
    }

    let result = 1n;
    for (let k = 0; k < hex.length; k++) {
      // Hex is big-endian; block k counts from the least significant digit.
      const digit = Number.parseInt(hex[hex.length - 1 - k]!, 16);
      if (digit !== 0) {
        result = (result * this.#table[k]![digit - 1]!) % this.#modulus;
      }
    }
    return result;
  }
}

/**
 * Jacobi symbol (a/n) for odd n > 0, by quadratic reciprocity.
 *
 * For PRIME n this equals the Legendre symbol, which is +1 exactly when a is a
 * quadratic residue mod n. That gives a subgroup-membership test costing
 * O(log^2 n) bit operations instead of the full modular exponentiation
 * a^((n-1)/2) mod n -- and subgroup checks run on every ciphertext and every
 * proof commitment, so this is the difference between an audit that takes
 * seconds and one that takes minutes.
 */
export function jacobiSymbol(a: bigint, n: bigint): number {
  if (n <= 0n || n % 2n === 0n) {
    throw new RangeError("jacobiSymbol: n must be a positive odd integer");
  }

  let x = mod(a, n);
  let y = n;
  let result = 1;

  while (x !== 0n) {
    // Pull out factors of 2. (2/y) is -1 when y = 3 or 5 (mod 8).
    while (x % 2n === 0n) {
      x /= 2n;
      const yMod8 = y % 8n;
      if (yMod8 === 3n || yMod8 === 5n) result = -result;
    }

    // Quadratic reciprocity: flip, negating when both are 3 (mod 4).
    [x, y] = [y, x];
    if (x % 4n === 3n && y % 4n === 3n) result = -result;

    x = mod(x, y);
  }

  return y === 1n ? result : 0;
}

/**
 * Extended Euclidean algorithm. Returns [gcd, x, y] with a*x + b*y = gcd.
 */
export function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  let [oldR, r] = [a, b];
  let [oldS, s] = [1n, 0n];
  let [oldT, t] = [0n, 1n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return [oldR, oldS, oldT];
}

/** Modular inverse. Throws if `a` is not invertible mod `m` (i.e. gcd != 1). */
export function modInverse(a: bigint, m: bigint): bigint {
  const [g, x] = egcd(mod(a, m), m);
  if (g !== 1n) throw new RangeError("modInverse: value is not invertible modulo m");
  return mod(x, m);
}

/**
 * Uniform random bigint in [1, upper). Rejection sampling -- no modulo bias.
 *
 * Naively doing `randomBigInt() % upper` skews the distribution toward small
 * values, which for a blinding factor would leak information about r and
 * therefore weaken unlinkability. Rejection sampling costs an occasional retry
 * and buys an exactly uniform distribution.
 */
export function randomBigIntBelow(
  upper: bigint,
  getRandomBytes: (n: number) => Uint8Array,
): bigint {
  if (upper < 2n) throw new RangeError("randomBigIntBelow: upper bound must be >= 2");
  const bits = bitLength(upper);
  const bytes = Math.ceil(bits / 8);
  const excessBits = BigInt(bytes * 8 - bits);

  // Bound the loop so a broken RNG surfaces as an error instead of hanging.
  // With the excess-bit mask the rejection probability is < 1/2 per draw, so
  // 256 attempts failing is a hardware/entropy fault, not bad luck.
  for (let attempt = 0; attempt < 256; attempt++) {
    const raw = getRandomBytes(bytes);
    let candidate = 0n;
    for (const b of raw) candidate = (candidate << 8n) | BigInt(b);
    candidate >>= excessBits;
    if (candidate >= 1n && candidate < upper) return candidate;
  }
  throw new Error("randomBigIntBelow: failed to sample after 256 attempts (RNG fault?)");
}
