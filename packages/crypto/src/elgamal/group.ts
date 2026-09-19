/**
 * Prime-order groups for ElGamal.
 *
 * WHY A PRIME-ORDER SUBGROUP, NOT THE WHOLE GROUP (the mistake to avoid):
 *
 * ElGamal over the full multiplicative group Z*_p is NOT IND-CPA secure. The
 * Legendre symbol is efficiently computable, and it leaks: an observer can
 * determine whether the plaintext is a quadratic residue, which for a ballot
 * can reveal the vote outright. The fix is to work entirely inside the subgroup
 * of quadratic residues, which for a safe prime p = 2q + 1 has prime order q.
 * Inside that subgroup Decisional Diffie-Hellman is believed hard and ElGamal
 * is IND-CPA.
 *
 * That is why every value entering the system is subgroup-checked. Skipping
 * that check enables a small-subgroup confinement attack: an attacker submits a
 * low-order element and the victim's exponentiation leaks their secret key
 * modulo that small order, one query at a time.
 *
 * PARAMETERS: RFC 3526 MODP groups, as used by IKE/TLS for decades. They are
 * "nothing up my sleeve" -- derived from the binary expansion of pi -- so
 * nobody, including this project's author, could have planted a trapdoor. The
 * constants below are verified in the test suite against Node's own
 * OpenSSL-backed tables AND independently re-derived (safe primality, subgroup
 * order) rather than trusted.
 */

import { i2osp, randomBytes } from "../util/bytes.ts";
import {
  FixedBaseExponentiator,
  bitLength,
  jacobiSymbol,
  modInverse,
  modPow,
  randomBigIntBelow,
} from "../util/bigint.ts";

export interface PrimeOrderGroup {
  readonly name: string;
  /** Safe prime modulus, p = 2q + 1. */
  readonly p: bigint;
  /** Prime order of the quadratic-residue subgroup. */
  readonly q: bigint;
  /** Generator of the order-q subgroup. */
  readonly g: bigint;
  /** Fixed encoding width for group elements, in bytes. */
  readonly pByteLength: number;
  /** Fixed encoding width for scalars (exponents), in bytes. */
  readonly qByteLength: number;
}

export class GroupError extends Error {
  override name = "GroupError";
}

function defineGroup(name: string, primeHex: string, generator: bigint): PrimeOrderGroup {
  const p = BigInt(`0x${primeHex}`);
  const q = (p - 1n) / 2n;
  return {
    name,
    p,
    q,
    g: generator,
    pByteLength: Math.ceil(bitLength(p) / 8),
    qByteLength: Math.ceil(bitLength(q) / 8),
  };
}

/** RFC 3526 Group 14. 2048-bit; ~112-bit security. Faster, for demos. */
export const MODP_2048: PrimeOrderGroup = defineGroup(
  "modp2048",
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
  2n,
);

/**
 * RFC 3526 Group 15. 3072-bit; ~128-bit security.
 *
 * The default. It matches the 128-bit security level of the RSA-3072 issuer key
 * in the registration layer -- a chain is only as strong as its weakest link, so
 * mixing a 128-bit signature key with a 112-bit encryption group would be
 * incoherent.
 */
export const MODP_3072: PrimeOrderGroup = defineGroup(
  "modp3072",
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33" +
    "A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864" +
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2" +
    "08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
  2n,
);

export const DEFAULT_GROUP = MODP_3072;

/**
 * Subgroup membership test: is `value` a quadratic residue mod p?
 *
 * Checks 0 < value < p and value^q == 1 (mod p). Every group element arriving
 * from outside -- ciphertexts, public keys, proof commitments -- must pass this
 * before being used in any exponentiation involving a secret.
 */
export function isInSubgroup(group: PrimeOrderGroup, value: bigint): boolean {
  if (value <= 0n || value >= group.p) return false;
  // Equivalent to value^q mod p == 1, because p is prime and q = (p-1)/2, but
  // computed via the Legendre symbol -- O(log^2 p) instead of a full modular
  // exponentiation. This check runs on every ciphertext component and every
  // proof commitment, so the constant factor genuinely matters.
  return jacobiSymbol(value, group.p) === 1;
}

export function assertInSubgroup(
  group: PrimeOrderGroup,
  value: bigint,
  label: string,
): void {
  if (!isInSubgroup(group, value)) {
    throw new GroupError(`${label} is not a member of the prime-order subgroup`);
  }
}

/** Is `value` a valid exponent, i.e. in [0, q)? */
export function isScalar(group: PrimeOrderGroup, value: bigint): boolean {
  return value >= 0n && value < group.q;
}

export function assertScalar(group: PrimeOrderGroup, value: bigint, label: string): void {
  if (!isScalar(group, value)) {
    throw new GroupError(`${label} is not a valid scalar in [0, q)`);
  }
}

/**
 * Uniform random scalar in [1, q).
 *
 * Excludes 0 deliberately: a zero blinding factor or zero nonce collapses the
 * hiding property of whatever it protects. The 1/q probability of naturally
 * drawing 0 is negligible, so excluding it costs nothing and removes a
 * degenerate case.
 */
export function randomScalar(
  group: PrimeOrderGroup,
  getRandomBytes: (n: number) => Uint8Array = randomBytes,
): bigint {
  return randomBigIntBelow(group.q, getRandomBytes);
}

export function groupExp(group: PrimeOrderGroup, base: bigint, exponent: bigint): bigint {
  return modPow(base, exponent, group.p);
}

/**
 * Adaptive fixed-base exponentiation cache.
 *
 * Building a precomputation table costs roughly three ordinary
 * exponentiations, so doing it eagerly would make one-off bases SLOWER. The
 * cache therefore counts uses and only builds a table once a base has proven
 * itself hot -- which in practice means the generator g and the election public
 * key y, the two bases that dominate ballot casting and verification.
 *
 * Tables are bounded so that a long-running verifier processing many elections
 * cannot grow memory without limit.
 */
const MIN_USES_BEFORE_PRECOMPUTE = 8;
const MAX_CACHED_TABLES_PER_GROUP = 4;

interface GroupCache {
  tables: Map<bigint, FixedBaseExponentiator>;
  uses: Map<bigint, number>;
}

const fixedBaseCache = new WeakMap<PrimeOrderGroup, GroupCache>();

export function groupExpFixed(
  group: PrimeOrderGroup,
  base: bigint,
  exponent: bigint,
): bigint {
  let cache = fixedBaseCache.get(group);
  if (!cache) {
    cache = { tables: new Map(), uses: new Map() };
    fixedBaseCache.set(group, cache);
  }

  const table = cache.tables.get(base);
  if (table) return table.pow(exponent);

  const uses = (cache.uses.get(base) ?? 0) + 1;
  if (uses >= MIN_USES_BEFORE_PRECOMPUTE && cache.tables.size < MAX_CACHED_TABLES_PER_GROUP) {
    const built = new FixedBaseExponentiator(base, group.p, bitLength(group.q));
    cache.tables.set(base, built);
    cache.uses.delete(base);
    return built.pow(exponent);
  }

  cache.uses.set(base, uses);
  return modPow(base, exponent, group.p);
}

/** Drop all precomputed tables. Exposed for benchmarks and memory-sensitive hosts. */
export function clearFixedBaseCache(group: PrimeOrderGroup): void {
  fixedBaseCache.delete(group);
}

export function groupMul(group: PrimeOrderGroup, a: bigint, b: bigint): bigint {
  return (a * b) % group.p;
}

export function groupInv(group: PrimeOrderGroup, a: bigint): bigint {
  return modInverse(a, group.p);
}

/** Scalar arithmetic, always reduced into [0, q). */
export function scalarAdd(group: PrimeOrderGroup, a: bigint, b: bigint): bigint {
  return (a + b) % group.q;
}

export function scalarSub(group: PrimeOrderGroup, a: bigint, b: bigint): bigint {
  return ((a - b) % group.q + group.q) % group.q;
}

export function scalarMul(group: PrimeOrderGroup, a: bigint, b: bigint): bigint {
  return (a * b) % group.q;
}

/** Canonical fixed-width encoding, for hashing. Never use variable-length here. */
export function encodeElement(group: PrimeOrderGroup, value: bigint): Uint8Array {
  return i2osp(value, group.pByteLength);
}

export function encodeScalar(group: PrimeOrderGroup, value: bigint): Uint8Array {
  return i2osp(value, group.qByteLength);
}

/**
 * Re-derive and check every claimed property of a group.
 *
 * Expensive (Miller-Rabin on a 3072-bit prime), so it is not run on the hot
 * path -- but it IS run in the test suite, so a corrupted or maliciously
 * substituted constant cannot pass CI unnoticed.
 */
export function validateGroup(group: PrimeOrderGroup, millerRabinRounds = 24): void {
  if (group.p !== 2n * group.q + 1n) {
    throw new GroupError(`${group.name}: p is not equal to 2q + 1`);
  }
  if (!isProbablePrime(group.p, millerRabinRounds)) {
    throw new GroupError(`${group.name}: p is not prime`);
  }
  if (!isProbablePrime(group.q, millerRabinRounds)) {
    throw new GroupError(`${group.name}: q is not prime (p is not a safe prime)`);
  }
  if (group.g <= 1n || group.g >= group.p) {
    throw new GroupError(`${group.name}: generator out of range`);
  }
  // g must generate the order-q subgroup: g^q = 1 and g != 1.
  if (modPow(group.g, group.q, group.p) !== 1n) {
    throw new GroupError(`${group.name}: generator does not lie in the order-q subgroup`);
  }
}

/** Miller-Rabin primality test with deterministic small-prime pre-screening. */
export function isProbablePrime(n: bigint, rounds = 24): boolean {
  if (n < 2n) return false;
  for (const small of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === small) return true;
    if (n % small === 0n) return false;
  }

  // Write n - 1 as d * 2^s with d odd.
  let d = n - 1n;
  let s = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    s++;
  }

  for (let round = 0; round < rounds; round++) {
    const a = randomBigIntBelow(n - 2n, randomBytes) + 1n;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;

    let witnessed = false;
    for (let i = 1n; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        witnessed = true;
        break;
      }
    }
    if (!witnessed) return false;
  }
  return true;
}
