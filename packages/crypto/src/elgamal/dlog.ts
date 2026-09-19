/**
 * Small discrete logarithm recovery, for turning a decrypted tally g^m back
 * into the number m.
 *
 * Exponential ElGamal decrypts to g^m rather than m, so the final step of the
 * count is a discrete log. That is only tractable because m is a vote count:
 * bounded by the size of the electorate, not by the size of the group. Solving
 * a DL over the full 3072-bit group would be infeasible -- which is exactly why
 * the scheme is secure for everything except this deliberately small range.
 *
 * Baby-step giant-step runs in O(sqrt(max)) time and space: one million voters
 * costs about 1000 table entries and 1000 multiplications.
 */

import { groupExp, groupInv, groupMul } from "./group.ts";
import type { PrimeOrderGroup } from "./group.ts";

export class DiscreteLogError extends Error {
  override name = "DiscreteLogError";
}

/**
 * Find m in [0, max] such that g^m == target, or throw.
 *
 * Throwing rather than returning null is deliberate: a tally that does not
 * decrypt to a plausible count means something is wrong (a corrupted ciphertext,
 * a wrong trustee set, a bug) and must never be silently reported as zero.
 */
export function discreteLogSmall(
  group: PrimeOrderGroup,
  target: bigint,
  max: number,
): number {
  if (max < 0) throw new DiscreteLogError("discreteLogSmall: max must be non-negative");
  if (target === 1n) return 0;

  const tableSize = Math.max(1, Math.ceil(Math.sqrt(max + 1)));

  // Baby steps: table of g^j for j in [0, tableSize).
  const table = new Map<bigint, number>();
  let value = 1n;
  for (let j = 0; j < tableSize; j++) {
    if (!table.has(value)) table.set(value, j);
    value = groupMul(group, value, group.g);
  }

  // Giant steps: target * (g^-tableSize)^i, looking for a baby step each time.
  const giantStride = groupInv(group, groupExp(group, group.g, BigInt(tableSize)));
  let current = target;
  const giantSteps = Math.floor(max / tableSize) + 1;

  for (let i = 0; i <= giantSteps; i++) {
    const j = table.get(current);
    if (j !== undefined) {
      const candidate = i * tableSize + j;
      if (candidate <= max) return candidate;
    }
    current = groupMul(group, current, giantStride);
  }

  throw new DiscreteLogError(
    `discreteLogSmall: no exponent in [0, ${max}] produces this value -- ` +
      "the tally is corrupt or the trustee set is wrong",
  );
}

/**
 * Precomputed table for repeatedly solving DLs over the same bound.
 *
 * An election decrypts one tally per candidate, so building the baby-step table
 * once and reusing it across candidates is worth it.
 */
export function createDiscreteLogTable(group: PrimeOrderGroup, max: number) {
  const tableSize = Math.max(1, Math.ceil(Math.sqrt(max + 1)));
  const table = new Map<bigint, number>();
  let value = 1n;
  for (let j = 0; j < tableSize; j++) {
    if (!table.has(value)) table.set(value, j);
    value = groupMul(group, value, group.g);
  }
  const giantStride = groupInv(group, groupExp(group, group.g, BigInt(tableSize)));

  return {
    max,
    solve(target: bigint): number {
      if (target === 1n) return 0;
      let current = target;
      const giantSteps = Math.floor(max / tableSize) + 1;
      for (let i = 0; i <= giantSteps; i++) {
        const j = table.get(current);
        if (j !== undefined) {
          const candidate = i * tableSize + j;
          if (candidate <= max) return candidate;
        }
        current = groupMul(group, current, giantStride);
      }
      throw new DiscreteLogError(
        `discreteLog: no exponent in [0, ${max}] produces this value -- tally is corrupt`,
      );
    },
  };
}
