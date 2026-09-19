/**
 * Committing to the electoral roll.
 *
 * ===========================================================================
 * THE PROBLEM THIS SOLVES, AND THE ONE IT DOES NOT.
 *
 * The single most effective attack on any election is not breaking the
 * cryptography -- it is adding voters. A commission that can quietly insert a
 * thousand names produces a thousand ballots that are cryptographically
 * perfect, individually valid, and completely fraudulent. No amount of ballot
 * secrecy or threshold decryption touches that.
 *
 * The real-world defence is not technical either: the roll is PUBLISHED before
 * polling, and parties and citizens are given a window to object. What
 * cryptography can add is a way to make the published roll and the used roll
 * provably the same one.
 *
 * So before the poll opens, the roll is frozen and hashed, and that hash is
 * sealed into the election's configuration block on the chain. Afterwards:
 *
 *   - anyone holding the published roll can recompute this digest and confirm
 *     it is the roll the election actually ran on;
 *   - a name added after the freeze changes the digest, so the addition cannot
 *     be hidden -- it can only be done openly, which is the point.
 *
 * WHAT IS COMMITTED: the roll identifiers only, sorted and length-prefixed.
 * Deliberately NOT the enrolment-code hashes. A commitment that included
 * secrets could only be checked by the party holding them, which would make it
 * a commitment nobody outside the commission could verify -- and an unverifiable
 * commitment is decoration.
 *
 * WHAT THIS DOES NOT DO: it says nothing about whether the roll is CORRECT.
 * Committing to a roll full of invented names commits to fraud, faithfully.
 * That problem is answered by publication and objection, not by a hash.
 * ===========================================================================
 */

import { digest, toBase64Url, utf8 } from "@dvoting/crypto";

/**
 * Digest over a set of roll identifiers.
 *
 * Sorted so the result does not depend on insertion order, and length-prefixed
 * so that ["ab","c"] and ["a","bc"] cannot produce the same digest -- without
 * that, entries could be reshaped to collide.
 */
export async function rollCommitment(
  electionId: string,
  rollIds: readonly string[],
): Promise<string> {
  const sorted = [...rollIds].sort();

  const parts: Uint8Array[] = [
    utf8("dvoting/electoral-roll/v1"),
    utf8(`\n${electionId.length}:${electionId}\n`),
    utf8(`${sorted.length}\n`),
  ];
  for (const rollId of sorted) {
    parts.push(utf8(`${rollId.length}:${rollId}\n`));
  }

  let total = 0;
  for (const part of parts) total += part.length;
  const input = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    input.set(part, offset);
    offset += part.length;
  }

  return toBase64Url(await digest("SHA-256", input));
}
