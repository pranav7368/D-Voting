import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MODP_2048, groupExp, groupMul, scalarAdd } from "../src/elgamal/group.ts";
import { encrypt } from "../src/elgamal/cipher.ts";
import { discreteLogSmall } from "../src/elgamal/dlog.ts";
import {
  collectComplaints,
  computeJointPublicKey,
  computeKeyShare,
  computePublicShare,
  createDkgContribution,
  finalizeDkg,
  runDkg,
  verifyDkgShare,
  type DkgContribution,
} from "../src/threshold/dkg.ts";
import {
  combinePartialDecryptions,
  partialDecrypt,
  verifyPartialDecryption,
  type PartialDecryption,
} from "../src/threshold/trustee.ts";
import { reconstructSecret } from "../src/threshold/shamir.ts";

const GROUP = MODP_2048;
const ELECTION = "dkg-test";

describe("Pedersen DKG", () => {
  it("produces a working joint key with no dealer", async () => {
    const dkg = runDkg(GROUP, 3, 5);

    assert.equal(dkg.qualified.length, 5);
    assert.deepEqual(dkg.complaints, []);
    assert.equal(dkg.keyShares.length, 5);

    const { ciphertext } = encrypt(dkg.publicKey, 42n);
    const partials: PartialDecryption[] = [];
    for (const keyShare of dkg.keyShares.slice(0, 3)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext));
    }

    const element = combinePartialDecryptions(GROUP, ciphertext, partials, 3);
    assert.equal(discreteLogSmall(GROUP, element, 100), 42);
  });

  it("works with any qualifying subset of trustees", async () => {
    const dkg = runDkg(GROUP, 3, 5);
    const { ciphertext } = encrypt(dkg.publicKey, 17n);

    for (const subset of [[0, 1, 2], [1, 3, 4], [0, 2, 4]]) {
      const partials: PartialDecryption[] = [];
      for (const i of subset) {
        partials.push(await partialDecrypt(GROUP, ELECTION, dkg.keyShares[i]!, ciphertext));
      }
      const element = combinePartialDecryptions(GROUP, ciphertext, partials, 3);
      assert.equal(discreteLogSmall(GROUP, element, 100), 17, `subset ${subset} failed`);
    }
  });

  it("CANNOT decrypt below the threshold", async () => {
    const dkg = runDkg(GROUP, 3, 5);
    const { ciphertext } = encrypt(dkg.publicKey, 42n);

    const partials: PartialDecryption[] = [];
    for (const keyShare of dkg.keyShares.slice(0, 2)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext));
    }
    assert.throws(() => combinePartialDecryptions(GROUP, ciphertext, partials, 3), /threshold/);
  });

  it("NO participant ever holds the election private key", async () => {
    // The whole point of a DKG. Reconstructing from t shares gives x; but x is
    // the SUM of everyone's contributions, and no participant's own secret
    // equals it. There is no moment at which any single party knows x.
    const dkg = runDkg(GROUP, 3, 5);

    const x = reconstructSecret(
      GROUP,
      dkg.keyShares.slice(0, 3).map((s) => ({ index: s.index, value: s.share })),
    );
    // The reconstructed key is the real one...
    assert.equal(groupExp(GROUP, GROUP.g, x), dkg.publicKey.y);
    // ...and no individual share equals it.
    for (const keyShare of dkg.keyShares) {
      assert.notEqual(keyShare.share, x);
    }
  });

  it("derives every public share from broadcast data alone", async () => {
    // Anyone can compute g^{x_j} for every participant without trusting them --
    // which is what makes the partial-decryption proofs checkable at tally time.
    const dkg = runDkg(GROUP, 3, 5);
    for (const keyShare of dkg.keyShares) {
      const published = dkg.publicShares.find((p) => p.index === keyShare.index)!;
      assert.equal(published.publicShare, groupExp(GROUP, GROUP.g, keyShare.share));
    }
  });

  it("produces partial decryptions that verify against the derived public shares", async () => {
    const dkg = runDkg(GROUP, 2, 3);
    const { ciphertext } = encrypt(dkg.publicKey, 5n);

    for (const keyShare of dkg.keyShares) {
      const partial = await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext);
      const publicShare = dkg.publicShares.find((p) => p.index === keyShare.index)!;
      assert.ok(await verifyPartialDecryption(GROUP, ELECTION, publicShare, ciphertext, partial));
    }
  });

  it("the joint key is the product of every contribution", () => {
    const contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 2, 3));
    const dkg = finalizeDkg(GROUP, 2, contributions);

    let expected = 1n;
    for (const contribution of contributions) {
      expected = groupMul(GROUP, expected, contribution.commitments[0]!);
    }
    assert.equal(dkg.publicKey.y, expected);
  });

  it("gives a different key every run", () => {
    const a = runDkg(GROUP, 2, 3);
    const b = runDkg(GROUP, 2, 3);
    assert.notEqual(a.publicKey.y, b.publicKey.y);
  });
});

describe("share verification catches a cheating participant", () => {
  /** Participant 2 sends participant 3 a share inconsistent with its commitments. */
  function withCorruptedShare(
    contributions: DkgContribution[],
    from: number,
    to: number,
  ): DkgContribution[] {
    return contributions.map((contribution) => {
      if (contribution.index !== from) return contribution;
      const shares = new Map(contribution.shares);
      shares.set(to, scalarAdd(GROUP, shares.get(to)!, 1n));
      return { ...contribution, shares };
    });
  }

  it("verifyDkgShare accepts honest shares", () => {
    const contribution = createDkgContribution(GROUP, 1, 3, 5);
    for (const [recipient, share] of contribution.shares) {
      assert.ok(
        verifyDkgShare(GROUP, contribution, recipient, share),
        `honest share to ${recipient} rejected`,
      );
    }
  });

  it("verifyDkgShare rejects a tampered share", () => {
    const contribution = createDkgContribution(GROUP, 1, 3, 5);
    const share = contribution.shares.get(2)!;
    assert.ok(!verifyDkgShare(GROUP, contribution, 2, scalarAdd(GROUP, share, 1n)));
  });

  it("disqualifies a participant who sends an inconsistent share", () => {
    const contributions = [1, 2, 3, 4, 5].map((i) => createDkgContribution(GROUP, i, 3, 5));
    const corrupted = withCorruptedShare(contributions, 2, 3);

    const { qualified, complaints } = collectComplaints(GROUP, corrupted, 3);

    assert.ok(!qualified.includes(2), "cheating participant was not disqualified");
    assert.deepEqual(qualified, [1, 3, 4, 5]);
    assert.equal(complaints.length, 1);
    assert.equal(complaints[0]!.against, 2);
    assert.equal(complaints[0]!.by, 3);
  });

  it("still produces a working key from the qualified participants", async () => {
    // The ceremony survives a cheater: the remaining four carry on.
    const contributions = [1, 2, 3, 4, 5].map((i) => createDkgContribution(GROUP, i, 3, 5));
    const dkg = finalizeDkg(GROUP, 3, withCorruptedShare(contributions, 2, 3));

    assert.deepEqual(dkg.qualified, [1, 3, 4, 5]);
    assert.equal(dkg.keyShares.length, 4);

    const { ciphertext } = encrypt(dkg.publicKey, 8n);
    const partials: PartialDecryption[] = [];
    for (const keyShare of dkg.keyShares.slice(0, 3)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext));
    }
    const element = combinePartialDecryptions(GROUP, ciphertext, partials, 3);
    assert.equal(discreteLogSmall(GROUP, element, 100), 8);
  });

  it("excludes the cheater's contribution from the joint key", () => {
    const contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 2, 3));
    const dkg = finalizeDkg(GROUP, 2, withCorruptedShare(contributions, 2, 3));

    // Only participants 1 and 3 contribute to y.
    const expected = groupMul(
      GROUP,
      contributions[0]!.commitments[0]!,
      contributions[2]!.commitments[0]!,
    );
    assert.equal(dkg.publicKey.y, expected);
  });

  it("disqualifies a participant publishing the wrong number of commitments", () => {
    const contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 2, 3));
    const malformed = contributions.map((c) =>
      c.index === 2 ? { ...c, commitments: c.commitments.slice(0, 1) } : c,
    );
    const { qualified, complaints } = collectComplaints(GROUP, malformed, 2);
    assert.ok(!qualified.includes(2));
    assert.match(complaints[0]!.reason, /commitments/);
  });

  it("disqualifies a participant who withholds a share", () => {
    const contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 2, 3));
    const withholding = contributions.map((c) => {
      if (c.index !== 2) return c;
      const shares = new Map(c.shares);
      shares.delete(3);
      return { ...c, shares };
    });
    const { qualified, complaints } = collectComplaints(GROUP, withholding, 2);
    assert.ok(!qualified.includes(2));
    assert.ok(complaints.some((c) => c.reason.includes("no share delivered")));
  });

  it("FAILS the ceremony when too few participants qualify", () => {
    // Better to abort loudly than to proceed with a key that can never be used.
    let contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 3, 3));
    contributions = withCorruptedShare(contributions, 2, 3);
    assert.throws(() => finalizeDkg(GROUP, 3, contributions), /only 2 participants qualified/);
  });
});

describe("DKG input validation", () => {
  it("rejects duplicate participant indices", () => {
    const a = createDkgContribution(GROUP, 1, 2, 3);
    assert.throws(() => finalizeDkg(GROUP, 2, [a, a]), /duplicate participant indices/);
  });

  it("rejects an out-of-range index", () => {
    assert.throws(() => createDkgContribution(GROUP, 0, 2, 3), /index must be/);
    assert.throws(() => createDkgContribution(GROUP, 4, 2, 3), /index must be/);
  });

  it("rejects an impossible threshold", () => {
    assert.throws(() => createDkgContribution(GROUP, 1, 5, 3), /threshold/);
  });

  it("rejects an empty contribution set", () => {
    assert.throws(() => finalizeDkg(GROUP, 2, []), /no contributions/);
    assert.throws(() => computeJointPublicKey(GROUP, []), /no qualified/);
  });

  it("rejects an out-of-range received share", () => {
    assert.throws(() => computeKeyShare(GROUP, 1, [GROUP.q]), /out of range/);
  });

  it("computes public shares consistently for any participant index", () => {
    const contributions = [1, 2, 3].map((i) => createDkgContribution(GROUP, i, 2, 3));
    const broadcasts = contributions.map((c) => ({ index: c.index, commitments: c.commitments }));

    for (const index of [1, 2, 3]) {
      const received = contributions.map((c) => c.shares.get(index)!);
      const keyShare = computeKeyShare(GROUP, index, received);
      const publicShare = computePublicShare(GROUP, index, broadcasts);
      assert.equal(publicShare.publicShare, groupExp(GROUP, GROUP.g, keyShare.share));
    }
  });
});
