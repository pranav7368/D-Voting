import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MODP_2048, groupExp, randomScalar, scalarAdd } from "../src/elgamal/group.ts";
import { encrypt } from "../src/elgamal/cipher.ts";
import { discreteLogSmall } from "../src/elgamal/dlog.ts";
import {
  lagrangeCoefficient,
  reconstructSecret,
  splitSecret,
  type Share,
} from "../src/threshold/shamir.ts";
import {
  combinePartialDecryptions,
  partialDecrypt,
  publicShareFromCommitments,
  setupTrustees,
  verifyPartialDecryption,
  verifyShare,
  type PartialDecryption,
} from "../src/threshold/trustee.ts";

const GROUP = MODP_2048;
const ELECTION = "test-election";

describe("Shamir secret sharing", () => {
  it("reconstructs from exactly the threshold number of shares", () => {
    const secret = randomScalar(GROUP);
    const { shares } = splitSecret(GROUP, secret, 3, 5);

    assert.equal(shares.length, 5);
    assert.equal(reconstructSecret(GROUP, shares.slice(0, 3)), secret);
    assert.equal(reconstructSecret(GROUP, shares.slice(2, 5)), secret);
  });

  it("reconstructs from any subset at or above the threshold", () => {
    const secret = randomScalar(GROUP);
    const { shares } = splitSecret(GROUP, secret, 3, 5);

    const subsets = [
      [0, 1, 2],
      [0, 2, 4],
      [1, 3, 4],
      [0, 1, 2, 3, 4],
    ];
    for (const subset of subsets) {
      const picked = subset.map((i) => shares[i]!);
      assert.equal(reconstructSecret(GROUP, picked), secret, `subset ${subset} failed`);
    }
  });

  it("reveals NOTHING with fewer than the threshold", () => {
    // Information-theoretic security: with k-1 shares, every candidate secret
    // is still exactly equally likely. We can only demonstrate the practical
    // consequence -- reconstruction from k-1 shares yields a wrong value.
    const secret = randomScalar(GROUP);
    const { shares } = splitSecret(GROUP, secret, 3, 5);
    const tooFew = reconstructSecret(GROUP, shares.slice(0, 2));
    assert.notEqual(tooFew, secret);
  });

  it("supports a 1-of-n degenerate sharing", () => {
    const secret = randomScalar(GROUP);
    const { shares } = splitSecret(GROUP, secret, 1, 3);
    for (const share of shares) {
      assert.equal(reconstructSecret(GROUP, [share]), secret);
    }
  });

  it("rejects invalid parameters", () => {
    assert.throws(() => splitSecret(GROUP, 1n, 0, 3), /threshold/);
    assert.throws(() => splitSecret(GROUP, 1n, 4, 3), /at least the threshold/);
    assert.throws(() => splitSecret(GROUP, GROUP.q, 2, 3), /out of range/);
  });

  it("rejects duplicate share indices", () => {
    const duplicate: Share[] = [
      { index: 1, value: 5n },
      { index: 1, value: 7n },
    ];
    assert.throws(() => reconstructSecret(GROUP, duplicate), /duplicate/);
  });

  it("computes Lagrange coefficients that interpolate to 1 at the right point", () => {
    // Sanity: sum of lambda_i * f(x_i) reconstructs f(0) for a known polynomial.
    const coefficients = [42n, 7n, 3n];
    const indices = [1, 2, 3];
    const evaluate = (x: bigint) => (coefficients[0]! + coefficients[1]! * x + coefficients[2]! * x * x) % GROUP.q;

    let total = 0n;
    for (const index of indices) {
      const lambda = lagrangeCoefficient(GROUP, indices, index);
      total = scalarAdd(GROUP, total, (lambda * evaluate(BigInt(index))) % GROUP.q);
    }
    assert.equal(total, 42n);
  });
});

describe("Feldman verifiable secret sharing", () => {
  it("accepts shares consistent with the published commitments", () => {
    const setup = setupTrustees(GROUP, 3, 5);
    for (const keyShare of setup.keyShares) {
      assert.ok(
        verifyShare(GROUP, keyShare.index, keyShare.share, setup.commitments),
        `trustee ${keyShare.index} could not verify their share`,
      );
    }
  });

  it("detects a tampered share", () => {
    // This is what protects trustees from a dishonest dealer handing out
    // inconsistent shares that would only fail at decryption time.
    const setup = setupTrustees(GROUP, 3, 5);
    const victim = setup.keyShares[0]!;
    assert.ok(!verifyShare(GROUP, victim.index, scalarAdd(GROUP, victim.share, 1n), setup.commitments));
  });

  it("derives public shares from the commitments", () => {
    const setup = setupTrustees(GROUP, 3, 5);
    for (const publicShare of setup.publicShares) {
      assert.equal(
        publicShareFromCommitments(GROUP, publicShare.index, setup.commitments),
        publicShare.publicShare,
      );
    }
  });

  it("commits to the election public key as C_0", () => {
    const setup = setupTrustees(GROUP, 2, 3);
    assert.equal(setup.commitments[0], setup.publicKey.y);
  });
});

describe("threshold decryption", () => {
  it("decrypts with exactly the threshold number of trustees", async () => {
    const setup = setupTrustees(GROUP, 3, 5);
    const { ciphertext } = encrypt(setup.publicKey, 42n);

    const partials = [];
    for (const keyShare of setup.keyShares.slice(0, 3)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext));
    }

    const element = combinePartialDecryptions(GROUP, ciphertext, partials, 3);
    assert.equal(discreteLogSmall(GROUP, element, 100), 42);
  });

  it("decrypts with any qualifying subset of trustees", async () => {
    const setup = setupTrustees(GROUP, 3, 5);
    const { ciphertext } = encrypt(setup.publicKey, 17n);

    for (const subset of [[0, 1, 2], [1, 3, 4], [0, 2, 4]]) {
      const partials: PartialDecryption[] = [];
      for (const i of subset) {
        partials.push(await partialDecrypt(GROUP, ELECTION, setup.keyShares[i]!, ciphertext));
      }
      const element = combinePartialDecryptions(GROUP, ciphertext, partials, 3);
      assert.equal(discreteLogSmall(GROUP, element, 100), 17, `subset ${subset} failed`);
    }
  });

  it("CANNOT decrypt below the threshold", async () => {
    // The central guarantee: no minority of trustees can read the result.
    const setup = setupTrustees(GROUP, 3, 5);
    const { ciphertext } = encrypt(setup.publicKey, 42n);

    const partials: PartialDecryption[] = [];
    for (const keyShare of setup.keyShares.slice(0, 2)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext));
    }

    assert.throws(() => combinePartialDecryptions(GROUP, ciphertext, partials, 3), /threshold/);

    // And forcing a combination with too few shares yields garbage, not the
    // plaintext -- there is no partial information to exploit.
    const forced = combinePartialDecryptions(GROUP, ciphertext, partials, 2);
    assert.throws(() => discreteLogSmall(GROUP, forced, 1000), /corrupt|no exponent/);
  });

  it("proves each partial decryption was computed honestly", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const { ciphertext } = encrypt(setup.publicKey, 5n);

    for (const [i, keyShare] of setup.keyShares.entries()) {
      const partial = await partialDecrypt(GROUP, ELECTION, keyShare, ciphertext);
      assert.ok(
        await verifyPartialDecryption(GROUP, ELECTION, setup.publicShares[i]!, ciphertext, partial),
      );
    }
  });

  it("REJECTS a malicious trustee's forged partial decryption", async () => {
    // Without the proof, this bogus factor would silently corrupt the tally and
    // be indistinguishable from an honest result.
    const setup = setupTrustees(GROUP, 2, 3);
    const { ciphertext } = encrypt(setup.publicKey, 5n);

    const honest = await partialDecrypt(GROUP, ELECTION, setup.keyShares[0]!, ciphertext);
    const forged = { ...honest, factor: groupExp(GROUP, GROUP.g, randomScalar(GROUP)) };

    assert.ok(
      !(await verifyPartialDecryption(GROUP, ELECTION, setup.publicShares[0]!, ciphertext, forged)),
    );
  });

  it("rejects a partial decryption replayed from another ciphertext", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const first = encrypt(setup.publicKey, 1n).ciphertext;
    const second = encrypt(setup.publicKey, 1n).ciphertext;

    const partial = await partialDecrypt(GROUP, ELECTION, setup.keyShares[0]!, first);
    assert.ok(
      !(await verifyPartialDecryption(GROUP, ELECTION, setup.publicShares[0]!, second, partial)),
    );
  });

  it("rejects a partial decryption bound to a different election", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const { ciphertext } = encrypt(setup.publicKey, 1n);
    const partial = await partialDecrypt(GROUP, ELECTION, setup.keyShares[0]!, ciphertext);

    assert.ok(
      !(await verifyPartialDecryption(
        GROUP,
        "a-different-election",
        setup.publicShares[0]!,
        ciphertext,
        partial,
      )),
    );
  });

  it("rejects a partial attributed to the wrong trustee", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const { ciphertext } = encrypt(setup.publicKey, 1n);
    const partial = await partialDecrypt(GROUP, ELECTION, setup.keyShares[0]!, ciphertext);

    assert.ok(
      !(await verifyPartialDecryption(GROUP, ELECTION, setup.publicShares[1]!, ciphertext, partial)),
    );
  });

  it("preserves the homomorphism through threshold decryption", async () => {
    const setup = setupTrustees(GROUP, 2, 3);
    const values = [1n, 1n, 0n, 1n];
    const ciphertexts = values.map((v) => encrypt(setup.publicKey, v).ciphertext);

    let sum = ciphertexts[0]!;
    for (const ct of ciphertexts.slice(1)) {
      sum = { alpha: (sum.alpha * ct.alpha) % GROUP.p, beta: (sum.beta * ct.beta) % GROUP.p };
    }

    const partials = [];
    for (const keyShare of setup.keyShares.slice(0, 2)) {
      partials.push(await partialDecrypt(GROUP, ELECTION, keyShare, sum));
    }
    const element = combinePartialDecryptions(GROUP, sum, partials, 2);
    assert.equal(discreteLogSmall(GROUP, element, 100), 3);
  });
});
