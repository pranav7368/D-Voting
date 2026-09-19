import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createHash } from "node:crypto";

import { utf8 } from "@dvoting/crypto";

import {
  hashLeaf,
  hashNode,
  merkleProof,
  merkleRoot,
  verifyMerkleProof,
} from "../src/merkle.ts";

function leaves(count: number): Uint8Array[] {
  return Array.from({ length: count }, (_, i) => utf8(`entry-${i}`));
}

describe("Merkle tree (RFC 6962)", () => {
  it("hashes the empty tree to SHA-256 of the empty string", async () => {
    const root = await merkleRoot([]);
    assert.equal(
      Buffer.from(root).toString("hex"),
      createHash("sha256").update(Buffer.alloc(0)).digest("hex"),
    );
  });

  it("hashes a single leaf with the 0x00 domain prefix", async () => {
    const data = utf8("only");
    const root = await merkleRoot([data]);
    const expected = createHash("sha256")
      .update(Buffer.concat([Buffer.of(0x00), Buffer.from(data)]))
      .digest("hex");
    assert.equal(Buffer.from(root).toString("hex"), expected);
  });

  it("hashes two leaves with the 0x01 node prefix", async () => {
    const a = utf8("a");
    const b = utf8("b");
    const expected = await hashNode(await hashLeaf(a), await hashLeaf(b));
    assert.deepEqual(Array.from(await merkleRoot([a, b])), Array.from(expected));
  });

  it("is deterministic", async () => {
    const data = leaves(9);
    assert.deepEqual(Array.from(await merkleRoot(data)), Array.from(await merkleRoot(data)));
  });

  it("changes root when any leaf changes", async () => {
    const original = leaves(8);
    const root = await merkleRoot(original);
    for (const index of [0, 3, 7]) {
      const modified = [...original];
      modified[index] = utf8("tampered");
      assert.notDeepEqual(Array.from(await merkleRoot(modified)), Array.from(root));
    }
  });

  it("changes root when leaves are reordered", async () => {
    const original = leaves(6);
    const swapped = [...original];
    [swapped[1], swapped[4]] = [swapped[4]!, swapped[1]!];
    assert.notDeepEqual(
      Array.from(await merkleRoot(swapped)),
      Array.from(await merkleRoot(original)),
    );
  });
});

describe("inclusion proofs", () => {
  it("verifies every leaf for every tree size up to 33", async () => {
    // Sizes that are not powers of two are where naive implementations break.
    for (let size = 1; size <= 33; size++) {
      const data = leaves(size);
      const root = await merkleRoot(data);
      for (let index = 0; index < size; index++) {
        const proof = await merkleProof(data, index);
        assert.ok(
          await verifyMerkleProof(data[index]!, proof, root),
          `size ${size}, leaf ${index} failed to verify`,
        );
      }
    }
  });

  it("keeps proofs logarithmic in tree size", async () => {
    const data = leaves(1024);
    const proof = await merkleProof(data, 500);
    // 1024 leaves -> 10 sibling hashes -> 320 bytes for a voter to check.
    assert.equal(proof.path.length, 10);
  });

  it("rejects a proof for the wrong leaf data", async () => {
    const data = leaves(16);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 5);
    assert.ok(!(await verifyMerkleProof(utf8("not-the-entry"), proof, root)));
  });

  it("rejects a proof against the wrong root", async () => {
    const data = leaves(16);
    const proof = await merkleProof(data, 5);
    const otherRoot = await merkleRoot(leaves(17));
    assert.ok(!(await verifyMerkleProof(data[5]!, proof, otherRoot)));
  });

  it("rejects a tampered audit path", async () => {
    const data = leaves(16);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 5);

    const tampered = {
      ...proof,
      path: proof.path.map((node, i) => {
        if (i !== 0) return node;
        const copy = Uint8Array.from(node);
        copy[0] = copy[0]! ^ 0xff;
        return copy;
      }),
    };
    assert.ok(!(await verifyMerkleProof(data[5]!, tampered, root)));
  });

  it("rejects a proof claiming the wrong leaf index", async () => {
    const data = leaves(16);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 5);
    assert.ok(!(await verifyMerkleProof(data[5]!, { ...proof, leafIndex: 6 }, root)));
  });

  it("rejects a truncated path", async () => {
    // A short path would otherwise verify against an internal subtree root.
    const data = leaves(16);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 5);
    assert.ok(!(await verifyMerkleProof(data[5]!, { ...proof, path: proof.path.slice(0, 2) }, root)));
  });

  it("rejects an over-long path", async () => {
    const data = leaves(4);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 1);
    const extended = { ...proof, path: [...proof.path, new Uint8Array(32)] };
    assert.ok(!(await verifyMerkleProof(data[1]!, extended, root)));
  });

  it("rejects an out-of-range leaf index", async () => {
    const data = leaves(4);
    const root = await merkleRoot(data);
    const proof = await merkleProof(data, 1);
    assert.ok(!(await verifyMerkleProof(data[1]!, { ...proof, leafIndex: 99 }, root)));
    await assert.rejects(() => merkleProof(data, 4), /out of range/);
  });
});

describe("known Merkle attacks are defeated", () => {
  it("resists the second-preimage attack (leaf/node confusion)", async () => {
    // Without domain separation an attacker could present an INTERNAL node hash
    // as if it were a leaf, proving inclusion of data the log never recorded.
    const data = leaves(4);
    const root = await merkleRoot(data);

    // The internal node covering leaves 0 and 1.
    const internal = await hashNode(await hashLeaf(data[0]!), await hashLeaf(data[1]!));

    // Try to pass that internal node off as a leaf of a 2-leaf tree.
    const forgedRoot = await merkleRoot([internal, await hashNode(
      await hashLeaf(data[2]!),
      await hashLeaf(data[3]!),
    )]);

    // The 0x00/0x01 prefixes make the two hash domains disjoint, so the forged
    // tree cannot reproduce the genuine root.
    assert.notDeepEqual(Array.from(forgedRoot), Array.from(root));
  });

  it("resists duplicate-last-leaf malleability (Bitcoin CVE-2012-2459)", async () => {
    // Implementations that pad odd levels by duplicating the last node let two
    // DIFFERENT leaf lists produce the SAME root -- so a ledger could be
    // rewritten without changing its published root. RFC 6962's split rule is
    // injective, so this must not happen.
    const three = leaves(3);
    const withDuplicate = [...three, three[2]!];

    assert.notDeepEqual(
      Array.from(await merkleRoot(withDuplicate)),
      Array.from(await merkleRoot(three)),
      "a duplicated trailing leaf produced the same root -- tree is malleable",
    );
  });

  it("distinguishes trees of every adjacent size", async () => {
    const roots = new Set<string>();
    for (let size = 0; size <= 20; size++) {
      const root = await merkleRoot(leaves(size));
      const hex = Buffer.from(root).toString("hex");
      assert.ok(!roots.has(hex), `size ${size} collided with a smaller tree`);
      roots.add(hex);
    }
  });
});
