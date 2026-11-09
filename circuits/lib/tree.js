"use strict";
// Registry tree helpers (Common rules, "Merkle tree"): @zk-kit/incremental-merkle-tree 1.1.0,
// Poseidon(2), arity 2, zero leaf 0, profile depth. pathIndices[i] = (leafIndex >> i) & 1;
// 1 = the current node is the right child, i.e. parent = Poseidon(2)(pathElements[i], current).
const { IncrementalMerkleTree } = require("@zk-kit/incremental-merkle-tree");
const { fail, toBigInt, parseField } = require("./field");
const { getPoseidon, poseidon } = require("./crypto");
const { getProfile } = require("./profiles");

/** new IncrementalMerkleTree(h, profile.depth, 0n, 2) with h = xs => F.toObject(poseidon(xs)). */
async function createTree(profile) {
  const { depth } = getProfile(profile);
  const h = await getPoseidon();
  return new IncrementalMerkleTree((xs) => h.F.toObject(h(xs)), depth, 0n, 2);
}

/**
 * Path for leaf `index`: {leafIndex, leaf, root, pathElements[depth], pathIndices[depth]}, all
 * field values canonical decimal strings (pathIndices "0"/"1"). The issuer API emits pathIndices
 * as JSON integers (Number(x)); the input builders accept either.
 */
function proofFor(tree, index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= tree.leaves.length) {
    fail("OUT_OF_RANGE", "proofFor: leaf index outside the issued leaves");
  }
  const p = tree.createProof(index);
  return {
    leafIndex: index,
    leaf: p.leaf.toString(),
    root: p.root.toString(),
    pathElements: p.siblings.map((s) => s[0].toString()),
    pathIndices: p.pathIndices.map((b) => String(b)),
  };
}

/** Parse a pathIndices entry: 0/1 as number, bigint or decimal string. */
function pathBit(i, x) {
  let v;
  try {
    v = toBigInt(`pathIndices[${i}]`, x);
  } catch (_) {
    v = -1n;
  }
  if (v !== 0n && v !== 1n) fail("INVALID_PATH_INDEX", `pathIndices[${i}]: must be 0 or 1`);
  return v;
}

/**
 * Normalise a path to {pathElements, pathIndices} (decimal strings) of length `depth` (when
 * given). Accepts {pathElements, pathIndices} or zk-kit createProof output {siblings: [[x]], ...}.
 */
function normalisePath(pathElements, pathIndices, depth) {
  if (!Array.isArray(pathElements) || !Array.isArray(pathIndices)) {
    fail("MISSING_FIELD", "Merkle path: pathElements (or siblings) and pathIndices arrays required");
  }
  if (pathElements.length !== pathIndices.length || (depth !== undefined && pathElements.length !== depth)) {
    fail("DEPTH_MISMATCH", `Merkle path: expected ${depth ?? pathElements.length} levels in pathElements and pathIndices`);
  }
  return {
    pathElements: pathElements.map((x, i) => {
      if (Array.isArray(x)) {
        if (x.length !== 1) fail("INVALID_VALUE", `siblings[${i}]: binary tree expected (one sibling per level)`);
        x = x[0];
      }
      return parseField(`pathElements[${i}]`, x).toString();
    }),
    pathIndices: pathIndices.map((x, i) => pathBit(i, x).toString()),
  };
}

/** Root reached from `leaf` along the path, as the circuit's MerkleMembership computes it. */
async function merkleRoot(leaf, pathElements, pathIndices) {
  const p = normalisePath(pathElements, pathIndices);
  let cur = parseField("leaf", leaf).toString();
  for (let i = 0; i < p.pathElements.length; i++) {
    cur = await poseidon(p.pathIndices[i] === "1" ? [p.pathElements[i], cur] : [cur, p.pathElements[i]]);
  }
  return cur;
}

module.exports = { createTree, proofFor, merkleRoot, normalisePath };
