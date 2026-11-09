"use strict";
// G1-S1-CIRC-030: MerkleMembershipN(depth), her MerkleMembership() with the depth as a parameter
// (circuits/components/merkle_membership_n.circom). Her file and her v3 main are untouched.
//
//   1. equivalence - MerkleMembershipN(2) compiles to her MerkleMembership()'s R1CS (O0/O1/O2) and
//                    agrees with it on the v3 fixtures, accept and reject alike
//   2. layout      - depth 4 / 16: public root at slot 1, private inputs, constraint counts
//   3. positives   - zk-kit-style sparse trees (Common rules) built in-test with circomlibjs
//   4. negatives   - input level: wrong root / sibling / leaf, flipped or non-boolean index
//   5. negatives   - witness level (--O0, depth 4): exactly one violated R1CS row per source
//                    constraint, every level (floor 1; recipe in agent memory v3-one-violated-row)
//
// All values are TEST-ONLY and computed in memory.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { CIRCUITS, expectReject, r1csInfo, NamedWitness, compilePoseidon2, mod } = require("./helpers");
const { H, merkleRoot, buildV3Input } = require("./fixtures");

const ASSERT = /Assert Failed/;
const CONSTRAINT = /Constraint doesn't match/;
const MAINS = path.join(__dirname, "circuits");
const COMPONENTS = path.join(CIRCUITS, "components");
const N_SOURCES = [path.join(COMPONENTS, "merkle_membership_n.circom")];
const V3_SOURCES = [path.join(COMPONENTS, "merkle_membership.circom")];

// ---- local build cache (same scheme as helpers.js compileCached, which is not exported) ----
const BUILD = path.join(__dirname, "..", "..", "build", "test");
const builds = new Map();
function compile(name, file, sources, options = {}) {
  if (!builds.has(name)) {
    builds.set(
      name,
      (async () => {
        const output = path.join(BUILD, name);
        const h = crypto.createHash("sha256");
        h.update(execSync("circom --version", { encoding: "utf8" }));
        h.update(JSON.stringify(options));
        for (const s of [file, ...sources]) h.update(fs.readFileSync(s));
        const stamp = h.digest("hex");
        const stampFile = path.join(output, "stamp.txt");
        const fresh = fs.existsSync(stampFile) && fs.readFileSync(stampFile, "utf8") === stamp;
        if (!fresh) fs.rmSync(output, { recursive: true, force: true });
        const t = await wasmTester(file, { output, recompile: !fresh, ...options });
        if (!fresh) fs.writeFileSync(stampFile, stamp);
        await t.loadSymbols();
        return t;
      })()
    );
  }
  return builds.get(name);
}
const compileN = (depth, O) =>
  compile(`bb-merkle-n${depth}-O${O}`, path.join(MAINS, `merkle_n_${depth}.circom`), N_SOURCES, { O });
const compileRef = (O) =>
  compile(`bb-merkle-v3ref-O${O}`, path.join(MAINS, "merkle_v3_ref.circom"), V3_SOURCES, { O });

// ---- zk-kit-style sparse tree (docs/CONTRACTS.md Common rules) ----
/**
 * Binary Poseidon(2) tree of `depth` with zero leaf 0 and empty subtree z[k+1] = H(z[k], z[k]);
 * `leaves` maps leaf index -> value. proof(i) gives pathIndices[k] = (i >> k) & 1 and
 * pathElements[k] = sibling at level k, exactly what zk-kit's createProof returns.
 */
async function sparseTree(depth, leaves) {
  const z = [0n];
  for (let k = 0; k < depth; k++) z.push(await H(z[k], z[k]));
  const levels = [new Map(Object.entries(leaves).map(([i, v]) => [Number(i), mod(v)]))];
  for (let k = 0; k < depth; k++) {
    const cur = levels[k];
    const next = new Map();
    for (const p of new Set([...cur.keys()].map((i) => i >> 1))) {
      const l = cur.has(2 * p) ? cur.get(2 * p) : z[k];
      const r = cur.has(2 * p + 1) ? cur.get(2 * p + 1) : z[k];
      next.set(p, await H(l, r));
    }
    levels.push(next);
  }
  const root = levels[depth].has(0) ? levels[depth].get(0) : z[depth];
  const at = (k, i) => (levels[k].has(i) ? levels[k].get(i) : k === 0 ? 0n : z[k]);
  const proof = (index) => ({
    pathElements: [...Array(depth).keys()].map((k) => at(k, (index >> k) ^ 1)),
    pathIndices: [...Array(depth).keys()].map((k) => BigInt((index >> k) & 1)),
  });
  return { root, proof, leaf: (i) => at(0, i) };
}

function toInput({ leaf, pathElements, pathIndices, root }) {
  return {
    leaf: mod(leaf).toString(),
    pathElements: pathElements.map((x) => mod(x).toString()),
    pathIndices: pathIndices.map((x) => mod(x).toString()),
    root: mod(root).toString(),
  };
}

async function accepts(t, input) {
  try {
    const w = await t.calculateWitness(input, true);
    await t.checkConstraints(w);
    return true;
  } catch (e) {
    if (!ASSERT.test(String(e.message || e))) throw e;
    return false;
  }
}

// Leaves at arbitrary indices per depth; the last one exercises high pathIndices bits.
const LEAF_INDICES = { 4: [0, 1, 2, 3, 13], 16: [0, 1, 2, 3, 40000, 65535] };
const TAMPER_LEVELS = { 4: [0, 1, 2, 3], 16: [0, 1, 7, 8, 15] };

describe("MerkleMembershipN(2) reproduces her MerkleMembership() (G1-S1-CIRC-030)", function () {
  for (const O of [0, 1, 2]) {
    it(`--O${O}: identical R1CS (header, every constraint row) and identical signal map`, async function () {
      const [n, ref] = await Promise.all([compileN(2, O), compileRef(O)]);
      expect(await r1csInfo(n)).to.deep.equal(await r1csInfo(ref));
      await Promise.all([n.loadConstraints(), ref.loadConstraints()]);
      expect(n.constraints.length).to.equal(ref.constraints.length);
      expect(n.constraints).to.deep.equal(ref.constraints);
      const sym = (t) => Object.fromEntries(Object.entries(t.symbols).map(([k, s]) => [k, s.varIdx]));
      expect(sym(n)).to.deep.equal(sym(ref));
    });
  }

  it("the zk-kit-style tree [11, commitment, 33, 44] gives the v3 fixture's path and root", async function () {
    const v = await buildV3Input();
    const tree = await sparseTree(2, { 0: 11n, 1: v.commitment, 2: 33n, 3: 44n });
    expect(tree.root.toString()).to.equal(v.input.root);
    const p = tree.proof(1);
    expect(p.pathElements.map(String)).to.deep.equal(v.input.pathElements);
    expect(p.pathIndices.map(String)).to.deep.equal(v.input.pathIndices);
  });

  for (const O of [1, 2]) {
    it(`--O${O}: accepts and rejects exactly what her template does on the v3 fixtures`, async function () {
      const [n, ref] = await Promise.all([compileN(2, O), compileRef(O)]);
      const v = await buildV3Input();
      const alt = await buildV3Input({ secretLabel: "alt", saltLabel: "alt" });
      const base = {
        leaf: v.commitment,
        pathElements: v.input.pathElements.map(BigInt),
        pathIndices: v.input.pathIndices.map(BigInt),
        root: BigInt(v.input.root),
      };
      const idx2root = (i) => {
        const pi = [...base.pathIndices];
        pi[i] = 2n;
        return merkleRoot(base.leaf, base.pathElements, pi).then((root) => ({ ...base, pathIndices: pi, root }));
      };
      const cases = [
        ["valid", base, true],
        ["other position, own root", { ...base, pathIndices: [0n, 1n], root: await merkleRoot(base.leaf, base.pathElements, [0n, 1n]) }, true],
        ["wrong root", { ...base, root: base.root + 1n }, false],
        ["other leaf", { ...base, leaf: alt.commitment }, false],
        ["wrong sibling 0", { ...base, pathElements: [base.pathElements[0] + 1n, base.pathElements[1]] }, false],
        ["wrong sibling 1", { ...base, pathElements: [base.pathElements[0], base.pathElements[1] + 1n] }, false],
        ["flipped index 0", { ...base, pathIndices: [0n, base.pathIndices[1]] }, false],
        ["index 0 = 2, original root", { ...base, pathIndices: [2n, base.pathIndices[1]] }, false],
        ["index 0 = 2, root recomputed", await idx2root(0), false],
        ["index 1 = 2, root recomputed", await idx2root(1), false],
      ];
      for (const [label, c, want] of cases) {
        const input = toInput(c);
        const [a, b] = [await accepts(n, input), await accepts(ref, input)];
        expect(a, `${label}: MerkleMembershipN(2)`).to.equal(want);
        expect(b, `${label}: MerkleMembership()`).to.equal(want);
      }
    });
  }
});

// Measured with circom 2.2.3 + circomlib 2.0.5 (243-246 non-linear rows per level).
const EXPECTED = {
  4: { 0: { nonLinear: 984, linear: 2102 }, 2: { nonLinear: 972, linear: 0 } },
  16: { 0: { nonLinear: 3936, linear: 8402 }, 2: { nonLinear: 3888, linear: 0 } },
};

for (const depth of [4, 16]) {
  describe(`MerkleMembershipN(${depth}) (G1-S1-CIRC-030)`, function () {
    let tree;
    before(async function () {
      const leaves = {};
      for (const i of LEAF_INDICES[depth]) leaves[i] = await H(1000n + BigInt(i), 7n);
      tree = await sparseTree(depth, leaves);
    });
    const member = (i) => ({ leaf: tree.leaf(i), ...tree.proof(i), root: tree.root });

    describe("layout", function () {
      for (const O of [0, 2]) {
        it(`--O${O}: root is the only public input (slot 1), ${1 + 2 * depth} private inputs, ${EXPECTED[depth][O].nonLinear} non-linear + ${EXPECTED[depth][O].linear} linear`, async function () {
          const t = await compileN(depth, O);
          const info = await r1csInfo(t);
          expect(info.nPubInputs).to.equal(1);
          expect(info.nOutputs).to.equal(0);
          expect(info.nPrvInputs).to.equal(1 + 2 * depth);
          expect(t.symbols["main.root"].varIdx).to.equal(1);
          expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(EXPECTED[depth][O]);
        });
      }
    });

    describe("positives (--O2)", function () {
      let t;
      before(async function () {
        t = await compileN(depth, 2);
      });

      for (const i of LEAF_INDICES[depth]) {
        it(`leaf at index ${i} with its zk-kit-style path is accepted`, async function () {
          const w = await t.calculateWitness(toInput(member(i)), true);
          await t.checkConstraints(w);
          expect(w[1].toString()).to.equal(tree.root.toString());
        });
      }

      it("documented property: the zero leaf at an EMPTY index is a member (v4 relies on leaf = attrHash != 0)", async function () {
        // Zero-leaf trees make every empty slot (and every revoked slot, leaf <- 0) provably 0.
        // Harmless in v4 only because the leaf is a Poseidon output, never 0 in practice.
        const empty = depth === 4 ? 9 : 12345;
        const w = await t.calculateWitness(toInput(member(empty)), true);
        await t.checkConstraints(w);
        expect(tree.leaf(empty)).to.equal(0n);
      });
    });

    describe("negatives, input level (--O2)", function () {
      let t;
      const i = LEAF_INDICES[depth][LEAF_INDICES[depth].length - 1];
      const rejects = (c) => expectReject(t.calculateWitness(toInput(c), true), ASSERT);
      before(async function () {
        t = await compileN(depth, 2);
      });

      it("wrong root is rejected", async function () {
        await rejects({ ...member(i), root: tree.root + 1n });
      });

      it("another member's leaf on this path is rejected", async function () {
        await rejects({ ...member(i), leaf: tree.leaf(1) });
      });

      it("a non-member leaf with a valid member's path is rejected", async function () {
        await rejects({ ...member(i), leaf: tree.leaf(i) + 1n });
      });

      for (const k of TAMPER_LEVELS[depth]) {
        it(`wrong sibling pathElements[${k}] is rejected`, async function () {
          const m = member(i);
          m.pathElements[k] += 1n;
          await rejects(m);
        });

        it(`flipped pathIndices[${k}] with the original root is rejected`, async function () {
          const m = member(i);
          m.pathIndices[k] = 1n - m.pathIndices[k];
          await rejects(m);
        });

        it(`pathIndices[${k}] = 2 is rejected even with the root recomputed for index 2 (boolean check)`, async function () {
          const m = member(i);
          m.pathIndices[k] = 2n;
          m.root = await merkleRoot(m.leaf, m.pathElements, m.pathIndices);
          await rejects(m);
        });

        it(`pathIndices[${k}] = p-1 is rejected even with the root recomputed (boolean check)`, async function () {
          const m = member(i);
          m.pathIndices[k] = mod(-1n);
          m.root = await merkleRoot(m.leaf, m.pathElements, m.pathIndices);
          await rejects(m);
        });
      }
    });
  });
}

describe("MerkleMembershipN(4) negatives, witness level (--O0, exactly one violated row each)", function () {
  const depth = 4;
  let t; // MerkleMembershipN(4) at O0
  let ph; // Poseidon(2) harness at O0
  let W; // valid witness for leaf 13
  let A; // valid witness for another leaf on the same path (other root)

  before(async function () {
    [t, ph] = await Promise.all([compileN(depth, 0), compilePoseidon2()]);
    const leaves = {};
    for (const i of LEAF_INDICES[depth]) leaves[i] = await H(1000n + BigInt(i), 7n);
    const tree = await sparseTree(depth, leaves);
    const m = { leaf: tree.leaf(13), ...tree.proof(13), root: tree.root };
    W = new NamedWitness(t, await t.calculateWitness(toInput(m), true));
    const otherLeaf = m.leaf + 5n;
    const otherRoot = await merkleRoot(otherLeaf, m.pathElements, m.pathIndices);
    A = new NamedWitness(t, await t.calculateWitness(toInput({ ...m, leaf: otherLeaf, root: otherRoot }), true));
  });

  async function expectOnly(nw, touches) {
    const v = await nw.violated();
    expect(v.length, `violated rows: ${JSON.stringify(v.map((r) => r.row))}`).to.equal(1);
    for (const name of [].concat(touches)) {
      expect(v[0].signals, `violated row should involve ${name}`).to.include(nw.idx(name));
    }
    await expectReject(t.checkConstraints(nw.w), CONSTRAINT);
  }

  async function splicePoseidon(nw, prefix, a, b) {
    const hw = new NamedWitness(ph, await ph.calculateWitness({ inputs: [mod(a), mod(b)] }, true));
    const src = Object.keys(ph.symbols);
    expect(nw.namesUnder(prefix).length, `layout of ${prefix} vs harness`).to.equal(src.length);
    for (const n of src) nw.set(n.replace(/^main\./, prefix), hw.get(n));
    return hw.get("main.out");
  }

  /** Recompute every level with the template's formulas, optionally perturbing one value at one level. */
  async function rebuild(nw, perturb = {}) {
    for (let i = 0; i < depth; i++) {
      const p = perturb.level === i ? perturb : {};
      const h = nw.get(`main.hashes[${i}]`);
      const s = nw.get(`main.pathElements[${i}]`);
      const b = nw.get(`main.pathIndices[${i}]`);
      let left = mod(h + b * (s - h));
      let right = mod(s + b * (h - s));
      if (p.left) left = mod(left + 1n);
      if (p.right) right = mod(right + 1n);
      nw.set(`main.left[${i}]`, left).set(`main.right[${i}]`, right);
      const out = await splicePoseidon(nw, `main.hashers[${i}].`, p.inL ? left + 1n : left, p.inR ? right + 1n : right);
      nw.set(`main.hashes[${i + 1}]`, p.out ? out + 1n : out);
    }
    return nw.set("main.root", nw.get(`main.hashes[${depth}]`));
  }

  it("control: the valid witnesses violate no row and rebuild() reproduces W", async function () {
    expect(await W.violated()).to.deep.equal([]);
    expect(await A.violated()).to.deep.equal([]);
    expect((await rebuild(W.clone())).w).to.deep.equal(W.w);
  });

  it("MerkleMembershipN: hashes[0] <== leaf (tree built over another leaf, leaf kept honest)", async function () {
    const nw = W.clone().copyFrom(A, "main.hashes[", "main.left[", "main.right[", "main.hashers[", "main.root");
    await expectOnly(nw, ["main.hashes[0]", "main.leaf"]);
  });

  for (let i = 0; i < depth; i++) {
    it(`MerkleMembershipN: pathIndices[${i}] * (pathIndices[${i}] - 1) === 0 (index 2, tree recomputed)`, async function () {
      await expectOnly(await rebuild(W.clone().set(`main.pathIndices[${i}]`, 2n)), `main.pathIndices[${i}]`);
    });

    it(`MerkleMembershipN: left[${i}] <== hashes + idx*(sibling - hashes) (left perturbed, tree recomputed)`, async function () {
      await expectOnly(await rebuild(W.clone(), { level: i, left: true }), `main.left[${i}]`);
    });

    it(`MerkleMembershipN: right[${i}] <== sibling + idx*(hashes - sibling) (right perturbed, tree recomputed)`, async function () {
      await expectOnly(await rebuild(W.clone(), { level: i, right: true }), `main.right[${i}]`);
    });

    it(`MerkleMembershipN: hashers[${i}].inputs[0] <== left[${i}] (hasher fed another value)`, async function () {
      await expectOnly(await rebuild(W.clone(), { level: i, inL: true }), [`main.left[${i}]`, `main.hashers[${i}].inputs[0]`]);
    });

    it(`MerkleMembershipN: hashers[${i}].inputs[1] <== right[${i}] (hasher fed another value)`, async function () {
      await expectOnly(await rebuild(W.clone(), { level: i, inR: true }), [`main.right[${i}]`, `main.hashers[${i}].inputs[1]`]);
    });

    it(`MerkleMembershipN: hashes[${i + 1}] <== hashers[${i}].out (hash output replaced, tree recomputed)`, async function () {
      await expectOnly(await rebuild(W.clone(), { level: i, out: true }), [`main.hashes[${i + 1}]`, `main.hashers[${i}].out`]);
    });
  }

  it("MerkleMembershipN: hashes[depth] === root (root tampered)", async function () {
    await expectOnly(W.clone().add("main.root"), [`main.hashes[${depth}]`, "main.root"]);
  });
});
