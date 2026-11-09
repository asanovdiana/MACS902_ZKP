"use strict";
// Test suite for the imported P1 circuit circuits/integrated_access_v3.circom (G0-S1-CIRC-020).
// No circuit behaviour is changed here; these tests pin what v3 does today.
//
// Tiers inside this file:
//   1. layout      - public signals, R1CS header, constraint counts (O0/O1/O2)
//   2. positives   - the TEST-ONLY input satisfies the circuit (O1 and O2 builds)
//   3. negatives   - input level: each bad input fails witness generation (O1 and O2 builds)
//   4. negatives   - witness level (O0 build): a valid witness is edited so that EXACTLY ONE R1CS
//                    row is violated, and that row involves the targeted signal. Removing the
//                    matching source constraint (or weakening `<==` to `<--`) makes the edited
//                    witness acceptable, so each test kills that mutant (floor 1).
//   5. GAP tests   - assert v3's INSECURE behaviour of documented gaps G-1, G-2
//                    (docs/plan/p2-plan.md §1). They pass on purpose: v3 keeps both gaps; v4 closes
//                    them (negatives in v4.test.js, G1-S1-CIRC-036).
//
// All inputs are TEST-ONLY and derived from public labels (see fixtures.js); nothing is written to
// the repository.
const { expect } = require("chai");
const {
  compileV3,
  compilePoseidon2,
  expectReject,
  r1csInfo,
  NamedWitness,
  mod,
} = require("./helpers");
const { issuerKey, sign, merkleRoot, buildV3Input, withInput } = require("./fixtures");

const ASSERT = /Assert Failed/;
const CONSTRAINT = /Constraint doesn't match/;

// Measured with circom 2.2.3 + circomlib 2.0.5; any change to the circuit must update these
// deliberately. O1 is circom's default (the level docs/plan/p2-plan.md §1 reports); O2 is the
// level the prototype used for trusted setup; O0 is the tamper build (no signal is merged).
const EXPECTED_COUNTS = {
  0: { nonLinear: 8133, linear: 15456 },
  1: { nonLinear: 8116, linear: 1529 },
  2: { nonLinear: 4935, linear: 0 },
};
const PRIVATE_INPUTS = 17; // secret, salt, 4 attrs, Ax, Ay, R8x, R8y, S, M, leaf, 2 + 2 path

let valid; // { input, commitment, key }
let alt; // a second valid credential: other secret/salt, same issuer, same path shape

before(async function () {
  valid = await buildV3Input();
  alt = await buildV3Input({ secretLabel: "alt", saltLabel: "alt" });
});

describe("v3 layout", function () {
  for (const O of [0, 1, 2]) {
    describe(`--O${O}`, function () {
      let t;
      before(async function () {
        t = await compileV3(O);
      });

      it("root is the only public signal (1 public input, 0 outputs, 17 private inputs)", async function () {
        const info = await r1csInfo(t);
        expect(info.nPubInputs).to.equal(1);
        expect(info.nOutputs).to.equal(0);
        expect(info.nPrvInputs).to.equal(PRIVATE_INPUTS);
      });

      it("witness slot 1 (the only public slot) is main.root", async function () {
        expect(t.symbols["main.root"].varIdx).to.equal(1);
        const w = await t.calculateWitness(valid.input, true);
        expect(w[0].toString()).to.equal("1");
        expect(w[1].toString()).to.equal(valid.input.root);
      });

      it(`constraint count at --O${O}: ${EXPECTED_COUNTS[O].nonLinear} non-linear + ${EXPECTED_COUNTS[O].linear} linear`, async function () {
        const info = await r1csInfo(t);
        expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(EXPECTED_COUNTS[O]);
      });
    });
  }

  it("--O0 keeps every signal (no merged .sym entries), so witness tampering by name works", async function () {
    const t = await compileV3(0);
    const merged = Object.entries(t.symbols).filter(([, s]) => s.varIdx < 0);
    expect(merged).to.deep.equal([]);
  });
});

for (const O of [1, 2]) {
  describe(`v3 positives (--O${O})`, function () {
    let t;
    before(async function () {
      t = await compileV3(O);
    });

    it("the TEST-ONLY valid input satisfies every constraint", async function () {
      const w = await t.calculateWitness(valid.input, true);
      await t.checkConstraints(w);
    });

    it("a second valid credential (other secret/salt, same issuer) satisfies the circuit", async function () {
      const w = await t.calculateWitness(alt.input, true);
      await t.checkConstraints(w);
    });

    it("role 3 / clearance 3 (the other allowed values) satisfy the policy", async function () {
      const w = await t.calculateWitness(withInput(valid.input, { role: 3, clearance: 3 }), true);
      await t.checkConstraints(w);
    });

    it("the leaf at the other position (pathIndices [0, 1]) with its own root is accepted", async function () {
      const pathIndices = [0n, 1n];
      const pathElements = valid.input.pathElements.map(BigInt);
      const root = await merkleRoot(valid.commitment, pathElements, pathIndices);
      const w = await t.calculateWitness(withInput(valid.input, { pathIndices, root }), true);
      await t.checkConstraints(w);
    });
  });
}

for (const O of [1, 2]) {
  describe(`v3 negatives, input level (--O${O})`, function () {
    let t;
    const rejects = (input) => expectReject(t.calculateWitness(input, true), ASSERT);
    before(async function () {
      t = await compileV3(O);
    });

    // --- commitment: Poseidon(credentialSecret, credentialSalt) ---
    it("wrong credentialSecret is rejected", async function () {
      await rejects(withInput(valid.input, { credentialSecret: BigInt(valid.input.credentialSecret) + 1n }));
    });

    it("wrong credentialSalt is rejected", async function () {
      await rejects(withInput(valid.input, { credentialSalt: BigInt(valid.input.credentialSalt) + 1n }));
    });

    // --- M === credentialCommitment ---
    it("M != commitment (M = another commitment, validly signed by the same issuer) is rejected", async function () {
      const sig = await sign(valid.key, alt.commitment);
      await rejects(withInput(valid.input, { M: alt.commitment, ...sig }));
    });

    it("M != commitment (M + 1, original signature) is rejected", async function () {
      await rejects(withInput(valid.input, { M: valid.commitment + 1n }));
    });

    // --- leaf === credentialCommitment ---
    it("leaf != commitment (leaf = another commitment, with that leaf's own root) is rejected", async function () {
      const root = await merkleRoot(alt.commitment, valid.input.pathElements, valid.input.pathIndices);
      await rejects(withInput(valid.input, { leaf: alt.commitment, root }));
    });

    // --- EdDSA-Poseidon signature over M ---
    it("tampered S is rejected", async function () {
      await rejects(withInput(valid.input, { S: BigInt(valid.input.S) + 1n }));
    });

    it("tampered R8x is rejected", async function () {
      await rejects(withInput(valid.input, { R8x: BigInt(valid.input.R8x) + 1n }));
    });

    it("tampered R8y is rejected", async function () {
      await rejects(withInput(valid.input, { R8y: BigInt(valid.input.R8y) + 1n }));
    });

    it("signature by a different key presented with the original Ax/Ay is rejected", async function () {
      const other = await issuerKey("other-issuer");
      const sig = await sign(other, valid.commitment);
      await rejects(withInput(valid.input, sig));
    });

    it("malleated signature S + subgroup order is rejected (circomlib S < l check)", async function () {
      const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
      await rejects(withInput(valid.input, { S: BigInt(valid.input.S) + l }));
    });

    // --- Merkle membership ---
    it("wrong root is rejected", async function () {
      await rejects(withInput(valid.input, { root: BigInt(valid.input.root) + 1n }));
    });

    for (const i of [0, 1]) {
      it(`wrong sibling pathElements[${i}] is rejected`, async function () {
        const pathElements = valid.input.pathElements.map(BigInt);
        pathElements[i] += 1n;
        await rejects(withInput(valid.input, { pathElements }));
      });

      it(`pathIndices[${i}] = 2 is rejected (original root)`, async function () {
        const pathIndices = valid.input.pathIndices.map(BigInt);
        pathIndices[i] = 2n;
        await rejects(withInput(valid.input, { pathIndices }));
      });

      it(`pathIndices[${i}] = 2 is rejected even with the root recomputed for index 2 (boolean check)`, async function () {
        const pathIndices = valid.input.pathIndices.map(BigInt);
        pathIndices[i] = 2n;
        const root = await merkleRoot(valid.commitment, valid.input.pathElements, pathIndices);
        await rejects(withInput(valid.input, { pathIndices, root }));
      });
    }

    it("flipped pathIndices[0] (1 -> 0) with the original root is rejected", async function () {
      await rejects(withInput(valid.input, { pathIndices: [0n, BigInt(valid.input.pathIndices[1])] }));
    });

    // --- FileShareAccess policy ---
    for (const v of [0n, 2n]) {
      it(`deviceCompliant = ${v} is rejected`, async function () {
        await rejects(withInput(valid.input, { deviceCompliant: v }));
      });

      it(`employeeActive = ${v} is rejected`, async function () {
        await rejects(withInput(valid.input, { employeeActive: v }));
      });
    }

    for (const v of [0n, 1n, 4n, mod(-1n)]) {
      it(`role = ${v === mod(-1n) ? "p-1" : v} (outside {2,3}) is rejected`, async function () {
        await rejects(withInput(valid.input, { role: v }));
      });

      it(`clearance = ${v === mod(-1n) ? "p-1" : v} (outside {2,3}) is rejected`, async function () {
        await rejects(withInput(valid.input, { clearance: v }));
      });
    }
  });
}

describe("v3 negatives, witness level (--O0, exactly one violated row each)", function () {
  let t; // v3 at O0
  let ph; // Poseidon(2) harness at O0
  let W; // valid witness
  let A; // alt (second valid credential) witness

  before(async function () {
    [t, ph] = await Promise.all([compileV3(0), compilePoseidon2()]);
    W = new NamedWitness(t, await t.calculateWitness(valid.input, true));
    A = new NamedWitness(t, await t.calculateWitness(alt.input, true));
  });

  /** The edited witness violates exactly one R1CS row, and that row involves every `touches`. */
  async function expectOnly(nw, touches) {
    const v = await nw.violated();
    expect(v.length, `violated rows: ${JSON.stringify(v.map((r) => r.row))}`).to.equal(1);
    for (const name of [].concat(touches)) {
      expect(v[0].signals, `violated row should involve ${name}`).to.include(nw.idx(name));
    }
    await expectReject(t.checkConstraints(nw.w), CONSTRAINT);
  }

  /** Overwrite the Poseidon(2) component at `prefix` with an honest sub-witness for (a, b). */
  async function splicePoseidon(nw, prefix, a, b) {
    const hw = new NamedWitness(ph, await ph.calculateWitness({ inputs: [mod(a), mod(b)] }, true));
    const srcNames = Object.keys(ph.symbols);
    const dstNames = nw.namesUnder(prefix);
    expect(dstNames.length, `layout of ${prefix} vs harness`).to.equal(srcNames.length);
    for (const n of srcNames) nw.set(n.replace(/^main\./, prefix), hw.get(n));
    return hw.get("main.out");
  }

  /**
   * Recompute MerkleMembership levels with her formulas, optionally perturbing one value at one
   * level: left/right (the selector outputs), inL/inR (what the hasher receives), out (hashes[i+1]).
   */
  async function rebuildMerkle(nw, perturb = {}) {
    const m = "main.merkle.";
    for (let i = 0; i < 2; i++) {
      const p = perturb.level === i ? perturb : {};
      const h = nw.get(`${m}hashes[${i}]`);
      const s = nw.get(`${m}pathElements[${i}]`);
      const b = nw.get(`${m}pathIndices[${i}]`);
      let left = mod(h + b * (s - h));
      let right = mod(s + b * (h - s));
      if (p.left) left = mod(left + 1n);
      if (p.right) right = mod(right + 1n);
      nw.set(`${m}left[${i}]`, left).set(`${m}right[${i}]`, right);
      const inL = p.inL ? left + 1n : left;
      const inR = p.inR ? right + 1n : right;
      const out = await splicePoseidon(nw, `${m}hashers[${i}].`, inL, inR);
      nw.set(`${m}hashes[${i + 1}]`, p.out ? out + 1n : out);
    }
    const root = nw.get(`${m}hashes[2]`);
    nw.set(`${m}root`, root).set("main.root", root);
    return nw;
  }

  it("control: the untampered valid and alt witnesses violate no row", async function () {
    expect(await W.violated()).to.deep.equal([]);
    expect(await A.violated()).to.deep.equal([]);
  });

  it("control: rebuildMerkle without perturbation reproduces a valid witness", async function () {
    const nw = await rebuildMerkle(W.clone());
    expect(nw.w).to.deep.equal(W.w);
  });

  // --- integrated_access_v3.circom: commitment ---
  it("v3: commitmentHasher.inputs[0] <== credentialSecret (credentialSecret tampered)", async function () {
    await expectOnly(W.clone().add("main.credentialSecret"), "main.credentialSecret");
  });

  it("v3: commitmentHasher.inputs[1] <== credentialSalt (credentialSalt tampered)", async function () {
    await expectOnly(W.clone().add("main.credentialSalt"), "main.credentialSalt");
  });

  it("v3: credentialCommitment <== commitmentHasher.out (hasher computes another commitment)", async function () {
    const nw = W.clone().copyFrom(A, "main.commitmentHasher.", "main.credentialSecret", "main.credentialSalt");
    await expectOnly(nw, ["main.credentialCommitment", "main.commitmentHasher.out"]);
  });

  it("v3: M === credentialCommitment (M is another validly signed commitment)", async function () {
    const nw = W.clone().copyFrom(A, "main.M", "main.R8x", "main.R8y", "main.S", "main.signature.");
    await expectOnly(nw, ["main.M", "main.credentialCommitment"]);
  });

  it("v3: leaf === credentialCommitment (leaf is another member of a valid tree)", async function () {
    const nw = W.clone().copyFrom(A, "main.leaf", "main.merkle.", "main.root");
    await expectOnly(nw, ["main.leaf", "main.credentialCommitment"]);
  });

  // --- integrated_access_v3.circom: wiring into FileShareAccess ---
  for (const [sig, bad] of [
    ["role", 1n],
    ["clearance", 1n],
    ["deviceCompliant", 0n],
    ["employeeActive", 0n],
  ]) {
    it(`v3: policy.${sig} <== ${sig} (main.${sig} = ${bad}, policy sees the honest value)`, async function () {
      await expectOnly(W.clone().set(`main.${sig}`, bad), [`main.${sig}`, `main.policy.${sig}`]);
    });
  }

  // --- integrated_access_v3.circom: wiring into IssuerSignatureCheck ---
  for (const sig of ["Ax", "Ay", "R8x", "R8y", "S"]) {
    it(`v3: signature.${sig} <== ${sig} (main.${sig} tampered)`, async function () {
      await expectOnly(W.clone().add(`main.${sig}`), [`main.${sig}`, `main.signature.${sig}`]);
    });
  }

  it("v3: signature.M <== M (signature checks the honest commitment, main carries another)", async function () {
    const nw = A.clone().copyFrom(W, "main.signature.", "main.Ax", "main.Ay", "main.R8x", "main.R8y", "main.S");
    await expectOnly(nw, ["main.M", "main.signature.M"]);
  });

  // --- integrated_access_v3.circom: wiring into MerkleMembership ---
  it("v3: merkle.leaf <== leaf (tree proves the honest leaf, main carries another)", async function () {
    const nw = A.clone().copyFrom(W, "main.merkle.", "main.root");
    await expectOnly(nw, ["main.leaf", "main.merkle.leaf"]);
  });

  it("v3: merkle.root <== root (public root tampered)", async function () {
    await expectOnly(W.clone().add("main.root"), ["main.root", "main.merkle.root"]);
  });

  for (const i of [0, 1]) {
    it(`v3: merkle.pathElements[${i}] <== pathElements[${i}] (main copy tampered)`, async function () {
      const n = `main.pathElements[${i}]`;
      await expectOnly(W.clone().add(n), [n, `main.merkle.pathElements[${i}]`]);
    });

    it(`v3: merkle.pathIndices[${i}] <== pathIndices[${i}] (main copy flipped)`, async function () {
      const n = `main.pathIndices[${i}]`;
      await expectOnly(W.clone().set(n, 1n - W.get(n)), [n, `main.merkle.pathIndices[${i}]`]);
    });
  }

  // --- components/access_policy.circom: FileShareAccess ---
  for (const [sig, bad, constraint] of [
    ["deviceCompliant", 0n, "deviceCompliant === 1"],
    ["employeeActive", 0n, "employeeActive === 1"],
    ["role", 1n, "(role - 2) * (role - 3) === 0"],
    ["clearance", 4n, "(clearance - 2) * (clearance - 3) === 0"],
  ]) {
    it(`FileShareAccess: ${constraint} (${sig} = ${bad} in main and policy)`, async function () {
      const nw = W.clone().set(`main.${sig}`, bad).set(`main.policy.${sig}`, bad);
      await expectOnly(nw, `main.policy.${sig}`);
    });
  }

  for (const sig of ["deviceCompliant", "employeeActive"]) {
    it(`v3: ${sig} * (${sig} - 1) === 0 is implied by FileShareAccess ${sig} === 1 (equivalent mutant)`, async function () {
      // Documented, not a kill: the main-template boolean check on ${sig} can never be the ONLY
      // violated row, because any value that breaks it also breaks `${sig} === 1` in the policy
      // (or the policy wiring). Removing it admits no new witness, so no negative can kill it;
      // v3 keeps it as defence in depth. A value of 2 violates exactly these two rows; this
      // count is a change detector (removal makes it 1), not a security kill.
      const nw = W.clone().set(`main.${sig}`, 2n).set(`main.policy.${sig}`, 2n);
      const v = await nw.violated();
      expect(v.length).to.equal(2);
      expect(v.every((r) => r.signals.includes(nw.idx(`main.${sig}`)) || r.signals.includes(nw.idx(`main.policy.${sig}`)))).to.equal(true);
    });
  }

  // --- components/eddsa_verifier.circom: IssuerSignatureCheck ---
  it("IssuerSignatureCheck: verifier.enabled <== 1 (enabled forced to 0)", async function () {
    const v = "main.signature.verifier.";
    const nw = W.clone().set(`${v}enabled`, 0n).set(`${v}eqCheckX.enabled`, 0n).set(`${v}eqCheckY.enabled`, 0n);
    await expectOnly(nw, `${v}enabled`);
  });

  for (const sig of ["Ax", "Ay", "R8x", "R8y", "S"]) {
    it(`IssuerSignatureCheck: verifier.${sig} <== ${sig} (main and signature copies tampered)`, async function () {
      const nw = W.clone().add(`main.${sig}`).add(`main.signature.${sig}`);
      await expectOnly(nw, [`main.signature.${sig}`, `main.signature.verifier.${sig}`]);
    });
  }

  it("IssuerSignatureCheck: verifier.M <== M (verifier checks the honest commitment, signature.M is another)", async function () {
    const nw = A.clone().copyFrom(
      W,
      "main.signature.verifier.",
      ...["Ax", "Ay", "R8x", "R8y", "S"].flatMap((s) => [`main.${s}`, `main.signature.${s}`])
    );
    await expectOnly(nw, ["main.signature.M", "main.signature.verifier.M"]);
  });

  // --- components/merkle_membership.circom: MerkleMembership ---
  it("MerkleMembership: hashes[0] <== leaf (tree built over another leaf, leaf kept honest)", async function () {
    const m = "main.merkle.";
    const nw = W.clone().copyFrom(A, `${m}hashes[`, `${m}left[`, `${m}right[`, `${m}hashers[`, `${m}root`, "main.root");
    await expectOnly(nw, [`${m}hashes[0]`, `${m}leaf`]);
  });

  for (const i of [0, 1]) {
    const m = "main.merkle.";
    it(`MerkleMembership: pathIndices[${i}] * (pathIndices[${i}] - 1) === 0 (index 2, tree recomputed)`, async function () {
      const nw = W.clone().set(`main.pathIndices[${i}]`, 2n).set(`${m}pathIndices[${i}]`, 2n);
      await expectOnly(await rebuildMerkle(nw), `${m}pathIndices[${i}]`);
    });

    it(`MerkleMembership: left[${i}] <== hashes + idx*(sibling - hashes) (left perturbed, tree recomputed)`, async function () {
      await expectOnly(await rebuildMerkle(W.clone(), { level: i, left: true }), `${m}left[${i}]`);
    });

    it(`MerkleMembership: right[${i}] <== sibling + idx*(hashes - sibling) (right perturbed, tree recomputed)`, async function () {
      await expectOnly(await rebuildMerkle(W.clone(), { level: i, right: true }), `${m}right[${i}]`);
    });

    it(`MerkleMembership: hashers[${i}].inputs[0] <== left[${i}] (hasher fed another value)`, async function () {
      await expectOnly(await rebuildMerkle(W.clone(), { level: i, inL: true }), [`${m}left[${i}]`, `${m}hashers[${i}].inputs[0]`]);
    });

    it(`MerkleMembership: hashers[${i}].inputs[1] <== right[${i}] (hasher fed another value)`, async function () {
      await expectOnly(await rebuildMerkle(W.clone(), { level: i, inR: true }), [`${m}right[${i}]`, `${m}hashers[${i}].inputs[1]`]);
    });

    it(`MerkleMembership: hashes[${i + 1}] <== hashers[${i}].out (hash output replaced, tree recomputed)`, async function () {
      await expectOnly(await rebuildMerkle(W.clone(), { level: i, out: true }), [`${m}hashes[${i + 1}]`, `${m}hashers[${i}].out`]);
    });
  }

  it("MerkleMembership: hashes[2] === root (root and merkle.root tampered together)", async function () {
    const nw = W.clone().add("main.root").add("main.merkle.root");
    await expectOnly(nw, ["main.merkle.hashes[2]", "main.merkle.root"]);
  });
});

// GAP tests: these assert v3's INSECURE behaviour so a regression or a fix is visible. v3 keeps both
// gaps BY DESIGN (her circuit is unchanged; Orchestrator decision at G1-S1-CIRC-036), so they are
// NOT flipped: they stay passing for v3. The gaps are closed in v4, where the matching negatives
// live in v4.test.js ("tampered attribute ... ORIGINAL signature", "self-signed credential ...").
for (const O of [1, 2]) {
  describe(`v3 documented gaps (--O${O}) — INSECURE in v3 by design, closed in v4`, function () {
    let t;
    before(async function () {
      t = await compileV3(O);
    });

    it("GAP G-1 (v3 only, closed in v4 — see v4.test.js \"tampered attribute\"): attributes are not bound — changing role/clearance with the same signature still satisfies v3", async function () {
      // Same commitment, same issuer signature; only the claimed attributes change.
      for (const [role, clearance] of [
        [3n, 3n],
        [3n, 2n],
        [2n, 3n],
      ]) {
        const w = await t.calculateWitness(withInput(valid.input, { role, clearance }), true);
        await t.checkConstraints(w);
        expect(w[1].toString()).to.equal(valid.input.root);
      }
    });

    it("GAP G-2 (v3 only, closed in v4 — see v4.test.js \"self-signed\"): issuer key is a private input — a self-signed credential satisfies v3", async function () {
      // An attacker-held TEST-ONLY key signs the same commitment; the public signals are identical
      // to the honest proof's, so a verifier cannot tell which issuer signed.
      const attacker = await issuerKey("attacker");
      const sig = await sign(attacker, valid.commitment);
      const forged = withInput(valid.input, { Ax: attacker.Ax, Ay: attacker.Ay, ...sig });
      expect(forged.Ax).to.not.equal(valid.input.Ax);
      const w = await t.calculateWitness(forged, true);
      await t.checkConstraints(w);
      expect(w[1].toString()).to.equal(valid.input.root);
    });
  });
}
