"use strict";
// Tests for circuits/components/challenge_binding.circom (G1-S1-CIRC-035), through the TEST-ONLY
// main circuits/test/circuits/challenge_binding_main.circom (public nonce, resourceId, epoch in
// v4 declaration order; output nullifier).
//
// Tiers:
//   1. layout     - public-signal slots, R1CS header, constraint counts, every public input in a row
//   2. positives  - nullifier = circomlibjs Poseidon(3)(secret, resourceId, epoch); determinism;
//                   unlinkability across resourceId / epoch / secret; nonce does not move it
//   3. negatives  - witness level (--O0 build): a valid witness is edited so that EXACTLY ONE
//                   R1CS row is violated and that row touches the targeted signal, so removing the
//                   matching source constraint (or `<==` -> `<--`) is caught (floor 1).
//
// Groth16-level binding (a proof with any public signal changed fails verify) is G1-S1-CIRC-037's
// job, against the v4 key; here the claim is proven at the R1CS level.
//
// All values are TEST-ONLY, derived from public labels; nothing is written to the repository.
const path = require("path");
const crypto = require("crypto");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");
const { BUILD, CIRCUITS, P, mod, r1csInfo, NamedWitness } = require("./helpers");

const MAIN = path.join(CIRCUITS, "test", "circuits", "challenge_binding_main.circom");

// circom 2.2.3 + circomlib 2.0.5. Poseidon(3) + CB1 (nonceSquared). Change deliberately.
const EXPECTED_COUNTS = {
  0: { nonLinear: 265, linear: 671 },
  2: { nonLinear: 262, linear: 0 }, // Poseidon(3) 261 + nonceSquared 1
};

const builds = new Map();
function compile(O) {
  if (!builds.has(O)) {
    builds.set(
      O,
      (async () => {
        const t = await wasmTester(MAIN, {
          output: path.join(BUILD, `challenge-binding-O${O}`),
          recompile: true,
          O,
        });
        await t.loadSymbols();
        return t;
      })()
    );
  }
  return builds.get(O);
}

/** TEST-ONLY field element from a public label (31 bytes, < p). */
function seed(label) {
  const d = crypto.createHash("sha256").update("zk-access-gate/TEST-ONLY/cb/" + label).digest();
  return BigInt("0x" + d.subarray(0, 31).toString("hex"));
}

const SECRET = seed("secret");
const OTHER_SECRET = seed("other-secret");
const NONCE = seed("nonce") >> 120n; // the gateway issues 128 random bits
const EPOCH = BigInt(Math.floor(1794000000 / 600)); // floor(t / 600)

function input({ secret = SECRET, nonce = NONCE, resourceId = 1n, epoch = EPOCH } = {}) {
  return {
    credentialSecret: secret.toString(),
    nonce: nonce.toString(),
    resourceId: resourceId.toString(),
    epoch: epoch.toString(),
  };
}

let poseidon;
let F;
function H3(a, b, c) {
  return F.toObject(poseidon([mod(a), mod(b), mod(c)]));
}

before(async function () {
  poseidon = await buildPoseidon();
  F = poseidon.F;
});

describe("challenge binding layout", function () {
  for (const O of [0, 2]) {
    describe(`--O${O}`, function () {
      let t;
      before(async function () {
        t = await compile(O);
      });

      it("3 public inputs, 1 output, 1 private input", async function () {
        const info = await r1csInfo(t);
        expect(info.nPubInputs).to.equal(3);
        expect(info.nOutputs).to.equal(1);
        expect(info.nPrvInputs).to.equal(1);
      });

      it("public slots are [nullifier, nonce, resourceId, epoch] (v4 slots 0, 9, 10, 11)", async function () {
        const slots = ["main.nullifier", "main.nonce", "main.resourceId", "main.epoch"].map(
          (n) => t.symbols[n].varIdx
        );
        expect(slots).to.deep.equal([1, 2, 3, 4]);
      });

      it(`constraint count at --O${O}: ${EXPECTED_COUNTS[O].nonLinear} non-linear + ${EXPECTED_COUNTS[O].linear} linear`, async function () {
        const info = await r1csInfo(t);
        expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(EXPECTED_COUNTS[O]);
      });

      it("every public input (nonce, resourceId, epoch) appears in at least one R1CS row", async function () {
        await t.loadConstraints();
        const used = new Set();
        for (const [a, b, c] of t.constraints) {
          for (const lc of [a, b, c]) for (const k of Object.keys(lc)) used.add(Number(k));
        }
        for (const slot of [2, 3, 4]) expect(used.has(slot), `slot ${slot}`).to.equal(true);
      });
    });
  }
});

describe("challenge binding positives", function () {
  let t;
  before(async function () {
    t = await compile(2);
  });

  async function nullifierOf(inp) {
    const w = await t.calculateWitness(inp, true);
    await t.checkConstraints(w);
    return BigInt(w[1]);
  }

  it("nullifier equals circomlibjs Poseidon(3)(credentialSecret, resourceId, epoch)", async function () {
    for (const resourceId of [1n, 2n, 3n]) {
      const n = await nullifierOf(input({ resourceId }));
      expect(n).to.equal(H3(SECRET, resourceId, EPOCH));
    }
  });

  it("argument order is (secret, resourceId, epoch): not a permutation", async function () {
    const n = await nullifierOf(input({ resourceId: 2n }));
    expect(n).to.not.equal(H3(SECRET, EPOCH, 2n));
    expect(n).to.not.equal(H3(2n, SECRET, EPOCH));
  });

  it("public outputs/inputs come back unchanged in the witness", async function () {
    const w = await t.calculateWitness(input({ resourceId: 3n }), true);
    expect(w.slice(2, 5).map(String)).to.deep.equal([NONCE, 3n, EPOCH].map(String));
  });

  it("same secret + resourceId + epoch gives the same nullifier (rate-limit key is stable)", async function () {
    const a = await nullifierOf(input());
    const b = await nullifierOf(input());
    expect(a).to.equal(b);
  });

  it("nonce does not change the nullifier", async function () {
    const a = await nullifierOf(input({ nonce: 1n }));
    const b = await nullifierOf(input({ nonce: NONCE }));
    const c = await nullifierOf(input({ nonce: P - 1n }));
    expect(a).to.equal(b);
    expect(b).to.equal(c);
  });

  it("unlinkability: different resourceId gives unrelated nullifiers", async function () {
    const ns = [];
    for (const resourceId of [1n, 2n, 3n]) ns.push(await nullifierOf(input({ resourceId })));
    expect(new Set(ns.map(String)).size).to.equal(3);
  });

  it("different epoch gives a different nullifier", async function () {
    const a = await nullifierOf(input({ epoch: EPOCH }));
    const b = await nullifierOf(input({ epoch: EPOCH + 1n }));
    expect(a).to.not.equal(b);
  });

  it("different secret gives a different nullifier (same resource, same epoch)", async function () {
    const a = await nullifierOf(input());
    const b = await nullifierOf(input({ secret: OTHER_SECRET }));
    expect(a).to.not.equal(b);
  });

  it("edge values (0 and p-1) are accepted: no in-circuit range on nonce/resourceId/epoch", async function () {
    const n = await nullifierOf(input({ nonce: 0n, resourceId: 0n, epoch: P - 1n }));
    expect(n).to.equal(H3(SECRET, 0n, P - 1n));
  });
});

describe("challenge binding negatives (witness level, --O0)", function () {
  let t;
  let base; // NamedWitness of a valid input

  before(async function () {
    t = await compile(0);
    base = new NamedWitness(t, await t.calculateWitness(input({ resourceId: 2n }), true));
    await t.checkConstraints(base.w);
  });

  /** Exactly one violated row, and it touches `name`. */
  async function expectOneRow(nw, name) {
    const rows = await nw.violated();
    expect(rows, JSON.stringify(rows)).to.have.length(1);
    expect(rows[0].signals).to.include(nw.idx(name));
    let err;
    try {
      await t.checkConstraints(nw.w);
    } catch (e) {
      err = e;
    }
    expect(err, "checkConstraints accepted a tampered witness").to.not.equal(undefined);
  }

  it("CB5: overwritten nullifier is rejected", async function () {
    await expectOneRow(base.clone().add("main.nullifier"), "main.nullifier");
  });

  it("CB5: a nullifier for another resourceId is rejected", async function () {
    await expectOneRow(base.clone().set("main.nullifier", H3(SECRET, 1n, EPOCH)), "main.nullifier");
  });

  it("CB1: overwritten nonceSquared is rejected", async function () {
    await expectOneRow(base.clone().add("main.nonceSquared"), "main.nonceSquared");
  });

  it("CB1: public nonce changed after witness generation is rejected", async function () {
    await expectOneRow(base.clone().add("main.nonce"), "main.nonce");
  });

  it("CB3: public resourceId changed after witness generation is rejected", async function () {
    await expectOneRow(base.clone().set("main.resourceId", 1n), "main.resourceId");
  });

  it("CB4: public epoch changed after witness generation is rejected", async function () {
    await expectOneRow(base.clone().add("main.epoch"), "main.epoch");
  });

  it("CB2: credentialSecret changed after witness generation is rejected", async function () {
    await expectOneRow(base.clone().set("main.credentialSecret", OTHER_SECRET), "main.credentialSecret");
  });
});

// The --O2 build is the one trusted setup uses. Linear constraints are substituted away there, so a
// binding that is only linear (e.g. a mutant `nonceSquared <== nonce`) leaves the public wire in no
// row and survives every --O0 test. These edit the public slots of an --O2 witness directly.
// (The circuit R1CS only: snarkjs `zkey new` still adds an input-binding row per public signal, so
// such a proof stays bound to its nonce under snarkjs; the in-circuit binding is defence in depth, SR-11.)
describe("challenge binding negatives (public slots, --O2)", function () {
  let t;
  let w;

  before(async function () {
    t = await compile(2);
    w = (await t.calculateWitness(input({ resourceId: 2n }), true)).map(BigInt);
    await t.checkConstraints(w);
  });

  const SLOTS = { nullifier: 1, nonce: 2, resourceId: 3, epoch: 4 };
  for (const [name, slot] of Object.entries(SLOTS)) {
    it(`--O2: public ${name} changed after witness generation is rejected`, async function () {
      const bad = w.slice();
      bad[slot] = mod(bad[slot] + 1n);
      let err;
      try {
        await t.checkConstraints(bad);
      } catch (e) {
        err = e;
      }
      expect(err, `--O2 accepted a witness with ${name} changed`).to.not.equal(undefined);
    });
  }
});
