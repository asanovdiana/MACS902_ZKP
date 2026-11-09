"use strict";
// Tests for the generic v4 access policy, circuits/components/access_policy_v4.circom
// (G1-S1-CIRC-033; contract `access.public_signals v4`, ADR 0007, ADR 0008).
//
// Tiers inside this file:
//   1. layout      - public/private input counts of the test main.
//   2. positives   - the contract's demo policies x personas give the contract's verdicts.
//   3. negatives   - input level: one rejected input per constraint (--O0 and --O2 builds), plus
//                    exhaustive mask/comparator tables.
//   4. negatives   - witness level (--O0): a valid witness is edited so that EXACTLY ONE R1CS row
//                    is violated and that row involves the targeted signal. Removing the source
//                    constraint (or weakening `<==` to `<--`) makes the edit acceptable, so each
//                    test kills that mutant (floor 1). Sub-witnesses for circomlib templates are
//                    spliced from standalone --O0 harness builds.
//
// All inputs are TEST-ONLY values; nothing is written to the repository.
const path = require("path");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { CIRCUITS, NODE_MODULES, BUILD, P, expectReject, r1csInfo, NamedWitness } = require("./helpers");

const MAIN = path.join(CIRCUITS, "test", "circuits", "access_policy_v4_main.circom");
const CIRCOMLIB = path.join(NODE_MODULES, "circomlib", "circuits");
const ASSERT = /Assert Failed/;

// ---- enums (ADR 0008) and demo policies (contract access.public_signals v4) ----
const ROLE = { engineer: 0, admin: 1, contractor: 2, finance: 3 };
const DEPT = { engineering: 0, it: 1, operations: 2, finance: 3 };

const PERSONAS = {
  alice: { role: ROLE.engineer, dept: DEPT.engineering, clearance: 2, deviceCompliant: 1, employeeActive: 1 },
  bob: { role: ROLE.contractor, dept: DEPT.operations, clearance: 1, deviceCompliant: 1, employeeActive: 1 },
  carol: { role: ROLE.admin, dept: DEPT.it, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
};

const POLICIES = {
  wiki: { roleMask: 15, deptMask: 15, minClearance: 0, requireDevice: 1 },
  fileShare: { roleMask: 3, deptMask: 15, minClearance: 2, requireDevice: 0 },
  adminPanel: { roleMask: 2, deptMask: 15, minClearance: 3, requireDevice: 1 },
};

const EXPECTED = {
  wiki: { alice: true, bob: true, carol: true },
  fileShare: { alice: true, bob: false, carol: true },
  adminPanel: { alice: false, bob: false, carol: true },
};

const input = (persona, policy, over = {}) => ({ ...persona, ...policy, ...over });

// ---- builds (memoised per process; always recompiled so a stale build cannot hide a change) ----
const builds = new Map();
function build(name, file, options = {}) {
  if (!builds.has(name)) {
    builds.set(
      name,
      (async () => {
        const t = await wasmTester(file, { output: path.join(BUILD, name), recompile: true, ...options });
        await t.loadSymbols();
        return t;
      })()
    );
  }
  return builds.get(name);
}
const policy = (O) => build(`policy-v4-O${O}`, MAIN, { O });
const harness = (template, params) =>
  build(`policy-v4-h-${template}-${params.join("_")}`, path.join(CIRCOMLIB, template === "Mux2" ? "mux2.circom" : template === "Num2Bits" ? "bitify.circom" : "comparators.circom"), {
    O: 0,
    templateName: template,
    templateParams: params,
  });

/** Overwrite every signal under `prefix` with an honest sub-witness of `template(params)` on `inp`. */
async function splice(nw, prefix, template, params, inp) {
  const h = await harness(template, params);
  const w = await h.calculateWitness(inp, true);
  for (const [name, sym] of Object.entries(h.symbols)) {
    if (!name.startsWith("main.")) continue;
    nw.set(prefix + name.slice("main".length), w[sym.varIdx]);
  }
  return nw;
}

async function validWitness(inp) {
  const t = await policy(0);
  const nw = new NamedWitness(t, await t.calculateWitness(inp, true));
  expect(await nw.violated(), "base witness must be valid").to.deep.equal([]);
  return nw;
}

async function expectOneViolatedRow(nw, target) {
  const rows = await nw.violated();
  expect(rows, JSON.stringify(rows)).to.have.length(1);
  expect(rows[0].signals).to.include(nw.idx(target));
}

// ---------------------------------------------------------------------------------------------

describe("policy v4 layout", function () {
  for (const O of [0, 2]) {
    it(`--O${O}: 4 public inputs (policy fields), 5 private attributes, no outputs`, async function () {
      const info = await r1csInfo(await policy(O));
      expect(info.nPubInputs).to.equal(4);
      expect(info.nPrvInputs).to.equal(5);
      expect(info.nOutputs).to.equal(0);
    });
  }

  // Measured with circom 2.2.3 + circomlib 2.0.5 (budget input for the v4 main, CIRC-036).
  const COUNTS = { 0: { nonLinear: 29, linear: 54 }, 2: { nonLinear: 28, linear: 0 } };
  for (const O of [0, 2]) {
    it(`constraint count at --O${O}: ${COUNTS[O].nonLinear} non-linear + ${COUNTS[O].linear} linear`, async function () {
      const info = await r1csInfo(await policy(O));
      expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(COUNTS[O]);
    });
  }

  it("public inputs are witness slots 1..4 in declaration order", async function () {
    const t = await policy(2);
    expect(["roleMask", "deptMask", "minClearance", "requireDevice"].map((n) => t.symbols[`main.${n}`].varIdx)).to.deep.equal([1, 2, 3, 4]);
  });
});

for (const O of [0, 2]) {
  describe(`policy v4 positives: demo policies x personas (--O${O})`, function () {
    let t;
    before(async function () {
      t = await policy(O);
    });

    for (const [pName, pol] of Object.entries(POLICIES)) {
      for (const [who, persona] of Object.entries(PERSONAS)) {
        const allow = EXPECTED[pName][who];
        it(`${pName} ${allow ? "admits" : "denies"} ${who}`, async function () {
          const run = t.calculateWitness(input(persona, pol), true);
          if (allow) await t.checkConstraints(await run);
          else await expectReject(run, ASSERT);
        });
      }
    }

    it("fileShare (requireDevice 0) admits alice with a non-compliant device", async function () {
      await t.checkConstraints(await t.calculateWitness(input(PERSONAS.alice, POLICIES.fileShare, { deviceCompliant: 0 }), true));
    });

    it("clearance equal to minClearance is admitted (>=, not >)", async function () {
      await t.checkConstraints(await t.calculateWitness(input(PERSONAS.carol, POLICIES.adminPanel, { clearance: 3 }), true));
      await t.checkConstraints(await t.calculateWitness(input(PERSONAS.alice, POLICIES.fileShare, { clearance: 2 }), true));
    });
  });
}

for (const O of [0, 2]) {
  describe(`policy v4 negatives, input level (--O${O})`, function () {
    let t;
    const rejects = (over, persona = PERSONAS.alice, pol = POLICIES.wiki) =>
      expectReject(t.calculateWitness(input(persona, pol, over), true), ASSERT);
    before(async function () {
      t = await policy(O);
    });

    it("role bit unset in roleMask is rejected (engineer vs 0b1110)", async function () {
      await rejects({ roleMask: 0b1110 });
    });
    it("dept bit unset in deptMask is rejected (operations vs 0b1011)", async function () {
      await rejects({ deptMask: 0b1011 }, PERSONAS.bob);
    });
    it("clearance one below minClearance is rejected", async function () {
      await rejects({ clearance: 1 }, PERSONAS.alice, POLICIES.fileShare);
      await rejects({ clearance: 2 }, PERSONAS.carol, POLICIES.adminPanel);
    });
    it("device required but not compliant is rejected", async function () {
      await rejects({ deviceCompliant: 0 });
    });
    it("employeeActive 0 is rejected under every demo policy", async function () {
      for (const pol of Object.values(POLICIES)) await rejects({ employeeActive: 0 }, PERSONAS.carol, pol);
    });
    it("employeeActive 2 is rejected (must be exactly 1)", async function () {
      await rejects({ employeeActive: 2 });
    });
    it("roleMask 16 and 17 (>= 2^4) are rejected", async function () {
      await rejects({ roleMask: 16 });
      await rejects({ roleMask: 17 });
    });
    it("deptMask 16 and 31 (>= 2^4) are rejected", async function () {
      await rejects({ deptMask: 16 });
      await rejects({ deptMask: 31 });
    });
    it("minClearance 4 and p-1 are rejected", async function () {
      await rejects({ clearance: 3, minClearance: 4 }, PERSONAS.carol);
      await rejects({ clearance: 0, minClearance: (P - 1n).toString() });
    });
    it("requireDevice 2 and p-1 are rejected", async function () {
      await rejects({ requireDevice: 2 });
      await rejects({ requireDevice: (P - 1n).toString() });
    });
    it("out-of-range attributes (role 4, dept 4, clearance 4, clearance p-1) are rejected", async function () {
      await rejects({ role: 4 });
      await rejects({ dept: 4 });
      await rejects({ clearance: 4 });
      await rejects({ clearance: (P - 1n).toString() });
    });
    it("roleMask 0 admits nobody", async function () {
      for (const persona of Object.values(PERSONAS)) await rejects({ roleMask: 0 }, persona);
    });

    if (O === 2) {
      it("exhaustive: (value, mask) for value 0..3, mask 0..15 is admitted iff bit `value` of mask is set (role and dept)", async function () {
        for (const field of ["role", "dept"]) {
          const maskField = `${field}Mask`;
          for (let v = 0; v < 4; v++) {
            for (let m = 0; m < 16; m++) {
              const run = t.calculateWitness(input(PERSONAS.alice, POLICIES.wiki, { [field]: v, [maskField]: m }), true);
              if ((m >> v) & 1) await t.checkConstraints(await run);
              else await expectReject(run, ASSERT);
            }
          }
        }
      });
      it("exhaustive: clearance x minClearance in 0..3 is admitted iff clearance >= minClearance", async function () {
        for (let c = 0; c < 4; c++) {
          for (let m = 0; m < 4; m++) {
            const run = t.calculateWitness(input(PERSONAS.alice, POLICIES.wiki, { clearance: c, minClearance: m }), true);
            if (c >= m) await t.checkConstraints(await run);
            else await expectReject(run, ASSERT);
          }
        }
      });
    }
  });
}

describe("policy v4 negatives, witness level (--O0, exactly one violated row)", function () {
  const base = (over) => input(PERSONAS.alice, POLICIES.wiki, over);

  // Recompute a selector Mux2 named `sel` over bits `c` with selector bits `s`.
  const mux = (nw, sel, c, s) => splice(nw, `main.${sel}`, "Mux2", [], { c, s });

  for (const f of ["role", "dept"]) {
    const bits = `${f}Bits`;
    const maskBits = `${f}MaskBits`;
    const sel = `${f}Sel`;
    const maskName = `${f}Mask`;

    it(`${bits}.in <== ${f}: the attribute differs from the value whose bits select the mask bit`, async function () {
      const nw = await validWitness(base({ [f]: 0, [maskName]: 1 }));
      nw.set(`main.${f}`, 1);
      await expectOneViolatedRow(nw, `main.${f}`);
    });

    it(`${maskBits}.in <== ${maskName}: the public mask differs from the bits the mux reads`, async function () {
      const nw = await validWitness(base({ [f]: 0, [maskName]: 1 }));
      nw.set(`main.${maskName}`, 2);
      await expectOneViolatedRow(nw, `main.${maskName}`);
    });

    for (let k = 0; k < 4; k++) {
      it(`${sel}.c[${k}] <== ${maskBits}.out[${k}]: unset mask bit ${k} fed to the mux as 1`, async function () {
        // honest: f = k, mask 15; attack: mask bit k cleared, mux input c[k] still 1
        const nw = await validWitness(base({ [f]: k, [maskName]: 15 }));
        nw.set(`main.${maskName}`, 15 - (1 << k));
        await splice(nw, `main.${maskBits}`, "Num2Bits", [4], { in: 15 - (1 << k) });
        await expectOneViolatedRow(nw, `main.${sel}.c[${k}]`);
      });
    }

    for (const j of [0, 1]) {
      it(`${sel}.s[${j}] <== ${bits}.out[${j}]: the mux selects a set bit other than bit ${f}`, async function () {
        // mask 0b1101 has bit 1 unset only when j = 0; mask 0b1011 has bit 2 unset when j = 1.
        const m = j === 0 ? 0b1101 : 0b1011;
        const nw = await validWitness(base({ [f]: 0, [maskName]: m }));
        const v = 1 << j; // the claimed value, whose mask bit is unset
        nw.set(`main.${f}`, v);
        await splice(nw, `main.${bits}`, "Num2Bits", [2], { in: v });
        await expectOneViolatedRow(nw, `main.${sel}.s[${j}]`);
      });
    }

    it(`${sel}.out === 1: the selected mask bit is 0`, async function () {
      const nw = await validWitness(base({ [f]: 0, [maskName]: 1 }));
      nw.set(`main.${f}`, 1);
      await splice(nw, `main.${bits}`, "Num2Bits", [2], { in: 1 });
      await mux(nw, sel, [1, 0, 0, 0], [1, 0]);
      expect(nw.get(`main.${sel}.out`)).to.equal(0n);
      await expectOneViolatedRow(nw, `main.${sel}.out`);
    });
  }

  it("clearanceBits.in <== clearance: clearance 5 passes the 2-bit comparator without the range check", async function () {
    const nw = await validWitness(base({ clearance: 3, minClearance: 3 }));
    nw.set("main.clearance", 5);
    await splice(nw, "main.clearanceOk", "GreaterEqThan", [2], { in: [5, 3] });
    expect(nw.get("main.clearanceOk.out")).to.equal(1n);
    await expectOneViolatedRow(nw, "main.clearance");
  });

  it("minClearanceBits.in <== minClearance: minClearance p-1 passes the 2-bit comparator without the range check", async function () {
    const nw = await validWitness(base({ clearance: 0, minClearance: 0 }));
    nw.set("main.minClearance", P - 1n);
    await splice(nw, "main.clearanceOk", "GreaterEqThan", [2], { in: ["0", (P - 1n).toString()] });
    expect(nw.get("main.clearanceOk.out")).to.equal(1n);
    await expectOneViolatedRow(nw, "main.minClearance");
  });

  it("clearanceOk.in[0] <== clearance: the comparator sees 3 while the attribute is 1", async function () {
    const nw = await validWitness(base({ clearance: 3, minClearance: 3 }));
    nw.set("main.clearance", 1);
    await splice(nw, "main.clearanceBits", "Num2Bits", [2], { in: 1 });
    await expectOneViolatedRow(nw, "main.clearanceOk.in[0]");
  });

  it("clearanceOk.in[1] <== minClearance: the comparator sees 2 while the policy says 3", async function () {
    const nw = await validWitness(base({ clearance: 2, minClearance: 2 }));
    nw.set("main.minClearance", 3);
    await splice(nw, "main.minClearanceBits", "Num2Bits", [2], { in: 3 });
    await expectOneViolatedRow(nw, "main.clearanceOk.in[1]");
  });

  it("clearanceOk.out === 1: clearance 1 below minClearance 3", async function () {
    const nw = await validWitness(base({ clearance: 3, minClearance: 3 }));
    nw.set("main.clearance", 1);
    await splice(nw, "main.clearanceBits", "Num2Bits", [2], { in: 1 });
    await splice(nw, "main.clearanceOk", "GreaterEqThan", [2], { in: [1, 3] });
    expect(nw.get("main.clearanceOk.out")).to.equal(0n);
    await expectOneViolatedRow(nw, "main.clearanceOk.out");
  });

  it("requireDevice boolean: requireDevice 2 with a compliant device", async function () {
    const nw = await validWitness(base({ requireDevice: 1, deviceCompliant: 1 }));
    nw.set("main.requireDevice", 2);
    await expectOneViolatedRow(nw, "main.requireDevice");
  });

  it("requireDevice * (1 - deviceCompliant) === 0: device required, not compliant", async function () {
    const nw = await validWitness(base({ requireDevice: 1, deviceCompliant: 1 }));
    nw.set("main.deviceCompliant", 0);
    await expectOneViolatedRow(nw, "main.deviceCompliant");
  });

  it("employeeActive === 1: inactive employee", async function () {
    const nw = await validWitness(base());
    nw.set("main.employeeActive", 0);
    await expectOneViolatedRow(nw, "main.employeeActive");
  });
});
