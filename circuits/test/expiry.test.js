"use strict";
// Tests for circuits/components/expiry.circom (G1-S1-CIRC-034; contract `credential v4`:
// `expiry` and `now` range-checked to 64 bits, `expiry > now` strictly).
//
// Tiers: layout; positives; input-level negatives (--O0 and --O2); witness-level negatives (--O0)
// that violate EXACTLY ONE R1CS row involving the targeted signal (see policy_v4.test.js), so each
// kills the matching constraint-removal / `<==`->`<--` mutant (floor 1).
const path = require("path");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { CIRCUITS, NODE_MODULES, BUILD, P, expectReject, r1csInfo, NamedWitness } = require("./helpers");

const MAIN = path.join(CIRCUITS, "test", "circuits", "expiry_main.circom");
const CIRCOMLIB = path.join(NODE_MODULES, "circomlib", "circuits");
const ASSERT = /Assert Failed/;

const TWO64 = 1n << 64n;
const NOW = 1_700_000_000n; // TEST-ONLY timestamps
const DAY = 86_400n;
const inp = (expiry, now) => ({ expiry: expiry.toString(), now: now.toString() });

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
const expiryMain = (O) => build(`expiry-O${O}`, MAIN, { O });
const harness = (template, params) =>
  build(`expiry-h-${template}-${params.join("_")}`, path.join(CIRCOMLIB, template === "Num2Bits" ? "bitify.circom" : "comparators.circom"), {
    O: 0,
    templateName: template,
    templateParams: params,
  });

async function splice(nw, prefix, template, params, input) {
  const h = await harness(template, params);
  const w = await h.calculateWitness(input, true);
  for (const [name, sym] of Object.entries(h.symbols)) {
    if (!name.startsWith("main.")) continue;
    nw.set(prefix + name.slice("main".length), w[sym.varIdx]);
  }
  return nw;
}

async function validWitness(expiry, now) {
  const t = await expiryMain(0);
  const nw = new NamedWitness(t, await t.calculateWitness(inp(expiry, now), true));
  expect(await nw.violated(), "base witness must be valid").to.deep.equal([]);
  return nw;
}

async function expectOneViolatedRow(nw, target) {
  const rows = await nw.violated();
  expect(rows, JSON.stringify(rows)).to.have.length(1);
  expect(rows[0].signals).to.include(nw.idx(target));
}

describe("expiry layout", function () {
  for (const O of [0, 2]) {
    it(`--O${O}: 1 public input (now), 1 private input (expiry), no outputs`, async function () {
      const info = await r1csInfo(await expiryMain(O));
      expect(info.nPubInputs).to.equal(1);
      expect(info.nPrvInputs).to.equal(1);
      expect(info.nOutputs).to.equal(0);
    });
  }

  // Measured with circom 2.2.3 + circomlib 2.0.5 (budget input for the v4 main, CIRC-036).
  const COUNTS = { 0: { nonLinear: 193, linear: 10 }, 2: { nonLinear: 192, linear: 0 } };
  for (const O of [0, 2]) {
    it(`constraint count at --O${O}: ${COUNTS[O].nonLinear} non-linear + ${COUNTS[O].linear} linear`, async function () {
      const info = await r1csInfo(await expiryMain(O));
      expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(COUNTS[O]);
    });
  }
});

for (const O of [0, 2]) {
  describe(`expiry positives (--O${O})`, function () {
    let t;
    before(async function () {
      t = await expiryMain(O);
    });
    const accepts = async (e, n) => t.checkConstraints(await t.calculateWitness(inp(e, n), true));

    it("a credential valid for a day is accepted", async function () {
      await accepts(NOW + DAY, NOW);
    });
    it("expiry = now + 1 is accepted (strict >)", async function () {
      await accepts(NOW + 1n, NOW);
    });
    it("boundaries: (expiry 1, now 0) and (expiry 2^64-1, now 2^64-2) are accepted", async function () {
      await accepts(1n, 0n);
      await accepts(TWO64 - 1n, TWO64 - 2n);
      await accepts(TWO64 - 1n, 0n);
    });
  });

  describe(`expiry negatives, input level (--O${O})`, function () {
    let t;
    before(async function () {
      t = await expiryMain(O);
    });
    const rejects = (e, n) => expectReject(t.calculateWitness(inp(e, n), true), ASSERT);

    it("expiry == now is rejected (expired at that second)", async function () {
      await rejects(NOW, NOW);
      await rejects(0n, 0n);
    });
    it("expiry < now is rejected", async function () {
      await rejects(NOW - 1n, NOW);
      await rejects(0n, 1n);
      await rejects(TWO64 - 2n, TWO64 - 1n);
    });
    it("expiry >= 2^64 is rejected (2^64, now + 2^64, p-1)", async function () {
      await rejects(TWO64, NOW);
      await rejects(NOW + TWO64, NOW);
      await rejects(P - 1n, NOW);
    });
    it("now >= 2^64 is rejected (2^64 with expiry 2^64+1, p-1)", async function () {
      await rejects(TWO64 + 1n, TWO64);
      await rejects(NOW, P - 1n);
    });
    it("field alias expiry = now - 1 + p is rejected", async function () {
      await rejects(NOW - 1n + P, NOW);
    });
  });
}

describe("expiry negatives, witness level (--O0, exactly one violated row)", function () {
  it("expiryBits.in <== expiry: expiry = now + 2^64 passes LessThan(64) without the range check", async function () {
    const nw = await validWitness(NOW + DAY, NOW);
    const e = NOW + TWO64;
    nw.set("main.expiry", e);
    await splice(nw, "main.notExpired", "LessThan", [64], { in: [NOW.toString(), e.toString()] });
    expect(nw.get("main.notExpired.out")).to.equal(1n);
    await expectOneViolatedRow(nw, "main.expiry");
  });

  it("nowBits.in <== now: now = p-1 passes LessThan(64) without the range check", async function () {
    const nw = await validWitness(NOW + DAY, NOW);
    nw.set("main.now", P - 1n);
    await splice(nw, "main.notExpired", "LessThan", [64], { in: [(P - 1n).toString(), (NOW + DAY).toString()] });
    expect(nw.get("main.notExpired.out")).to.equal(1n);
    await expectOneViolatedRow(nw, "main.now");
  });

  it("notExpired.in[0] <== now: the comparator sees an older now than the public one", async function () {
    const nw = await validWitness(NOW + DAY, NOW);
    const later = NOW + 2n * DAY;
    nw.set("main.now", later);
    await splice(nw, "main.nowBits", "Num2Bits", [64], { in: later.toString() });
    await expectOneViolatedRow(nw, "main.notExpired.in[0]");
  });

  it("notExpired.in[1] <== expiry: the comparator sees a later expiry than the attribute", async function () {
    const nw = await validWitness(NOW + DAY, NOW);
    const past = NOW - DAY;
    nw.set("main.expiry", past);
    await splice(nw, "main.expiryBits", "Num2Bits", [64], { in: past.toString() });
    await expectOneViolatedRow(nw, "main.notExpired.in[1]");
  });

  it("notExpired.out === 1: an expired credential", async function () {
    const nw = await validWitness(NOW + DAY, NOW);
    const past = NOW - DAY;
    nw.set("main.expiry", past);
    await splice(nw, "main.expiryBits", "Num2Bits", [64], { in: past.toString() });
    await splice(nw, "main.notExpired", "LessThan", [64], { in: [NOW.toString(), past.toString()] });
    expect(nw.get("main.notExpired.out")).to.equal(0n);
    await expectOneViolatedRow(nw, "main.notExpired.out");
  });
});
