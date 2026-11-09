"use strict";
// G1-S1-CIRC-032: SignaturePointsOnCurve() (circuits/components/issuer_key.circom) and the
// public issuer key (credential v4, access.public_signals v4 slots 2-3; closes gap G-2).
//
//   1. layout   - 4 private inputs, 6 non-linear rows (two circomlib BabyCheck)
//   2. on-curve - valid key / R8 / base point accepted; off-curve key or R8 rejected
//   3. witness  - (--O0) exactly one violated R1CS row per wiring line (floor 1)
//   4. G-2 fix  - test main signed_attributes.circom: issuerAx/issuerAy are PUBLIC and feed both
//                 her IssuerSignatureCheck and the on-curve check. A self-signed credential only
//                 satisfies the circuit with the FORGER's key in the public signals, so a gateway
//                 that pins the issuer key (gateway obligation 2) rejects it; the forger's
//                 signature under the pinned key does not satisfy the circuit at all (floor 2).
//
// In-circuit part of the fix: the issuer key is a public input wired into the verifier. The pin
// itself is a gateway check on publicSignals[2..3]; `gatewayAdmits` below models only that check.
// All keys are TEST-ONLY (fixtures.js labels).
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { buildBabyjub, buildPoseidon } = require("circomlibjs");
const { CIRCUITS, expectReject, r1csInfo, NamedWitness, mod } = require("./helpers");
const { H, seedField, issuerKey, sign } = require("./fixtures");

const ASSERT = /Assert Failed/;
const CONSTRAINT = /Constraint doesn't match/;
const MAINS = path.join(__dirname, "circuits");
const COMPONENTS = path.join(CIRCUITS, "components");
const KEY_SOURCES = [path.join(COMPONENTS, "issuer_key.circom")];
const SIGNED_SOURCES = [
  path.join(COMPONENTS, "attribute_hash.circom"),
  path.join(COMPONENTS, "eddsa_verifier.circom"),
  ...KEY_SOURCES,
];

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
const compilePoints = (O) =>
  compile(`bb-signature-points-O${O}`, path.join(MAINS, "signature_points.circom"), KEY_SOURCES, { O });
// Same build name as attribute_hash.test.js: one shared build per process is fine, the stamp
// covers the same sources either way.
const compileSigned = (O) =>
  compile(`bb-signed-attributes-O${O}`, path.join(MAINS, "signed_attributes.circom"), SIGNED_SOURCES, { O });

const ATTRS = ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry", "credentialCommitment"];

function toInput(obj) {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, mod(v).toString()]));
}

let babyjub;
const onCurve = (x, y) => babyjub.inCurve([babyjub.F.e(mod(x)), babyjub.F.e(mod(y))]);

let issuer; // pinned TEST-ONLY issuer key
let attacker; // TEST-ONLY forger key
let attrs; // an in-range v4 attribute set
let attrHash;
let issuerSig;

before(async function () {
  babyjub = await buildBabyjub();
  const poseidon = await buildPoseidon();
  issuer = await issuerKey("issuer");
  attacker = await issuerKey("attacker");
  attrs = {
    role: 3n,
    dept: 3n,
    clearance: 2n,
    deviceCompliant: 1n,
    employeeActive: 1n,
    expiry: 1798761600n,
    credentialCommitment: await H(seedField("credential-secret/v4"), seedField("credential-salt/v4")),
  };
  attrHash = poseidon.F.toObject(poseidon(ATTRS.map((f) => attrs[f])));
  issuerSig = await sign(issuer, attrHash);
});

describe("SignaturePointsOnCurve layout (G1-S1-CIRC-032)", function () {
  const EXPECTED = { 0: { nonLinear: 6, linear: 4 }, 2: { nonLinear: 6, linear: 0 } };
  for (const O of [0, 2]) {
    it(`--O${O}: 4 private inputs, no public signals, ${EXPECTED[O].nonLinear} non-linear + ${EXPECTED[O].linear} linear`, async function () {
      const info = await r1csInfo(await compilePoints(O));
      expect(info.nPubInputs).to.equal(0);
      expect(info.nOutputs).to.equal(0);
      expect(info.nPrvInputs).to.equal(4);
      expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(EXPECTED[O]);
    });
  }
});

for (const O of [1, 2]) {
  describe(`SignaturePointsOnCurve on-curve checks (--O${O})`, function () {
    let t;
    let valid;
    const accepts = async (input) => t.checkConstraints(await t.calculateWitness(toInput(input), true));
    const rejects = (input) => expectReject(t.calculateWitness(toInput(input), true), ASSERT);
    before(async function () {
      t = await compilePoints(O);
      valid = { Ax: issuer.Ax, Ay: issuer.Ay, R8x: issuerSig.R8x, R8y: issuerSig.R8y };
    });

    it("a real issuer key and signature R8 are accepted", async function () {
      expect(onCurve(valid.Ax, valid.Ay)).to.equal(true);
      expect(onCurve(valid.R8x, valid.R8y)).to.equal(true);
      await accepts(valid);
    });

    it("the base point B8 and the attacker's (on-curve) key are accepted: on-curve is not a pin", async function () {
      const B8 = babyjub.Base8.map((c) => babyjub.F.toObject(c));
      await accepts({ ...valid, Ax: B8[0], Ay: B8[1], R8x: B8[0], R8y: B8[1] });
      await accepts({ ...valid, Ax: attacker.Ax, Ay: attacker.Ay });
    });

    const offCurve = [
      ["Ax + 1", { Ax: 1n }],
      ["Ay + 1", { Ay: 1n }],
      ["R8x + 1", { R8x: 1n }],
      ["R8y + 1", { R8y: 1n }],
    ];
    for (const [label, delta] of offCurve) {
      it(`off-curve point (${label}) is rejected`, async function () {
        const input = { ...valid };
        for (const [k, d] of Object.entries(delta)) input[k] = BigInt(input[k]) + d;
        const [x, y] = "Ax" in delta || "Ay" in delta ? [input.Ax, input.Ay] : [input.R8x, input.R8y];
        expect(onCurve(x, y), "fixture must really be off-curve").to.equal(false);
        await rejects(input);
      });
    }

    it("off-curve key (0, 0) is rejected", async function () {
      await rejects({ ...valid, Ax: 0n, Ay: 0n });
    });

    it("off-curve R8 (0, 0) is rejected", async function () {
      await rejects({ ...valid, R8x: 0n, R8y: 0n });
    });

    it("swapped key coordinates (Ay, Ax) are rejected", async function () {
      expect(onCurve(valid.Ay, valid.Ax)).to.equal(false);
      await rejects({ ...valid, Ax: valid.Ay, Ay: valid.Ax });
    });
  });
}

describe("SignaturePointsOnCurve negatives, witness level (--O0, exactly one violated row each)", function () {
  let t;
  let W;
  before(async function () {
    t = await compilePoints(0);
    W = new NamedWitness(
      t,
      await t.calculateWitness(toInput({ Ax: issuer.Ax, Ay: issuer.Ay, R8x: issuerSig.R8x, R8y: issuerSig.R8y }), true)
    );
  });

  it("control: the valid witness violates no row", async function () {
    expect(await W.violated()).to.deep.equal([]);
  });

  for (const [sig, comp, coord] of [
    ["Ax", "keyOnCurve", "x"],
    ["Ay", "keyOnCurve", "y"],
    ["R8x", "r8OnCurve", "x"],
    ["R8y", "r8OnCurve", "y"],
  ]) {
    it(`SignaturePointsOnCurve: ${comp}.${coord} <== ${sig} (main.${sig} tampered, BabyCheck sees the honest point)`, async function () {
      const nw = W.clone().add(`main.${sig}`);
      const v = await nw.violated();
      expect(v.length, `violated rows: ${JSON.stringify(v.map((r) => r.row))}`).to.equal(1);
      expect(v[0].signals).to.include(nw.idx(`main.${sig}`));
      expect(v[0].signals).to.include(nw.idx(`main.${comp}.${coord}`));
      await expectReject(t.checkConstraints(nw.w), CONSTRAINT);
    });
  }
});

/** The gateway's pin (access.public_signals v4 obligation 2), on this test main's slots. */
function gatewayAdmits(publicSignals, pinned) {
  return publicSignals[1] === String(pinned.Ax) && publicSignals[2] === String(pinned.Ay);
}

for (const O of [1, 2]) {
  describe(`G-2 closed: issuer key is public and pinnable (signed_attributes test main, --O${O})`, function () {
    let t;
    const publicSignals = (w) => [w[1], w[2], w[3]].map(String); // [attrHash, issuerAx, issuerAy]
    const inputFor = (key, sig) => toInput({ issuerAx: key.Ax, issuerAy: key.Ay, ...attrs, ...sig });
    before(async function () {
      t = await compileSigned(O);
    });

    it("issuerAx, issuerAy are the 2 public inputs, in witness slots 2 and 3 (after the output)", async function () {
      const info = await r1csInfo(t);
      expect(info.nPubInputs).to.equal(2);
      expect(info.nOutputs).to.equal(1);
      expect(t.symbols["main.issuerAx"].varIdx).to.equal(2);
      expect(t.symbols["main.issuerAy"].varIdx).to.equal(3);
    });

    it("control: the issuer-signed credential satisfies the circuit and the pinned key is in the public signals", async function () {
      const w = await t.calculateWitness(inputFor(issuer, issuerSig), true);
      await t.checkConstraints(w);
      expect(gatewayAdmits(publicSignals(w), issuer)).to.equal(true);
    });

    it("self-signed credential: satisfies the circuit only under the FORGER's key, which the pinned-key check rejects", async function () {
      const forgedSig = await sign(attacker, attrHash);
      const w = await t.calculateWitness(inputFor(attacker, forgedSig), true);
      await t.checkConstraints(w); // the circuit alone cannot know which key is "the issuer"...
      const ps = publicSignals(w);
      expect(ps[1]).to.equal(String(attacker.Ax)); // ...but the key is public, so it is visible
      expect(gatewayAdmits(ps, issuer)).to.equal(false);
    });

    it("self-signed credential presented under the PINNED key is rejected by the circuit", async function () {
      const forgedSig = await sign(attacker, attrHash);
      await expectReject(t.calculateWitness(inputFor(issuer, forgedSig), true), ASSERT);
    });

    it("issuer's signature over OTHER attributes (pinned key) is rejected", async function () {
      const sigOther = await sign(issuer, attrHash + 1n);
      await expectReject(t.calculateWitness(inputFor(issuer, sigOther), true), ASSERT);
    });

    it("off-curve public key (issuerAx + 1) is rejected", async function () {
      const key = { Ax: BigInt(issuer.Ax) + 1n, Ay: issuer.Ay };
      await expectReject(t.calculateWitness(inputFor(key, issuerSig), true), ASSERT);
    });

    it("off-curve R8 (R8y + 1) is rejected", async function () {
      await expectReject(t.calculateWitness(inputFor(issuer, { ...issuerSig, R8y: BigInt(issuerSig.R8y) + 1n }), true), ASSERT);
    });
  });
}
