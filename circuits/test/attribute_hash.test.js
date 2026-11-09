"use strict";
// G1-S1-CIRC-031: AttributeHash() (circuits/components/attribute_hash.circom), credential v4 /
// ADR 0006: attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry,
// credentialCommitment), with 2-bit enums and boolean flags range-checked here.
//
//   1. layout      - 7 private inputs, 1 output, constraint counts
//   2. vectors     - circuit output == circomlibjs Poseidon(7) in contract order (floor 8 parity)
//   3. ranges      - every in-range value accepted; out-of-range enums / non-boolean flags rejected
//   4. witness     - (--O0) exactly one violated R1CS row per source constraint (floor 1)
//   5. G-1 fix     - test main signed_attributes.circom (AttributeHash -> her IssuerSignatureCheck):
//                    any tampered attribute with the ORIGINAL signature is rejected (floor 2)
//
// All values are TEST-ONLY (fixtures.js labels); nothing is written to the repository.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { expect } = require("chai");
const { wasm: wasmTester } = require("circom_tester");
const { buildPoseidon } = require("circomlibjs");
const { CIRCUITS, NODE_MODULES, expectReject, r1csInfo, NamedWitness, mod } = require("./helpers");
const { H, seedField, issuerKey, sign } = require("./fixtures");

const ASSERT = /Assert Failed/;
const CONSTRAINT = /Constraint doesn't match/;
const MAINS = path.join(__dirname, "circuits");
const COMPONENTS = path.join(CIRCUITS, "components");
const ATTR_SOURCES = [path.join(COMPONENTS, "attribute_hash.circom")];
const SIGNED_SOURCES = [
  ...ATTR_SOURCES,
  path.join(COMPONENTS, "eddsa_verifier.circom"),
  path.join(COMPONENTS, "issuer_key.circom"),
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
const compileAttr = (O) => compile(`bb-attribute-hash-O${O}`, path.join(MAINS, "attribute_hash.circom"), ATTR_SOURCES, { O });
const compileSigned = (O) =>
  compile(`bb-signed-attributes-O${O}`, path.join(MAINS, "signed_attributes.circom"), SIGNED_SOURCES, { O });
function compilePoseidon7() {
  const file = path.join(NODE_MODULES, "circomlib", "circuits", "poseidon.circom");
  return compile("bb-poseidon7-O0", file, [], { O: 0, templateName: "Poseidon", templateParams: [7] });
}

const FIELDS = ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry", "credentialCommitment"];
const TWO64 = 1n << 64n;

let poseidonJs;
/** circomlibjs Poseidon over the attributes in CONTRACT order (credential v4). */
async function attrHashJs(a) {
  if (!poseidonJs) poseidonJs = await buildPoseidon();
  return poseidonJs.F.toObject(poseidonJs(FIELDS.map((f) => mod(a[f]))));
}

function toInput(obj) {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, mod(v).toString()]));
}

let commitment; // TEST-ONLY Poseidon(2)(secret, salt)
let altCommitment;
let base; // an in-range attribute set
before(async function () {
  commitment = await H(seedField("credential-secret/v4"), seedField("credential-salt/v4"));
  altCommitment = await H(seedField("credential-secret/v4-alt"), seedField("credential-salt/v4-alt"));
  base = {
    role: 1n, // admin (ADR 0008)
    dept: 2n, // operations
    clearance: 3n,
    deviceCompliant: 1n,
    employeeActive: 1n,
    expiry: 1798761600n, // 2027-01-01T00:00:00Z
    credentialCommitment: commitment,
  };
});

describe("AttributeHash layout (G1-S1-CIRC-031)", function () {
  const EXPECTED = {
    0: { nonLinear: 392, linear: 1425 },
    2: { nonLinear: 389, linear: 0 },
  };
  for (const O of [0, 2]) {
    it(`--O${O}: 7 private inputs, attrHash the only output (slot 1), ${EXPECTED[O].nonLinear} non-linear + ${EXPECTED[O].linear} linear`, async function () {
      const t = await compileAttr(O);
      const info = await r1csInfo(t);
      expect(info.nPubInputs).to.equal(0);
      expect(info.nOutputs).to.equal(1);
      expect(info.nPrvInputs).to.equal(7);
      expect(t.symbols["main.attrHash"].varIdx).to.equal(1);
      expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal(EXPECTED[O]);
    });
  }
});

for (const O of [1, 2]) {
  describe(`AttributeHash vectors and ranges (--O${O})`, function () {
    let t;
    const out = async (a) => {
      const w = await t.calculateWitness(toInput(a), true);
      await t.checkConstraints(w);
      return BigInt(w[1]);
    };
    const rejects = (a) => expectReject(t.calculateWitness(toInput(a), true), ASSERT);
    before(async function () {
      t = await compileAttr(O);
    });

    it("attrHash equals circomlibjs Poseidon(7) in contract order on in-test vectors", async function () {
      const vectors = [
        base,
        { ...base, role: 0n, dept: 0n, clearance: 0n, deviceCompliant: 0n, employeeActive: 0n, expiry: 0n },
        { ...base, role: 3n, dept: 3n, clearance: 3n, expiry: TWO64 - 1n },
        { ...base, expiry: (1n << 53n) - 1n, credentialCommitment: altCommitment },
        { ...base, role: 2n, dept: 1n, clearance: 0n, deviceCompliant: 0n },
      ];
      for (const v of vectors) expect(await out(v)).to.equal(await attrHashJs(v));
    });

    it("order is normative: the result is NOT Poseidon(7) with role and dept swapped", async function () {
      const got = await out(base);
      expect(got).to.not.equal(await attrHashJs({ ...base, role: base.dept, dept: base.role }));
    });

    it("every attribute changes attrHash (each field is bound)", async function () {
      const h0 = await out(base);
      const bumps = {
        role: 0n,
        dept: 3n,
        clearance: 2n,
        deviceCompliant: 0n,
        employeeActive: 0n,
        expiry: base.expiry + 1n,
        credentialCommitment: altCommitment,
      };
      for (const f of FIELDS) expect(await out({ ...base, [f]: bumps[f] }), f).to.not.equal(h0);
    });

    it("every in-range value of role, dept, clearance (0..3) and the flags (0, 1) is accepted", async function () {
      for (const f of ["role", "dept", "clearance"]) for (const v of [0n, 1n, 2n, 3n]) await out({ ...base, [f]: v });
      for (const f of ["deviceCompliant", "employeeActive"]) for (const v of [0n, 1n]) await out({ ...base, [f]: v });
    });

    for (const f of ["role", "dept", "clearance"]) {
      for (const [label, v] of [
        ["4", 4n],
        ["5", 5n],
        ["2^64", TWO64],
        ["p-1", mod(-1n)],
      ]) {
        it(`${f} = ${label} is rejected (Num2Bits(2))`, async function () {
          await rejects({ ...base, [f]: v });
        });
      }
    }

    for (const f of ["deviceCompliant", "employeeActive"]) {
      for (const [label, v] of [
        ["2", 2n],
        ["p-1", mod(-1n)],
      ]) {
        it(`${f} = ${label} is rejected (boolean)`, async function () {
          await rejects({ ...base, [f]: v });
        });
      }
    }

    it("boundary: expiry is NOT range-checked here (2^64 and p-1 hash fine); the expiry component owns Num2Bits(64)", async function () {
      for (const v of [TWO64, mod(-1n)]) expect(await out({ ...base, expiry: v })).to.equal(await attrHashJs({ ...base, expiry: v }));
    });
  });
}

describe("AttributeHash negatives, witness level (--O0, exactly one violated row each)", function () {
  let t;
  let ph; // Poseidon(7) harness at O0
  let W;

  before(async function () {
    [t, ph] = await Promise.all([compileAttr(0), compilePoseidon7()]);
    W = new NamedWitness(t, await t.calculateWitness(toInput(base), true));
  });

  async function expectOnly(nw, touches) {
    const v = await nw.violated();
    expect(v.length, `violated rows: ${JSON.stringify(v.map((r) => r.row))}`).to.equal(1);
    for (const name of [].concat(touches)) {
      expect(v[0].signals, `violated row should involve ${name}`).to.include(nw.idx(name));
    }
    await expectReject(t.checkConstraints(nw.w), CONSTRAINT);
  }

  /** Re-hash: splice an honest Poseidon(7) sub-witness for `inputs` into main.hasher, set attrHash. */
  async function rehash(nw, inputs, { bumpOut = false } = {}) {
    const hw = new NamedWitness(ph, await ph.calculateWitness({ inputs: inputs.map((x) => mod(x)) }, true));
    const src = Object.keys(ph.symbols);
    expect(nw.namesUnder("main.hasher.").length, "layout of main.hasher vs harness").to.equal(src.length);
    for (const n of src) nw.set(n.replace(/^main\./, "main.hasher."), hw.get(n));
    return nw.set("main.attrHash", bumpOut ? hw.get("main.out") + 1n : hw.get("main.out"));
  }
  const honest = () => FIELDS.map((f) => W.get(`main.${f}`));

  it("control: the valid witness violates no row and rehash() reproduces it", async function () {
    expect(await W.violated()).to.deep.equal([]);
    expect((await rehash(W.clone(), honest())).w).to.deep.equal(W.w);
  });

  for (const [f, comp] of [
    ["role", "roleBits"],
    ["dept", "deptBits"],
    ["clearance", "clearanceBits"],
  ]) {
    it(`AttributeHash: ${comp}.in <== ${f} (${f} = 4 hashed, range check sees the honest value)`, async function () {
      const nw = W.clone().set(`main.${f}`, 4n);
      await expectOnly(await rehash(nw, FIELDS.map((g) => nw.get(`main.${g}`))), [`main.${f}`, `main.${comp}.in`]);
    });
  }

  for (const f of ["deviceCompliant", "employeeActive"]) {
    it(`AttributeHash: ${f} * (${f} - 1) === 0 (${f} = 2, hash recomputed)`, async function () {
      const nw = W.clone().set(`main.${f}`, 2n);
      await expectOnly(await rehash(nw, FIELDS.map((g) => nw.get(`main.${g}`))), `main.${f}`);
    });
  }

  FIELDS.forEach((f, k) => {
    it(`AttributeHash: hasher.inputs[${k}] <== ${f} (hasher fed another ${f}, attrHash recomputed)`, async function () {
      const inputs = honest();
      inputs[k] = mod(inputs[k] + 1n);
      await expectOnly(await rehash(W.clone(), inputs), [`main.${f}`, `main.hasher.inputs[${k}]`]);
    });
  });

  it("AttributeHash: attrHash <== hasher.out (output replaced)", async function () {
    await expectOnly(await rehash(W.clone(), honest(), { bumpOut: true }), ["main.attrHash", "main.hasher.out"]);
  });
});

for (const O of [1, 2]) {
  describe(`G-1 closed: signed attributes cannot be tampered (signed_attributes test main, --O${O})`, function () {
    let t;
    let key;
    let signed; // honest input
    const inputFor = (a, sig) => toInput({ issuerAx: key.Ax, issuerAy: key.Ay, ...a, ...sig });
    before(async function () {
      t = await compileSigned(O);
      key = await issuerKey("issuer");
      signed = inputFor(base, await sign(key, await attrHashJs(base)));
    });

    it("control: the issuer's signature over attrHash is accepted; publicSignals = [attrHash, issuerAx, issuerAy]", async function () {
      const w = await t.calculateWitness(signed, true);
      await t.checkConstraints(w);
      expect(BigInt(w[1])).to.equal(await attrHashJs(base));
      expect([w[2], w[3]].map(String)).to.deep.equal([key.Ax, key.Ay].map(String));
    });

    const tampers = {
      role: 0n, // admin -> engineer
      dept: 0n,
      clearance: 2n,
      deviceCompliant: 0n,
      employeeActive: 0n,
      expiry: 1830297600n, // +1 year
      credentialCommitment: null, // another holder's commitment (set in test)
    };
    for (const f of FIELDS) {
      it(`tampered ${f} with the ORIGINAL signature is rejected`, async function () {
        const v = f === "credentialCommitment" ? altCommitment : tampers[f];
        const forged = { ...signed, [f]: mod(v).toString() };
        expect(forged[f]).to.not.equal(signed[f]);
        await expectReject(t.calculateWitness(forged, true), ASSERT);
      });
    }

    it("control: the same tampered attributes re-signed BY THE ISSUER are accepted (rejection is the binding, not the value)", async function () {
      const a = { ...base, role: 0n, clearance: 2n };
      const w = await t.calculateWitness(inputFor(a, await sign(key, await attrHashJs(a))), true);
      await t.checkConstraints(w);
    });
  });
}
