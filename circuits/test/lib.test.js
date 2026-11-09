"use strict";
// circuits/lib: the one shared encoder (ADR 0004; G0-S1-CIRC-021 profile v3, G1-S1-CIRC-038
// profile v4). Contracts: docs/CONTRACTS.md `credential v3`, `access.public_signals v3`,
// `credential v4`, `access.public_signals v4`, Common rules. Floor 8 (identical Poseidon).
//
// Run alone:  npx mocha --no-config --exit circuits/test/lib.test.js
//
// Pins the lib to the committed TEST-ONLY vectors (circuits/test/vectors/{v3,v4}), checks the zk-kit
// tree against a manual Poseidon(2) recomputation and the contract's pathIndices convention, and
// runs the v3 input through the real v3 witness calculator (circom_tester, build/test/lib).
// The v4 witness check lands with the v4 circuit (G1-S1-CIRC-036).
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { expect } = require("chai");
const { buildPoseidon } = require("circomlibjs");

const lib = require("../lib");

const REPO = path.join(__dirname, "..", "..");
const VDIR = path.join(__dirname, "vectors");
const readVec = (rel) => JSON.parse(fs.readFileSync(path.join(VDIR, rel), "utf8"));
const GEN = path.join(REPO, "circuits", "scripts", "gen-vectors.js");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const CANONICAL = /^(0|[1-9][0-9]*)$/;

const V4_PUBLIC = [
  "nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance",
  "requireDevice", "now", "nonce", "resourceId", "epoch",
];
const V3_INPUT_KEYS = [
  "credentialSecret", "credentialSalt", "role", "clearance", "deviceCompliant", "employeeActive",
  "Ax", "Ay", "R8x", "R8y", "S", "M", "leaf", "pathElements", "pathIndices", "root",
];
// credential v4 "Circuit inputs (v4)": private, then the 11 public inputs.
const V4_INPUT_KEYS = [
  "credentialSecret", "credentialSalt", "role", "dept", "clearance", "deviceCompliant",
  "employeeActive", "expiry", "R8x", "R8y", "S", "pathElements", "pathIndices",
  "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance", "requireDevice",
  "now", "nonce", "resourceId", "epoch",
];

/** Assert that `fn` rejects (or throws) an AccessInputError with `code`. */
async function rejectsWith(fn, code, re) {
  let err;
  try {
    await fn();
  } catch (e) {
    err = e;
  }
  expect(err, `expected AccessInputError ${code}`).to.be.instanceOf(lib.AccessInputError);
  expect(err.code, err.message).to.equal(code);
  if (re) expect(err.message).to.match(re);
  return err;
}

const v3 = readVec("v3/credentials.json");
const v3Input = readVec("v3/input.alice.json");
const v4 = readVec("v4/credentials.json");
const v4Input = readVec("v4/input.alice.wiki.json");
const persona = (vec, name) => vec.credentials.find((c) => c.persona === name);

/** Builder arguments for a v3 persona, as the client assembles them from credential.file v1 + GET /path. */
function v3Args(name, over = {}) {
  const c = persona(v3, name);
  return {
    credentialSecret: c.credentialSecret,
    credentialSalt: c.credentialSalt,
    commitment: c.commitment,
    attributes: { ...c.attributes },
    signature: { ...c.signature },
    issuer: { Ax: v3.issuer.Ax, Ay: v3.issuer.Ay },
    merkleProof: { root: v3.tree.root, leaf: c.commitment, ...c.merkle },
    ...over,
  };
}

/** Builder arguments for a v4 persona -> resource with the vector challenge. */
function v4Args(name, resource, over = {}) {
  const c = persona(v4, name);
  const r = v4.resources[resource];
  return {
    credentialSecret: c.credentialSecret,
    credentialSalt: c.credentialSalt,
    commitment: c.commitment,
    attributes: { ...c.attributes },
    signature: { ...c.signature },
    issuer: { Ax: v4.issuer.Ax, Ay: v4.issuer.Ay },
    merkleProof: { root: v4.tree.root, leaf: c.attrHash, ...c.merkle },
    policy: resource,
    challenge: { nonce: v4.nonces[0].value, resourceId: r.resourceId, epoch: v4.epoch, now: v4.now },
    ...over,
  };
}

describe("circuits/lib shared encoder (profiles v3, v4)", function () {
  this.timeout(60000);

  describe("vectors reproduce", function () {
    it("gen-vectors generate() reproduces every committed vector file byte for byte", async function () {
      const gen = require("../scripts/gen-vectors");
      const out = await gen.generate();
      const files = Object.keys(out).sort();
      expect(files).to.deep.equal([
        "v3/credentials.json", "v3/input.alice.json", "v3/poseidon.json",
        "v4/credentials.json", "v4/input.alice.wiki.json", "v4/poseidon.json",
      ]);
      for (const f of files) {
        expect(gen.serialise(out[f]), f).to.equal(fs.readFileSync(path.join(VDIR, f), "utf8"));
      }
    });

    it("gen-vectors --check exits 0 when the vectors are up to date", function () {
      const out = execFileSync(process.execPath, [GEN, "--check"], { encoding: "utf8" });
      expect(out).to.match(/up to date/);
    });

    it("vectors carry the TEST-ONLY banner and no issuer private key, only its label (floor 9)", function () {
      for (const vec of [v3, v4]) {
        expect(vec.TEST_ONLY).to.match(/TEST-ONLY/);
        expect(vec.issuer.seedLabel).to.match(/TEST-ONLY/);
        expect(Object.keys(vec.issuer).sort()).to.deep.equal(["Ax", "Ay", "seedLabel"]);
        for (const c of vec.credentials) {
          expect(c.secretLabel).to.match(/TEST-ONLY/);
          expect(c.saltLabel).to.match(/TEST-ONLY/);
        }
      }
    });

    for (const [profile, file, arities] of [["v3", "v3/poseidon.json", ["2"]], ["v4", "v4/poseidon.json", ["2", "3", "7"]]]) {
      it(`poseidon samples in ${file} match lib.poseidon and raw circomlibjs (floor 8)`, async function () {
        const vec = readVec(file);
        const h = await buildPoseidon();
        expect(Object.keys(vec.samples).sort()).to.deep.equal(arities);
        for (const n of arities) {
          for (const s of vec.samples[n]) {
            expect(s.inputs).to.have.length(Number(n));
            expect(await lib.poseidon(s.inputs), `${profile} Poseidon(${n})`).to.equal(s.out);
            expect(h.F.toObject(h(s.inputs.map(BigInt))).toString()).to.equal(s.out);
          }
        }
      });
    }

    it("v3: commitment, signature over M = commitment and Merkle path reproduce for every persona", async function () {
      expect(v3.profile).to.equal("v3");
      expect(v3.depth).to.equal(2);
      expect(await lib.publicKey(Buffer.alloc(32, 7))).to.have.keys("Ax", "Ay");
      for (const c of v3.credentials) {
        const cm = await lib.commitment(c.credentialSecret, c.credentialSalt);
        expect(cm, c.persona).to.equal(c.commitment);
        expect(await lib.profiles.v3.message({ commitment: cm, attributes: c.attributes })).to.equal(cm);
        expect(await lib.profiles.v3.leaf({ commitment: cm, attributes: c.attributes })).to.equal(cm);
        expect(await lib.verifySignature(cm, c.signature, v3.issuer), c.persona).to.equal(true);
        expect(await lib.merkleRoot(cm, c.merkle.pathElements, c.merkle.pathIndices)).to.equal(v3.tree.root);
      }
    });

    it("v4: commitment, attrHash = Poseidon(7) in contract order, signature, path and nullifiers reproduce", async function () {
      expect(v4.profile).to.equal("v4");
      expect(v4.depth).to.equal(16);
      const h = await buildPoseidon();
      for (const c of v4.credentials) {
        const cm = await lib.commitment(c.credentialSecret, c.credentialSalt);
        expect(cm, c.persona).to.equal(c.commitment);
        const a = c.attributes;
        const manual = h.F.toObject(
          h([a.role, a.dept, a.clearance, a.deviceCompliant, a.employeeActive, a.expiry, cm].map(BigInt))
        ).toString();
        expect(await lib.attrHash(a, cm)).to.equal(manual);
        expect(manual).to.equal(c.attrHash);
        expect(await lib.profiles.v4.message({ commitment: cm, attributes: a })).to.equal(c.attrHash);
        expect(await lib.profiles.v4.leaf({ commitment: cm, attributes: a })).to.equal(c.attrHash);
        expect(await lib.verifySignature(c.attrHash, c.signature, v4.issuer)).to.equal(true);
        expect(await lib.merkleRoot(c.attrHash, c.merkle.pathElements, c.merkle.pathIndices)).to.equal(v4.tree.root);
        for (const [name, r] of Object.entries(v4.resources)) {
          const n = await lib.nullifier(c.credentialSecret, r.resourceId, v4.epoch);
          const manualN = h.F.toObject(h([c.credentialSecret, r.resourceId, v4.epoch].map(BigInt))).toString();
          expect(n, `${c.persona}/${name}`).to.equal(manualN);
          expect(n).to.equal(c.nullifiers[name]);
        }
      }
    });

    it("v4 personas: Alice, Bob, Carol with the D6 attributes the task names, expiry far in the future", function () {
      const want = {
        alice: { role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1 },
        bob: { role: 2, dept: 2, clearance: 1, deviceCompliant: 1, employeeActive: 1 },
        carol: { role: 1, dept: 1, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
      };
      expect(v4.credentials.map((c) => c.persona)).to.deep.equal(["alice", "bob", "carol"]);
      for (const c of v4.credentials) {
        expect(c.attributes).to.deep.include(want[c.persona]);
        expect(c.attributes.expiry).to.be.greaterThan(Number(v4.now) + 10 * 365 * 86400);
        expect(c.attributes.expiry).to.be.at.most(Number.MAX_SAFE_INTEGER);
      }
      expect(v4.epoch).to.equal(lib.epochOf(v4.now));
      expect(v4.nonces.length).to.be.at.least(2);
      for (const n of v4.nonces) expect(BigInt(n.value) < 1n << 128n).to.equal(true);
    });

    it("nullifiers of one user differ across resources and epochs (floor 5 unlinkability input)", async function () {
      const a = persona(v4, "alice");
      const ns = Object.values(a.nullifiers);
      expect(new Set(ns).size).to.equal(ns.length);
      const next = await lib.nullifier(a.credentialSecret, 1, BigInt(v4.epoch) + 1n);
      expect(ns).to.not.include(next);
    });

    it("v4 forged block: a non-issuer self-signature verifies under the forger key but not the issuer's", async function () {
      const f = v4.forged;
      expect(f.seedLabel).to.match(/TEST-ONLY/);
      expect(await lib.verifySignature(f.message, f.signature, f.publicKey)).to.equal(true);
      expect(await lib.verifySignature(f.message, f.signature, v4.issuer)).to.equal(false);
    });
  });

  describe("crypto", function () {
    it("sign/verifySignature round-trip; any changed message, signature or key fails", async function () {
      const prv = Buffer.alloc(32, 9);
      const pub = await lib.publicKey(prv);
      const sig = await lib.sign(prv, "12345");
      for (const k of ["R8x", "R8y", "S", "Ax", "Ay"]) expect({ ...sig, ...pub }[k]).to.match(CANONICAL);
      expect(BigInt(sig.S) < L).to.equal(true);
      expect(await lib.verifySignature("12345", sig, pub)).to.equal(true);
      expect(await lib.verifySignature("12346", sig, pub)).to.equal(false);
      expect(await lib.verifySignature("12345", { ...sig, S: (BigInt(sig.S) + 1n).toString() }, pub)).to.equal(false);
      expect(await lib.verifySignature("12345", { ...sig, R8x: "1" }, pub)).to.equal(false);
      expect(await lib.verifySignature("12345", sig, await lib.publicKey(Buffer.alloc(32, 8)))).to.equal(false);
    });

    it("sign rejects a private key that is not 32 bytes and a message >= p", async function () {
      await rejectsWith(() => lib.sign(Buffer.alloc(31), "1"), "INVALID_KEY");
      await rejectsWith(() => lib.sign("deadbeef", "1"), "INVALID_KEY");
      await rejectsWith(() => lib.sign(Buffer.alloc(32, 1), P.toString()), "OUT_OF_RANGE");
    });

    it("verifySignature rejects S >= l with OUT_OF_RANGE (circomlib checks S < l)", async function () {
      const c = persona(v3, "alice");
      await rejectsWith(() => lib.verifySignature(c.commitment, { ...c.signature, S: L.toString() }, v3.issuer), "OUT_OF_RANGE");
    });

    it("commitment / attrHash / nullifier reject non-canonical and out-of-field inputs", async function () {
      await rejectsWith(() => lib.commitment("01", "2"), "INVALID_VALUE");
      await rejectsWith(() => lib.commitment(P.toString(), "2"), "OUT_OF_RANGE");
      await rejectsWith(() => lib.nullifier("1", "0x2", "3"), "INVALID_VALUE");
      await rejectsWith(() => lib.attrHash({ ...persona(v4, "alice").attributes, role: 4 }, "1"), "OUT_OF_RANGE");
    });
  });

  describe("field codec (contract Common rules)", function () {
    it("exports p and accepts exactly ^(0|[1-9][0-9]*)$ below p", function () {
      expect(lib.P).to.equal(P);
      for (const s of ["0", "1", "10", (P - 1n).toString()]) expect(lib.parseField("x", s)).to.equal(BigInt(s));
      for (const s of ["", "00", "01", "-1", "+1", " 1", "1 ", "0x1", "1e3", "1.0", "１"]) {
        expect(lib.isCanonical(s), JSON.stringify(s)).to.equal(false);
        expect(() => lib.parseField("x", s)).to.throw(lib.AccessInputError).with.property("code", "INVALID_VALUE");
      }
      expect(() => lib.parseField("x", P.toString())).to.throw().with.property("code", "OUT_OF_RANGE");
      expect(() => lib.parseField("x", (P + 5n).toString())).to.throw().with.property("code", "OUT_OF_RANGE");
      expect(() => lib.parseField("x", undefined)).to.throw().with.property("code", "MISSING_FIELD");
      expect(() => lib.parseField("x", 1.5)).to.throw().with.property("code", "INVALID_VALUE");
      expect(() => lib.parseField("x", 2 ** 60)).to.throw().with.property("code", "INVALID_VALUE");
      expect(() => lib.parseField("x", -1n)).to.throw().with.property("code", "OUT_OF_RANGE");
      expect(() => lib.parseField("x", 7, { stringsOnly: true })).to.throw().with.property("code", "INVALID_VALUE");
    });

    it("formatField emits canonical decimal and refuses values outside [0, p)", function () {
      expect(lib.formatField(0n)).to.equal("0");
      expect(lib.formatField(42)).to.equal("42");
      expect(lib.formatField("7")).to.equal("7");
      expect(() => lib.formatField(P)).to.throw().with.property("code", "OUT_OF_RANGE");
    });

    it("AccessInputError codes are a frozen, documented table", function () {
      expect(Object.isFrozen(lib.CODES)).to.equal(true);
      for (const c of [
        "INVALID_VALUE", "OUT_OF_RANGE", "MISSING_FIELD", "UNKNOWN_FIELD", "BAD_LENGTH", "DEPTH_MISMATCH",
        "INVALID_PATH_INDEX", "INVALID_KEY", "UNKNOWN_PROFILE", "PROFILE_MISMATCH", "SECRET_MISMATCH",
        "LEAF_MISMATCH", "BAD_SIGNATURE", "ROOT_MISMATCH", "POLICY_NOT_SATISFIED", "CREDENTIAL_EXPIRED",
        "EMPLOYEE_INACTIVE", "EPOCH_MISMATCH", "RESOURCE_MISMATCH",
      ]) {
        expect(lib.CODES[c], c).to.equal(c);
      }
    });
  });

  describe("enums, policies, epochs (ADR 0008, access.public_signals v4)", function () {
    it("ROLES and DEPTS follow D6", function () {
      expect(lib.ROLES).to.deep.equal({ engineer: 0, admin: 1, contractor: 2, finance: 3 });
      expect(lib.DEPTS).to.deep.equal({ engineering: 0, it: 1, operations: 2, finance: 3 });
      expect(Object.isFrozen(lib.ROLES) && Object.isFrozen(lib.DEPTS)).to.equal(true);
    });

    it("demo policies equal the contract table and the vectors", function () {
      expect(lib.policies).to.deep.equal({
        wiki: { name: "wiki", label: "Wiki", resourceId: 1, roleMask: 15, deptMask: 15, minClearance: 0, requireDevice: 1 },
        file_share: { name: "file_share", label: "File Share", resourceId: 2, roleMask: 3, deptMask: 15, minClearance: 2, requireDevice: 0 },
        admin_panel: { name: "admin_panel", label: "Admin Panel", resourceId: 3, roleMask: 2, deptMask: 15, minClearance: 3, requireDevice: 1 },
      });
      expect(Object.isFrozen(lib.policies.wiki)).to.equal(true);
      expect(v4.resources).to.deep.equal(lib.policies);
    });

    it("epochOf = floor(t / 600) as a canonical decimal", function () {
      expect(lib.epochOf(0)).to.equal("0");
      expect(lib.epochOf(599)).to.equal("0");
      expect(lib.epochOf(600)).to.equal("1");
      expect(lib.epochOf("1793350800")).to.equal("2988918");
      expect(lib.epochOf(1793350800n)).to.equal("2988918");
      expect(() => lib.epochOf(-1)).to.throw().with.property("code", "OUT_OF_RANGE");
      expect(() => lib.epochOf(1.5)).to.throw().with.property("code", "INVALID_VALUE");
    });
  });

  describe("policy pre-check (v4 checkPolicyLocally)", function () {
    const matrix = {
      alice: { wiki: [], file_share: [], admin_panel: ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"] },
      bob: { wiki: [], file_share: ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"], admin_panel: ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"] },
      carol: { wiki: [], file_share: [], admin_panel: [] },
    };
    for (const [who, row] of Object.entries(matrix)) {
      for (const [res, reasons] of Object.entries(row)) {
        it(`${who} -> ${res}: ${reasons.length ? "denied (" + reasons.join(", ") + ")" : "allowed"}`, function () {
          const v = lib.checkPolicyLocally(persona(v4, who).attributes, lib.policies[res], v4.now);
          expect(v.ok).to.equal(reasons.length === 0);
          expect(v.reasons.map((r) => r.code)).to.deep.equal(reasons);
          for (const r of v.reasons) expect(r.message).to.be.a("string");
          expect(persona(v4, who).expectedAccess[res]).to.deep.equal({ ok: v.ok, reasons });
        });
      }
    }

    it("accepts a policy name and role/dept labels; reports device, inactive and expiry (expiry == now is expired)", function () {
      const a = { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 0, employeeActive: 0, expiry: 1000 };
      const v = lib.checkPolicyLocally(a, "wiki", 1000);
      expect(v.ok).to.equal(false);
      expect(v.reasons.map((r) => r.code)).to.deep.equal(["DEVICE_NOT_COMPLIANT", "EMPLOYEE_INACTIVE", "CREDENTIAL_EXPIRED"]);
      expect(lib.checkPolicyLocally({ ...a, deviceCompliant: 1, employeeActive: 1, expiry: 1001 }, "wiki", 1000).ok).to.equal(true);
    });

    it("dept mask is enforced bit by bit", function () {
      const a = { ...persona(v4, "alice").attributes, dept: 3 };
      const v = lib.checkPolicyLocally(a, { roleMask: 15, deptMask: 7, minClearance: 0, requireDevice: 0 }, v4.now);
      expect(v.reasons.map((r) => r.code)).to.deep.equal(["DEPT_NOT_ALLOWED"]);
    });

    it("throws on out-of-range attributes or policy fields and on unknown names", async function () {
      const a = persona(v4, "alice").attributes;
      await rejectsWith(() => lib.checkPolicyLocally({ ...a, role: 4 }, "wiki", v4.now), "OUT_OF_RANGE");
      await rejectsWith(() => lib.checkPolicyLocally({ ...a, role: "ceo" }, "wiki", v4.now), "INVALID_VALUE");
      await rejectsWith(() => lib.checkPolicyLocally(a, { roleMask: 16, deptMask: 15, minClearance: 0, requireDevice: 0 }, v4.now), "OUT_OF_RANGE");
      await rejectsWith(() => lib.checkPolicyLocally(a, "payroll", v4.now), "INVALID_VALUE");
      await rejectsWith(() => lib.checkPolicyLocally(a, "wiki", undefined), "MISSING_FIELD");
    });

    it("v3 FileShareAccess pre-check: role and clearance in {2,3}, device and active = 1", function () {
      expect(lib.checkFileShareV3({ role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 }).ok).to.equal(true);
      expect(lib.checkFileShareV3({ role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 }).ok).to.equal(true);
      const v = lib.checkFileShareV3({ role: 1, clearance: 1, deviceCompliant: 0, employeeActive: 0 });
      expect(v.reasons.map((r) => r.code)).to.deep.equal([
        "ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW", "DEVICE_NOT_COMPLIANT", "EMPLOYEE_INACTIVE",
      ]);
      for (const c of v3.credentials) {
        expect(c.expectedAccess.file_share_v3.ok, c.persona).to.equal(lib.checkFileShareV3(c.attributes).ok);
      }
      expect(persona(v3, "alice").expectedAccess.file_share_v3.ok).to.equal(true);
    });
  });

  describe("tree (zk-kit 1.1.0, Common rules)", function () {
    let H;
    before(async function () {
      const h = await buildPoseidon();
      H = (a, b) => h.F.toObject(h([BigInt(a), BigInt(b)])).toString();
    });

    it("profiles pin depth 2 (v3) and 16 (v4)", async function () {
      expect((await lib.createTree(lib.profiles.v3)).depth).to.equal(2);
      expect((await lib.createTree("v4")).depth).to.equal(16);
    });

    it("contract example: leaves [11, c, 33, 44] -> proofFor(1) has pathIndices [1, 0] and root = manual Poseidon(2)", async function () {
      const c = persona(v3, "alice").commitment;
      const tree = await lib.createTree("v3");
      for (const x of [11n, BigInt(c), 33n, 44n]) tree.insert(x);
      const pr = lib.proofFor(tree, 1);
      expect(pr.pathIndices).to.deep.equal(["1", "0"]);
      expect(pr.pathElements).to.deep.equal(["11", H(33, 44)]);
      expect(pr.leaf).to.equal(c);
      expect(pr.leafIndex).to.equal(1);
      const manualRoot = H(H(11, c), H(33, 44));
      expect(pr.root).to.equal(manualRoot);
      expect(await lib.merkleRoot(c, pr.pathElements, pr.pathIndices)).to.equal(manualRoot);
    });

    it("pathIndices[i] = (leafIndex >> i) & 1 and every proof recomputes the root (depth 16, sparse indices)", async function () {
      const tree = await lib.createTree("v4");
      for (let i = 0; i < 6; i++) tree.insert(BigInt(1000 + i));
      for (const idx of [0, 1, 2, 5]) {
        const pr = lib.proofFor(tree, idx);
        expect(pr.pathElements).to.have.length(16);
        expect(pr.pathIndices).to.deep.equal(Array.from({ length: 16 }, (_, i) => String((idx >> i) & 1)));
        for (const x of [pr.root, ...pr.pathElements, ...pr.pathIndices]) expect(x).to.match(CANONICAL);
        expect(await lib.merkleRoot(String(1000 + idx), pr.pathElements, pr.pathIndices)).to.equal(pr.root);
      }
    });

    it("empty-tree root equals the zero chain z_{k+1} = Poseidon(2)(z_k, z_k) from zero leaf 0", async function () {
      let z = "0";
      for (let k = 0; k < 16; k++) z = H(z, z);
      expect((await lib.createTree("v4")).root.toString()).to.equal(z);
      expect(v4.tree.emptyRoot).to.equal(z);
    });

    it("revocation = delete(i) sets the leaf to 0 and changes the root; the old path no longer reaches it", async function () {
      const tree = await lib.createTree("v3");
      tree.insert(5n);
      tree.insert(6n);
      const before = lib.proofFor(tree, 1);
      tree.delete(1);
      const after = lib.proofFor(tree, 1);
      expect(after.leaf).to.equal("0");
      expect(after.root).to.not.equal(before.root);
      expect(await lib.merkleRoot("6", before.pathElements, before.pathIndices)).to.not.equal(after.root);
    });

    it("proofFor rejects an index outside the tree; merkleRoot rejects non-boolean indices", async function () {
      const tree = await lib.createTree("v3");
      tree.insert(1n);
      await rejectsWith(() => lib.proofFor(tree, 4), "OUT_OF_RANGE");
      await rejectsWith(() => lib.proofFor(tree, -1), "OUT_OF_RANGE");
      await rejectsWith(() => lib.merkleRoot("1", ["0", "0"], ["2", "0"]), "INVALID_PATH_INDEX");
      await rejectsWith(() => lib.merkleRoot("1", ["0"], ["0", "0"]), "DEPTH_MISMATCH");
    });

    it("vector trees: zk-kit root with personas inserted in order equals the committed roots", async function () {
      for (const [vec, leafKey] of [[v3, "commitment"], [v4, "attrHash"]]) {
        const tree = await lib.createTree(vec.profile);
        for (const c of vec.credentials) {
          expect(c.leafIndex).to.equal(tree.leaves.length);
          tree.insert(BigInt(c[leafKey]));
        }
        expect(tree.root.toString()).to.equal(vec.tree.root);
        for (const c of vec.credentials) {
          const pr = lib.proofFor(tree, c.leafIndex);
          expect(pr.pathElements).to.deep.equal(c.merkle.pathElements);
          expect(pr.pathIndices).to.deep.equal(c.merkle.pathIndices);
        }
      }
    });
  });

  describe("profiles", function () {
    it("v3 and v4 carry depth, public-signal list and artefact names", function () {
      const { v3: p3, v4: p4 } = lib.profiles;
      expect(p3.name).to.equal("v3");
      expect(p3.depth).to.equal(2);
      expect(p3.publicSignals).to.deep.equal(["root"]);
      expect(p3.artefacts.name).to.equal("integrated_access_v3");
      expect(p4.name).to.equal("v4");
      expect(p4.depth).to.equal(16);
      expect(p4.publicSignals).to.deep.equal(V4_PUBLIC);
      expect(p4.artefacts.name).to.equal("integrated_access_v4");
      for (const p of [p3, p4]) {
        expect(p.artefacts.wasm).to.equal(`${p.artefacts.name}_js/${p.artefacts.name}.wasm`);
        expect(p.artefacts.zkey).to.equal(`${p.artefacts.name}.zkey`);
        expect(p.artefacts.vkey).to.equal(`${p.artefacts.name}.vkey.json`);
        expect(Object.isFrozen(p)).to.equal(true);
      }
      expect(lib.getProfile("v4")).to.equal(p4);
      expect(lib.getProfile(p3)).to.equal(p3);
    });

    it("unknown profile -> UNKNOWN_PROFILE", async function () {
      await rejectsWith(() => lib.getProfile("v5"), "UNKNOWN_PROFILE");
      await rejectsWith(() => lib.createTree("v1.1"), "UNKNOWN_PROFILE");
      await rejectsWith(() => lib.decodePublicSignals("v2", ["1"]), "UNKNOWN_PROFILE");
    });
  });

  describe("buildInputV3 -> credential v3 input", function () {
    it("Alice's built input equals the committed vector, has exactly the v3 signal names, all canonical decimal", async function () {
      const input = await lib.buildInputV3(v3Args("alice"));
      expect(input).to.deep.equal(v3Input.input);
      expect(Object.keys(input)).to.deep.equal(V3_INPUT_KEYS);
      for (const [k, v] of Object.entries(input)) {
        for (const x of [].concat(v)) expect(x, k).to.be.a("string").and.match(CANONICAL);
      }
      expect(input.M).to.equal(input.leaf);
      expect(input.M).to.equal(persona(v3, "alice").commitment);
      expect(await lib.expectedPublicSignals("v3", input)).to.deep.equal([v3.tree.root]);
      expect(v3Input.expectedPublicSignals).to.deep.equal([v3.tree.root]);
    });

    it("v3 Alice is the File Share TEST credential (opaque role 2, clearance 2; not D6, see README)", function () {
      expect(persona(v3, "alice").attributes).to.deep.equal({ role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 });
      expect(v3.note).to.match(/opaque/);
    });

    it("accepts zk-kit createProof shape (siblings) and integer pathIndices from GET /path", async function () {
      const c = persona(v3, "alice");
      const tree = await lib.createTree("v3");
      for (const x of v3.credentials) tree.insert(BigInt(x.commitment));
      const raw = tree.createProof(c.leafIndex);
      const a = await lib.buildInputV3(v3Args("alice", { merkleProof: { root: raw.root, leaf: raw.leaf, siblings: raw.siblings, pathIndices: raw.pathIndices } }));
      expect(a).to.deep.equal(v3Input.input);
      const b = await lib.buildInputV3(v3Args("alice", {
        merkleProof: { profile: "v3", leafIndex: c.leafIndex, leaf: c.commitment, root: v3.tree.root, pathElements: c.merkle.pathElements, pathIndices: c.merkle.pathIndices.map(Number) },
      }));
      expect(b).to.deep.equal(v3Input.input);
    });

    const negatives = [
      ["missing credentialSecret", (a) => ({ ...a, credentialSecret: undefined }), "MISSING_FIELD"],
      ["non-canonical secret '01'", (a) => ({ ...a, credentialSecret: "01" }), "INVALID_VALUE"],
      ["salt >= p", (a) => ({ ...a, credentialSalt: P.toString() }), "OUT_OF_RANGE"],
      ["unknown top-level key", (a) => ({ ...a, userSecret: "1" }), "UNKNOWN_FIELD"],
      ["v4 attribute (dept) on a v3 credential", (a) => ({ ...a, attributes: { ...a.attributes, dept: 0 } }), "UNKNOWN_FIELD"],
      ["missing attribute", (a) => ({ ...a, attributes: { role: 2, clearance: 2, deviceCompliant: 1 } }), "MISSING_FIELD"],
      ["role 4", (a) => ({ ...a, attributes: { ...a.attributes, role: 4 } }), "OUT_OF_RANGE"],
      ["deviceCompliant 2", (a) => ({ ...a, attributes: { ...a.attributes, deviceCompliant: 2 } }), "OUT_OF_RANGE"],
      ["secret does not match commitment", (a) => ({ ...a, credentialSalt: "5" }), "SECRET_MISMATCH"],
      ["S >= l", (a) => ({ ...a, signature: { ...a.signature, S: L.toString() } }), "OUT_OF_RANGE"],
      ["signature by another key", (a) => ({ ...a, issuer: { Ax: v4.forged.publicKey.Ax, Ay: v4.forged.publicKey.Ay } }), "BAD_SIGNATURE"],
      ["depth 3 path", (a) => ({ ...a, merkleProof: { ...a.merkleProof, pathElements: [...a.merkleProof.pathElements, "0"], pathIndices: [...a.merkleProof.pathIndices, "0"] } }), "DEPTH_MISMATCH"],
      ["pathIndices 2", (a) => ({ ...a, merkleProof: { ...a.merkleProof, pathIndices: ["2", "0"] } }), "INVALID_PATH_INDEX"],
      ["flipped pathIndices", (a) => ({ ...a, merkleProof: { ...a.merkleProof, pathIndices: a.merkleProof.pathIndices.map((x) => String(1 - Number(x))) } }), "ROOT_MISMATCH"],
      ["stale root", (a) => ({ ...a, merkleProof: { ...a.merkleProof, root: "1" } }), "ROOT_MISMATCH"],
      ["path for another leaf", (a) => ({ ...a, merkleProof: { ...a.merkleProof, leaf: "9" } }), "LEAF_MISMATCH"],
      ["path from a v4 registry", (a) => ({ ...a, merkleProof: { ...a.merkleProof, profile: "v4" } }), "PROFILE_MISMATCH"],
      ["FileShareAccess not satisfied (role 1)", (a) => ({ ...a, attributes: { ...a.attributes, role: 1 } }), "POLICY_NOT_SATISFIED"],
    ];
    for (const [title, mut, code] of negatives) {
      it(`rejects ${title} with ${code}`, async function () {
        await rejectsWith(() => lib.buildInputV3(mut(v3Args("alice"))), code);
      });
    }

    it("policy failure carries reasons; precheck:false still validates encodings and crypto", async function () {
      const err = await rejectsWith(() => lib.buildInputV3(v3Args("bob")), "POLICY_NOT_SATISFIED");
      expect(err.reasons.map((r) => r.code)).to.deep.equal(["CLEARANCE_TOO_LOW"]);
      const input = await lib.buildInputV3(v3Args("bob"), { precheck: false });
      expect(input.clearance).to.equal("1");
      await rejectsWith(() => lib.buildInputV3(v3Args("bob", { credentialSalt: "5" }), { precheck: false }), "SECRET_MISMATCH");
    });

    it("error messages never echo the secret or salt (floor 6)", async function () {
      const a = v3Args("alice");
      for (const bad of [{ credentialSalt: "5" }, { credentialSecret: a.credentialSecret + "x" }]) {
        let err;
        try {
          await lib.buildInputV3({ ...a, ...bad });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(lib.AccessInputError);
        expect(err.message).to.not.include(a.credentialSecret);
        expect(err.message).to.not.include(a.credentialSalt);
      }
    });
  });

  describe("v3 circuit accepts the lib's input (circom_tester, --O2, build/test/lib)", function () {
    this.timeout(600000);
    let circuit;

    before(async function () {
      const cargoBin = path.join(os.homedir(), ".cargo", "bin");
      if (!process.env.PATH.split(path.delimiter).includes(cargoBin)) {
        process.env.PATH = cargoBin + path.delimiter + process.env.PATH;
      }
      const wasmTester = require("circom_tester").wasm;
      const out = path.join(REPO, "build", "test", "lib");
      fs.mkdirSync(out, { recursive: true });
      circuit = await wasmTester(path.join(REPO, "circuits", "integrated_access_v3.circom"), { output: out, O: 2 });
    });

    it("Alice's v3 input (built by buildInputV3) yields a witness that satisfies every constraint", async function () {
      const input = await lib.buildInputV3(v3Args("alice"));
      const w = await circuit.calculateWitness(input, true);
      await circuit.checkConstraints(w);
      expect(w[0]).to.equal(1n);
    });

    it("the committed v3/input.alice.json is accepted as is", async function () {
      const w = await circuit.calculateWitness(v3Input.input, true);
      await circuit.checkConstraints(w);
    });

    it("a lib-built input with precheck:false for Bob (clearance 1) is rejected by the circuit", async function () {
      const input = await lib.buildInputV3(v3Args("bob"), { precheck: false });
      let threw = false;
      try {
        await circuit.calculateWitness(input, true);
      } catch (_) {
        threw = true;
      }
      expect(threw).to.equal(true);
    });

    it("the same input against a different root is rejected by the circuit", async function () {
      const input = { ...(await lib.buildInputV3(v3Args("alice"))), root: "1" };
      let threw = false;
      try {
        await circuit.calculateWitness(input, true);
      } catch (_) {
        threw = true;
      }
      expect(threw).to.equal(true);
    });
  });

  describe("buildInputV4 -> credential v4 input (contract-validated; witness check in CIRC-036)", function () {
    it("Alice -> Wiki equals the committed vector, with exactly the contract signal names", async function () {
      const input = await lib.buildInputV4(v4Args("alice", "wiki"));
      expect(input).to.deep.equal(v4Input.input);
      expect(Object.keys(input)).to.deep.equal(V4_INPUT_KEYS);
      expect(input.pathElements).to.have.length(16);
      expect(input.pathIndices).to.have.length(16);
      for (const [k, v] of Object.entries(input)) {
        for (const x of [].concat(v)) expect(x, k).to.be.a("string").and.match(CANONICAL);
      }
      expect(input).to.not.have.any.keys("M", "leaf", "Ax", "Ay", "nullifier");
    });

    it("public inputs match the contract policy table and the challenge", async function () {
      const input = await lib.buildInputV4(v4Args("alice", "wiki"));
      expect(input).to.include({
        root: v4.tree.root, issuerAx: v4.issuer.Ax, issuerAy: v4.issuer.Ay,
        roleMask: "15", deptMask: "15", minClearance: "0", requireDevice: "1",
        now: v4.now, nonce: v4.nonces[0].value, resourceId: "1", epoch: v4.epoch,
      });
    });

    it("expected public signals: 12 in contract order, nullifier = Poseidon(3)(secret, resourceId, epoch)", async function () {
      const input = await lib.buildInputV4(v4Args("alice", "wiki"));
      const sig = await lib.expectedPublicSignals("v4", input);
      expect(sig).to.deep.equal(v4Input.expectedPublicSignals);
      expect(sig).to.have.length(12);
      expect(sig[0]).to.equal(persona(v4, "alice").nullifiers.wiki);
      expect(lib.decodePublicSignals("v4", sig)).to.deep.equal(v4Input.expectedPublicSignalsByName);
      expect(Object.keys(v4Input.expectedPublicSignalsByName)).to.deep.equal(V4_PUBLIC);
      for (const k of V4_PUBLIC.slice(1)) expect(v4Input.expectedPublicSignalsByName[k], k).to.equal(input[k]);
    });

    it("Carol builds for every resource; Bob builds for Wiki", async function () {
      for (const r of ["wiki", "file_share", "admin_panel"]) {
        const input = await lib.buildInputV4(v4Args("carol", r));
        expect(input.resourceId).to.equal(String(lib.policies[r].resourceId));
      }
      expect((await lib.buildInputV4(v4Args("bob", "wiki"))).role).to.equal("2");
    });

    it("accepts a policy object, role/dept labels and number/bigint challenge values", async function () {
      const a = v4Args("alice", "wiki", {
        policy: { roleMask: 15, deptMask: 15, minClearance: 0, requireDevice: 1 },
        attributes: { ...persona(v4, "alice").attributes, role: "engineer", dept: "engineering" },
        challenge: { nonce: BigInt(v4.nonces[0].value), resourceId: 1, epoch: Number(v4.epoch), now: Number(v4.now) },
      });
      expect(await lib.buildInputV4(a)).to.deep.equal(v4Input.input);
    });

    const negatives = [
      ["unknown top-level key", (a) => ({ ...a, depth: 16 }), "UNKNOWN_FIELD"],
      ["missing dept", (a) => { const { dept, ...rest } = a.attributes; return { ...a, attributes: rest }; }, "MISSING_FIELD"],
      ["extra attribute", (a) => ({ ...a, attributes: { ...a.attributes, email: "x" } }), "UNKNOWN_FIELD"],
      ["dept 4", (a) => ({ ...a, attributes: { ...a.attributes, dept: 4 } }), "OUT_OF_RANGE"],
      ["clearance -1", (a) => ({ ...a, attributes: { ...a.attributes, clearance: -1 } }), "OUT_OF_RANGE"],
      ["expiry 2^64", (a) => ({ ...a, attributes: { ...a.attributes, expiry: (1n << 64n).toString() } }), "OUT_OF_RANGE"],
      ["unknown role label", (a) => ({ ...a, attributes: { ...a.attributes, role: "ceo" } }), "INVALID_VALUE"],
      ["tampered clearance (attrHash changes, signature fails)", (a) => ({ ...a, attributes: { ...a.attributes, clearance: 3 } }), "BAD_SIGNATURE"],
      ["tampered expiry", (a) => ({ ...a, attributes: { ...a.attributes, expiry: a.attributes.expiry + 1 } }), "BAD_SIGNATURE"],
      ["secret does not match commitment", (a) => ({ ...a, credentialSecret: "5" }), "SECRET_MISMATCH"],
      ["depth 2 path", (a) => ({ ...a, merkleProof: { ...a.merkleProof, pathElements: a.merkleProof.pathElements.slice(0, 2), pathIndices: a.merkleProof.pathIndices.slice(0, 2) } }), "DEPTH_MISMATCH"],
      ["pathIndices '-1'", (a) => ({ ...a, merkleProof: { ...a.merkleProof, pathIndices: ["-1", ...a.merkleProof.pathIndices.slice(1)] } }), "INVALID_PATH_INDEX"],
      ["root after revocation", (a) => ({ ...a, merkleProof: { ...a.merkleProof, root: v4.tree.emptyRoot } }), "ROOT_MISMATCH"],
      ["expired: expiry == now", (a) => ({ ...a, challenge: { ...a.challenge, now: String(a.attributes.expiry), epoch: lib.epochOf(a.attributes.expiry) } }), "CREDENTIAL_EXPIRED"],
      ["now >= 2^64", (a) => ({ ...a, challenge: { ...a.challenge, now: (1n << 64n).toString() } }), "OUT_OF_RANGE"],
      ["epoch != floor(now / 600)", (a) => ({ ...a, challenge: { ...a.challenge, epoch: String(BigInt(a.challenge.epoch) + 1n) } }), "EPOCH_MISMATCH"],
      ["challenge resourceId != policy resourceId", (a) => ({ ...a, challenge: { ...a.challenge, resourceId: "2" } }), "RESOURCE_MISMATCH"],
      ["missing nonce", (a) => ({ ...a, challenge: { ...a.challenge, nonce: undefined } }), "MISSING_FIELD"],
      ["non-canonical nonce", (a) => ({ ...a, challenge: { ...a.challenge, nonce: "0" + a.challenge.nonce } }), "INVALID_VALUE"],
      ["policy roleMask 16", (a) => ({ ...a, policy: { roleMask: 16, deptMask: 15, minClearance: 0, requireDevice: 1 } }), "OUT_OF_RANGE"],
      ["unknown policy name", (a) => ({ ...a, policy: "payroll" }), "INVALID_VALUE"],
    ];
    for (const [title, mut, code] of negatives) {
      it(`rejects ${title} with ${code}`, async function () {
        await rejectsWith(() => lib.buildInputV4(mut(v4Args("alice", "wiki"))), code);
      });
    }

    it("Bob -> File Share fails the pre-check with POLICY_NOT_SATISFIED and the reasons", async function () {
      const err = await rejectsWith(() => lib.buildInputV4(v4Args("bob", "file_share")), "POLICY_NOT_SATISFIED");
      expect(err.reasons.map((r) => r.code)).to.deep.equal(["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"]);
      const input = await lib.buildInputV4(v4Args("bob", "file_share"), { precheck: false });
      expect(input.roleMask).to.equal("3");
    });

    it("a self-signed credential builds, but exposes the forger key as issuerAx/issuerAy (the gateway pin rejects it)", async function () {
      const input = await lib.buildInputV4(v4Args("alice", "wiki", { signature: v4.forged.signature, issuer: v4.forged.publicKey }));
      expect(input.issuerAx).to.equal(v4.forged.publicKey.Ax);
      expect(input.issuerAx).to.not.equal(v4.issuer.Ax);
      await rejectsWith(
        () => lib.buildInputV4(v4Args("alice", "wiki", { signature: v4.forged.signature })),
        "BAD_SIGNATURE"
      );
    });

    it("an inactive employee fails with EMPLOYEE_INACTIVE before any crypto (ADR 0007)", async function () {
      await rejectsWith(
        () => lib.buildInputV4(v4Args("alice", "wiki", { attributes: { ...persona(v4, "alice").attributes, employeeActive: 0 } })),
        "EMPLOYEE_INACTIVE"
      );
    });

    it("buildInput(profile, args) dispatches by profile", async function () {
      expect(await lib.buildInput("v4", v4Args("alice", "wiki"))).to.deep.equal(v4Input.input);
      expect(await lib.buildInput(lib.profiles.v3, v3Args("alice"))).to.deep.equal(v3Input.input);
    });
  });

  describe("public-signal codec", function () {
    it("PUBLIC_SIGNALS: [root] for v3, the 12-signal order for v4", function () {
      expect(lib.PUBLIC_SIGNALS.v3).to.deep.equal(["root"]);
      expect(lib.PUBLIC_SIGNALS.v4).to.deep.equal(V4_PUBLIC);
      expect(Object.isFrozen(lib.PUBLIC_SIGNALS.v4)).to.equal(true);
    });

    it("round-trips v3 and v4 (decode(encode(x)) == x and encode(decode(a)) == a)", function () {
      const arr = v4Input.expectedPublicSignals;
      const obj = lib.decodePublicSignals("v4", arr);
      expect(lib.encodePublicSignals("v4", obj)).to.deep.equal(arr);
      const objBig = Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, BigInt(v)]));
      expect(lib.encodePublicSignals(lib.profiles.v4, objBig)).to.deep.equal(arr);
      expect(lib.decodePublicSignals("v3", [v3.tree.root])).to.deep.equal({ root: v3.tree.root });
      expect(lib.encodePublicSignals("v3", { root: v3.tree.root })).to.deep.equal([v3.tree.root]);
    });

    const arr = () => [...v4Input.expectedPublicSignals];
    const decodeNeg = [
      ["leading zero on the nullifier", (a) => { a[0] = "0" + a[0]; return a; }, "INVALID_VALUE"],
      ["a JSON number", (a) => { a[10] = 1; return a; }, "INVALID_VALUE"],
      ["hex", (a) => { a[9] = "0x10"; return a; }, "INVALID_VALUE"],
      ["whitespace", (a) => { a[1] = " " + a[1]; return a; }, "INVALID_VALUE"],
      ["nonce + p (aliases nonce mod p)", (a) => { a[9] = (BigInt(a[9]) + P).toString(); return a; }, "OUT_OF_RANGE"],
      ["roleMask 16", (a) => { a[4] = "16"; return a; }, "OUT_OF_RANGE"],
      ["deptMask 16", (a) => { a[5] = "16"; return a; }, "OUT_OF_RANGE"],
      ["minClearance 4", (a) => { a[6] = "4"; return a; }, "OUT_OF_RANGE"],
      ["requireDevice 2", (a) => { a[7] = "2"; return a; }, "OUT_OF_RANGE"],
      ["now 2^64", (a) => { a[8] = (1n << 64n).toString(); return a; }, "OUT_OF_RANGE"],
      ["11 entries", (a) => a.slice(0, 11), "BAD_LENGTH"],
      ["13 entries", (a) => [...a, "0"], "BAD_LENGTH"],
    ];
    for (const [title, mut, code] of decodeNeg) {
      it(`decode v4 rejects ${title} with ${code}`, async function () {
        await rejectsWith(() => lib.decodePublicSignals("v4", mut(arr())), code);
      });
    }

    it("decode v3 rejects non-arrays, wrong length and non-canonical roots", async function () {
      await rejectsWith(() => lib.decodePublicSignals("v3", "1"), "BAD_LENGTH");
      await rejectsWith(() => lib.decodePublicSignals("v3", ["1", "2"]), "BAD_LENGTH");
      await rejectsWith(() => lib.decodePublicSignals("v3", ["01"]), "INVALID_VALUE");
      await rejectsWith(() => lib.decodePublicSignals("v3", [P.toString()]), "OUT_OF_RANGE");
    });

    it("encode rejects unknown and missing fields and out-of-range values", async function () {
      const obj = lib.decodePublicSignals("v4", arr());
      await rejectsWith(() => lib.encodePublicSignals("v4", { ...obj, extra: "1" }), "UNKNOWN_FIELD");
      const { nonce, ...missing } = obj;
      await rejectsWith(() => lib.encodePublicSignals("v4", missing), "MISSING_FIELD");
      await rejectsWith(() => lib.encodePublicSignals("v4", { ...obj, minClearance: 4 }), "OUT_OF_RANGE");
      await rejectsWith(() => lib.encodePublicSignals("v3", { root: "01" }), "INVALID_VALUE");
    });
  });
});
