// G1-S1-CIRC-037: circuits/scripts/verify.js verify() runs on the fast Groth16 verifier
// (circuits/scripts/fast-verify.js, ported from the removed circuits prototype) behind its unchanged interface.
// This is the gateway's obligation 1 (access.public_signals v4): floors 2-5 rest on "verify() is
// true only for a valid proof of exactly these signals".
//
// Differential: on every committed v4 fixture (circuits/fixtures/v4/*) and a v3 proof made in
// memory from the committed v3 pair, under systematic mutations of each, the shipped verify()
// (fast, default), verify() with ZKGATE_VERIFY_IMPL=snarkjs and a bare fast verifier all return
// what stock snarkjs.groth16.verify returns once verify()'s documented input rules (canonical
// signals and coordinates, coordinates < q, proof/vkey shape) are applied to it too; none throws.
// Plus: exact exported API, never-throws, one cached verifier per vkey content hash, and the
// proof-point checks snarkjs lacks (G2 subgroup, point at infinity, coordinate + q).
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { expect } = require("chai");
const snarkjs = require("snarkjs");
const { buildBn128 } = require("ffjavascript");

const CIRCUITS = path.resolve(__dirname, "..");
const SETUP = path.join(CIRCUITS, "setup");
const FIX = path.join(CIRCUITS, "fixtures", "v4");
const VERIFY_JS = path.join(CIRCUITS, "scripts", "verify.js");
const FAST_JS = path.join(CIRCUITS, "scripts", "fast-verify.js");

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const clone = (x) => JSON.parse(JSON.stringify(x));

const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // r (= p)
const FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583n; // q

const V4_VKEY = readJson(path.join(SETUP, "integrated_access_v4.verification_key.json"));
const V3_VKEY = readJson(path.join(SETUP, "integrated_access_v3.verification_key.json"));
const V4_NAMES = fs.existsSync(FIX)
  ? fs
      .readdirSync(FIX, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort()
  : [];
const FIXTURES = V4_NAMES.map((n) => ({
  name: `v4/${n}`,
  vkey: V4_VKEY,
  pub: readJson(path.join(FIX, n, "public.json")),
  proof: readJson(path.join(FIX, n, "proof.json")),
}));
const V3_FIXTURE = { name: "v3/alice (in-memory proof, committed v3 pair)", vkey: V3_VKEY, pub: null, proof: null };

const verifier = () => require(VERIFY_JS);
const fast = () => require(FAST_JS);

// ---- the reference: stock snarkjs + the documented input rules of verify() --------------------
const CANON = /^(?:0|[1-9][0-9]*)$/;
const canonical = (s) => typeof s === "string" && s.length <= 77 && CANON.test(s) && BigInt(s) < FR;
const coord = (x) => typeof x === "string" && x.length <= 78 && CANON.test(x) && BigInt(x) < FQ;
const coords = (a, n) => Array.isArray(a) && a.length === n && a.every(coord);
function inputRulesOk(vkey, pub, proof) {
  if (!vkey || typeof vkey !== "object" || vkey.protocol !== "groth16" || vkey.curve !== "bn128") return false;
  if (!Number.isInteger(vkey.nPublic) || vkey.nPublic < 0) return false;
  if (!Array.isArray(vkey.IC) || vkey.IC.length !== vkey.nPublic + 1) return false;
  if (!Array.isArray(pub) || pub.length !== vkey.nPublic || !pub.every(canonical)) return false;
  if (!proof || typeof proof !== "object") return false;
  if (proof.protocol !== undefined && proof.protocol !== "groth16") return false;
  if (proof.curve !== undefined && proof.curve !== "bn128") return false;
  if (!coords(proof.pi_a, 3) || !coords(proof.pi_c, 3)) return false;
  return Array.isArray(proof.pi_b) && proof.pi_b.length === 3 && proof.pi_b.every((r) => coords(r, 2));
}
async function stockSnarkjs(vkey, pub, proof) {
  try {
    return (await snarkjs.groth16.verify(vkey, pub, proof)) === true;
  } catch (_) {
    return false;
  }
}
async function reference(vkey, pub, proof) {
  try {
    if (!inputRulesOk(vkey, pub, proof)) return false;
  } catch (_) {
    return false;
  }
  return stockSnarkjs(vkey, pub, proof);
}

async function noThrow(label, fn) {
  try {
    return await fn();
  } catch (e) {
    expect.fail(`${label} threw: ${e && e.message}`);
  }
}

async function withImpl(impl, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, "ZKGATE_VERIFY_IMPL");
  const old = process.env.ZKGATE_VERIFY_IMPL;
  if (impl === undefined) delete process.env.ZKGATE_VERIFY_IMPL;
  else process.env.ZKGATE_VERIFY_IMPL = impl;
  try {
    return await fn();
  } finally {
    if (had) process.env.ZKGATE_VERIFY_IMPL = old;
    else delete process.env.ZKGATE_VERIFY_IMPL;
  }
}

// ---- mutations ---------------------------------------------------------------------------------
const inc = (s) => (BigInt(s) + 1n).toString();
const dec = (s) => (BigInt(s) === 0n ? FR - 1n : BigInt(s) - 1n).toString();
const negY = (y) => ((FQ - BigInt(y)) % FQ).toString();

function setPath(obj, keys, v) {
  const o = clone(obj);
  let t = o;
  for (let i = 0; i < keys.length - 1; i++) t = t[keys[i]];
  t[keys[keys.length - 1]] = v;
  return o;
}
const getPath = (obj, keys) => keys.reduce((t, k) => t[k], obj);

const COORD_PATHS = [
  ["pi_a", 0], ["pi_a", 1],
  ["pi_b", 0, 0], ["pi_b", 0, 1], ["pi_b", 1, 0], ["pi_b", 1, 1],
  ["pi_c", 0], ["pi_c", 1],
];

/** [label, vkey, pub, proof] cases derived from one honest fixture. */
function mutations(fx, nonSubgroupB) {
  const { vkey, pub, proof } = fx;
  const out = [["honest", vkey, pub, proof]];
  const add = (label, v, p, pr) => out.push([label, v === undefined ? vkey : v, p === undefined ? pub : p, pr === undefined ? proof : pr]);
  const withPub = (i, x) => pub.map((y, j) => (j === i ? x : y));

  // every public signal +1 and -1, and as a leading-zero spelling of itself
  pub.forEach((s, i) => {
    add(`pub[${i}] + 1`, undefined, withPub(i, inc(s)));
    add(`pub[${i}] - 1`, undefined, withPub(i, dec(s)));
    add(`pub[${i}] leading zero`, undefined, withPub(i, "0" + s));
  });
  if (pub.length >= 2) {
    add("pub[0] <-> pub[1]", undefined, withPub(1, pub[0]).map((x, j) => (j === 0 ? pub[1] : x)));
    add("pub reversed", undefined, [...pub].reverse());
  }
  add("pub[0] + r", undefined, withPub(0, (BigInt(pub[0]) + FR).toString()));
  add("pub[0] as number", undefined, withPub(0, Number(pub[0])));
  add("pub[0] as bigint", undefined, withPub(0, BigInt(pub[0])));
  add("pub[0] with space", undefined, withPub(0, " " + pub[0]));
  add("pub[0] hex", undefined, withPub(0, "0x" + BigInt(pub[0]).toString(16)));
  add("pub[0] negative", undefined, withPub(0, "-" + pub[0]));
  add("one signal short", undefined, pub.slice(0, -1));
  add("one signal extra", undefined, [...pub, "0"]);
  add("no signals", undefined, []);
  add("publicSignals not an array", undefined, { 0: pub[0], length: pub.length });
  // every proof coordinate +1 (off curve), and every coordinate + q (snarkjs reduces it)
  for (const k of COORD_PATHS) {
    add(`${k.join(".")} + 1`, undefined, undefined, setPath(proof, k, inc(getPath(proof, k))));
    add(`${k.join(".")} + q`, undefined, undefined, setPath(proof, k, (BigInt(getPath(proof, k)) + FQ).toString()));
    add(`${k.join(".")} leading zero`, undefined, undefined, setPath(proof, k, "0" + getPath(proof, k)));
  }
  // swaps
  add("pi_b c0/c1 swapped in x and y", undefined, undefined, {
    ...clone(proof),
    pi_b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]], proof.pi_b[2]],
  });
  add("pi_b x/y swapped", undefined, undefined, { ...clone(proof), pi_b: [proof.pi_b[1], proof.pi_b[0], proof.pi_b[2]] });
  add("pi_a x/y swapped", undefined, undefined, { ...clone(proof), pi_a: [proof.pi_a[1], proof.pi_a[0], proof.pi_a[2]] });
  add("pi_a <-> pi_c", undefined, undefined, { ...clone(proof), pi_a: proof.pi_c, pi_c: proof.pi_a });
  // valid group elements that are the wrong ones
  add("pi_a = G1 generator", undefined, undefined, { ...clone(proof), pi_a: ["1", "2", "1"] });
  add("pi_a negated", undefined, undefined, setPath(proof, ["pi_a", 1], negY(proof.pi_a[1])));
  add("pi_c negated", undefined, undefined, setPath(proof, ["pi_c", 1], negY(proof.pi_c[1])));
  // (-A, -B, C) is the same pairing product: both must ACCEPT it (Groth16 malleability)
  add("pi_a and pi_b negated (valid re-encoding)", undefined, undefined, {
    ...clone(proof),
    pi_a: [proof.pi_a[0], negY(proof.pi_a[1]), "1"],
    pi_b: [proof.pi_b[0], [negY(proof.pi_b[1][0]), negY(proof.pi_b[1][1])], ["1", "0"]],
  });
  // points at infinity / zero coordinates (off curve)
  add("pi_a infinity (z = 0)", undefined, undefined, { ...clone(proof), pi_a: ["0", "1", "0"] });
  add("pi_a = (0, 0, 1)", undefined, undefined, { ...clone(proof), pi_a: ["0", "0", "1"] });
  add("pi_c infinity (z = 0)", undefined, undefined, { ...clone(proof), pi_c: ["0", "1", "0"] });
  add("pi_c = (0, 0, 1)", undefined, undefined, { ...clone(proof), pi_c: ["0", "0", "1"] });
  add("pi_b infinity (z = 0)", undefined, undefined, { ...clone(proof), pi_b: [["0", "0"], ["1", "0"], ["0", "0"]] });
  add("pi_b all zero", undefined, undefined, { ...clone(proof), pi_b: [["0", "0"], ["0", "0"], ["1", "0"]] });
  add("pi_a x = 0 (off curve)", undefined, undefined, setPath(proof, ["pi_a", 0], "0"));
  add("pi_a z = 2", undefined, undefined, setPath(proof, ["pi_a", 2], "2"));
  // B on the twist but outside G2
  add("pi_b on twist, not in G2", undefined, undefined, { ...clone(proof), pi_b: nonSubgroupB });
  // wrong vkey
  add("other circuit's vkey", fx.vkey === V4_VKEY ? V3_VKEY : V4_VKEY);
  const icSwap = clone(vkey);
  if (icSwap.IC.length > 2) [icSwap.IC[1], icSwap.IC[2]] = [icSwap.IC[2], icSwap.IC[1]];
  else icSwap.IC[1] = icSwap.IC[0];
  add("vkey IC[1] swapped/replaced", icSwap);
  add("vkey gamma/delta swapped", { ...clone(vkey), vk_gamma_2: vkey.vk_delta_2, vk_delta_2: vkey.vk_gamma_2 });
  add("vkey alpha replaced by IC[0]", { ...clone(vkey), vk_alpha_1: vkey.IC[0] });
  add("vkey nPublic + 1", { ...clone(vkey), nPublic: vkey.nPublic + 1 });
  add("vkey protocol plonk", { ...clone(vkey), protocol: "plonk" });
  add("vkey null", null);
  // malformed shapes
  add("proof null", undefined, undefined, null);
  add("proof {}", undefined, undefined, {});
  add("pi_a missing", undefined, undefined, { pi_b: proof.pi_b, pi_c: proof.pi_c });
  add("pi_a length 2", undefined, undefined, { ...clone(proof), pi_a: proof.pi_a.slice(0, 2) });
  add("pi_b flat", undefined, undefined, { ...clone(proof), pi_b: proof.pi_b.flat() });
  add("coordinate as number", undefined, undefined, setPath(proof, ["pi_a", 0], 1));
  add("coordinate 'abc'", undefined, undefined, setPath(proof, ["pi_c", 0], "abc"));
  add("coordinate negative", undefined, undefined, setPath(proof, ["pi_c", 0], "-" + proof.pi_c[0]));
  add("coordinate 79 digits", undefined, undefined, setPath(proof, ["pi_a", 0], "9".repeat(79)));
  add("protocol plonk", undefined, undefined, { ...clone(proof), protocol: "plonk" });
  add("curve bls12381", undefined, undefined, { ...clone(proof), curve: "bls12381" });
  return out;
}

// A point on the twist E'(Fp2): y^2 = x^3 + b' that is not in the order-r subgroup G2.
function twistPointOutsideG2(curve) {
  const { G2 } = curve;
  const F2 = G2.F;
  for (let k = 1n; k < 1000n; k++) {
    const x = F2.fromObject([k, 1n]);
    const rhs = F2.add(F2.mul(F2.square(x), x), G2.b);
    if (!F2.isSquare(rhs)) continue;
    const P = new Uint8Array(F2.n8 * 2);
    P.set(x);
    P.set(F2.sqrt(rhs), F2.n8);
    if (G2.isValid(P) && !G2.isZero(G2.timesScalar(P, FR))) return P;
  }
  throw new Error("no non-subgroup twist point found");
}
const g2ToJson = (curve, P) => curve.G2.toObject(curve.G2.toAffine(P)).map((c) => c.map(String));

// ---- tests -------------------------------------------------------------------------------------
// verify() and stock snarkjs share ffjavascript's multi-thread curve (globalThis.curve_bn128); the
// bare verifiers use single-thread curves. The root after hook releases every worker (agent memory
// snarkjs-workers-hang-mocha).
let testCurve;
let nonSubgroupB;

before(async function () {
  this.timeout(120000);
  testCurve = await buildBn128(true);
  nonSubgroupB = g2ToJson(testCurve, twistPointOutsideG2(testCurve));
  const v3 = readJson(path.join(CIRCUITS, "test", "vectors", "v3", "input.alice.json"));
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    v3.input,
    path.join(SETUP, "integrated_access_v3.wasm"),
    path.join(SETUP, "integrated_access_v3.zkey"),
  );
  V3_FIXTURE.pub = publicSignals;
  V3_FIXTURE.proof = proof;
});

after(async function () {
  try {
    await verifier().terminate();
  } catch (_) {
    /* nothing to release */
  }
  if (testCurve) await testCurve.terminate();
});

describe("G1-S1-CIRC-037 fast verifier: verify.js keeps its interface", function () {
  it("exports verify, loadVerificationKey, terminate, isCanonicalSignal, canonicalizeSignals, FIELD_P, FIELD_Q", function () {
    expect(Object.keys(verifier()).sort()).to.deep.equal(
      ["FIELD_P", "FIELD_Q", "canonicalizeSignals", "isCanonicalSignal", "loadVerificationKey", "terminate", "verify"].sort(),
    );
    expect(verifier().FIELD_P).to.equal(FR);
    expect(verifier().FIELD_Q).to.equal(FQ);
  });

  it("verify() resolves to false and never throws on hostile or odd arguments (both impls)", async function () {
    const { verify } = verifier();
    const fx = FIXTURES.find((f) => f.name === "v4/alice_wiki");
    expect(fx, "fixture v4/alice_wiki").to.exist;
    const throwing = { ...clone(fx.proof) };
    Object.defineProperty(throwing, "pi_a", { enumerable: true, get() { throw new Error("boom"); } });
    const hostileVkey = { ...clone(fx.vkey) };
    Object.defineProperty(hostileVkey, "IC", { enumerable: true, get() { throw new Error("boom"); } });
    const odd = [undefined, null, 0, "", "x", [], {}, Symbol("s"), () => true, new Proxy({}, { get() { throw new Error("proxy"); } })];
    const cases = [[hostileVkey, fx.pub, fx.proof], [fx.vkey, fx.pub, throwing]];
    for (const a of odd) cases.push([a, fx.pub, fx.proof], [fx.vkey, a, fx.proof], [fx.vkey, fx.pub, a]);
    for (const impl of [undefined, "snarkjs"]) {
      await withImpl(impl, async () => {
        for (const [i, c] of cases.entries()) {
          const r = await noThrow(`case ${i} (${impl || "fast"})`, () => verify(...c));
          expect(r, `case ${i} (${impl || "fast"})`).to.equal(false);
        }
      });
    }
  });
});

describe("G1-S1-CIRC-037 fast verifier: differential against stock snarkjs.groth16.verify", function () {
  this.timeout(900000);

  it("there are v4 fixtures to compare (circuits/fixtures/v4)", function () {
    expect(FIXTURES.length).to.be.at.least(10);
  });

  for (const fx of [...FIXTURES, V3_FIXTURE]) {
    it(`${fx.name}: verify() (fast + snarkjs impls) and a bare fast verifier equal the reference on every mutation`, async function () {
      const { verify } = verifier();
      const own = await fast().makeVerifier(fx.vkey, { singleThread: true });
      const disagreements = [];
      let accepted = 0;
      let n = 0;
      try {
        for (const [label, vkey, pub, proof] of mutations(fx, nonSubgroupB)) {
          n++;
          const ref = await reference(vkey, pub, proof);
          const vFast = await noThrow(`${label} fast`, () => withImpl(undefined, () => verify(vkey, pub, proof)));
          const vStock = await noThrow(`${label} snarkjs`, () => withImpl("snarkjs", () => verify(vkey, pub, proof)));
          // the bare verifier is bound to fx.vkey and does not police JSON shape: compare it where
          // the input rules hold
          const bare = vkey === fx.vkey && inputRulesOk(vkey, pub, proof) ? await noThrow(`${label} bare`, () => own.verify(pub, proof)) : ref;
          if (ref) accepted++;
          if (vFast !== ref || vStock !== ref || bare !== ref) disagreements.push(`${label}: ref=${ref} fast=${vFast} snarkjs=${vStock} bare=${bare}`);
        }
      } finally {
        await own.terminate();
      }
      expect(disagreements, disagreements.join("\n")).to.deep.equal([]);
      // honest and the (-A, -B, C) re-encoding; anything else accepted would be a soundness bug
      expect(accepted).to.equal(2);
      expect(n).to.be.at.least(70 + 3 * fx.pub.length);
    });
  }
});

describe("G1-S1-CIRC-037 fast verifier: checks that exceed stock snarkjs", function () {
  const alice = () => FIXTURES.find((f) => f.name === "v4/alice_wiki");

  it("snarkjs accepts a proof coordinate written as x + q (it reduces mod q); verify() rejects it in both impls", async function () {
    const fx = alice();
    const bumped = setPath(fx.proof, ["pi_a", 0], (BigInt(fx.proof.pi_a[0]) + FQ).toString());
    expect(await stockSnarkjs(fx.vkey, fx.pub, bumped), "documents stock snarkjs behaviour").to.equal(true);
    expect(await withImpl(undefined, () => verifier().verify(fx.vkey, fx.pub, bumped))).to.equal(false);
    expect(await withImpl("snarkjs", () => verifier().verify(fx.vkey, fx.pub, bumped))).to.equal(false);
  });

  it("snarkjs accepts a leading-zero public signal; verify() rejects it in both impls", async function () {
    const fx = alice();
    const padded = fx.pub.map((x, i) => (i === 9 ? "0" + x : x));
    expect(await stockSnarkjs(fx.vkey, padded, fx.proof), "documents stock snarkjs behaviour").to.equal(true);
    expect(await withImpl(undefined, () => verifier().verify(fx.vkey, padded, fx.proof))).to.equal(false);
    expect(await withImpl("snarkjs", () => verifier().verify(fx.vkey, padded, fx.proof))).to.equal(false);
  });

  it("G2 subgroup: a twist point outside G2 passes G2.isValid but fails proofPointsValid", function () {
    const fx = alice();
    const { proofPointsValid, parseProof } = fast();
    const bad = { ...clone(fx.proof), pi_b: nonSubgroupB };
    const { A, B, C } = parseProof(testCurve, bad);
    expect(testCurve.G2.isValid(B), "on the twist").to.equal(true);
    expect(proofPointsValid(testCurve, A, B, C)).to.equal(false);
    const good = parseProof(testCurve, fx.proof);
    expect(proofPointsValid(testCurve, good.A, good.B, good.C)).to.equal(true);
  });

  it("g2InSubgroup agrees with [r]Q == O on G2 multiples and on twist points outside G2", function () {
    const { g2InSubgroup } = fast();
    const { G2 } = testCurve;
    for (const k of [1n, 2n, 12345n, FR - 1n]) expect(g2InSubgroup(testCurve, G2.toAffine(G2.timesScalar(G2.g, k)))).to.equal(true);
    const T = twistPointOutsideG2(testCurve);
    expect(g2InSubgroup(testCurve, T)).to.equal(false);
    expect(g2InSubgroup(testCurve, G2.toAffine(G2.add(T, G2.g)))).to.equal(false);
  });

  it("the point at infinity is rejected for A, B and C by proofPointsValid (G1/G2.isValid(O) is true)", function () {
    const fx = alice();
    const { proofPointsValid, parseProof } = fast();
    const { G1, G2 } = testCurve;
    const { A, B, C } = parseProof(testCurve, fx.proof);
    expect(G1.isValid(G1.zero) && G2.isValid(G2.zero)).to.equal(true);
    expect(proofPointsValid(testCurve, G1.zero, B, C)).to.equal(false);
    expect(proofPointsValid(testCurve, A, G2.zero, C)).to.equal(false);
    expect(proofPointsValid(testCurve, A, B, G1.zero)).to.equal(false);
  });

  it("vk_x (wasm multiexp) equals IC0 + sum s_i*IC_i by timesScalar, incl. scalars 0, 1, r-1 and an infinity result", async function () {
    const fx = alice();
    const { makeVerifier } = fast();
    const { G1 } = testCurve;
    const v = await makeVerifier(fx.vkey, { curve: testCurve });
    const IC = fx.vkey.IC.map((p) => G1.fromObject(p.map(BigInt)));
    const ref = (s) => s.reduce((acc, x, i) => G1.add(acc, G1.timesScalar(IC[i + 1], BigInt(x))), IC[0]);
    const R1 = (FR - 1n).toString();
    const vectors = [
      fx.pub,
      fx.pub.map(() => "0"),
      fx.pub.map(() => "1"),
      fx.pub.map(() => R1),
      fx.pub.map((x, i) => (i % 2 ? R1 : "0")),
      fx.pub.map((x, i) => (BigInt(x) * 7919n + BigInt(i)) % FR).map(String),
    ];
    for (const s of vectors) expect(G1.eq(v.linearCombination(s), ref(s))).to.equal(true);
    const g = ["1", "2", "1"];
    const tiny = await makeVerifier({ ...clone(fx.vkey), nPublic: 1, IC: [g, g] }, { curve: testCurve });
    expect(G1.isZero(tiny.linearCombination([R1]))).to.equal(true);
    expect(G1.eq(tiny.linearCombination(["5"]), G1.timesScalar(G1.g, 6n))).to.equal(true);
  });

  it("makeVerifier rejects a vkey whose G2 points are outside G2 or whose IC length mismatches nPublic", async function () {
    const fx = alice();
    const { makeVerifier } = fast();
    const attempts = [
      { ...clone(fx.vkey), vk_delta_2: nonSubgroupB },
      { ...clone(fx.vkey), IC: fx.vkey.IC.slice(1) },
      { ...clone(fx.vkey), vk_alpha_1: ["1", "3", "1"] },
    ];
    for (const bad of attempts) {
      let err = null;
      try {
        await makeVerifier(bad, { curve: testCurve });
      } catch (e) {
        err = e;
      }
      expect(err).to.be.an("error");
    }
  });
});

describe("G1-S1-CIRC-037 fast verifier: one cached verifier per vkey content hash", function () {
  let real;
  let builds;
  beforeEach(async function () {
    await verifier().terminate(); // empty the cache
    const fv = fast();
    real = fv.makeVerifier;
    builds = [];
    fv.makeVerifier = async (vkey, opt) => {
      builds.push(fv.vkeyHash(vkey));
      return real(vkey, opt);
    };
  });
  afterEach(function () {
    fast().makeVerifier = real;
  });

  const alice = () => FIXTURES.find((f) => f.name === "v4/alice_wiki");

  it("vkeyHash depends on content, not object identity or key order", function () {
    const { vkeyHash } = fast();
    const v = alice().vkey;
    const reordered = Object.fromEntries(Object.entries(clone(v)).reverse());
    expect(vkeyHash(reordered)).to.equal(vkeyHash(v));
    expect(vkeyHash(clone(v))).to.equal(vkeyHash(v));
    const changed = clone(v);
    changed.IC[3][0] = inc(changed.IC[3][0]);
    expect(vkeyHash(changed)).to.not.equal(vkeyHash(v));
    expect(vkeyHash(V3_VKEY)).to.not.equal(vkeyHash(v));
  });

  it("builds once per vkey content and reuses it (same object, a deep copy, concurrent first calls)", async function () {
    const { verify } = verifier();
    const a = alice();
    const first = await Promise.all([1, 2, 3, 4, 5].map(() => verify(a.vkey, a.pub, a.proof)));
    expect(first).to.deep.equal([true, true, true, true, true]);
    expect(await verify(a.vkey, a.pub, a.proof)).to.equal(true);
    expect(await verify(clone(a.vkey), a.pub, a.proof)).to.equal(true);
    expect(builds).to.have.length(1);
    expect(await verify(V3_VKEY, V3_FIXTURE.pub, V3_FIXTURE.proof)).to.equal(true);
    expect(builds).to.have.length(2);
    expect(await verify(a.vkey, a.pub, a.proof)).to.equal(true);
    expect(builds).to.have.length(2);
  });

  it("a vkey object mutated after first use is not served the stale cached verifier", async function () {
    const { verify } = verifier();
    const a = alice();
    const v = clone(a.vkey);
    expect(await verify(v, a.pub, a.proof)).to.equal(true);
    [v.IC[1], v.IC[2]] = [v.IC[2], v.IC[1]];
    expect(await verify(v, a.pub, a.proof)).to.equal(false);
    expect(builds).to.have.length(2);
  });

  it("ZKGATE_VERIFY_IMPL=snarkjs bypasses the fast verifier entirely and still verifies", async function () {
    const { verify } = verifier();
    const a = alice();
    await withImpl("snarkjs", async () => {
      expect(await verify(a.vkey, a.pub, a.proof)).to.equal(true);
      expect(await verify(a.vkey, a.pub.map((x, i) => (i === 9 ? inc(x) : x)), a.proof)).to.equal(false);
    });
    expect(builds).to.have.length(0);
    for (const impl of ["fast", "", "bogus"]) {
      await withImpl(impl, async () => expect(await verify(a.vkey, a.pub, a.proof), impl).to.equal(true));
    }
    expect(builds).to.have.length(1);
  });

  it("an invalid vkey is not cached as a failure: a later valid call still builds and verifies", async function () {
    const { verify } = verifier();
    const a = alice();
    const bad = { ...clone(a.vkey), vk_delta_2: nonSubgroupB };
    expect(await verify(bad, a.pub, a.proof)).to.equal(false);
    expect(await verify(bad, a.pub, a.proof)).to.equal(false);
    expect(builds).to.have.length(2);
    expect(await verify(a.vkey, a.pub, a.proof)).to.equal(true);
  });

  it("after 20 distinct vkeys (cache bound 16, oldest evicted) the original key still verifies", async function () {
    const { verify } = verifier();
    const a = alice();
    for (let i = 0; i < 20; i++) {
      const v = clone(a.vkey);
      v.IC[1] = v.IC[0]; // distinct content, still valid points; the proof no longer verifies
      v.IC[2] = i % 2 ? a.vkey.IC[3] : a.vkey.IC[4];
      v.IC[5] = a.vkey.IC[(i % 10) + 1];
      await verify(v, a.pub, a.proof);
    }
    expect(await verify(a.vkey, a.pub, a.proof)).to.equal(true);
  });
});
