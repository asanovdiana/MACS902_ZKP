"use strict";
// Test harness for the P1 v3 circuit and the v4 suite (v4.test.js imports `compileCached`, exported
// since G1-S1-CIRC-036): cached circom_tester builds, rejection helper, R1CS header
// and constraint counts, and a named-witness editor for witness-level tamper tests.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const { wasm: wasmTester } = require("circom_tester");
const { readR1cs } = require("r1csfile");
const { F1Field } = require("ffjavascript");

const REPO = path.join(__dirname, "..", "..");
const CIRCUITS = path.join(REPO, "circuits");
const NODE_MODULES = path.join(REPO, "node_modules");
const BUILD = path.join(REPO, "build", "test"); // gitignored (`build/`)

const V3_MAIN = path.join(CIRCUITS, "integrated_access_v3.circom");
// Her components that v3 includes.
const V3_SOURCES = [
  V3_MAIN,
  path.join(CIRCUITS, "components", "access_policy.circom"),
  path.join(CIRCUITS, "components", "eddsa_verifier.circom"),
  path.join(CIRCUITS, "components", "merkle_membership.circom"),
];

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((BigInt(x) % P) + P) % P;

function circomlibVersion() {
  return JSON.parse(fs.readFileSync(path.join(NODE_MODULES, "circomlib", "package.json"))).version;
}

/** Hash of everything that changes the compiled output, used to skip recompiles. */
function buildStamp(sources, extra) {
  const h = crypto.createHash("sha256");
  h.update(execSync("circom --version", { encoding: "utf8" }));
  h.update(`circomlib ${circomlibVersion()}\n`);
  h.update(JSON.stringify(extra));
  for (const s of sources) h.update(fs.readFileSync(s));
  return h.digest("hex");
}

const testers = new Map();

/**
 * Compile `circomFile` with circom_tester into build/test/<name>/ (once per source change: a stamp
 * file holds the hash of sources + compiler + options) and return the wasm tester. Memoised per
 * process, so every test file shares one build per (name).
 */
async function compileCached(name, circomFile, sources, options = {}) {
  if (testers.has(name)) return testers.get(name);
  const promise = (async () => {
    const output = path.join(BUILD, name);
    const stampFile = path.join(output, "stamp.txt");
    const stamp = buildStamp(sources, { name, ...options });
    const fresh = fs.existsSync(stampFile) && fs.readFileSync(stampFile, "utf8") === stamp;
    if (!fresh) fs.rmSync(output, { recursive: true, force: true });
    const tester = await wasmTester(circomFile, {
      output,
      recompile: !fresh,
      ...options,
    });
    if (!fresh) fs.writeFileSync(stampFile, stamp);
    await tester.loadSymbols();
    return tester;
  })();
  testers.set(name, promise);
  return promise;
}

/** The v3 main at optimisation level O (0, 1 = circom default, 2). */
function compileV3(O) {
  return compileCached(`v3-O${O}`, V3_MAIN, V3_SOURCES, { O });
}

/** circomlib Poseidon(2) as a standalone main at --O0: produces sub-witnesses for hashers. */
function compilePoseidon2() {
  const file = path.join(NODE_MODULES, "circomlib", "circuits", "poseidon.circom");
  return compileCached("poseidon2-O0", file, [file], {
    O: 0,
    templateName: "Poseidon",
    templateParams: [2],
  });
}

/** Assert that a promise rejects; optionally that the message matches `re`. */
async function expectReject(promise, re) {
  let err;
  try {
    await promise;
  } catch (e) {
    err = e;
  }
  if (!err) throw new Error("expected rejection, but the circuit accepted the input");
  if (re && !re.test(String(err.message || err))) {
    throw new Error(`rejected with unexpected error: ${err.message || err}`);
  }
  return err;
}

/** R1CS header + non-linear/linear split (linear = A or B empty, as circom reports it). */
async function r1csInfo(tester) {
  const r1cs = await readR1cs(path.join(tester.dir, `${tester.baseName}.r1cs`), {
    loadConstraints: true,
    loadMap: false,
    getFieldFromPrime: (p) => new F1Field(p),
  });
  let nonLinear = 0;
  for (const [a, b] of r1cs.constraints) {
    if (Object.keys(a).length > 0 && Object.keys(b).length > 0) nonLinear++;
  }
  return {
    nConstraints: r1cs.nConstraints,
    nonLinear,
    linear: r1cs.nConstraints - nonLinear,
    nPubInputs: r1cs.nPubInputs,
    nPrvInputs: r1cs.nPrvInputs,
    nOutputs: r1cs.nOutputs,
    nVars: r1cs.nVars,
  };
}

/**
 * Indices of R1CS rows the witness violates, each with the witness indices it touches. A tamper
 * that violates exactly ONE row proves the matching source constraint is the only thing rejecting
 * it: remove that constraint (or weaken `<==` to `<--`) and the tampered witness is accepted.
 */
async function violatedRows(tester, witness) {
  await tester.loadConstraints();
  const F = tester.F;
  const evalLC = (lc) => {
    let v = F.zero;
    for (const k in lc) v = F.add(v, F.mul(lc[k], F.e(witness[k])));
    return v;
  };
  const out = [];
  tester.constraints.forEach((c, i) => {
    if (!F.isZero(F.sub(F.mul(evalLC(c[0]), evalLC(c[1])), evalLC(c[2])))) {
      const signals = new Set([...Object.keys(c[0]), ...Object.keys(c[1]), ...Object.keys(c[2])]);
      out.push({ row: i, signals: [...signals].map(Number) });
    }
  });
  return out;
}

/** A witness addressed by signal name (requires a build where no signal is merged, i.e. --O0). */
class NamedWitness {
  constructor(tester, witness) {
    this.tester = tester;
    this.w = witness.map((x) => BigInt(x));
  }

  clone() {
    return new NamedWitness(this.tester, this.w);
  }

  idx(name) {
    const s = this.tester.symbols[name];
    if (!s) throw new Error(`no such signal: ${name}`);
    if (s.varIdx < 0) throw new Error(`signal ${name} was optimised away (use an --O0 build)`);
    return s.varIdx;
  }

  get(name) {
    return this.w[this.idx(name)];
  }

  set(name, value) {
    this.w[this.idx(name)] = mod(value);
    return this;
  }

  add(name, delta = 1n) {
    return this.set(name, this.get(name) + BigInt(delta));
  }

  /** Every signal name under `prefix` (e.g. "main.merkle.hashers[0].") or equal to it. */
  namesUnder(prefix) {
    return Object.keys(this.tester.symbols).filter((n) => n === prefix || n.startsWith(prefix));
  }

  /** Copy the listed signals (names or prefixes ending in "." or "[") from another witness. */
  copyFrom(other, ...namesOrPrefixes) {
    for (const p of namesOrPrefixes) {
      const names = /[.[]$/.test(p) ? this.namesUnder(p) : [p];
      if (names.length === 0) throw new Error(`nothing matches ${p}`);
      for (const n of names) this.set(n, other.get(n));
    }
    return this;
  }

  async violated() {
    return violatedRows(this.tester, this.w);
  }
}

module.exports = {
  REPO,
  CIRCUITS,
  NODE_MODULES,
  BUILD,
  V3_MAIN,
  V3_SOURCES,
  P,
  mod,
  compileCached,
  compileV3,
  compilePoseidon2,
  expectReject,
  r1csInfo,
  violatedRows,
  NamedWitness,
};
