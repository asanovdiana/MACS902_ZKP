#!/usr/bin/env node
// v4 proving and verification timings against the scope targets (G1-S1-CIRC-037):
//
//   npm run perf:v4                                   # = node circuits/scripts/perf-v4.js
//   node circuits/scripts/perf-v4.js --prove-runs 60 --verify-runs 500 --warmup 20 --out-dir <dir>
//
// prove   snarkjs.groth16.fullProve(Alice -> Wiki TEST-ONLY vector input, committed
//         circuits/setup/integrated_access_v4.{wasm,zkey}): witness + proof, depth 16, in memory.
//         One untimed warm-up, then --prove-runs timed runs.
// verify  on circuits/fixtures/v4/alice_wiki, three series round-robin (load drift hits all
//         equally), warm (curve built, per-vkey verifier cached), --warmup untimed rounds first:
//           fast     verify() default (circuits/scripts/fast-verify.js)
//           snarkjs  verify() with ZKGATE_VERIFY_IMPL=snarkjs (stock + G2 subgroup/infinity checks)
//           stock    bare snarkjs.groth16.verify (reference, no input rules)
//         plus the cold first verify() call of the process (curve build + verifier precomputation).
//
// Writes <out-dir>/perf-v4.json (raw samples, machine) and perf-v4.md (default circuits/reports/).
// p95 is nearest-rank. Benchmarks share the host with peer agents: check `uptime` first; the
// 1/5/15-minute load average before and after is recorded.
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const CIRCUITS = path.resolve(__dirname, "..");
const REPO = path.resolve(CIRCUITS, "..");
const NAME = "integrated_access_v4";
const SETUP = path.join(CIRCUITS, "setup");
const FIX = path.join(CIRCUITS, "fixtures", "v4", "alice_wiki");
const VECTOR = path.join(CIRCUITS, "test", "vectors", "v4", "input.alice.wiki.json");

const TARGETS = { prove_ms: 3000, verify_ms: 10, proof_bytes: 200 }; // scope: prove < 3 s, verify < 10 ms, proof ~200 B

function parseArgs(argv) {
  const o = { proveRuns: 60, verifyRuns: 500, warmup: 20, outDir: path.join(CIRCUITS, "reports") };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (argv[i + 1] === undefined) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === "--prove-runs") o.proveRuns = Number(next());
    else if (a === "--verify-runs") o.verifyRuns = Number(next());
    else if (a === "--warmup") o.warmup = Number(next());
    else if (a === "--out-dir") o.outDir = path.resolve(next());
    else throw new Error(`unknown argument ${a}`);
  }
  for (const k of ["proveRuns", "verifyRuns", "warmup"]) if (!Number.isInteger(o[k]) || o[k] < 0) throw new Error(`--${k} must be a non-negative integer`);
  return o;
}

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const ms = (t0) => Number(process.hrtime.bigint() - t0) / 1e6;
const r2 = (x) => Math.round(x * 100) / 100;

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  const rank = (q) => s[Math.min(n - 1, Math.max(0, Math.ceil(q * n) - 1))];
  const median = n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
  return { n, median: r2(median), p95: r2(rank(0.95)), min: r2(s[0]), max: r2(s[n - 1]), mean: r2(s.reduce((a, b) => a + b, 0) / n) };
}

function machine() {
  let commit = "unknown";
  try {
    commit = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: REPO, encoding: "utf8" }).trim();
  } catch (_) {
    /* not a checkout */
  }
  const cpus = os.cpus();
  return {
    cpu: cpus[0] ? cpus[0].model.trim() : "unknown",
    logical_cores: cpus.length,
    mem_gb: r2(os.totalmem() / 2 ** 30),
    os: `${os.type()} ${os.release()} ${os.arch()}`,
    node: process.version,
    snarkjs: readJson(path.join(REPO, "node_modules", "snarkjs", "package.json")).version,
    commit,
  };
}

async function main() {
  const opt = parseArgs(process.argv.slice(2));
  const snarkjs = require("snarkjs");
  const verifyLib = require("./verify.js");
  const vkey = readJson(path.join(SETUP, `${NAME}.verification_key.json`));
  const manifest = readJson(path.join(SETUP, `${NAME}.manifest.json`));
  const wasm = path.join(SETUP, `${NAME}.wasm`);
  const zkey = path.join(SETUP, `${NAME}.zkey`);
  const input = readJson(VECTOR).input; // TEST-ONLY vector, read-only
  const proof = readJson(path.join(FIX, "proof.json"));
  const pub = readJson(path.join(FIX, "public.json"));
  const loadBefore = os.loadavg().map(r2);
  const log = (...a) => console.error("[perf-v4]", ...a);

  // ---- cold verify (first call in this process) -------------------------------------------------
  let t0 = process.hrtime.bigint();
  if (!(await verifyLib.verify(vkey, pub, proof))) throw new Error("alice_wiki fixture does not verify");
  const coldVerify = r2(ms(t0));
  log(`cold verify() ${coldVerify} ms`);

  // ---- prove -------------------------------------------------------------------------------------
  const prove = [];
  let last;
  for (let i = 0; i <= opt.proveRuns; i++) {
    t0 = process.hrtime.bigint();
    last = await snarkjs.groth16.fullProve(input, wasm, zkey);
    const t = ms(t0);
    if (i > 0) prove.push(t); // run 0 is the warm-up
  }
  if (!(await verifyLib.verify(vkey, last.publicSignals, last.proof))) throw new Error("fresh proof does not verify");
  log(`prove: ${JSON.stringify(stats(prove))}`);

  // ---- verify (warm, round-robin) ----------------------------------------------------------------
  const setImpl = (v) => {
    if (v === undefined) delete process.env.ZKGATE_VERIFY_IMPL;
    else process.env.ZKGATE_VERIFY_IMPL = v;
  };
  const series = {
    fast: async () => {
      setImpl(undefined);
      return verifyLib.verify(vkey, pub, proof);
    },
    snarkjs: async () => {
      setImpl("snarkjs");
      return verifyLib.verify(vkey, pub, proof);
    },
    stock: async () => snarkjs.groth16.verify(vkey, pub, proof),
  };
  const samples = { fast: [], snarkjs: [], stock: [] };
  for (let i = 0; i < opt.warmup + opt.verifyRuns; i++) {
    for (const [k, fn] of Object.entries(series)) {
      t0 = process.hrtime.bigint();
      const ok = await fn();
      const t = ms(t0);
      if (ok !== true) throw new Error(`${k} returned ${ok}`);
      if (i >= opt.warmup) samples[k].push(t);
    }
  }
  setImpl(undefined);
  const verify = Object.fromEntries(Object.entries(samples).map(([k, v]) => [k, stats(v)]));
  log(`verify: ${JSON.stringify(verify)}`);

  const proofJsonBytes = fs.statSync(path.join(FIX, "proof.json")).size;
  const compactJsonBytes = Buffer.byteLength(JSON.stringify(proof));
  const report = {
    generated: new Date().toISOString(),
    command: `node circuits/scripts/perf-v4.js --prove-runs ${opt.proveRuns} --verify-runs ${opt.verifyRuns} --warmup ${opt.warmup}`,
    circuit: { name: NAME, depth: 16, constraints: manifest.constraints, n_public: manifest.n_public, zkey_sha256: manifest.zkey_sha256 },
    machine: machine(),
    load_before: loadBefore,
    load_after: os.loadavg().map(r2),
    targets: TARGETS,
    prove_ms: stats(prove),
    verify_cold_ms: coldVerify,
    verify_warm_ms: verify,
    proof_bytes: { raw_uncompressed_points: 256, json_committed: proofJsonBytes, json_compact: compactJsonBytes, public_signals: 12 },
    samples: { prove_ms: prove.map(r2), verify_ms: Object.fromEntries(Object.entries(samples).map(([k, v]) => [k, v.map(r2)])) },
  };
  fs.mkdirSync(opt.outDir, { recursive: true });
  fs.writeFileSync(path.join(opt.outDir, "perf-v4.json"), JSON.stringify(report, null, 1) + "\n");
  fs.writeFileSync(path.join(opt.outDir, "perf-v4.md"), markdown(report));
  log(`wrote ${path.join(opt.outDir, "perf-v4.{md,json}")}`);
  await verifyLib.terminate();
}

function markdown(r) {
  const m = r.machine;
  const row = (name, what, s) => `| ${name} | ${what} | **${s.median}** | ${s.p95} | ${s.min} | ${s.max} | ${s.mean} | ${s.n} |`;
  const pass = (ok) => (ok ? "**pass**" : "**miss**");
  const p = r.prove_ms;
  const v = r.verify_warm_ms;
  return `# v4 prove and verify performance (G1-S1-CIRC-037)

Generated by \`${r.command}\` on ${r.generated.slice(0, 10)} at ${m.commit}. Raw samples: \`circuits/reports/perf-v4.json\`.

**Machine.** ${m.cpu}, ${m.logical_cores} logical cores, ${m.mem_gb} GB RAM, ${m.os}, Node ${m.node}, snarkjs ${m.snarkjs}. Shared sandbox host (peer agents may run); 1/5/15-minute load average before ${r.load_before.join(" / ")}, after ${r.load_after.join(" / ")}.

**Circuit.** \`circuits/integrated_access_v4.circom\`, depth 16, ${r.circuit.constraints} constraints (--O2), ${r.circuit.n_public} public signals; committed DEV-ONLY key (zkey sha256 \`${r.circuit.zkey_sha256.slice(0, 16)}...\`).

**Method.** Prove: \`snarkjs.groth16.fullProve\` (witness + Groth16 prove, in memory, ffjavascript worker pool) on the TEST-ONLY Alice -> Wiki vector input with the committed wasm/zkey; one untimed warm-up, then ${p.n} timed runs. Verify: \`circuits/fixtures/v4/alice_wiki\`, ${r.samples.verify_ms.fast.length} timed rounds after warm-up, each round calls every series once (round-robin). Warm = curve built and per-vkey verifier cached, as in a long-running gateway. p95 is nearest-rank. Times in ms.

| series | what | median | p95 | min | max | mean | n |
|---|---|---:|---:|---:|---:|---:|---:|
${row("prove", "`fullProve` (witness + proof), depth 16", p)}
${row("verify fast", "\`verify()\` default: \`circuits/scripts/fast-verify.js\`", v.fast)}
${row("verify snarkjs", "\`verify()\` with \`ZKGATE_VERIFY_IMPL=snarkjs\` (stock + subgroup/infinity checks)", v.snarkjs)}
${row("verify stock", "bare \`snarkjs.groth16.verify\` (reference, no input rules)", v.stock)}

Cold first \`verify()\` in a fresh process (curve build + verifier precomputation): ${r.verify_cold_ms} ms.

## Against the scope targets

| Metric | Target | Measured | Result |
|---|---|---|---|
| Client prove (fullProve, depth 16) | < 3 s | median ${p.median} ms, p95 ${p.p95} ms | ${pass(p.p95 < r.targets.prove_ms)} |
| Gateway verify, shipped \`verify()\` (fast), warm | < 10 ms | median ${v.fast.median} ms, p95 ${v.fast.p95} ms | ${pass(v.fast.p95 < r.targets.verify_ms)} |
| Gateway verify, \`ZKGATE_VERIFY_IMPL=snarkjs\`, warm | < 10 ms | median ${v.snarkjs.median} ms, p95 ${v.snarkjs.p95} ms | ${pass(v.snarkjs.p95 < r.targets.verify_ms)} (escape hatch only) |
| Proof size | ~200 B | ${r.proof_bytes.raw_uncompressed_points} B as raw points (A, C in G1: 64 B each; B in G2: 128 B); ${r.proof_bytes.json_compact} B compact snarkjs JSON (${r.proof_bytes.json_committed} B as committed, indented) | ${pass(true)} at the point level (128 B compressed); the JSON wire form is ~3x |

Pass/fail is judged on p95. Groth16 verify cost depends on the number of public signals (12), not
on the constraint count, so it does not change between depth 8, 16 and 20. Prove time grows with
the constraint count; the depth sweep (8/16/20) is \`qa\`'s M8 benchmark (\`bench/\`).
`;
}

if (require.main === module) {
  main().catch(async (e) => {
    console.error("[perf-v4]", e.stack || e);
    try {
      await require("./verify.js").terminate();
    } catch (_) {
      /* nothing to release */
    }
    process.exit(1);
  });
}

module.exports = { stats, parseArgs };
