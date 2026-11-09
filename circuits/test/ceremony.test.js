// G2-S1-CIRC-040b: multi-party phase-2 ceremony tooling (circuits/scripts/ceremony.sh).
//
// End to end on the small ChallengeBinding test main (262 constraints at --O2) in a temp dir:
// init -> 3 contributions -> finalize (public beacon) -> install -> a fresh proof verifies under the
// installed vkey. Negatives: tampered intermediate zkey, transcript entry removed / reordered /
// relabelled, forked chain, finalize with 1 contribution, install after a tamper, and no entropy in
// any log, transcript or manifest. Phase 1 is the cached PSE ppot 0080 file when present (as for
// the real ceremony), else a power-8 DEV-ONLY ptau built in the temp dir.
//
// The end-to-end suite is skipped with SKIP_SETUP=1; the static and manifest checks always run.
// Nothing here touches circuits/setup/ or circuits/ceremony/: every path goes through env overrides.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const CIRCUITS = path.resolve(__dirname, "..");
const REPO = path.resolve(CIRCUITS, "..");
const SCRIPTS = path.join(CIRCUITS, "scripts");
const CEREMONY_SH = path.join(SCRIPTS, "ceremony.sh");
const TOY = "circuits/test/circuits/challenge_binding_main.circom";
const PSE_PTAU = path.join(os.homedir(), "zkp-cache", "ptau", "ppot_0080_15.ptau");
const SKIP = process.env.SKIP_SETUP === "1";

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const writeJson = (p, o) => fs.writeFileSync(p, JSON.stringify(o, null, 2) + "\n");
const sha256 = (p) => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const { buildManifest, parseVerifyLog } = require("../scripts/ceremony-transcript.js");

// The forward-safe part of tests/safety F9.09 / F9.06, applied to a manifest this tooling writes.
function assertFloor9Compatible(m, pins) {
  assert.ok(["pse-ppot-0080", "hermez"].includes(m.ptau.source) || m.status === "DEV-ONLY", "non-public phase 1 must stay DEV-ONLY");
  assert.equal(typeof m.phase2.contributions, "number", "F9.09 compares phase2.contributions >= 2");
  if (m.ptau.source === "pse-ppot-0080") {
    assert.equal(m.ptau.file, `ppot_0080_${m.ptau.power}.ptau`);
    if (pins) assert.equal(m.ptau.blake2b, pins[String(m.ptau.power)]);
    assert.match(m.ptau.provenance, /pinned on first download/);
    assert.match(m.ptau.provenance, /full snarkjs powersoftau verify not run/);
    assert.ok(m.limitations.some((l) => /pinned on first download/.test(l)));
  }
  if (!(m.phase2.contributions >= 2)) {
    assert.equal(m.status, "DEV-ONLY");
    assert.ok(m.limitations.some((l) => /single-party phase 2.*could forge proofs/.test(l)));
  }
}

function psePins() {
  const src = fs.readFileSync(path.join(SCRIPTS, "ptau.sh"), "utf8");
  const block = /declare -A PSE_B2=\(([\s\S]*?)\n\)/.exec(src)[1];
  return Object.fromEntries([...block.matchAll(/\[(\d+)\]=([0-9a-f]{128})/g)].map((m) => [m[1], m[2]]));
}

describe("ceremony: static checks", () => {
  it("ceremony.sh exists and never passes entropy on the command line", () => {
    const src = fs.readFileSync(CEREMONY_SH, "utf8");
    // snarkjs takes entropy with -e / --entropy; argv is visible in `ps` and shell history.
    assert.doesNotMatch(src, /\s-e[= ]|--entropy/);
    assert.match(src, /\/dev\/urandom/);
    assert.match(src, /printf '%s\\n' "\$ent" \| snarkjs_out zkey contribute/);
    for (const sub of ["init", "contribute", "verify", "finalize", "install"]) assert.match(src, new RegExp(`cmd_${sub}\\(\\)`));
  });

  it("package.json exposes ceremony:* scripts that call circuits/scripts/ceremony.sh", () => {
    const pkg = readJson(path.join(REPO, "package.json"));
    for (const s of ["ceremony:init:v4", "ceremony:contribute", "ceremony:verify", "ceremony:finalize", "ceremony:install"]) {
      assert.ok(pkg.scripts[s], s);
      assert.match(pkg.scripts[s], /circuits\/scripts\/ceremony\.sh/, s);
    }
  });

  it("circuits/ceremony/.gitignore keeps zkeys, ptau and build output out of git; README covers every step", () => {
    const gi = fs.readFileSync(path.join(CIRCUITS, "ceremony", ".gitignore"), "utf8");
    assert.match(gi, /^\*\.zkey$/m);
    assert.match(gi, /^\*\.ptau$/m);
    assert.match(gi, /build/);
    const readme = fs.readFileSync(path.join(CIRCUITS, "ceremony", "README.md"), "utf8");
    for (const re of [/drand|Bitcoin/, /beacon/i, /prove:fixtures:v4/, /contribute/, /verify/, /install/, /F9\.06/]) {
      assert.match(readme, re);
    }
  });

  it("ARTIFACTS.md Re-keying points at the ceremony", () => {
    const a = fs.readFileSync(path.join(CIRCUITS, "setup", "ARTIFACTS.md"), "utf8");
    const rekey = a.slice(a.indexOf("## Re-keying"));
    assert.match(rekey, /circuits\/ceremony\/README\.md/);
    assert.match(rekey, /ceremony\.sh install/);
  });
});

describe("ceremony: manifest (buildManifest, no setup)", () => {
  const H = (c) => c.repeat(128);
  const base = {
    name: "x",
    status: "DEV-ONLY",
    status_detail: "DEMO-ONLY (single-party phase 2): ...",
    ptau: {
      source: "pse-ppot-0080", file: "ppot_0080_15.ptau", power: 15, blake2b: "b".repeat(128),
      provenance: "... pinned on first download ...; full snarkjs powersoftau verify not run (...)",
    },
    phase2: { contributions: 1, beacon: true, beacon_hash: "aa", beacon_iterations_exp: 10 },
    limitations: [
      "single-party phase 2 — whoever ran setup could forge proofs; replace via the multi-party ceremony before any real use",
      "phase 1 blake2b-512 pinned on first download (PSE publishes no hash for prepared files); full snarkjs powersoftau verify not run (see ptau.provenance)",
    ],
  };
  const transcript = (n, pub, source = "pse-ppot-0080") => ({
    name: "x",
    ptau: { source },
    contributions: Array.from({ length: n }, (_, i) => ({ order: i + 1, participant: `P${i + 1}`, contribution_hash: H(String(i + 1)) })),
    beacon: { hash: "cd".repeat(32), iterations_exp: 10, source: "drand round R", public: pub, contribution_hash: H("e") },
  });

  it("3 contributions + public beacon + PSE phase 1 -> DEMO-ONLY, numeric contributions, multi-party limitation, phase-1 TOFU kept", () => {
    const m = buildManifest(base, transcript(3, true), "circuits/ceremony/x/transcript.json", "f".repeat(64));
    assert.equal(m.status, "DEMO-ONLY");
    assert.match(m.status_detail, /multi-party phase 2: 3 contributors \+ public beacon/);
    assert.equal(m.phase2.contributions, 3);
    assert.deepEqual(m.phase2.contributors.map((c) => c.participant), ["P1", "P2", "P3"]);
    assert.equal(m.phase2.beacon_public, true);
    assert.ok(!m.limitations.some((l) => /single-party/.test(l)));
    assert.match(m.limitations[0], /^multi-party phase 2 \(3 contributors: P1, P2, P3\): sound as long as at least one/);
    assert.ok(m.limitations.some((l) => /pinned on first download/.test(l)));
    assertFloor9Compatible(m);
  });

  it("a non-public beacon or a dev phase 1 keeps status DEV-ONLY and says why", () => {
    const local = buildManifest(base, transcript(2, false), "t", "f");
    assert.equal(local.status, "DEV-ONLY");
    assert.match(local.status_detail, /beacon not public/);
    assert.ok(local.limitations.some((l) => /beacon is local randomness/.test(l)));
    const dev = buildManifest({ ...base, ptau: { source: "dev", file: "pot15_DEV-ONLY_final.ptau" } }, transcript(3, true, "dev"), "t", "f");
    assert.equal(dev.status, "DEV-ONLY");
    assert.match(dev.status_detail, /local or unknown phase 1/);
  });

  it("a 1-contribution transcript (never produced by finalize) keeps the single-party limitation", () => {
    const m = buildManifest(base, transcript(1, true), "t", "f");
    assert.equal(m.status, "DEV-ONLY");
    assert.equal(m.phase2.contributions, 1);
    assertFloor9Compatible(m);
  });

  it("parseVerifyLog reads the newest-first contribution list in order", () => {
    const hex = (c) => Array.from({ length: 4 }, () => `\t\t${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)} ${c.repeat(8)}`).join("\n");
    const log = `[INFO]  snarkJS: Circuit hash: \n${hex("1")}\n[INFO]  snarkJS: contribution #2 Bob:\n${hex("b")}\n` +
      `[INFO]  snarkJS: contribution #1 Alice:\n${hex("a")}\n[INFO]  snarkJS: ZKey Ok!\n`;
    const r = parseVerifyLog(log);
    assert.equal(r.ok, true);
    assert.equal(r.circuitHash, "1".repeat(128));
    assert.deepEqual(r.contributions.map((c) => [c.n, c.name, c.hash]), [[1, "Alice", "a".repeat(128)], [2, "Bob", "b".repeat(128)]]);
  });
});

(SKIP ? describe.skip : describe)("ceremony: multi-party phase 2 end to end on the ChallengeBinding toy (SKIP_SETUP=1 skips)", function () {
  this.timeout(1800000);

  const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "zkag-ceremony-"));
  const CDIR = path.join(WORK, "ceremony");
  const ENTROPY = crypto.randomBytes(64); // TEST-ONLY entropy source; must never appear in any output
  const BEACON = "8f0c1e2d3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f"; // stands in for a drand round
  const PEOPLE = ["Alice Example", "Bob Example", "Carol Example"];
  const usePse = fs.existsSync(PSE_PTAU);
  const baseEnv = {
    ...process.env,
    BUILD_DIR: path.join(WORK, "build"),
    SETUP_OUT: path.join(WORK, "setup"),
    CEREMONY_DIR: CDIR,
    CEREMONY_ENTROPY_FILE: path.join(WORK, "entropy.bin"),
    CEREMONY_NO_PROMPT: "1",
    ...(usePse ? { PTAU_SOURCE: "pse" } : { PTAU_SOURCE: "dev", PTAU_POWER: "8", PTAU_DIR: path.join(WORK, "ptau") }),
  };
  let logs = "";
  const run = (args, env = {}) => {
    const r = spawnSync("bash", [CEREMONY_SH, ...args], { cwd: REPO, env: { ...baseEnv, ...env }, encoding: "utf8" });
    logs += `${r.stdout}\n${r.stderr}\n`;
    return r;
  };
  const mustRun = (args, env) => {
    const r = run(args, env);
    if (r.status !== 0) throw new Error(`ceremony.sh ${args.join(" ")} exited ${r.status}\n${r.stdout}\n${r.stderr}`);
    return r;
  };
  const z = (name, i, dir = CDIR) => path.join(dir, name, `${name}_${String(i).padStart(4, "0")}.zkey`);
  const fin = (name, dir = CDIR) => path.join(dir, name, `${name}_final.zkey`);
  const tpath = (dir, name) => path.join(dir, name, "transcript.json");

  // Copy the toy ceremony into a scratch CEREMONY_DIR so a tamper never touches the real one.
  let nCopies = 0;
  const copyCeremony = () => {
    const dst = path.join(WORK, `tamper-${++nCopies}`);
    fs.mkdirSync(dst);
    fs.cpSync(path.join(CDIR, "toy"), path.join(dst, "toy"), { recursive: true });
    return dst;
  };

  let transcript, manifest, vkey, proof, pub, snarkjs, verifyLib;

  before(async function () {
    fs.writeFileSync(baseEnv.CEREMONY_ENTROPY_FILE, ENTROPY);
    mustRun(["init", TOY, "toy"]);
    PEOPLE.forEach((who, i) => mustRun(["contribute", "toy", z("toy", i), who]));
    mustRun(["finalize", "toy", z("toy", 3), BEACON], { BEACON_SOURCE: "test beacon (stands in for drand round N)" });
    mustRun(["install", "toy"]);

    transcript = readJson(tpath(CDIR, "toy"));
    manifest = readJson(path.join(CDIR, "toy", "toy.manifest.json"));
    vkey = readJson(path.join(baseEnv.SETUP_OUT, "toy.verification_key.json"));

    // A fresh proof, in process, with the INSTALLED pair (what the client does with circuits/setup/).
    snarkjs = require("snarkjs");
    verifyLib = require("../scripts/verify.js");
    const input = { credentialSecret: "123456789", nonce: "42", resourceId: "2", epoch: "2990214" }; // TEST-ONLY
    ({ proof, publicSignals: pub } = await snarkjs.groth16.fullProve(
      input,
      path.join(baseEnv.SETUP_OUT, "toy.wasm"),
      path.join(baseEnv.SETUP_OUT, "toy.zkey"),
    ));
  });

  after(async () => {
    if (verifyLib) await verifyLib.terminate();
    if (snarkjs && globalThis.curve_bn128) await globalThis.curve_bn128.terminate();
    fs.rmSync(WORK, { recursive: true, force: true });
  });

  it("transcript lists the 3 contributions in order, chained by zkey hash, then the public beacon", () => {
    assert.match(transcript.format, /ceremony-transcript v1/);
    assert.equal(transcript.circuit, TOY);
    assert.match(transcript.r1cs_sha256, /^[0-9a-f]{64}$/);
    assert.match(transcript.snarkjs_circuit_hash, /^[0-9a-f]{128}$/);
    assert.equal(transcript.ptau.source, usePse ? "pse-ppot-0080" : "dev");
    assert.deepEqual(transcript.contributions.map((c) => c.participant), PEOPLE);
    assert.deepEqual(transcript.contributions.map((c) => c.order), [1, 2, 3]);
    let prev = transcript.initial.zkey_sha256;
    for (const [i, c] of transcript.contributions.entries()) {
      assert.match(c.contribution_hash, /^[0-9a-f]{128}$/);
      assert.equal(c.prev_zkey_sha256, prev);
      assert.equal(c.zkey_sha256, sha256(z("toy", i + 1)));
      prev = c.zkey_sha256;
    }
    assert.equal(new Set(transcript.contributions.map((c) => c.contribution_hash)).size, 3);
    assert.equal(transcript.beacon.hash, BEACON);
    assert.equal(transcript.beacon.public, true);
    assert.equal(transcript.beacon.prev_zkey_sha256, prev);
  });

  it("manifest has the setup-manifest.js fields, numeric phase2.contributions + contributors, and is floor-9 compatible", () => {
    for (const k of ["name", "status", "status_detail", "circuit", "protocol", "curve", "circom_version", "circom_flags",
      "snarkjs_version", "constraints", "n_public", "public_signals", "r1cs_sha256", "wasm_sha256", "zkey_sha256",
      "verification_key_sha256", "ptau", "phase2", "limitations", "date"]) {
      assert.ok(k in manifest, k);
    }
    assert.equal(manifest.constraints, 262);
    assert.deepEqual(manifest.public_signals, ["nullifier", "nonce", "resourceId", "epoch"]);
    assert.equal(manifest.phase2.contributions, 3);
    assert.deepEqual(manifest.phase2.contributors,
      transcript.contributions.map((c) => ({ order: c.order, participant: c.participant, hash: c.contribution_hash })));
    assert.equal(manifest.phase2.beacon_hash, BEACON);
    assert.equal(manifest.phase2.transcript_sha256, sha256(tpath(CDIR, "toy")));
    assert.doesNotMatch(JSON.stringify(manifest), new RegExp(WORK.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), "machine path in manifest");
    assert.equal(manifest.status, usePse ? "DEMO-ONLY" : "DEV-ONLY");
    assertFloor9Compatible(manifest, psePins());
    // install put the same files where setup.sh + the committed layout would
    for (const [f, k] of [["toy.zkey", "zkey_sha256"], ["toy.wasm", "wasm_sha256"], ["toy.verification_key.json", "verification_key_sha256"]]) {
      assert.equal(sha256(path.join(baseEnv.SETUP_OUT, f)), manifest[k], f);
    }
    assert.deepEqual(readJson(path.join(baseEnv.SETUP_OUT, "toy.manifest.json")), manifest);
    assert.equal(sha256(path.join(baseEnv.BUILD_DIR, "toy", "toy.zkey")), manifest.zkey_sha256);
    assert.equal(spawnSync("bash", [path.join(SCRIPTS, "artifacts.sh"), "check", "toy"], { env: baseEnv }).status, 0);
  });

  it("a fresh proof verifies under the installed vkey, and not with a changed public signal", async () => {
    assert.equal(await verifyLib.verify(vkey, pub, proof), true);
    const bad = [...pub];
    bad[1] = String(BigInt(bad[1]) + 1n);
    assert.equal(await verifyLib.verify(vkey, bad, proof), false);
  });

  it("verify accepts the final zkey and every intermediate zkey", () => {
    assert.equal(run(["verify", "toy", fin("toy")]).status, 0);
    for (let i = 0; i <= 3; i++) assert.equal(run(["verify", "toy", z("toy", i)]).status, 0, `zkey ${i}`);
  });

  it("verify and contribute refuse a tampered intermediate zkey (even with its transcript hash patched)", () => {
    const dir = copyCeremony();
    const zk = z("toy", 2, dir);
    const buf = fs.readFileSync(zk);
    for (let off = buf.length - 200; off < buf.length - 100; off++) buf[off] ^= 0x5a;
    fs.writeFileSync(zk, buf);
    assert.notEqual(run(["verify", "toy", zk], { CEREMONY_DIR: dir }).status, 0);
    // Patch the transcript so that only the cryptographic check can catch it.
    const t = readJson(tpath(dir, "toy"));
    t.contributions[1].zkey_sha256 = sha256(zk);
    t.contributions[2].prev_zkey_sha256 = sha256(zk);
    t.contributions.splice(2, 1);
    t.beacon = null;
    writeJson(tpath(dir, "toy"), t);
    const r = run(["verify", "toy", zk], { CEREMONY_DIR: dir });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /snarkjs zkey verify FAILED/);
    const c = run(["contribute", "toy", zk, "Mallory Example"], { CEREMONY_DIR: dir });
    assert.notEqual(c.status, 0);
    assert.equal(sha256(z("toy", 3, dir)), sha256(z("toy", 3)), "the copied _0003 was not overwritten");
    assert.equal(readJson(tpath(dir, "toy")).contributions.length, 2);
  });

  it("verify refuses when a transcript entry is removed", () => {
    const dir = copyCeremony();
    const t = readJson(tpath(dir, "toy"));
    t.contributions.splice(1, 1);
    t.contributions[1].order = 2;
    writeJson(tpath(dir, "toy"), t);
    assert.notEqual(run(["verify", "toy", fin("toy", dir)], { CEREMONY_DIR: dir }).status, 0);
    assert.notEqual(run(["verify", "toy", z("toy", 3, dir)], { CEREMONY_DIR: dir }).status, 0);
  });

  it("verify refuses when transcript entries are reordered", () => {
    const dir = copyCeremony();
    const t = readJson(tpath(dir, "toy"));
    [t.contributions[0], t.contributions[1]] = [t.contributions[1], t.contributions[0]];
    writeJson(tpath(dir, "toy"), t);
    const r = run(["verify", "toy", z("toy", 3, dir)], { CEREMONY_DIR: dir });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /transcript check FAILED/);
  });

  it("verify refuses two participants' names and hashes swapped in an otherwise consistent transcript", () => {
    const dir = copyCeremony();
    const t = readJson(tpath(dir, "toy"));
    const [a, b] = t.contributions;
    [a.participant, b.participant] = [b.participant, a.participant];
    [a.contribution_hash, b.contribution_hash] = [b.contribution_hash, a.contribution_hash];
    writeJson(tpath(dir, "toy"), t);
    const r = run(["verify", "toy", z("toy", 3, dir)], { CEREMONY_DIR: dir });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /contribution #1/);
  });

  it("contribute refuses to fork the chain from a zkey that is not the latest", () => {
    const dir = copyCeremony();
    const t = readJson(tpath(dir, "toy"));
    t.beacon = null; // pretend the ceremony is still open
    writeJson(tpath(dir, "toy"), t);
    const r = run(["contribute", "toy", z("toy", 1, dir), "Mallory Example"], { CEREMONY_DIR: dir });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /not the latest|fork/);
    assert.equal(readJson(tpath(dir, "toy")).contributions.length, 3);
    // a finalized ceremony takes no further contribution, even on the final zkey
    const f = run(["contribute", "toy", fin("toy"), "Mallory Example"]);
    assert.notEqual(f.status, 0);
  });

  it("finalize refuses a ceremony with 1 contribution, even with CEREMONY_MIN_CONTRIBUTIONS=1", () => {
    mustRun(["init", TOY, "toy1"]);
    mustRun(["contribute", "toy1", z("toy1", 0), "Alice Example"]);
    for (const env of [{}, { CEREMONY_MIN_CONTRIBUTIONS: "1" }]) {
      const r = run(["finalize", "toy1", z("toy1", 1), BEACON], env);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /only 1 contribution/);
    }
    assert.equal(fs.existsSync(fin("toy1")), false);
    assert.equal(readJson(tpath(CDIR, "toy1")).beacon, null);
  });

  it("a ceremony without a beacon argument records beacon.public false and stays DEV-ONLY; its vkey differs", () => {
    mustRun(["contribute", "toy1", z("toy1", 1), "Bob Example"]);
    mustRun(["finalize", "toy1", z("toy1", 2)]);
    const t = readJson(tpath(CDIR, "toy1"));
    assert.equal(t.beacon.public, false);
    const m = readJson(path.join(CDIR, "toy1", "toy1.manifest.json"));
    assert.equal(m.status, "DEV-ONLY");
    assert.equal(m.phase2.beacon_public, false);
    assert.ok(m.limitations.some((l) => /beacon is local randomness/.test(l)));
    const vk1 = readJson(path.join(CDIR, "toy1", "toy1.verification_key.json"));
    assert.notDeepEqual(vk1.vk_delta_2, vkey.vk_delta_2);
  });

  it("install refuses (and copies nothing) when the final zkey or the transcript changed after finalize", () => {
    for (const tamper of ["zkey", "transcript"]) {
      const dir = copyCeremony();
      const out = path.join(WORK, `setup-${tamper}`);
      if (tamper === "zkey") fs.appendFileSync(fin("toy", dir), Buffer.from([0]));
      else {
        const t = readJson(tpath(dir, "toy"));
        t.contributions[0].date = "2000-01-01T00:00:00.000Z";
        writeJson(tpath(dir, "toy"), t);
      }
      const r = run(["install", "toy"], { CEREMONY_DIR: dir, SETUP_OUT: out, BUILD_DIR: path.join(WORK, `build-${tamper}`) });
      assert.notEqual(r.status, 0, tamper);
      assert.equal(fs.existsSync(path.join(out, "toy.zkey")), false, tamper);
    }
  });

  it("contribute rejects a participant name that could break the transcript", () => {
    assert.notEqual(run(["contribute", "toy1", z("toy1", 2), "Eve: #1\nforged"]).status, 0);
  });

  it("no entropy appears in any log, transcript or manifest", () => {
    const hex = ENTROPY.toString("hex");
    const needles = [hex, hex.toUpperCase(), hex.slice(0, 32), hex.slice(64), ENTROPY.toString("base64").slice(0, 24)];
    const texts = [logs];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else if (/\.(json|log|txt|md)$/.test(e.name)) texts.push(fs.readFileSync(p, "utf8"));
      }
    };
    walk(CDIR);
    walk(baseEnv.SETUP_OUT);
    assert.ok(logs.length > 1000, "the runs were captured");
    for (const t of texts) for (const n of needles) assert.equal(t.includes(n), false, `entropy fragment ${n.slice(0, 8)}...`);
  });
});
