// G0-S1-CIRC-022: trusted setup, committed proving pair and prove/verify for integrated_access_v3.
//
// Uses ONLY the committed artefacts in circuits/setup/ (it never re-runs setup.sh, which would make
// a new key). The TEST-ONLY witness input is built here in memory from fixed seeds with
// circomlibjs; the only file it is ever written to is inside a temp dir that is removed afterwards.
//
// SKIP_SETUP=1 skips the suite (Groth16 proving takes a few seconds).
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const snarkjs = require("snarkjs");
const { buildPoseidon, buildEddsa } = require("circomlibjs");
const verifyLib = require("../scripts/verify.js");

const NAME = "integrated_access_v3";
const CIRCUITS = path.resolve(__dirname, "..");
const REPO = path.resolve(CIRCUITS, "..");
const SETUP = path.join(CIRCUITS, "setup");
const SCRIPTS = path.join(CIRCUITS, "scripts");
const ZKEY = path.join(SETUP, `${NAME}.zkey`);
const WASM = path.join(SETUP, `${NAME}.wasm`);
const VKEY_FILE = path.join(SETUP, `${NAME}.verification_key.json`);
const MANIFEST_FILE = path.join(SETUP, `${NAME}.manifest.json`);
const P = verifyLib.FIELD_P;

const SKIP = process.env.SKIP_SETUP === "1";

// ---- helpers (kept in this file: the rest of circuits/test is owned by another task) -------------

/** Run a circuits/scripts/*.sh script; never throws, returns { status, stdout, stderr }. */
function runScript(script, args, env = {}) {
  const r = spawnSync("bash", [path.join(SCRIPTS, script), ...args], {
    cwd: REPO,
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 120000,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `zkag-${tag}-`));
}

/** Fixed TEST-ONLY field element from a label (sha256, reduced mod p). Not a secret of anyone. */
function seed(label) {
  return BigInt("0x" + crypto.createHash("sha256").update(`ZKAG TEST-ONLY v3 ${label}`).digest("hex")) % P;
}

/**
 * A valid TEST-ONLY input for IntegratedAccessGate (v3), built exactly as the circuit needs:
 *   commitment = Poseidon(secret, salt); M = leaf = commitment
 *   (R8, S) = EdDSA-Poseidon signPoseidon(issuer prv, commitment), (Ax, Ay) = issuer public key
 *   depth-2 tree, leaves [l0, commitment, l2, l3] (commitment at index 1);
 *   pathIndices[i] = 1 means the current node is the RIGHT child at level i.
 *   role 2, clearance 2, deviceCompliant 1, employeeActive 1.
 */
async function buildV3Input() {
  const poseidon = await buildPoseidon();
  const eddsa = await buildEddsa();
  const F = poseidon.F;
  const H = (a, b) => F.toObject(poseidon([a, b]));

  const secret = seed("secret");
  const salt = seed("salt");
  const commitment = H(secret, salt);

  const issuerPrv = crypto.createHash("sha256").update("ZKAG TEST-ONLY v3 issuer key").digest();
  const A = eddsa.prv2pub(issuerPrv);
  const sig = eddsa.signPoseidon(issuerPrv, F.e(commitment));
  assert.ok(eddsa.verifyPoseidon(F.e(commitment), sig, A), "circomlibjs signature self-check");

  const leaves = [H(seed("leaf0"), 0n), commitment, H(seed("leaf2"), 0n), H(seed("leaf3"), 0n)];
  const n01 = H(leaves[0], leaves[1]);
  const n23 = H(leaves[2], leaves[3]);
  const root = H(n01, n23);

  const input = {
    credentialSecret: secret.toString(),
    credentialSalt: salt.toString(),
    role: "2",
    clearance: "2",
    deviceCompliant: "1",
    employeeActive: "1",
    Ax: F.toObject(A[0]).toString(),
    Ay: F.toObject(A[1]).toString(),
    R8x: F.toObject(sig.R8[0]).toString(),
    R8y: F.toObject(sig.R8[1]).toString(),
    S: sig.S.toString(),
    M: commitment.toString(),
    leaf: commitment.toString(),
    pathElements: [leaves[0].toString(), n23.toString()],
    pathIndices: ["1", "0"],
    root: root.toString(),
  };
  return { input, root: root.toString() };
}

const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

// Release snarkjs / ffjavascript worker threads so mocha can exit (memory: snarkjs-workers-hang-mocha).
after(async () => {
  await verifyLib.terminate();
});

(SKIP ? describe.skip : describe)("G0-S1-CIRC-022 integrated_access_v3 setup + prove/verify", function () {
  this.timeout(180000);

  let vkey;
  let manifest;
  let fixture; // { input, root }
  let proof;
  let publicSignals;

  before(async () => {
    vkey = readJson(VKEY_FILE);
    manifest = readJson(MANIFEST_FILE);
    fixture = await buildV3Input();
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(fixture.input, WASM, ZKEY));
  });

  describe("manifest provenance", () => {
    it("names the circuit, toolchain and public signals", () => {
      assert.equal(manifest.name, NAME);
      assert.equal(manifest.circuit, "circuits/integrated_access_v3.circom");
      assert.equal(manifest.protocol, "groth16");
      assert.equal(manifest.curve, "bn128");
      assert.equal(manifest.circom_version, "2.2.3");
      assert.equal(manifest.snarkjs_version, readJson(path.join(REPO, "node_modules/snarkjs/package.json")).version);
      assert.deepEqual(manifest.public_signals, ["root"]);
      assert.equal(manifest.n_public, 1);
      assert.equal(vkey.nPublic, 1);
      assert.ok(Number.isInteger(manifest.constraints) && manifest.constraints > 0 && manifest.constraints < 2 ** manifest.ptau.power);
      for (const k of ["r1cs_sha256", "wasm_sha256", "zkey_sha256", "verification_key_sha256"]) {
        assert.match(manifest[k], /^[0-9a-f]{64}$/, k);
      }
    });

    it("records DEV-ONLY status and the single-party limitation", () => {
      assert.equal(manifest.status, "DEV-ONLY");
      assert.match(manifest.status_detail, /^DEMO-ONLY \(single-party phase 2\)/);
      assert.match(manifest.ptau.blake2b, /^[0-9a-f]{128}$/);
      const lim = manifest.limitations.join("\n");
      assert.match(lim, /single-party phase 2/);
      assert.ok(
        manifest.limitations.includes(
          "single-party phase 2 — whoever ran setup could forge proofs; replace via the multi-party ceremony before any real use",
        ),
      );
      assert.equal(manifest.phase2.contributions, 1);
      assert.match(manifest.phase2.beacon_hash, /^[0-9a-f]+$/);
      // No machine paths leak into the committed manifest.
      assert.doesNotMatch(JSON.stringify(manifest), /\/home\/|\/root\/|\/tmp\//);
    });

    it("G2-S1-CIRC-040a: phase 1 is the pinned PSE ppot 0080 power-15 file, with its provenance and no DEV-ONLY phase 1", () => {
      const r = runScript("ptau.sh", ["--print-pse-pins"]);
      assert.equal(r.status, 0, r.stderr);
      const pins = Object.fromEntries(r.stdout.trim().split("\n").map((l) => l.split(" ")));
      assert.deepEqual(pins, {
        15: "a6dd3adcf80f6716c4d082be2626e790af1f5ed3d760814dc439a07d91e93421382c91d4f705abe8cd90ef1956e4b7eaf58db29d81be5abe624dab4dae827f24",
      });
      assert.equal(manifest.ptau.source, "pse-ppot-0080");
      assert.equal(manifest.ptau.file, "ppot_0080_15.ptau");
      assert.equal(manifest.ptau.power, 15);
      assert.equal(manifest.ptau.blake2b, pins[15]);
      assert.equal(manifest.ptau.warning, undefined);
      for (const s of ["7,325,000", "d9ec6fad4a7a7e3358a0c4bed7171622", "4bf672f3ba1de1bb6105e1ab88359612", "pinned on first download", "pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com"]) {
        assert.ok(manifest.ptau.provenance.includes(s), s);
      }
      assert.doesNotMatch(manifest.limitations.join("\n"), /DEV-ONLY phase 1/);
    });

    it("every pinned Hermez blake2b appears in the installed snarkjs README", () => {
      const r = runScript("ptau.sh", ["--print-pins"]);
      assert.equal(r.status, 0, r.stderr);
      const readme = fs.readFileSync(path.join(REPO, "node_modules/snarkjs/README.md"), "utf8");
      const pins = r.stdout.trim().split("\n").map((l) => l.split(" "));
      assert.ok(pins.length >= 8);
      for (const [n, b2] of pins) {
        const row = readme.split("\n").find((l) => l.includes(`powersOfTau28_hez_final_${String(n).padStart(2, "0")}.ptau`));
        assert.ok(row && row.includes(b2), `pin for power ${n} not in snarkjs README`);
      }
    });
  });

  describe("committed proving pair (artifacts.sh)", () => {
    it("check passes: hashes equal the manifest and the vkey exported from the zkey is the committed vkey", () => {
      const r = runScript("artifacts.sh", ["check", NAME]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /vkey exported from integrated_access_v3\.zkey equals/);
    });

    it("check fails (exit 1) on a corrupted zkey", () => {
      const dir = tmpDir("corrupt");
      try {
        for (const f of [`${NAME}.zkey`, `${NAME}.wasm`, `${NAME}.verification_key.json`, `${NAME}.manifest.json`]) {
          fs.copyFileSync(path.join(SETUP, f), path.join(dir, f));
        }
        const z = path.join(dir, `${NAME}.zkey`);
        const buf = fs.readFileSync(z);
        buf[buf.length - 100] ^= 0xff;
        fs.writeFileSync(z, buf);
        const r = runScript("artifacts.sh", ["check", NAME], { SETUP_OUT: dir });
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stderr, /FAIL: integrated_access_v3\.zkey sha256/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("check fails (exit 1) when the vkey does not match the zkey, even with a consistent manifest", () => {
      const dir = tmpDir("vkmismatch");
      try {
        for (const f of [`${NAME}.zkey`, `${NAME}.wasm`]) fs.copyFileSync(path.join(SETUP, f), path.join(dir, f));
        const vk = readJson(VKEY_FILE);
        vk.vk_alpha_1 = vk.IC[0]; // a different, still well-formed key
        const vkFile = path.join(dir, `${NAME}.verification_key.json`);
        fs.writeFileSync(vkFile, JSON.stringify(vk, null, 1));
        const m = { ...manifest, verification_key_sha256: crypto.createHash("sha256").update(fs.readFileSync(vkFile)).digest("hex") };
        fs.writeFileSync(path.join(dir, `${NAME}.manifest.json`), JSON.stringify(m));
        const r = runScript("artifacts.sh", ["check", NAME], { SETUP_OUT: dir });
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stderr, /is not integrated_access_v3\.verification_key\.json/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe("prove + verify (verify.js)", () => {
    it("a proof from the committed zkey + wasm for a valid TEST-ONLY input verifies", async () => {
      assert.deepEqual(publicSignals, [fixture.root]);
      assert.equal(await verifyLib.verify(vkey, publicSignals, proof), true);
    });

    it("a tampered root public signal does not verify", async () => {
      const tampered = (((BigInt(fixture.root) + 1n) % P)).toString();
      assert.equal(await verifyLib.verify(vkey, [tampered], proof), false);
    });

    it("a leading-zero spelling of the root does not verify (raw snarkjs would accept it)", async () => {
      const padded = "0" + fixture.root;
      assert.equal(await snarkjs.groth16.verify(vkey, [padded], proof), true, "documents why verify.js checks");
      assert.equal(await verifyLib.verify(vkey, [padded], proof), false);
    });

    it("root + p, a signed or a whitespace-padded root do not verify", async () => {
      for (const s of [(BigInt(fixture.root) + P).toString(), "+" + fixture.root, fixture.root + " ", Number(1)]) {
        assert.equal(await verifyLib.verify(vkey, [s], proof), false, String(s));
      }
    });

    it("a tampered proof element or a proof coordinate >= q does not verify", async () => {
      const p1 = JSON.parse(JSON.stringify(proof));
      p1.pi_a[0] = ((BigInt(p1.pi_a[0]) + 1n) % verifyLib.FIELD_Q).toString();
      assert.equal(await verifyLib.verify(vkey, publicSignals, p1), false);
      const p2 = JSON.parse(JSON.stringify(proof));
      p2.pi_c[0] = (BigInt(p2.pi_c[0]) + verifyLib.FIELD_Q).toString();
      assert.equal(await verifyLib.verify(vkey, publicSignals, p2), false);
    });

    it("never throws on malformed input", async () => {
      const cases = [
        [null, publicSignals, proof],
        [vkey, null, proof],
        [vkey, publicSignals, null],
        [vkey, [], proof],
        [vkey, [fixture.root, "1"], proof],
        [{ ...vkey, protocol: "plonk" }, publicSignals, proof],
        [vkey, publicSignals, { ...proof, pi_b: [["1"]] }],
        ["x", 1, "y"],
      ];
      for (const c of cases) assert.equal(await verifyLib.verify(...c), false);
    });

    it("isCanonicalSignal / canonicalizeSignals", () => {
      const ok = ["0", "1", "123", (P - 1n).toString(), fixture.root];
      const bad = ["", "00", "0123", "-1", "+1", " 1", "1 ", "1e3", "0x1", P.toString(), (P + 1n).toString(), "9".repeat(78), 1, 1n, null, undefined, ["1"]];
      for (const s of ok) assert.equal(verifyLib.isCanonicalSignal(s), true, String(s));
      for (const s of bad) assert.equal(verifyLib.isCanonicalSignal(s), false, String(s));
      assert.deepEqual(verifyLib.canonicalizeSignals(["0123", "0", "00"]), ["123", "0", "0"]);
      assert.equal(verifyLib.canonicalizeSignals(["-1"]), null);
      assert.equal(verifyLib.canonicalizeSignals([P.toString()]), null);
      assert.equal(verifyLib.canonicalizeSignals("1"), null);
    });
  });

  describe("CLI pipeline: artifacts.sh install -> prove.sh -> verify.sh (temp dirs only)", () => {
    let dir;
    before(() => {
      dir = tmpDir("cli");
    });
    after(() => {
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    });

    it("install copies the checked pair into BUILD_DIR/<name>/", () => {
      const r = runScript("artifacts.sh", ["install", NAME], { BUILD_DIR: path.join(dir, "build") });
      assert.equal(r.status, 0, r.stderr);
      for (const f of [`${NAME}.zkey`, `${NAME}.wasm`, "verification_key.json"]) {
        assert.ok(fs.existsSync(path.join(dir, "build", NAME, f)), f);
      }
    });

    it("prove.sh proves a valid input; verify.sh accepts it and rejects a tampered root", () => {
      const inputFile = path.join(dir, "input.json"); // PRIVATE: temp dir only, removed in after()
      fs.writeFileSync(inputFile, JSON.stringify(fixture.input), { mode: 0o600 });
      const out = path.join(dir, "out");
      let r = runScript("prove.sh", [NAME, inputFile, out], { BUILD_DIR: path.join(dir, "build") });
      fs.rmSync(inputFile);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readJson(path.join(out, "public.json")), [fixture.root]);

      r = runScript("verify.sh", [NAME, path.join(out, "proof.json"), path.join(out, "public.json")]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /^OK$/m);

      const bad = path.join(out, "public_tampered.json");
      fs.writeFileSync(bad, JSON.stringify([((BigInt(fixture.root) + 1n) % P).toString()]));
      r = runScript("verify.sh", [NAME, path.join(out, "proof.json"), bad]);
      assert.equal(r.status, 1, r.stderr);
      assert.match(r.stdout, /^INVALID$/m);
    });

    it("prove.sh exits 1 and writes nothing for an input that violates the policy (role 1)", () => {
      const inputFile = path.join(dir, "input_bad.json");
      fs.writeFileSync(inputFile, JSON.stringify({ ...fixture.input, role: "1" }), { mode: 0o600 });
      const out = path.join(dir, "out_bad");
      const r = runScript("prove.sh", [NAME, inputFile, out], { BUILD_DIR: path.join(dir, "build") });
      fs.rmSync(inputFile);
      assert.equal(r.status, 1, r.stderr);
      assert.equal(fs.existsSync(out), false);
    });
  });
});

// G2-S1-CIRC-040a: the pse phase-1 source and the manifest labels per source. Synthetic: no network,
// no proving; temp dirs only.
describe("G2-S1-CIRC-040a ptau.sh pse source + setup-manifest.js labels", function () {
  this.timeout(90000);
  let dir;
  before(() => {
    dir = tmpDir("pse");
  });
  after(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("PTAU_SOURCE=pse refuses (exit 2) a cached ppot_0080_15.ptau whose blake2b is not the pin", () => {
    const d = path.join(dir, "bad");
    fs.mkdirSync(d);
    fs.writeFileSync(path.join(d, "ppot_0080_15.ptau"), "not the PSE file");
    const r = runScript("ptau.sh", [], { PTAU_SOURCE: "pse", PTAU_POWER: "15", PTAU_DIR: d, PSE_PTAU_URL: "http://127.0.0.1:9" });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /cached ppot_0080_15\.ptau blake2b [0-9a-f]{128} != pinned/);
    assert.equal(r.stdout, "");
  });

  it("PTAU_SOURCE=pse fails closed (exit 2) for an unpinned power, with no dev fallback", () => {
    const d = path.join(dir, "unpinned");
    fs.mkdirSync(d);
    const r = runScript("ptau.sh", [], { PTAU_SOURCE: "pse", PTAU_POWER: "14", PTAU_DIR: d, PSE_PTAU_URL: "http://127.0.0.1:9" });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /no pinned PSE ppot 0080 hash for power 14/);
    assert.match(r.stderr, /PTAU_SOURCE=pse forbids any fallback/);
    assert.deepEqual(fs.readdirSync(d), []);
  });

  it("PTAU_SOURCE=pse fails closed (exit 2) when the download fails and leaves no partial file", () => {
    const d = path.join(dir, "offline");
    fs.mkdirSync(d);
    const r = runScript("ptau.sh", [], { PTAU_SOURCE: "pse", PTAU_POWER: "15", PTAU_DIR: d, PSE_PTAU_URL: "http://127.0.0.1:9" });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /PSE download failed/);
    assert.deepEqual(fs.readdirSync(d), []);
  });

  it("an unknown PTAU_SOURCE is a usage error that lists pse", () => {
    const r = runScript("ptau.sh", [], { PTAU_SOURCE: "nope", PTAU_DIR: path.join(dir, "x") });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /auto\|pse\|hermez\|dev/);
  });

  const cachedPse = path.join(os.homedir(), "zkp-cache", "ptau", "ppot_0080_15.ptau");
  (fs.existsSync(cachedPse) ? it : it.skip)("PTAU_SOURCE=pse returns the cached pinned file (when present on this machine)", () => {
    const r = runScript("ptau.sh", [], { PTAU_SOURCE: "pse", PTAU_POWER: "15", PTAU_DIR: path.dirname(cachedPse), PSE_PTAU_URL: "http://127.0.0.1:9" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim().split("\n").pop(), cachedPse);
    const info = readJson(`${cachedPse}.info.json`);
    assert.equal(info.source, "pse-ppot-0080");
    assert.match(info.provenance, /0080_carter_response/);
  });

  /** Run setup-manifest.js on dummy files with a given ptau .info.json. */
  function manifestFor(info) {
    const d = fs.mkdtempSync(path.join(dir, "m-"));
    const f = (n, body) => {
      fs.writeFileSync(path.join(d, n), body);
      return path.join(d, n);
    };
    const args = {
      name: "t", circuit: "circuits/t.circom", circom: "2.2.3", snarkjs: "0.7.6",
      r1cs: f("t.r1cs", "r"), sym: f("t.sym", "1,1,0,main.root\n"), wasm: f("t.wasm", "w"), zkey: f("t.zkey", "z"), vkey: f("vk.json", "{}"),
      ptau: f("p.ptau", "p"), "ptau-info": f("p.ptau.info.json", JSON.stringify(info)),
      constraints: "10", "n-pub-in": "1", "n-out": "0", beacon: "ab",
    };
    const argv = Object.entries(args).flatMap(([k, v]) => [`--${k}`, v]);
    const r = spawnSync("node", [path.join(SCRIPTS, "setup-manifest.js"), ...argv], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  }

  it("a pse-ppot-0080 phase 1 gives DEMO-ONLY detail, the single-party limitation, the provenance and no DEV-ONLY phase 1", () => {
    const m = manifestFor({ file: "ppot_0080_15.ptau", source: "pse-ppot-0080", power: 15, blake2b: "aa", provenance: "PSE 0080" });
    assert.equal(m.status, "DEV-ONLY");
    assert.match(m.status_detail, /^DEMO-ONLY \(single-party phase 2\)/);
    assert.equal(m.ptau.provenance, "PSE 0080");
    assert.match(m.limitations[0], /^single-party phase 2 — whoever ran setup could forge proofs/);
    assert.doesNotMatch(m.limitations.join("\n"), /DEV-ONLY phase 1/);
    assert.match(m.limitations.join("\n"), /pinned on first download/);
  });

  it("a dev phase 1 still records a DEV-ONLY phase 1 limitation", () => {
    const m = manifestFor({ file: "pot15_DEV-ONLY_final.ptau", source: "dev", power: 15, blake2b: "aa" });
    assert.equal(m.status, "DEV-ONLY");
    assert.match(m.status_detail, /^DEV-ONLY \(local phase 1/);
    assert.match(m.limitations[0], /^DEV-ONLY phase 1/);
    assert.match(m.limitations.join("\n"), /single-party phase 2/);
  });
});
