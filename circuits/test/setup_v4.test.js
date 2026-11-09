// G1-S1-CIRC-037: trusted setup and committed proving artefacts for integrated_access_v4 (ADR 0009,
// decision D7; phase 1 PSE ppot 0080 since G2-S1-CIRC-040a, phase 2 single-party: DEMO-ONLY).
//
// Uses ONLY the committed artefacts in circuits/setup/ (never re-runs setup.sh). The Alice -> Wiki
// input is the TEST-ONLY vector circuits/test/vectors/v4/input.alice.wiki.json (built by
// circuits/lib buildInputV4); it is proved in memory and never written anywhere.
//
// SKIP_SETUP=1 skips the suite.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const snarkjs = require("snarkjs");
const zk = require("../lib");
const verifyLib = require("../scripts/verify.js");

const NAME = "integrated_access_v4";
const CIRCUITS = path.resolve(__dirname, "..");
const REPO = path.resolve(CIRCUITS, "..");
const SETUP = path.join(CIRCUITS, "setup");
const SCRIPTS = path.join(CIRCUITS, "scripts");
const ZKEY = path.join(SETUP, `${NAME}.zkey`);
const WASM = path.join(SETUP, `${NAME}.wasm`);
const VKEY_FILE = path.join(SETUP, `${NAME}.verification_key.json`);
const MANIFEST_FILE = path.join(SETUP, `${NAME}.manifest.json`);
const VECTOR = path.join(CIRCUITS, "test", "vectors", "v4", "input.alice.wiki.json");
const P = verifyLib.FIELD_P;

// access.public_signals v4 (docs/CONTRACTS.md), spelled out here so a drift in the lib is caught too.
const CONTRACT_ORDER = [
  "nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance",
  "requireDevice", "now", "nonce", "resourceId", "epoch",
];

const SKIP = process.env.SKIP_SETUP === "1";
const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const sha256 = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");

function runScript(script, args, env = {}) {
  const r = spawnSync("bash", [path.join(SCRIPTS, script), ...args], {
    cwd: REPO,
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 180000,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

after(async () => {
  await verifyLib.terminate();
});

(SKIP ? describe.skip : describe)("G1-S1-CIRC-037 integrated_access_v4 setup + prove/verify", function () {
  this.timeout(300000);

  let vkey;
  let manifest;
  let vector;
  let proof;
  let publicSignals;

  before(async () => {
    vkey = readJson(VKEY_FILE);
    manifest = readJson(MANIFEST_FILE);
    vector = readJson(VECTOR);
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(vector.input, WASM, ZKEY));
  });

  describe("manifest provenance", () => {
    it("names the v4 depth-16 main, the toolchain, 9208 constraints at --O2 and 12 public signals", () => {
      assert.equal(manifest.name, NAME);
      assert.equal(manifest.circuit, "circuits/integrated_access_v4.circom");
      assert.equal(manifest.protocol, "groth16");
      assert.equal(manifest.curve, "bn128");
      assert.equal(manifest.circom_version, "2.2.3");
      assert.match(manifest.circom_flags, /--O2/);
      assert.equal(manifest.snarkjs_version, readJson(path.join(REPO, "node_modules/snarkjs/package.json")).version);
      assert.equal(manifest.constraints, 9208);
      assert.ok(manifest.constraints + 12 < 2 ** manifest.ptau.power);
      assert.equal(manifest.n_public, 12);
      assert.equal(vkey.nPublic, 12);
      assert.equal(vkey.IC.length, 13);
      for (const k of ["r1cs_sha256", "wasm_sha256", "zkey_sha256", "verification_key_sha256"]) {
        assert.match(manifest[k], /^[0-9a-f]{64}$/, k);
      }
    });

    it("public_signals equals the access.public_signals v4 contract order and circuits/lib", () => {
      assert.deepEqual(manifest.public_signals, CONTRACT_ORDER);
      assert.deepEqual([...zk.PUBLIC_SIGNALS.v4], CONTRACT_ORDER);
    });

    it("records DEV-ONLY status, the single-party limitation and no machine paths", () => {
      assert.equal(manifest.status, "DEV-ONLY");
      assert.match(manifest.status_detail, /^DEMO-ONLY \(single-party phase 2\)/);
      // G2-S1-CIRC-040a: phase 1 is PSE ppot 0080 (Hermez is no longer downloadable).
      assert.equal(manifest.ptau.source, "pse-ppot-0080");
      assert.equal(manifest.ptau.file, "ppot_0080_15.ptau");
      assert.equal(manifest.ptau.power, 15);
      assert.equal(
        manifest.ptau.blake2b,
        "a6dd3adcf80f6716c4d082be2626e790af1f5ed3d760814dc439a07d91e93421382c91d4f705abe8cd90ef1956e4b7eaf58db29d81be5abe624dab4dae827f24",
      );
      assert.match(manifest.ptau.provenance, /0080_carter_response/);
      const lim = manifest.limitations.join("\n");
      assert.ok(
        manifest.limitations.includes(
          "single-party phase 2 — whoever ran setup could forge proofs; replace via the multi-party ceremony before any real use",
        ),
      );
      assert.doesNotMatch(lim, /DEV-ONLY phase 1/);
      assert.equal(manifest.phase2.contributions, 1);
      assert.match(manifest.phase2.beacon_hash, /^[0-9a-f]+$/);
      assert.doesNotMatch(JSON.stringify(manifest), /\/home\/|\/root\/|\/tmp\//);
    });

    it("the committed files hash to the manifest (zkey, wasm, vkey)", () => {
      assert.equal(sha256(ZKEY), manifest.zkey_sha256);
      assert.equal(sha256(WASM), manifest.wasm_sha256);
      assert.equal(sha256(VKEY_FILE), manifest.verification_key_sha256);
    });

    it("circuits/lib names the same artefact (the client's ARTEFACT_DIR layout)", () => {
      assert.equal(zk.profiles.v4.artefacts.name, NAME);
    });
  });

  describe("committed proving pair (artifacts.sh, .gitignore)", () => {
    it("artifacts.sh check integrated_access_v4: hashes = manifest, vkey exported from the zkey = committed vkey", () => {
      const r = runScript("artifacts.sh", ["check", NAME]);
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /vkey exported from integrated_access_v4\.zkey equals integrated_access_v4\.verification_key\.json/);
    });

    it("artifacts.sh install integrated_access_v4 fills BUILD_DIR/<name>/ (v3 still installs by name too)", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zkag-v4-install-"));
      try {
        for (const name of [NAME, "integrated_access_v3"]) {
          const r = runScript("artifacts.sh", ["install", name], { BUILD_DIR: dir });
          assert.equal(r.status, 0, r.stderr);
          for (const f of [`${name}.zkey`, `${name}.wasm`, "verification_key.json"]) assert.ok(fs.existsSync(path.join(dir, name, f)), `${name}/${f}`);
        }
        assert.equal(sha256(path.join(dir, NAME, `${NAME}.zkey`)), manifest.zkey_sha256);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("artifacts.sh check fails (exit 1) on a v4 vkey that is not the zkey's, even with a consistent manifest", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zkag-v4-vk-"));
      try {
        for (const f of [`${NAME}.zkey`, `${NAME}.wasm`]) fs.copyFileSync(path.join(SETUP, f), path.join(dir, f));
        const vk = readJson(VKEY_FILE);
        [vk.IC[1], vk.IC[2]] = [vk.IC[2], vk.IC[1]];
        const vkFile = path.join(dir, `${NAME}.verification_key.json`);
        fs.writeFileSync(vkFile, JSON.stringify(vk, null, 1));
        fs.writeFileSync(path.join(dir, `${NAME}.manifest.json`), JSON.stringify({ ...manifest, verification_key_sha256: sha256(vkFile) }));
        const r = runScript("artifacts.sh", ["check", NAME], { SETUP_OUT: dir });
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stderr, /is not integrated_access_v4\.verification_key\.json/);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it(".gitignore exempts exactly the v3 and v4 proving pairs", () => {
      const ignored = (rel) => spawnSync("git", ["check-ignore", "--no-index", "-q", rel], { cwd: REPO }).status === 0;
      for (const n of [NAME, "integrated_access_v3"]) {
        assert.equal(ignored(`circuits/setup/${n}.zkey`), false, `${n}.zkey must be tracked`);
        assert.equal(ignored(`circuits/setup/${n}.wasm`), false, `${n}.wasm must be tracked`);
      }
      for (const rel of ["circuits/setup/integrated_access_v4_d8.zkey", "circuits/setup/integrated_access_v4_d20.wasm", "circuits/setup/other.zkey"]) {
        assert.equal(ignored(rel), true, rel);
      }
    });
  });

  describe("prove + verify (verify.js)", () => {
    it("a fresh Alice -> Wiki proof from the committed pair verifies and carries the expected 12 signals", async () => {
      assert.deepEqual(publicSignals, vector.expectedPublicSignals);
      assert.deepEqual(publicSignals, await zk.expectedPublicSignals("v4", vector.input));
      const byName = zk.decodePublicSignals("v4", publicSignals);
      assert.equal(byName.resourceId, "1");
      assert.equal(byName.epoch, zk.epochOf(byName.now));
      assert.equal(await verifyLib.verify(vkey, publicSignals, proof), true);
    });

    for (const [i, name] of CONTRACT_ORDER.entries()) {
      it(`public signal ${i} (${name}) + 1 does not verify`, async () => {
        const tampered = publicSignals.map((x, j) => (j === i ? ((BigInt(x) + 1n) % P).toString() : x));
        assert.equal(await verifyLib.verify(vkey, tampered, proof), false);
      });
    }

    it("a leading-zero spelling of nonce or nullifier does not verify (raw snarkjs would accept it)", async () => {
      for (const i of [0, 9]) {
        const padded = publicSignals.map((x, j) => (j === i ? "0" + x : x));
        assert.equal(await snarkjs.groth16.verify(vkey, padded, proof), true, "documents why verify.js checks");
        assert.equal(await verifyLib.verify(vkey, padded, proof), false);
      }
      const zeroMin = publicSignals.map((x, j) => (j === 6 ? "00" : x)); // minClearance "0" -> "00"
      assert.equal(await verifyLib.verify(vkey, zeroMin, proof), false);
    });

    it("signal + p, swapped signals and the v3 key do not verify", async () => {
      const plusP = publicSignals.map((x, j) => (j === 9 ? (BigInt(x) + P).toString() : x));
      assert.equal(await verifyLib.verify(vkey, plusP, proof), false);
      const swapped = [...publicSignals];
      [swapped[2], swapped[3]] = [swapped[3], swapped[2]];
      assert.equal(await verifyLib.verify(vkey, swapped, proof), false);
      const v3 = readJson(path.join(SETUP, "integrated_access_v3.verification_key.json"));
      assert.equal(await verifyLib.verify(v3, publicSignals, proof), false);
    });

    it("verify.sh <name> resolves the committed v4 key (exit 0 valid, 1 tampered)", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zkag-v4-cli-"));
      try {
        fs.writeFileSync(path.join(dir, "proof.json"), JSON.stringify(proof));
        fs.writeFileSync(path.join(dir, "public.json"), JSON.stringify(publicSignals));
        let r = runScript("verify.sh", [NAME, path.join(dir, "proof.json"), path.join(dir, "public.json")]);
        assert.equal(r.status, 0, r.stderr);
        assert.match(r.stdout, /^OK$/m);
        fs.writeFileSync(path.join(dir, "public.json"), JSON.stringify(publicSignals.map((x, j) => (j === 10 ? "3" : x))));
        r = runScript("verify.sh", [NAME, path.join(dir, "proof.json"), path.join(dir, "public.json")]);
        assert.equal(r.status, 1, r.stderr);
        assert.match(r.stdout, /^INVALID$/m);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
