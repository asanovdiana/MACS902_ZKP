// G1-S1-CIRC-037: trusted setup and committed proving artefacts for integrated_access_v4 (ADR 0009,
// decision D7; phase 1 PSE ppot 0080 since G2-S1-CIRC-040a). Since G2-S1-FINAL-001 phase 2 is the
// simulated 3-party ceremony (docs/ceremony/v4-ceremony-log.md): three contributions made by separate
// agents on ONE machine under one operator, closed by the public drand beacon, round 6667474. The
// manifest says DEMO-ONLY; the multi-party trust guarantee does NOT hold for these keys.
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

// The simulated 3-party ceremony (G2-S1-FINAL-001), as published in docs/ceremony/v4-ceremony-log.md.
const TRANSCRIPT_REL = "circuits/ceremony/integrated_access_v4/transcript.json";
const CEREMONY = {
  contributions: [
    "b94c7befc2143dac2ee41c774716c8e2d641ba7beac2f23df96b826dfa9070e3b68897b4b96da046b5a0feaec0b631535f74026f6ec2d0a00bf5ea0232f81ccf",
    "65c1a72c1dac225ba16a973dabb762d32b32176ab6a2c520875acbccaa0c3f4a6ffbc6d5eddd1368f12e0e1b3e05e6eb91e2566ddacb4b8ad30d25e899a807cc",
    "6ae8dc38bc675c88796e62e566b353dab2911b76fd199726902d8e444981ce29bf6d0ac43e92e8178f5a24997b4ae259314d832c18cf6788dd1ccc9f1938c7c9",
  ],
  beacon: "9c26abbf0594815ac1e143bc5c586518f1ddf2264411ebd7af4a8d17d6d022d2", // drand mainnet round 6667474
  beaconContribution:
    "88c9928e5ad06a82d07a01679633a7607aef64eb2ec3128a653e567396ce1e27d9c47c49208f46178c457ca51778884faaf6a2c372338391b1100575c01151d4",
};

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

    it("records DEMO-ONLY status from the 3-party ceremony (never production), the public drand beacon, the committed transcript and no machine paths", () => {
      assert.equal(manifest.status, "DEMO-ONLY");
      assert.match(manifest.status_detail, /^DEMO-ONLY \(multi-party phase 2: 3 contributors \+ public beacon; phase 1 is a public ceremony\)/);
      assert.match(manifest.status_detail, /not for production/);
      assert.doesNotMatch(JSON.stringify(manifest), /PRODUCTION/);
      // G2-S1-CIRC-040a: phase 1 is PSE ppot 0080 (Hermez is no longer downloadable).
      assert.equal(manifest.ptau.source, "pse-ppot-0080");
      assert.equal(manifest.ptau.file, "ppot_0080_15.ptau");
      assert.equal(manifest.ptau.power, 15);
      assert.equal(
        manifest.ptau.blake2b,
        "a6dd3adcf80f6716c4d082be2626e790af1f5ed3d760814dc439a07d91e93421382c91d4f705abe8cd90ef1956e4b7eaf58db29d81be5abe624dab4dae827f24",
      );
      assert.match(manifest.ptau.provenance, /0080_carter_response/);

      // phase 2: exactly the three published contributions, in order (docs/ceremony/v4-ceremony-log.md §2)
      const p2 = manifest.phase2;
      assert.equal(p2.contributions, 3);
      assert.deepEqual(p2.contributors, [
        { order: 1, participant: "P1 circuits - simulated by agent on same machine", hash: CEREMONY.contributions[0] },
        { order: 2, participant: "P2 identity - simulated by agent on same machine", hash: CEREMONY.contributions[1] },
        { order: 3, participant: "P3 gateway - simulated by agent on same machine", hash: CEREMONY.contributions[2] },
      ]);
      // closed by the beacon announced in advance (drand mainnet round 6667474), applied 2^10 times
      assert.equal(p2.beacon, true);
      assert.equal(p2.beacon_public, true);
      assert.equal(p2.beacon_source, "drand mainnet round 6667474");
      assert.equal(p2.beacon_hash, CEREMONY.beacon);
      assert.equal(p2.beacon_iterations_exp, 10);
      assert.equal(p2.beacon_contribution_hash, CEREMONY.beaconContribution);

      // the transcript it names is committed and hashes to the manifest; its chain agrees
      assert.equal(p2.transcript, TRANSCRIPT_REL);
      const transcriptFile = path.join(REPO, ...TRANSCRIPT_REL.split("/"));
      assert.equal(sha256(transcriptFile), p2.transcript_sha256);
      const t = readJson(transcriptFile);
      assert.equal(t.name, NAME);
      assert.equal(t.r1cs_sha256, manifest.r1cs_sha256);
      assert.equal(t.ptau.blake2b, manifest.ptau.blake2b);
      assert.deepEqual(
        t.contributions.map((c) => [c.order, c.participant, c.contribution_hash]),
        p2.contributors.map((c) => [c.order, c.participant, c.hash]),
      );
      for (let i = 1; i < t.contributions.length; i++) {
        assert.equal(t.contributions[i].prev_zkey_sha256, t.contributions[i - 1].zkey_sha256, `chain link ${i + 1}`);
      }
      assert.equal(t.contributions[0].prev_zkey_sha256, t.initial.zkey_sha256);
      assert.equal(t.beacon.public, true);
      assert.equal(t.beacon.hash, p2.beacon_hash);
      assert.equal(t.beacon.contribution_hash, p2.beacon_contribution_hash);
      assert.equal(t.beacon.prev_zkey_sha256, t.contributions[2].zkey_sha256);
      assert.equal(t.beacon.zkey_sha256, manifest.zkey_sha256, "the committed zkey is the ceremony's final zkey");
      // the ceremony's exported vkey is the committed one
      assert.equal(
        sha256(path.join(REPO, "circuits", "ceremony", NAME, `${NAME}.verification_key.json`)),
        manifest.verification_key_sha256,
      );

      // limitations: the multi-party line replaces the single-party one; the phase-1 pin line stays
      const lim = manifest.limitations.join("\n");
      assert.match(lim, /^multi-party phase 2 \(3 contributors: /m);
      assert.match(lim, /all of them colluding \(or all being compromised\) could forge proofs/);
      assert.doesNotMatch(lim, /single-party/);
      assert.match(lim, /pinned on first download/);
      assert.doesNotMatch(lim, /DEV-ONLY phase 1/);
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
