#!/usr/bin/env node
// Writes the provenance manifest for one trusted-setup run to stdout. Called by setup.sh.
//
//   node circuits/scripts/setup-manifest.js --name <n> --circuit <repo-relative path> \
//     --circom <ver> --snarkjs <ver> --r1cs <f> --sym <f> --wasm <f> --zkey <f> --vkey <f> \
//     --ptau <f> --ptau-info <f|""> --constraints <n> --n-pub-in <n> --n-out <n> --beacon <hex>
//
// Only basenames of the ptau are recorded (no machine paths in a committed file).
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith("--")) throw new Error(`unexpected argument ${argv[i]}`);
    args[argv[i].slice(2)] = argv[i + 1] ?? "";
  }
  return args;
}

const hash = (algo, file) => crypto.createHash(algo).update(fs.readFileSync(file)).digest("hex");
const sha256 = (file) => hash("sha256", file);

// The single-party phase-2 limitation, word for word (tests/safety F9.06/F9.12 and the circuits
// tests match it). ceremony-transcript.js buildManifest reuses it for a 1-contribution ceremony.
const SINGLE_PARTY_LIMITATION =
  "single-party phase 2 — whoever ran setup could forge proofs; replace via the multi-party ceremony before any real use";

// Public signals in snarkjs order = .sym entries with signal index 1..nOut+nPubIn
// (outputs first, then public inputs in template declaration order). At --O2 merged signals get
// witness index -1 (2nd column); the signal index (1st column) of a public signal is its position.
function publicSignalNames(symFile, n) {
  const names = new Array(n).fill(null);
  for (const line of fs.readFileSync(symFile, "utf8").split("\n")) {
    const [idx, , , name] = line.split(",");
    const i = Number(idx);
    if (Number.isInteger(i) && i >= 1 && i <= n && names[i - 1] === null) names[i - 1] = name.replace(/^main\./, "");
  }
  if (names.some((x) => x === null)) throw new Error(`could not name every public signal from ${symFile}`);
  return names;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  let ptau;
  if (args["ptau-info"]) {
    const info = JSON.parse(fs.readFileSync(args["ptau-info"], "utf8"));
    ptau = { source: info.source, file: info.file, power: info.power, blake2b: info.blake2b };
    if (info.warning) ptau.warning = info.warning;
    if (info.provenance) ptau.provenance = info.provenance;
  } else {
    ptau = { source: "external", file: path.basename(args.ptau), blake2b: hash("blake2b512", args.ptau) };
  }

  // Phase 1 from a public multi-party ceremony (PSE ppot 0080, or Hermez while it was downloadable)
  // is fine for a demo; a local dev ceremony or an unknown external file is not.
  const publicPhase1 = ptau.source === "pse-ppot-0080" || ptau.source === "hermez";
  const limitations = [SINGLE_PARTY_LIMITATION];
  if (!publicPhase1) {
    limitations.unshift(
      `DEV-ONLY phase 1 (ptau source "${ptau.source}"): not a public ceremony; re-run with PTAU_SOURCE=pse before any real use`,
    );
  } else if (ptau.source === "pse-ppot-0080") {
    limitations.push(
      "phase 1 blake2b-512 pinned on first download (PSE publishes no hash for prepared files); full snarkjs powersoftau verify not run (see ptau.provenance)",
    );
  }

  const nPublic = Number(args["n-pub-in"]) + Number(args["n-out"]);
  const manifest = {
    name: args.name,
    // "DEV-ONLY" stays the machine-checked status label (tests/safety F9.06 pins it); the detail
    // says what kind of non-production key this is.
    status: "DEV-ONLY",
    status_detail: publicPhase1
      ? "DEMO-ONLY (single-party phase 2): phase 1 is a public ceremony, phase 2 is one local contribution + beacon; not for production"
      : "DEV-ONLY (local phase 1 and single-party phase 2): not for production",
    circuit: args.circuit,
    protocol: "groth16",
    curve: "bn128",
    circom_version: args.circom,
    circom_flags: "--O2 --r1cs --wasm --sym",
    snarkjs_version: args.snarkjs,
    constraints: Number(args.constraints),
    n_public: nPublic,
    public_signals: publicSignalNames(args.sym, nPublic),
    r1cs_sha256: sha256(args.r1cs),
    wasm_sha256: sha256(args.wasm),
    zkey_sha256: sha256(args.zkey),
    verification_key_sha256: sha256(args.vkey),
    ptau,
    phase2: {
      contributions: 1,
      entropy: "/dev/urandom (64 bytes) on stdin, mixed by snarkjs with crypto.randomBytes",
      beacon: true,
      beacon_hash: args.beacon,
      beacon_iterations_exp: 10,
    },
    limitations,
    date: new Date().toISOString(),
  };
  process.stdout.write(JSON.stringify(manifest, null, 2) + "\n");
}

if (require.main === module) main();
module.exports = { publicSignalNames, SINGLE_PARTY_LIMITATION };
