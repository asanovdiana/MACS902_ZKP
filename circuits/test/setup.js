// Mocha bootstrap (see /.mocharc.json): make sure the pinned circom compiler is reachable before
// any test compiles a circuit. circom_tester shells out to plain `circom` on PATH, so ~/.cargo/bin
// (where `cargo install` puts it) is prepended. The v3 circuit says `pragma circom 2.2.3` and does
// not compile on 2.2.2, so anything other than exactly 2.2.3 fails fast with an install hint:
// constraint counts asserted in v3.test.js are only meaningful for one compiler version.
"use strict";
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const REQUIRED = "2.2.3";
const INSTALL_HINT =
  `  cargo install --git https://github.com/iden3/circom.git --tag v${REQUIRED} circom\n` +
  "  export PATH=\"$HOME/.cargo/bin:$PATH\"\n" +
  "See circuits/README.md.";

const cargoBin = path.join(os.homedir(), ".cargo", "bin");
if (!process.env.PATH.split(path.delimiter).includes(cargoBin)) {
  process.env.PATH = cargoBin + path.delimiter + process.env.PATH;
}

let version;
try {
  version = execSync("circom --version", { encoding: "utf8" }).trim();
} catch (e) {
  throw new Error(`circom compiler not found on PATH. Install circom ${REQUIRED}:\n${INSTALL_HINT}`);
}
const m = /(\d+\.\d+\.\d+)/.exec(version);
if (!m || m[1] !== REQUIRED) {
  throw new Error(
    `circom ${REQUIRED} required (circuits/integrated_access_v3.circom pins it), found: ` +
      `"${version}". Install it with:\n${INSTALL_HINT}`
  );
}

module.exports = { REQUIRED_CIRCOM: REQUIRED, circomVersion: m[1] };
