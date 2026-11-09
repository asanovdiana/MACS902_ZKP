"use strict";
// Attack Lab library (G2-S1-IDEN-021). See ../README.md.
const verifier = require("../../../circuits/scripts/verify.js");
const { ATTACKS, ATTACK_IDS, buildAttack } = require("./attacks");
const { CODES } = require("./codes");
const { createWorld, WorldError } = require("./world");
const { runAttack, httpSender, httpChallengeSource } = require("./runner");

/** Release the verifier's and snarkjs's worker threads (CLI exit, test teardown). */
async function shutdown() {
  await verifier.terminate();
  if (globalThis.curve_bn128 && globalThis.curve_bn128.terminate) await globalThis.curve_bn128.terminate();
}

module.exports = { ATTACKS, ATTACK_IDS, buildAttack, CODES, createWorld, WorldError, runAttack, httpSender, httpChallengeSource, shutdown };
