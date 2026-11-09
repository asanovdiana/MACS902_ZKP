#!/usr/bin/env node
// Groth16 verification interface for Node consumers (gateway, client self-check, tests).
//
//   const { verify, loadVerificationKey, terminate } = require("<repo>/circuits/scripts/verify.js");
//   const vkey = loadVerificationKey("circuits/setup/integrated_access_v3.verification_key.json");
//   const ok = await verify(vkey, publicSignals, proof);   // true | false, never throws
//   isCanonicalSignal("0123") === false;  canonicalizeSignals(["0123"]) -> ["123"]
//   await terminate();   // release the worker threads (tests / CLI / shutdown only, not per request)
//
//   CLI: node circuits/scripts/verify.js <vkey.json> <public.json> <proof.json>
//        prints OK | INVALID; exit 0 valid, 1 invalid, 2 usage
//
// verify() checks only the cryptography: that `proof` is a valid Groth16 proof for exactly these
// `publicSignals` under `vkey`. It returns false (rather than throwing) for any malformed input:
// wrong vkey shape, wrong signal count, non-canonical or out-of-field signals, wrong proof shape,
// proof coordinates that are not canonical decimals < q, a proof point off its curve or at
// infinity, a B outside the order-r subgroup of G2, or a failing pairing check.
//
// Implementation (G1-S1-CIRC-037): by default verify() runs circuits/scripts/fast-verify.js, the
// same pairing equation as snarkjs on the same ffjavascript wasm, with the vkey parsed and
// validated, e(alpha, beta) and the gamma/delta Miller-loop lines precomputed once per vkey, and
// vk_x computed on the calling thread while two Miller loops and the G2 subgroup check run on
// ffjavascript's worker pool (the same globalThis.curve_bn128 snarkjs uses; terminate() releases
// it). One verifier is built per vkey CONTENT (fast-verify vkeyHash) and reused; a different or
// mutated vkey object gets its own (cache bounded to 16 keys). Numbers: circuits/reports/perf-v4.md.
// Escape hatch: env ZKGATE_VERIFY_IMPL=snarkjs (read on every call) routes to stock
// snarkjs.groth16.verify instead, with the same input rules and the same extra point checks.
// Any other value, or unset, selects the fast verifier.
//
// Public signals must be CANONICAL decimal strings: ASCII digits only, no sign, no whitespace, no
// leading zero except "0" itself, value < p (BN254 scalar field). snarkjs alone parses "0123" as
// 123, so the same proof would verify under many spellings of a signal (root, nonce, nullifier)
// and a gateway keying state on the string could be bypassed. Callers must still key replay /
// rate-limit state on canonical values, never on proof bytes (Groth16 proofs are
// re-randomisable: (-A, -B, C) verifies too), and still apply the semantic checks of the
// access.public_signals contract (gateway obligations 2-8 in docs/CONTRACTS.md: pinned issuer
// key, current root, policy, now, nonce, nullifier per epoch).
"use strict";
const fs = require("fs");
const snarkjs = require("snarkjs");
const fastVerify = require("./fast-verify");

// BN254 scalar field order (public signals) and base field order (proof coordinates).
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const FIELD_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const FIELD_P_DIGITS = FIELD_P.toString().length; // 77

const DIGITS = /^[0-9]+$/;
const CANONICAL = /^(?:0|[1-9][0-9]*)$/;

/**
 * True iff `s` is a canonical public-signal encoding: a string of ASCII digits with no leading
 * zero (except "0"), no sign or whitespace, and value < p. Never throws.
 * @param {unknown} s
 * @returns {boolean}
 */
function isCanonicalSignal(s) {
  if (typeof s !== "string" || s.length > FIELD_P_DIGITS || !CANONICAL.test(s)) return false;
  return BigInt(s) < FIELD_P;
}

/**
 * Canonical form of an array of public signals, for deriving state keys from signals seen before
 * or without verify(). Each element must be a string of ASCII digits (leading zeros allowed here,
 * nothing else) whose value is < p. Returns a new array, or null. Never throws.
 * @param {unknown} arr
 * @returns {string[] | null}
 */
function canonicalizeSignals(arr) {
  if (!Array.isArray(arr)) return null;
  const out = new Array(arr.length);
  for (let i = 0; i < arr.length; i++) {
    const s = arr[i];
    if (typeof s !== "string" || s.length > 1024 || !DIGITS.test(s)) return null;
    const v = BigInt(s);
    if (v >= FIELD_P) return null;
    out[i] = v.toString();
  }
  return out;
}

// Proof coordinates: canonical decimal strings with value < q. snarkjs would silently reduce a
// coordinate >= q (x + q verifies as x) and accept leading zeros; no honest prover emits either.
const isCoord = (x) => typeof x === "string" && x.length <= 78 && CANONICAL.test(x) && BigInt(x) < FIELD_Q;
const isCoordArray = (a, n) => Array.isArray(a) && a.length === n && a.every(isCoord);

function wellFormed(vkey, publicSignals, proof) {
  if (!vkey || typeof vkey !== "object" || vkey.protocol !== "groth16" || vkey.curve !== "bn128") return false;
  if (!Number.isInteger(vkey.nPublic) || vkey.nPublic < 0) return false;
  if (!Array.isArray(vkey.IC) || vkey.IC.length !== vkey.nPublic + 1) return false;
  if (!Array.isArray(publicSignals) || publicSignals.length !== vkey.nPublic) return false;
  if (!publicSignals.every(isCanonicalSignal)) return false;
  if (!proof || typeof proof !== "object") return false;
  if (proof.protocol !== undefined && proof.protocol !== "groth16") return false;
  if (proof.curve !== undefined && proof.curve !== "bn128") return false;
  if (!isCoordArray(proof.pi_a, 3) || !isCoordArray(proof.pi_c, 3)) return false;
  if (!Array.isArray(proof.pi_b) || proof.pi_b.length !== 3 || !proof.pi_b.every((r) => isCoordArray(r, 2))) return false;
  return true;
}

/**
 * @param {object} vkey           verification key JSON (snarkjs `zkey export verificationkey`)
 * @param {string[]} publicSignals canonical decimal strings, snarkjs order (outputs, then public
 *                                 inputs in declaration order; the manifest's public_signals)
 * @param {object} proof          snarkjs Groth16 proof JSON {pi_a, pi_b, pi_c, protocol, curve}
 * @returns {Promise<boolean>}    never rejects
 */
async function verify(vkey, publicSignals, proof) {
  try {
    if (!wellFormed(vkey, publicSignals, proof)) return false;
    if (useSnarkjs()) return await verifyWithSnarkjs(vkey, publicSignals, proof);
    const v = await getVerifier(vkey);
    return (await v.verify(publicSignals, proof)) === true;
  } catch (_) {
    return false;
  }
}

const MAX_CACHED_VERIFIERS = 16;
const verifiers = new Map(); // vkeyHash -> Promise<fast verifier>

/** The cached fast verifier for this vkey's content; built at most once per content hash. */
function getVerifier(vkey) {
  const hash = fastVerify.vkeyHash(vkey);
  let p = verifiers.get(hash);
  if (!p) {
    if (verifiers.size >= MAX_CACHED_VERIFIERS) verifiers.delete(verifiers.keys().next().value);
    p = fastVerify.getSharedCurve().then((curve) => fastVerify.makeVerifier(vkey, { curve }));
    verifiers.set(hash, p);
    p.catch(() => {
      if (verifiers.get(hash) === p) verifiers.delete(hash); // never cache a failed build
    });
  }
  return p;
}

const useSnarkjs = () => process.env.ZKGATE_VERIFY_IMPL === "snarkjs";

// Escape hatch: stock snarkjs, after the proof-point checks snarkjs lacks (infinity, G2 subgroup).
async function verifyWithSnarkjs(vkey, publicSignals, proof) {
  const curve = await fastVerify.getSharedCurve();
  const { A, B, C } = fastVerify.parseProof(curve, proof);
  if (!fastVerify.proofPointsValid(curve, A, B, C)) return false;
  return (await snarkjs.groth16.verify(vkey, publicSignals, proof)) === true;
}

function loadVerificationKey(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Drop the cached verifiers and release the fast verifier's curve and snarkjs's worker threads. */
async function terminate() {
  verifiers.clear();
  await fastVerify.terminateSharedCurve();
  if (globalThis.curve_bn128 && typeof globalThis.curve_bn128.terminate === "function") {
    await globalThis.curve_bn128.terminate();
    delete globalThis.curve_bn128;
  }
}

module.exports = { verify, loadVerificationKey, terminate, isCanonicalSignal, canonicalizeSignals, FIELD_P, FIELD_Q };

if (require.main === module) {
  (async () => {
    const [vk, pub, prf] = process.argv.slice(2);
    if (!vk || !pub || !prf) {
      console.error("usage: verify.js <vkey.json> <public.json> <proof.json>");
      process.exit(2);
    }
    let ok = false;
    try {
      const read = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
      ok = await verify(read(vk), read(pub), read(prf));
    } catch (e) {
      console.error(`verify.js: ${e.message}`);
    }
    await terminate();
    console.log(ok ? "OK" : "INVALID");
    process.exit(ok ? 0 : 1);
  })();
}
