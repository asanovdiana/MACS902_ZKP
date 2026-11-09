"use strict";
// TEST-ONLY v3 inputs built in memory from fixed public labels.
//
// Every "secret" here (credentialSecret, credentialSalt, issuer private keys) is sha256 of a
// PUBLIC label string, so it is reproducible and worthless: it must never be used outside tests.
// Nothing in this file writes to disk; private inputs never land in the repository (floors 6, 9).
// The tree shape mirrors scripts/generate_integrated_v3.js (depth 2, siblings [11, H(33,44)],
// pathIndices [1, 0]) so results are comparable with her generator, minus the randomness.
const crypto = require("crypto");
const { buildEddsa, buildPoseidon } = require("circomlibjs");
const { mod } = require("./helpers");

const LABEL_PREFIX = "zk-access-gate/TEST-ONLY/v3/";

/** sha256(LABEL_PREFIX + label) as raw bytes. */
function seedBytes(label) {
  return crypto.createHash("sha256").update(LABEL_PREFIX + label).digest();
}

/** A field element from a label: first 31 bytes of the digest (< 2^248 < p). */
function seedField(label) {
  return BigInt("0x" + seedBytes(label).subarray(0, 31).toString("hex"));
}

let libs;
async function crypto3() {
  if (!libs) {
    const [eddsa, poseidon] = await Promise.all([buildEddsa(), buildPoseidon()]);
    libs = { eddsa, poseidon, F: poseidon.F };
  }
  return libs;
}

/** Poseidon over field elements, returned as a BigInt. */
async function H(...xs) {
  const { poseidon, F } = await crypto3();
  return F.toObject(poseidon(xs.map((x) => mod(x))));
}

/** TEST-ONLY issuer key from a label. */
async function issuerKey(label) {
  const { eddsa, F } = await crypto3();
  const prv = seedBytes(`issuer-key/${label}`);
  const pub = eddsa.prv2pub(prv);
  return { prv, Ax: F.toObject(pub[0]), Ay: F.toObject(pub[1]) };
}

/** EdDSA-Poseidon signature over message m with a TEST-ONLY key. */
async function sign(key, m) {
  const { eddsa, F } = await crypto3();
  const sig = eddsa.signPoseidon(key.prv, F.e(mod(m)));
  return { R8x: F.toObject(sig.R8[0]), R8y: F.toObject(sig.R8[1]), S: sig.S };
}

/**
 * Root for her MerkleMembership: at level i, with h the running hash, s the sibling and b the
 * index, left = h + b*(s - h), right = s + b*(h - s) (mod p), h' = Poseidon(left, right).
 * b = 1 means h is the RIGHT child. Works for non-boolean b too (used to isolate the boolean check).
 */
async function merkleRoot(leaf, pathElements, pathIndices) {
  let h = mod(leaf);
  for (let i = 0; i < pathElements.length; i++) {
    const s = mod(pathElements[i]);
    const b = mod(pathIndices[i]);
    const left = mod(h + b * (s - h));
    const right = mod(s + b * (h - s));
    h = await H(left, right);
  }
  return h;
}

async function defaultPath() {
  return { pathElements: [11n, await H(33n, 44n)], pathIndices: [1n, 0n] };
}

/**
 * Build a TEST-ONLY v3 input. Options:
 *   secretLabel, saltLabel  seeds for credentialSecret / credentialSalt
 *   issuer                  label of the issuer key that signs (default "issuer")
 *   role, clearance, deviceCompliant, employeeActive
 * Returns { input (decimal strings, ready for calculateWitness), commitment, key }.
 */
async function buildV3Input(opts = {}) {
  const {
    secretLabel = "secret",
    saltLabel = "salt",
    issuer = "issuer",
    role = 2n,
    clearance = 2n,
    deviceCompliant = 1n,
    employeeActive = 1n,
  } = opts;
  const credentialSecret = seedField(`credential-secret/${secretLabel}`);
  const credentialSalt = seedField(`credential-salt/${saltLabel}`);
  const commitment = await H(credentialSecret, credentialSalt);
  const key = await issuerKey(issuer);
  const sig = await sign(key, commitment);
  const { pathElements, pathIndices } = await defaultPath();
  const root = await merkleRoot(commitment, pathElements, pathIndices);
  const input = toInput({
    credentialSecret,
    credentialSalt,
    role,
    clearance,
    deviceCompliant,
    employeeActive,
    Ax: key.Ax,
    Ay: key.Ay,
    ...sig,
    M: commitment,
    leaf: commitment,
    pathElements,
    pathIndices,
    root,
  });
  return { input, commitment, key };
}

/** Normalise every value to a decimal string (arrays element-wise). */
function toInput(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = Array.isArray(v) ? v.map((x) => BigInt(x).toString()) : BigInt(v).toString();
  }
  return out;
}

/** Shallow copy with overrides (values normalised to decimal strings). */
function withInput(input, overrides) {
  return { ...input, ...toInput(overrides) };
}

module.exports = {
  LABEL_PREFIX,
  seedField,
  H,
  issuerKey,
  sign,
  merkleRoot,
  buildV3Input,
  withInput,
};
