"use strict";
// Profile-driven validation and signing (issuer.api v1). All Poseidon/EdDSA work is circuits/lib;
// the private key is held in a closure and never exposed.
const zk = require("../../circuits/lib");
const { err } = require("./errors");

const RANGES = {
  role: 3, dept: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1,
};

/** Commitment: canonical decimal string, < p, non-zero. Returns the string. */
function validateCommitment(c) {
  if (typeof c !== "string" || !zk.isCanonical(c)) throw err(400, "invalid_commitment", "commitment must be a canonical decimal field element");
  const v = BigInt(c);
  if (v >= zk.P || v === 0n) throw err(400, "invalid_commitment", "commitment must be a canonical decimal field element");
  return c;
}

const bad = () => err(400, "invalid_attributes", "attributes do not match the profile");

/** Strict per-profile attribute check. Integers only (no labels, strings or booleans). */
function validateAttributes(profile, attrs, now) {
  const names = zk.getProfile(profile).attributes;
  if (attrs === null || typeof attrs !== "object" || Array.isArray(attrs)) throw bad();
  const keys = Object.keys(attrs);
  if (keys.length !== names.length || !names.every((k) => Object.prototype.hasOwnProperty.call(attrs, k))) throw bad();
  const out = {};
  for (const k of names) {
    const v = attrs[k];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw bad();
    if (k === "expiry") {
      if (v <= now) throw bad(); // expiry == now is expired
    } else if (v > RANGES[k]) throw bad();
    out[k] = v;
  }
  return out;
}

/** createSigner({profile, prv}) -> {profile, publicKey, issue(commitment, attributes, now)}. */
async function createSigner({ profile, prv }) {
  const p = zk.getProfile(profile);
  const publicKey = await zk.publicKey(prv);
  return Object.freeze({
    profile: p.name,
    publicKey: Object.freeze({ Ax: publicKey.Ax, Ay: publicKey.Ay }),
    /** Validate, sign the profile's message, return {leaf, attributes, signature}. */
    async issue(commitment, attributes, now) {
      const c = validateCommitment(commitment);
      const attrs = validateAttributes(p.name, attributes, now);
      const cred = { commitment: c, attributes: attrs };
      const M = await p.message(cred);
      const signature = await zk.sign(prv, M);
      const leaf = await p.leaf(cred);
      return { leaf, attributes: attrs, signature };
    },
  });
}

module.exports = { createSigner, validateCommitment, validateAttributes };
