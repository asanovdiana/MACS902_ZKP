"use strict";
// Profiles v3 and v4: everything that differs between the two circuits (design.md, circuits
// boundary): depth, signed message and leaf layout, public-signal order, artefact names.
// Artefact paths are relative file names; the directory is chosen by the setup tasks
// (G0-S1-CIRC-022 for v3, G1-S1-CIRC-037 for v4).
const { fail, parseField } = require("./field");
const crypto = require("./crypto");
const { PUBLIC_SIGNALS } = require("./signals");
const { V3_ATTRIBUTES, V4_ATTRIBUTES, encodeAttributesV4 } = require("./policy");

const artefacts = (name) =>
  Object.freeze({ name, wasm: `${name}_js/${name}.wasm`, zkey: `${name}.zkey`, vkey: `${name}.vkey.json` });

/** Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment) (ADR 0006). */
async function attrHash(attributes, commitment) {
  const a = encodeAttributesV4(attributes);
  const c = parseField("commitment", commitment);
  return crypto.poseidon([a.role, a.dept, a.clearance, a.deviceCompliant, a.employeeActive, a.expiry, c]);
}

const commitmentOf = (cred) => {
  if (!cred || typeof cred !== "object") fail("MISSING_FIELD", "credential: missing");
  return parseField("commitment", cred.commitment).toString();
};

const v3 = Object.freeze({
  name: "v3",
  depth: 2,
  attributes: Object.freeze([...V3_ATTRIBUTES]),
  publicSignals: PUBLIC_SIGNALS.v3,
  artefacts: artefacts("integrated_access_v3"),
  /** Signed message M = credentialCommitment (credential v3). */
  message: async (cred) => commitmentOf(cred),
  /** Leaf = credentialCommitment. */
  leaf: async (cred) => commitmentOf(cred),
});

const v4 = Object.freeze({
  name: "v4",
  depth: 16,
  attributes: Object.freeze([...V4_ATTRIBUTES]),
  publicSignals: PUBLIC_SIGNALS.v4,
  artefacts: artefacts("integrated_access_v4"),
  /** Signed message M = attrHash(attributes, commitment) (credential v4). */
  message: async (cred) => attrHash(cred.attributes, commitmentOf(cred)),
  /** Leaf = attrHash. */
  leaf: async (cred) => attrHash(cred.attributes, commitmentOf(cred)),
});

const profiles = Object.freeze({ v3, v4 });

/** "v3" | "v4" | a profile object -> the frozen profile. */
function getProfile(p) {
  if (p === v3 || p === v4) return p;
  if (typeof p === "string" && Object.prototype.hasOwnProperty.call(profiles, p)) return profiles[p];
  return fail("UNKNOWN_PROFILE", "profile: expected \"v3\" or \"v4\"");
}

module.exports = { profiles, getProfile, attrHash };
