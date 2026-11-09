"use strict";
// ZK Access Gate shared encoder (ADR 0004): the only place that encodes circuit-facing values for
// issuer, registry and client. Profiles v3 (G0-S1-CIRC-021) and v4 (G1-S1-CIRC-038).
// Contracts: docs/CONTRACTS.md (Common rules, credential v3/v4, access.public_signals v3/v4).
// See circuits/lib/README.md.
const field = require("./field");
const crypto = require("./crypto");
const policy = require("./policy");
const signals = require("./signals");
const { profiles, getProfile, attrHash } = require("./profiles");
const tree = require("./tree");
const inputs = require("./inputs");

const listFor = (profile) => getProfile(profile).publicSignals;

module.exports = {
  // field (Common rules)
  P: field.P,
  L: field.L,
  TWO64: field.TWO64,
  CODES: field.CODES,
  AccessInputError: field.AccessInputError,
  isCanonical: field.isCanonical,
  parseField: field.parseField,
  formatField: field.formatField,

  // crypto (circomlibjs; async)
  poseidon: crypto.poseidon,
  commitment: crypto.commitment,
  attrHash,
  nullifier: crypto.nullifier,
  publicKey: crypto.publicKey,
  sign: crypto.sign,
  verifySignature: crypto.verifySignature,

  // enums, policies, epochs, pre-checks (ADR 0008)
  ROLES: policy.ROLES,
  DEPTS: policy.DEPTS,
  policies: policy.policies,
  epochOf: policy.epochOf,
  checkPolicyLocally: policy.checkPolicyLocally,
  checkFileShareV3: policy.checkFileShareV3,

  // profiles
  profiles,
  getProfile,

  // registry tree (zk-kit 1.1.0)
  createTree: tree.createTree,
  proofFor: tree.proofFor,
  merkleRoot: tree.merkleRoot,

  // circuit inputs (client only)
  buildInputV3: inputs.buildInputV3,
  buildInputV4: inputs.buildInputV4,
  buildInput: inputs.buildInput,
  expectedPublicSignals: inputs.expectedPublicSignals,

  // public signals
  PUBLIC_SIGNALS: signals.PUBLIC_SIGNALS,
  decodePublicSignals: (profile, arr) => signals.decode(listFor(profile), arr),
  encodePublicSignals: (profile, obj) => signals.encode(listFor(profile), obj),
};
