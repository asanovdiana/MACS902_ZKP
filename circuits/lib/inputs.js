"use strict";
// Circuit input builders (credential v3, credential v4). Client-side only: the output contains
// credentialSecret, credentialSalt, the attributes, the signature and the Merkle path, none of
// which may leave the client (floor 6). Only the proof and its public signals go to the gateway.
const { fail, parseField, below, strictKeys, L, TWO64 } = require("./field");
const crypto = require("./crypto");
const { profiles, getProfile } = require("./profiles");
const { normalisePath, merkleRoot } = require("./tree");
const signals = require("./signals");
const {
  EPOCH_SECONDS, encodeAttributesV3, encodeAttributesV4, encodePolicy, checkPolicyLocally, checkFileShareV3,
} = require("./policy");

const V3_ARGS = ["credentialSecret", "credentialSalt", "commitment", "attributes", "signature", "issuer", "merkleProof"];
const V4_ARGS = [...V3_ARGS, "policy", "challenge"];
const PROOF_KEYS = ["root", "leaf", "pathElements", "siblings", "pathIndices", "profile", "leafIndex"];

function parseSignature(sig) {
  strictKeys("signature", sig, ["R8x", "R8y", "S"]);
  return {
    R8x: parseField("signature.R8x", sig.R8x),
    R8y: parseField("signature.R8y", sig.R8y),
    S: below("signature.S", sig.S, L, "l (BabyJubJub subgroup order)"),
  };
}

function parseIssuer(iss) {
  strictKeys("issuer", iss, ["Ax", "Ay"]);
  return { Ax: parseField("issuer.Ax", iss.Ax), Ay: parseField("issuer.Ay", iss.Ay) };
}

/** {root, leaf?, pathElements | siblings, pathIndices, profile?, leafIndex?} for `profile`. */
function parseMerkleProof(mp, profile) {
  strictKeys("merkleProof", mp, PROOF_KEYS);
  if (mp.profile !== undefined && mp.profile !== profile.name) {
    fail("PROFILE_MISMATCH", `merkleProof: path is for profile ${JSON.stringify(String(mp.profile))}, building ${profile.name}`);
  }
  const { pathElements, pathIndices } = normalisePath(mp.pathElements ?? mp.siblings, mp.pathIndices, profile.depth);
  return {
    root: parseField("merkleProof.root", mp.root),
    leaf: mp.leaf === undefined ? undefined : parseField("merkleProof.leaf", mp.leaf).toString(),
    pathElements,
    pathIndices,
  };
}

/** Shared checks: secret <-> commitment, leaf, issuer signature over M, root recompute. */
async function verifyCredential(profile, { secret, salt, commitment, attributes, sig, iss, mp }) {
  const cm = await crypto.commitment(secret, salt);
  if (commitment !== undefined && parseField("commitment", commitment).toString() !== cm) {
    fail("SECRET_MISMATCH", "credentialSecret/credentialSalt do not hash to the credential's commitment");
  }
  const cred = { commitment: cm, attributes };
  const M = await profile.message(cred);
  const leaf = await profile.leaf(cred);
  if (!(await crypto.verifySignature(M, { R8x: sig.R8x, R8y: sig.R8y, S: sig.S }, { Ax: iss.Ax, Ay: iss.Ay }))) {
    fail("BAD_SIGNATURE", `issuer signature does not verify over the ${profile.name} message under the given issuer key`);
  }
  if (mp.leaf !== undefined && mp.leaf !== leaf) {
    fail("LEAF_MISMATCH", "merkleProof.leaf is not this credential's leaf");
  }
  if ((await merkleRoot(leaf, mp.pathElements, mp.pathIndices)) !== mp.root.toString()) {
    fail("ROOT_MISMATCH", "the Merkle path from this credential's leaf does not reach merkleProof.root");
  }
  return { commitment: cm, M, leaf };
}

const s = (x) => x.toString();

/**
 * credential v3 input for circuits/integrated_access_v3.circom (IntegratedAccessGate, depth 2).
 *
 *   args.credentialSecret, args.credentialSalt  field elements (client secrets, floor 6)
 *   args.commitment     optional; checked against Poseidon(2)(secret, salt)
 *   args.attributes     {role, clearance, deviceCompliant, employeeActive} (issuer.api v1, v3)
 *   args.signature      {R8x, R8y, S}  over M = commitment
 *   args.issuer         {Ax, Ay}
 *   args.merkleProof    GET /path response, proofFor() output or zk-kit createProof output
 *   opts.precheck       default true: fail POLICY_NOT_SATISFIED (err.reasons) when v3
 *                       FileShareAccess would reject; false only for negative tests
 *
 * Resolves to {credentialSecret, credentialSalt, role, clearance, deviceCompliant, employeeActive,
 * Ax, Ay, R8x, R8y, S, M, leaf, pathElements[2], pathIndices[2], root}, all decimal strings.
 */
async function buildInputV3(args, { precheck = true } = {}) {
  const profile = profiles.v3;
  strictKeys("args", args, V3_ARGS);
  const secret = parseField("credentialSecret", args.credentialSecret);
  const salt = parseField("credentialSalt", args.credentialSalt);
  const a = encodeAttributesV3(args.attributes);
  const sig = parseSignature(args.signature);
  const iss = parseIssuer(args.issuer);
  const mp = parseMerkleProof(args.merkleProof, profile);
  if (precheck) {
    const v = checkFileShareV3(args.attributes);
    if (!v.ok) fail("POLICY_NOT_SATISFIED", "v3 FileShareAccess not satisfied: " + v.reasons.map((r) => r.code).join(", "), { reasons: v.reasons });
  }
  const { M, leaf } = await verifyCredential(profile, {
    secret, salt, commitment: args.commitment, attributes: args.attributes, sig, iss, mp,
  });
  return {
    credentialSecret: s(secret),
    credentialSalt: s(salt),
    role: s(a.role),
    clearance: s(a.clearance),
    deviceCompliant: s(a.deviceCompliant),
    employeeActive: s(a.employeeActive),
    Ax: s(iss.Ax),
    Ay: s(iss.Ay),
    R8x: s(sig.R8x),
    R8y: s(sig.R8y),
    S: s(sig.S),
    M,
    leaf,
    pathElements: mp.pathElements,
    pathIndices: mp.pathIndices,
    root: s(mp.root),
  };
}

/**
 * credential v4 input for circuits/integrated_access_v4.circom (depth 16). As buildInputV3, plus
 *
 *   args.attributes  {role, dept, clearance, deviceCompliant, employeeActive, expiry}; role/dept
 *                    may be D6 labels ("engineer", "it", ...)
 *   args.signature   over M = attrHash
 *   args.policy      "wiki" | "file_share" | "admin_panel" or {roleMask, deptMask, minClearance,
 *                    requireDevice, resourceId?}
 *   args.challenge   {nonce, resourceId, epoch, now} exactly as the gateway issued it
 *   opts.precheck    default true: EPOCH_MISMATCH, RESOURCE_MISMATCH, CREDENTIAL_EXPIRED,
 *                    EMPLOYEE_INACTIVE, POLICY_NOT_SATISFIED (err.reasons) before any crypto
 *
 * Resolves to the private inputs (credentialSecret, credentialSalt, role, dept, clearance,
 * deviceCompliant, employeeActive, expiry, R8x, R8y, S, pathElements[16], pathIndices[16]) then the
 * 11 public inputs in access.public_signals v4 order (root, issuerAx, issuerAy, roleMask, deptMask,
 * minClearance, requireDevice, now, nonce, resourceId, epoch). M and leaf are not inputs in v4.
 */
async function buildInputV4(args, { precheck = true } = {}) {
  const profile = profiles.v4;
  strictKeys("args", args, V4_ARGS);
  const secret = parseField("credentialSecret", args.credentialSecret);
  const salt = parseField("credentialSalt", args.credentialSalt);
  const a = encodeAttributesV4(args.attributes);
  const sig = parseSignature(args.signature);
  const iss = parseIssuer(args.issuer);
  const mp = parseMerkleProof(args.merkleProof, profile);
  const pol = encodePolicy(args.policy);
  const ch = strictKeys("challenge", args.challenge, ["nonce", "resourceId", "epoch", "now"]);
  const nonce = parseField("challenge.nonce", ch.nonce);
  const resourceId = parseField("challenge.resourceId", ch.resourceId);
  const epoch = parseField("challenge.epoch", ch.epoch);
  const now = below("challenge.now", ch.now, TWO64, "2^64");

  if (precheck) {
    if (epoch !== now / EPOCH_SECONDS) fail("EPOCH_MISMATCH", "challenge.epoch != floor(challenge.now / 600)");
    if (pol.resourceId !== undefined && pol.resourceId !== resourceId) {
      fail("RESOURCE_MISMATCH", "challenge.resourceId does not match the policy's resource");
    }
    const v = checkPolicyLocally(args.attributes, args.policy, now);
    const codes = v.reasons.map((r) => r.code);
    if (codes.includes("CREDENTIAL_EXPIRED")) fail("CREDENTIAL_EXPIRED", "credential expired (expiry <= now)", { reasons: v.reasons });
    if (codes.includes("EMPLOYEE_INACTIVE")) fail("EMPLOYEE_INACTIVE", "employeeActive must be 1 (ADR 0007)", { reasons: v.reasons });
    if (!v.ok) fail("POLICY_NOT_SATISFIED", "policy not satisfied: " + codes.join(", "), { reasons: v.reasons });
  }

  // The canonical attribute integers (labels resolved) are what the issuer signed.
  const attrs = Object.fromEntries(Object.entries(a).map(([k, v]) => [k, s(v)]));
  await verifyCredential(profile, { secret, salt, commitment: args.commitment, attributes: attrs, sig, iss, mp });

  return {
    credentialSecret: s(secret),
    credentialSalt: s(salt),
    role: s(a.role),
    dept: s(a.dept),
    clearance: s(a.clearance),
    deviceCompliant: s(a.deviceCompliant),
    employeeActive: s(a.employeeActive),
    expiry: s(a.expiry),
    R8x: s(sig.R8x),
    R8y: s(sig.R8y),
    S: s(sig.S),
    pathElements: mp.pathElements,
    pathIndices: mp.pathIndices,
    root: s(mp.root),
    issuerAx: s(iss.Ax),
    issuerAy: s(iss.Ay),
    roleMask: s(pol.roleMask),
    deptMask: s(pol.deptMask),
    minClearance: s(pol.minClearance),
    requireDevice: s(pol.requireDevice),
    now: s(now),
    nonce: s(nonce),
    resourceId: s(resourceId),
    epoch: s(epoch),
  };
}

/** buildInputV3 / buildInputV4 by profile. */
function buildInput(profile, args, opts) {
  const p = getProfile(profile);
  return p.name === "v3" ? buildInputV3(args, opts) : buildInputV4(args, opts);
}

/** The publicSignals array a proof over `input` will carry (v4: nullifier computed off-circuit). */
async function expectedPublicSignals(profile, input) {
  const p = getProfile(profile);
  if (p.name === "v3") return signals.encode(p.publicSignals, { root: input.root });
  const obj = { nullifier: await crypto.nullifier(input.credentialSecret, input.resourceId, input.epoch) };
  for (const k of p.publicSignals.slice(1)) obj[k] = input[k];
  return signals.encode(p.publicSignals, obj);
}

module.exports = { buildInputV3, buildInputV4, buildInput, expectedPublicSignals };
