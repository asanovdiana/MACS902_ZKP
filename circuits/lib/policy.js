"use strict";
// Enums (ADR 0008 / D6), demo policies (access.public_signals v4), epochs and the local policy
// pre-checks: v4 `checkPolicyLocally` (the circuit's AccessPolicy + expiry + employeeActive) and
// v3 `checkFileShareV3` (P1's hard-coded FileShareAccess).
const { fail, toBigInt, bounded, below, strictKeys, TWO64 } = require("./field");

const ROLES = Object.freeze({ engineer: 0, admin: 1, contractor: 2, finance: 3 });
const DEPTS = Object.freeze({ engineering: 0, it: 1, operations: 2, finance: 3 });

const policy = (o) => Object.freeze(o);
/** Demo policies; `resourceId` per the contract (1 wiki, 2 file share, 3 admin panel). */
const policies = Object.freeze({
  wiki: policy({ name: "wiki", label: "Wiki", resourceId: 1, roleMask: 15, deptMask: 15, minClearance: 0, requireDevice: 1 }),
  file_share: policy({ name: "file_share", label: "File Share", resourceId: 2, roleMask: 3, deptMask: 15, minClearance: 2, requireDevice: 0 }),
  admin_panel: policy({ name: "admin_panel", label: "Admin Panel", resourceId: 3, roleMask: 2, deptMask: 15, minClearance: 3, requireDevice: 1 }),
});

const EPOCH_SECONDS = 600n;

/** epoch = floor(unixSeconds / 600), canonical decimal. */
const epochOf = (unixSeconds) => (toBigInt("unixSeconds", unixSeconds) / EPOCH_SECONDS).toString();

const labelOf = (map, v) => Object.keys(map).find((k) => BigInt(map[k]) === v);

/** Enum attribute: integer 0..3 or a label of `map`. */
function enumValue(name, v, map) {
  if (typeof v === "string" && v !== "" && !/^[0-9]/.test(v)) {
    if (!Object.prototype.hasOwnProperty.call(map, v)) fail("INVALID_VALUE", `${name}: unknown label`);
    return BigInt(map[v]);
  }
  return bounded(name, v, 3n);
}

const V3_ATTRIBUTES = ["role", "clearance", "deviceCompliant", "employeeActive"];
const V4_ATTRIBUTES = ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry"];

const req = (obj, keys, name) => {
  for (const k of keys) if (obj[k] === undefined || obj[k] === null) fail("MISSING_FIELD", `${name}.${k}: missing`);
};

/** v3 attributes -> BigInt (issuer.api v1: role, clearance 0..3; booleans 0/1). Strict keys. */
function encodeAttributesV3(attrs) {
  strictKeys("attributes", attrs, V3_ATTRIBUTES);
  req(attrs, V3_ATTRIBUTES, "attributes");
  return {
    role: bounded("attributes.role", attrs.role, 3n),
    clearance: bounded("attributes.clearance", attrs.clearance, 3n),
    deviceCompliant: bounded("attributes.deviceCompliant", attrs.deviceCompliant, 1n),
    employeeActive: bounded("attributes.employeeActive", attrs.employeeActive, 1n),
  };
}

/** v4 attributes -> BigInt (credential v4 ranges). role/dept accept D6 labels. Strict keys. */
function encodeAttributesV4(attrs) {
  strictKeys("attributes", attrs, V4_ATTRIBUTES);
  req(attrs, V4_ATTRIBUTES, "attributes");
  return {
    role: enumValue("attributes.role", attrs.role, ROLES),
    dept: enumValue("attributes.dept", attrs.dept, DEPTS),
    clearance: bounded("attributes.clearance", attrs.clearance, 3n),
    deviceCompliant: bounded("attributes.deviceCompliant", attrs.deviceCompliant, 1n),
    employeeActive: bounded("attributes.employeeActive", attrs.employeeActive, 1n),
    expiry: below("attributes.expiry", attrs.expiry, TWO64, "2^64"),
  };
}

const POLICY_KEYS = ["roleMask", "deptMask", "minClearance", "requireDevice", "resourceId", "name", "label"];

/** Policy name or object -> BigInt fields (+ resourceId when the policy names one). */
function encodePolicy(p) {
  if (typeof p === "string") {
    if (!Object.prototype.hasOwnProperty.call(policies, p)) fail("INVALID_VALUE", "policy: unknown policy name");
    p = policies[p];
  }
  strictKeys("policy", p, POLICY_KEYS);
  req(p, ["roleMask", "deptMask", "minClearance", "requireDevice"], "policy");
  return {
    roleMask: bounded("policy.roleMask", p.roleMask, 15n),
    deptMask: bounded("policy.deptMask", p.deptMask, 15n),
    minClearance: bounded("policy.minClearance", p.minClearance, 3n),
    requireDevice: bounded("policy.requireDevice", p.requireDevice, 1n),
    resourceId: p.resourceId === undefined ? undefined : toBigInt("policy.resourceId", p.resourceId),
  };
}

const bin4 = (x) => "0b" + x.toString(2).padStart(4, "0");

/**
 * Predict the v4 circuit's verdict for these attributes, policy and `now`, without proving.
 * Returns {ok, reasons: [{code, message}]}; codes in check order: ROLE_NOT_ALLOWED,
 * DEPT_NOT_ALLOWED, CLEARANCE_TOO_LOW, DEVICE_NOT_COMPLIANT, EMPLOYEE_INACTIVE, CREDENTIAL_EXPIRED
 * (expiry == now is expired). Throws AccessInputError on out-of-contract values. Messages hold
 * the user's attributes: show them to the user, never send them to the gateway (floor 7).
 */
function checkPolicyLocally(attrs, pol, now) {
  const a = encodeAttributesV4(attrs);
  const p = encodePolicy(pol);
  const t = below("now", now, TWO64, "2^64");
  const reasons = [];
  const add = (code, message) => reasons.push({ code, message });
  if (((p.roleMask >> a.role) & 1n) !== 1n) add("ROLE_NOT_ALLOWED", `role ${labelOf(ROLES, a.role)} not in roleMask ${bin4(p.roleMask)}`);
  if (((p.deptMask >> a.dept) & 1n) !== 1n) add("DEPT_NOT_ALLOWED", `dept ${labelOf(DEPTS, a.dept)} not in deptMask ${bin4(p.deptMask)}`);
  if (a.clearance < p.minClearance) add("CLEARANCE_TOO_LOW", `clearance ${a.clearance} < minClearance ${p.minClearance}`);
  if (p.requireDevice === 1n && a.deviceCompliant !== 1n) add("DEVICE_NOT_COMPLIANT", "device not compliant but the policy requires it");
  if (a.employeeActive !== 1n) add("EMPLOYEE_INACTIVE", "employeeActive must be 1 for every proof");
  if (a.expiry <= t) add("CREDENTIAL_EXPIRED", "credential expired (expiry <= now)");
  return { ok: reasons.length === 0, reasons };
}

/**
 * P1's v3 FileShareAccess as a predicate: role and clearance in {2,3} (opaque v3 numbers, not
 * D6), deviceCompliant = employeeActive = 1. Same {ok, reasons} shape.
 */
function checkFileShareV3(attrs) {
  const a = encodeAttributesV3(attrs);
  const reasons = [];
  const add = (code, message) => reasons.push({ code, message });
  if (a.role !== 2n && a.role !== 3n) add("ROLE_NOT_ALLOWED", "v3 FileShareAccess requires role 2 or 3");
  if (a.clearance !== 2n && a.clearance !== 3n) add("CLEARANCE_TOO_LOW", "v3 FileShareAccess requires clearance 2 or 3");
  if (a.deviceCompliant !== 1n) add("DEVICE_NOT_COMPLIANT", "v3 FileShareAccess requires deviceCompliant 1");
  if (a.employeeActive !== 1n) add("EMPLOYEE_INACTIVE", "v3 FileShareAccess requires employeeActive 1");
  return { ok: reasons.length === 0, reasons };
}

module.exports = {
  ROLES, DEPTS, policies, EPOCH_SECONDS, epochOf,
  V3_ATTRIBUTES, V4_ATTRIBUTES, encodeAttributesV3, encodeAttributesV4, encodePolicy,
  checkPolicyLocally, checkFileShareV3,
};
