"use strict";
// Field constants, canonical-decimal parse/format and the library's error type
// (docs/CONTRACTS.md, Common rules). Internally the library works with BigInt; every value it
// emits is a canonical decimal string.
//
// Error messages never echo the offending value: the same parsers handle credentialSecret and
// credentialSalt, which must never reach a log (floor 6).

/** BN254 scalar field (circom default prime). */
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** BabyJubJub prime-order subgroup order l; an EdDSA `S` must be < l (circomlib checks it). */
const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const TWO64 = 1n << 64n;

/** Canonical decimal: ASCII digits, no sign, no whitespace, no 0x, no leading zero but "0". */
const DECIMAL = /^(0|[1-9][0-9]*)$/;

/** Stable error codes (AccessInputError.code). Programs branch on these, never on messages. */
const CODES = Object.freeze(
  Object.fromEntries(
    [
      "INVALID_VALUE", // not a canonical decimal / integer / known label
      "OUT_OF_RANGE", // integer outside its contract range (field, enum, 2^64, l)
      "MISSING_FIELD",
      "UNKNOWN_FIELD", // strict schemas: a key the contract does not define
      "BAD_LENGTH", // public-signal array or Poseidon arity
      "DEPTH_MISMATCH", // Merkle path length != profile depth
      "INVALID_PATH_INDEX", // pathIndices entry not 0/1
      "INVALID_KEY", // issuer private key not 32 bytes
      "UNKNOWN_PROFILE",
      "PROFILE_MISMATCH", // a registry path labelled with another profile
      "SECRET_MISMATCH", // Poseidon(2)(secret, salt) != the credential's commitment
      "LEAF_MISMATCH", // the path's leaf != the leaf this credential produces
      "BAD_SIGNATURE", // issuer signature does not verify over the profile's message
      "ROOT_MISMATCH", // the path does not reach the given root
      "POLICY_NOT_SATISFIED", // see err.reasons
      "CREDENTIAL_EXPIRED", // v4: expiry <= now
      "EMPLOYEE_INACTIVE", // v4: employeeActive != 1 (ADR 0007)
      "EPOCH_MISMATCH", // v4: epoch != floor(now / 600)
      "RESOURCE_MISMATCH", // v4: challenge.resourceId != policy.resourceId
    ].map((c) => [c, c])
  )
);

class AccessInputError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.name = "AccessInputError";
    this.code = code;
    Object.assign(this, extra);
  }
}

function fail(code, message, extra) {
  throw new AccessInputError(code, message, extra);
}

const isCanonical = (s) => typeof s === "string" && DECIMAL.test(s);

/**
 * Unsigned integer from a canonical decimal string, a bigint >= 0 or a safe non-negative integer
 * Number. `stringsOnly` rejects anything but strings (public-signal decoding).
 */
function toBigInt(name, v, { stringsOnly = false } = {}) {
  if (v === undefined || v === null) fail("MISSING_FIELD", `${name}: missing`);
  if (typeof v === "string") {
    if (!DECIMAL.test(v)) fail("INVALID_VALUE", `${name}: expected a canonical decimal string`);
    return BigInt(v);
  }
  if (stringsOnly) fail("INVALID_VALUE", `${name}: expected a canonical decimal string, got ${typeof v}`);
  if (typeof v === "bigint") {
    if (v < 0n) fail("OUT_OF_RANGE", `${name}: must be non-negative`);
    return v;
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) fail("INVALID_VALUE", `${name}: expected a safe integer`);
    if (v < 0) fail("OUT_OF_RANGE", `${name}: must be non-negative`);
    return BigInt(v);
  }
  return fail("INVALID_VALUE", `${name}: expected an integer, got ${typeof v}`);
}

/** Field element 0 <= x < p (no reduction: p + x is rejected, not mapped to x). */
function parseField(name, v, opts) {
  const x = toBigInt(name, v, opts);
  if (x >= P) fail("OUT_OF_RANGE", `${name}: must be < p (BN254 scalar field)`);
  return x;
}

/** Integer 0 <= x <= max. */
function bounded(name, v, max, opts) {
  const x = toBigInt(name, v, opts);
  if (x > max) fail("OUT_OF_RANGE", `${name}: must be in 0..${max}`);
  return x;
}

/** Integer 0 <= x < limit. */
function below(name, v, limit, limitLabel, opts) {
  const x = toBigInt(name, v, opts);
  if (x >= limit) fail("OUT_OF_RANGE", `${name}: must be < ${limitLabel}`);
  return x;
}

/** Canonical decimal of a field element (accepts the same inputs as parseField). */
const formatField = (v, name = "value") => parseField(name, v).toString();

/** Reject keys outside `allowed` (strict schemas, as issuer.api v1). */
function strictKeys(name, obj, allowed) {
  if (obj === undefined || obj === null) fail("MISSING_FIELD", `${name}: missing`);
  if (typeof obj !== "object" || Array.isArray(obj)) fail("INVALID_VALUE", `${name}: object expected`);
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) fail("UNKNOWN_FIELD", `${name}: unknown field ${JSON.stringify(k)}`);
  }
  return obj;
}

module.exports = {
  P, L, TWO64, DECIMAL, CODES, AccessInputError,
  fail, isCanonical, toBigInt, parseField, bounded, below, formatField, strictKeys,
};
