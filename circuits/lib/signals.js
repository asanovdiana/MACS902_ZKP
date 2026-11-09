"use strict";
// Public-signal codec: access.public_signals v3 ([root]) and v4 (12 signals). snarkjs puts
// outputs first, then public inputs in template declaration order.
const { fail, parseField, bounded, below, TWO64 } = require("./field");

const PUBLIC_SIGNALS = Object.freeze({
  v3: Object.freeze(["root"]),
  v4: Object.freeze([
    "nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance",
    "requireDevice", "now", "nonce", "resourceId", "epoch",
  ]),
});

/** Per-signal ranges (v4 table); anything not listed is a field element < p. */
const RANGES = Object.freeze({
  roleMask: { max: 15n },
  deptMask: { max: 15n },
  minClearance: { max: 3n },
  requireDevice: { max: 1n },
  now: { below: TWO64, label: "2^64" },
});

function parseSignal(name, v, opts, label = name) {
  const r = RANGES[name];
  if (!r) return parseField(label, v, opts);
  if (r.max !== undefined) return bounded(label, v, r.max, opts);
  return below(label, v, r.below, r.label, opts);
}

/**
 * publicSignals array -> {name: canonical decimal}. Strict: exact length, strings only, canonical
 * decimal, < p, v4 policy/time fields in range. Never reduces mod p.
 */
function decode(names, arr) {
  if (!Array.isArray(arr) || arr.length !== names.length) {
    fail("BAD_LENGTH", `publicSignals: expected an array of ${names.length} entries`);
  }
  const out = {};
  names.forEach((name, i) => {
    out[name] = parseSignal(name, arr[i], { stringsOnly: true }, `publicSignals[${i}] (${name})`).toString();
  });
  return out;
}

/** {name: value} -> publicSignals array. Values: bigint, safe Number or canonical decimal. */
function encode(names, obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) fail("INVALID_VALUE", "publicSignals: object expected");
  for (const k of Object.keys(obj)) if (!names.includes(k)) fail("UNKNOWN_FIELD", `publicSignals: unknown field ${JSON.stringify(k)}`);
  return names.map((name) => {
    if (obj[name] === undefined) fail("MISSING_FIELD", `publicSignals: missing field ${name}`);
    return parseSignal(name, obj[name]).toString();
  });
}

module.exports = { PUBLIC_SIGNALS, RANGES, decode, encode };
