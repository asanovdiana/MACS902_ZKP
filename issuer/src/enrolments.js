"use strict";
// Admin-approved enrolments (issuer.api v2 / issuer.admin v1.1). The admin assigns the attributes
// of one employee and receives a single-use, short-lived code; the user redeems it with a
// commitment. State: one JSON file (atomic write, mode 0600) holding the code HASH (never the code),
// the employeeId (issuer-side identity, never logged), the pending attributes (erased at
// redemption) and, once redeemed, the leaf index.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { err } = require("./errors");

const STATE_FILE = "enrolments.json";
const STATE_VERSION = 1;
const CODE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const EMPLOYEE_RE = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;
const TTL_MIN = 60;
const TTL_MAX = 604800;

const sha256hex = (s) => crypto.createHash("sha256").update(s).digest("hex");

function createEnrolments({ dir, clock, defaultTtlSeconds = 3600 }) {
  const file = path.join(dir, STATE_FILE);
  let records = []; // {id, employeeId, codeHash, attributes|null, createdAt, expiresAt, status, redeemedAt, leafIndex}
  if (fs.existsSync(file)) {
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    if (s.version !== STATE_VERSION) throw new Error("enrolment state: unsupported version");
    records = s.enrolments;
  }
  const byHash = new Map(records.map((r) => [r.codeHash, r]));

  function save() {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ version: STATE_VERSION, enrolments: records }), { mode: 0o600 });
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, file);
  }

  /** Run `mutate`, persist; on a persist failure restore the previous in-memory state and rethrow. */
  function persisted(mutate, undo) {
    mutate();
    try {
      save();
    } catch (e) {
      undo();
      throw e;
    }
  }

  const isExpired = (r) => r.status === "pending" && clock() >= r.expiresAt;
  const statusOf = (r) => (isExpired(r) ? "expired" : r.status);

  return {
    file,

    validateEmployeeId(id) {
      if (typeof id !== "string" || !EMPLOYEE_RE.test(id)) throw err(400, "invalid_employee_id", "employeeId must be 1..128 characters of [A-Za-z0-9._@+-]");
      return id;
    },

    validateTtl(ttl) {
      if (ttl === undefined) return defaultTtlSeconds;
      if (!Number.isSafeInteger(ttl) || ttl < TTL_MIN || ttl > TTL_MAX) throw err(400, "invalid_ttl", `ttlSeconds must be an integer ${TTL_MIN}..${TTL_MAX}`);
      return ttl;
    },

    /**
     * Create an enrolment for validated `employeeId` / `attributes`. `isLive(leafIndex)` says whether
     * a redeemed credential's leaf is still unrevoked. Returns {id, code, expiresAt}.
     */
    create({ employeeId, attributes, ttlSeconds, isLive }) {
      const key = employeeId.toLowerCase();
      for (const r of records) {
        if (r.employeeId.toLowerCase() !== key) continue;
        if (r.status === "pending" && !isExpired(r)) throw err(409, "enrolment_pending", "the employee has an unredeemed enrolment; cancel it first");
        if (r.status === "redeemed" && isLive(r.leafIndex)) throw err(409, "employee_has_credential", "the employee holds a live credential; revoke it first");
      }
      const code = crypto.randomBytes(24).toString("base64url");
      const now = clock();
      const rec = {
        id: crypto.randomBytes(8).toString("hex"), employeeId, codeHash: sha256hex(code), attributes: { ...attributes },
        createdAt: now, expiresAt: now + ttlSeconds, status: "pending", redeemedAt: null, leafIndex: null,
      };
      persisted(() => { records.push(rec); byHash.set(rec.codeHash, rec); }, () => { records.pop(); byHash.delete(rec.codeHash); });
      return { id: rec.id, code, expiresAt: rec.expiresAt };
    },

    /** The redeemable record for `code`, or throws 403 / 409 / 410. Does not consume it. */
    lookup(code) {
      if (typeof code !== "string" || !CODE_RE.test(code)) throw err(403, "invalid_enrolment_code", "enrolment code missing or not valid");
      const r = byHash.get(sha256hex(code));
      if (!r || r.status === "cancelled") throw err(403, "invalid_enrolment_code", "enrolment code missing or not valid");
      if (r.status === "redeemed") throw err(409, "enrolment_used", "enrolment code already used");
      if (isExpired(r)) throw err(410, "enrolment_expired", "enrolment code expired");
      return r;
    },

    /** Consume `rec` for the leaf about to be inserted; erases the attributes. */
    markRedeemed(rec, leafIndex) {
      const prev = { status: rec.status, attributes: rec.attributes, redeemedAt: rec.redeemedAt, leafIndex: rec.leafIndex };
      persisted(
        () => Object.assign(rec, { status: "redeemed", attributes: null, redeemedAt: clock(), leafIndex }),
        () => Object.assign(rec, prev),
      );
      return prev;
    },

    /** Undo markRedeemed (the leaf insert failed). Best effort. */
    revertRedeemed(rec, prev) {
      Object.assign(rec, prev);
      try { save(); } catch (_) { /* stays consumed on disk: fail safe, the admin cancels and re-enrols */ }
    },

    cancel(id) {
      const r = records.find((x) => x.id === id);
      if (!r) throw err(404, "unknown_enrolment", "no such enrolment");
      if (r.status !== "pending") throw err(409, "enrolment_not_pending", "only a pending enrolment can be cancelled");
      const prev = { status: r.status, attributes: r.attributes };
      persisted(() => Object.assign(r, { status: "cancelled", attributes: null }), () => Object.assign(r, prev));
      return { enrolmentId: id, status: "cancelled" };
    },

    total: () => records.length,
    pending: () => records.filter((r) => r.status === "pending" && !isExpired(r)).length,

    list(from, limit) {
      return records.slice(from, from + limit).map((r) => ({
        enrolmentId: r.id, employeeId: r.employeeId, status: statusOf(r), createdAt: r.createdAt,
        expiresAt: r.expiresAt, redeemedAt: r.redeemedAt, leafIndex: r.leafIndex,
      }));
    },
  };
}

module.exports = { createEnrolments, STATE_FILE };
