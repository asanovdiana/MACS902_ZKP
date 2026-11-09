"use strict";
// Test harness: temp key/data dirs (never the real issuer/keys), an app built with an injectable
// clock and a captured log stream, and shared fixtures from circuits/test/vectors.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Writable } = require("stream");
const zk = require("../../circuits/lib");
const { buildServer } = require("../src/server");

const VECTORS = path.join(__dirname, "..", "..", "circuits", "test", "vectors");
const vectors = (profile) => JSON.parse(fs.readFileSync(path.join(VECTORS, profile, "credentials.json"), "utf8"));

const T0 = 1_800_000_000; // fixed test clock (unix s)

function tmpDir(prefix = "issuer-test-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function mutableClock(start = T0) {
  const c = { t: start, now: () => c.t, advance: (s) => (c.t += s) };
  return c;
}

function logSink() {
  const lines = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      for (const l of chunk.toString().split("\n")) if (l.trim()) lines.push(l);
      cb();
    },
  });
  return { stream, lines, text: () => lines.join("\n") };
}

const ADMIN_TOKEN = "test-admin-token-0123456789";

/**
 * Build an app on fresh temp dirs (or the given ones). Returns {app, clock, sink, keyDir, dataDir, config}.
 * Default: insecure-dev mode (no admin token, open admin surface) so the older suites stay terse;
 * `secure: true` is the production posture (ADMIN_TOKEN set, insecureDev off).
 */
async function makeApp({ profile = "v3", keyDir, dataDir, clock = mutableClock(), overrides = {}, secure = false } = {}) {
  keyDir = keyDir || tmpDir("issuer-keys-");
  dataDir = dataDir || tmpDir("issuer-data-");
  const sink = logSink();
  const posture = secure ? { adminToken: ADMIN_TOKEN, insecureDev: false } : { insecureDev: true };
  const config = { profile, keyDir, dataDir, host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, ...posture, ...overrides };
  const app = await buildServer({ config, clock: clock.now, logStream: sink.stream });
  app.testAdminToken = config.adminToken || null;
  return { app, clock, sink, keyDir, dataDir, config };
}

const json = (res) => JSON.parse(res.body);

async function post(app, url, body) {
  return app.inject({
    method: "POST",
    url,
    headers: { "content-type": "application/json" },
    payload: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** A fresh client-side secret/salt/commitment (test stand-in for client keygen). */
async function newSecrets() {
  const rnd = () => BigInt("0x" + require("crypto").randomBytes(31).toString("hex")).toString();
  const credentialSecret = rnd();
  const credentialSalt = rnd();
  const commitment = await zk.commitment(credentialSecret, credentialSalt);
  return { credentialSecret, credentialSalt, commitment };
}

const V3_ATTRS = { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 };
const v4Attrs = (expiry = T0 + 86400, extra = {}) => ({
  role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry, ...extra,
});
const attrsFor = (profile) => (profile === "v3" ? { ...V3_ATTRS } : v4Attrs());

/** Admin request (adds the bearer token when the app has one). */
async function adminReq(app, method, url, body) {
  const headers = { "content-type": "application/json" };
  if (app.testAdminToken) headers.authorization = `Bearer ${app.testAdminToken}`;
  return app.inject({ method, url, headers, payload: body === undefined ? undefined : JSON.stringify(body) });
}

let employeeSeq = 0;
const nextEmployee = () => `emp-${++employeeSeq}`;

/** Admin creates an enrolment. Returns {res, enrolmentId, code, employeeId}. */
async function adminEnrol(app, profile = "v3", attrs, employeeId = nextEmployee(), extra = {}) {
  const res = await adminReq(app, "POST", "/admin/enrolments", { employeeId, attributes: attrs === undefined ? attrsFor(profile) : attrs, ...extra });
  const b = res.statusCode === 201 ? json(res) : {};
  return { res, employeeId, enrolmentId: b.enrolmentId, code: b.code, expiresAt: b.expiresAt };
}

/** Full flow: admin enrolment, then the user redeems the code with a fresh commitment. */
async function issue(app, profile = "v3", attrs, { employeeId, commitmentOf } = {}) {
  const e = await adminEnrol(app, profile, attrs, employeeId);
  if (e.res.statusCode !== 201) return { res: e.res, secrets: null, cred: null, enrol: e };
  const s = commitmentOf ? { commitment: commitmentOf } : await newSecrets();
  const res = await post(app, "/credentials", { commitment: s.commitment, enrolmentCode: e.code });
  return { res, secrets: s, cred: res.statusCode === 201 ? json(res).credential : null, enrol: e };
}

module.exports = {
  zk, vectors, T0, tmpDir, mutableClock, logSink, makeApp, json, post, newSecrets,
  V3_ATTRS, v4Attrs, attrsFor, issue, adminReq, adminEnrol, ADMIN_TOKEN,
};
