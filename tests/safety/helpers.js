"use strict";
// Shared harness for the floor test tier (tests/safety, G1-S1-SAFETY-020).
//
// Reuses the REAL code under review: circuits/lib (shared encoder), the committed v4 proving
// artefacts (circuits/setup/integrated_access_v4.{wasm,verification_key.json}), the committed
// fixtures, circuits/scripts/verify.js, issuer/src (in-process Fastify on temp dirs) and client/src.
// Nothing here writes outside os.tmpdir(); the real issuer key directory is never touched.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { Writable } = require("stream");
const { execFileSync } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..");
const r = (...p) => path.join(REPO, ...p);

const zk = require(r("circuits", "lib"));
const verifier = require(r("circuits", "scripts", "verify.js"));
const snarkjs = require(r("node_modules", "snarkjs"));

const V4_WASM = r("circuits", "setup", "integrated_access_v4.wasm");
const V4_VKEY = r("circuits", "setup", "integrated_access_v4.verification_key.json");
const V3_VKEY = r("circuits", "setup", "integrated_access_v3.verification_key.json");
const FIXTURES = r("circuits", "fixtures", "v4");

const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const vectorsV4 = () => readJson(r("circuits", "test", "vectors", "v4", "credentials.json"));
const aliceWikiInput = () => readJson(r("circuits", "test", "vectors", "v4", "input.alice.wiki.json"));
const fixtureIndex = () => readJson(path.join(FIXTURES, "fixtures.json"));
const fixture = (name) => ({
  proof: readJson(path.join(FIXTURES, name, "proof.json")),
  publicSignals: readJson(path.join(FIXTURES, name, "public.json")),
});
const v4Vkey = () => readJson(V4_VKEY);

/**
 * Run the committed v4 witness calculator (the artefact the client prover ships) on `input`.
 * Resolves {ok: true, nullifier, witness} or {ok: false, error}. Never rejects. The circom wasm
 * checks every constraint while it computes, so ok:false means "no witness, hence no proof".
 */
async function witnessV4(input) {
  const sink = { type: "mem" };
  const quiet = console.log;
  const quietErr = console.error;
  console.error = () => {};
  console.log = () => {}; // circom's wasm prints "ERROR: ..." on a failed assert
  try {
    await snarkjs.wtns.calculate(input, V4_WASM, sink);
    const w = await snarkjs.wtns.exportJson(sink);
    return { ok: true, nullifier: w[1].toString(), witness: w };
  } catch (e) {
    return { ok: false, error: String((e && e.message) || e) };
  } finally {
    console.log = quiet;
    console.error = quietErr;
  }
}

/** The TEST-ONLY issuer key of the committed vectors: sha256 of its public label (gen-vectors.js). */
function testOnlyIssuerPrv() {
  const v = vectorsV4();
  return crypto.createHash("sha256").update(v.issuer.seedLabel, "utf8").digest();
}

/**
 * A v4 credential signed by `prv` over attributes `attrs`, alone (or with `others` leaves) in a fresh
 * depth-16 tree. Returns {secret, salt, commitment, attrHash, signature, issuer, tree, leafIndex}.
 */
async function signedCredential(prv, attrs, { others = [] } = {}) {
  const rnd = () => BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString();
  const secret = rnd();
  const salt = rnd();
  const commitment = await zk.commitment(secret, salt);
  const attrHash = await zk.attrHash(attrs, commitment);
  const signature = await zk.sign(prv, attrHash);
  const issuer = await zk.publicKey(prv);
  const tree = await zk.createTree("v4");
  for (const l of others) tree.insert(BigInt(l));
  const leafIndex = tree.leaves.length;
  tree.insert(BigInt(attrHash));
  return { secret, salt, commitment, attrHash, signature, issuer, tree, leafIndex };
}

/** Circuit input for a signed credential (no lib pre-check: we want to see the CIRCUIT refuse). */
function rawInputV4(cred, attrs, { policy = "wiki", now, nonce = "12345", root, issuer, signature } = {}) {
  const pol = typeof policy === "string" ? zk.policies[policy] : policy;
  const p = zk.proofFor(cred.tree, cred.leafIndex);
  const s = (x) => String(x);
  const sig = signature || cred.signature;
  const iss = issuer || cred.issuer;
  return {
    credentialSecret: cred.secret,
    credentialSalt: cred.salt,
    role: s(attrs.role), dept: s(attrs.dept), clearance: s(attrs.clearance),
    deviceCompliant: s(attrs.deviceCompliant), employeeActive: s(attrs.employeeActive), expiry: s(attrs.expiry),
    R8x: sig.R8x, R8y: sig.R8y, S: sig.S,
    pathElements: p.pathElements, pathIndices: p.pathIndices,
    root: root || p.root,
    issuerAx: iss.Ax, issuerAy: iss.Ay,
    roleMask: s(pol.roleMask), deptMask: s(pol.deptMask), minClearance: s(pol.minClearance), requireDevice: s(pol.requireDevice),
    now: s(now), nonce: s(nonce), resourceId: s(pol.resourceId), epoch: (BigInt(now) / 600n).toString(),
  };
}

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `zkgate-safety-${prefix}-`));
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

/** A mutable unix-seconds clock. */
function clockAt(t) {
  const c = { t, now: () => c.t, advance: (s) => (c.t += s) };
  return c;
}

/** Bearer token the tier's issuers run with (issuer.api v2: no token, no start; SR-04). */
const ADMIN_TOKEN = "safety-tier-admin-token-7f3a9c1e";

/**
 * The real issuer (issuer/src/server.js) on fresh temp key/data dirs, logs captured, in the
 * PRODUCTION posture of issuer.api v2: admin token set, insecureDev off. `overrides` may replace
 * either; tests that probe the fail-closed start do so explicitly.
 * Returns {app, sink, clock, keyDir, dataDir, config, token, admin(method, url, body?, token?)}.
 */
async function makeIssuer({ profile = "v4", t0 = 1_800_000_000, overrides = {} } = {}) {
  const { buildServer } = require(r("issuer", "src", "server.js"));
  const keyDir = tmpDir("issuer-key");
  const dataDir = tmpDir("issuer-data");
  const sink = logSink();
  const clock = clockAt(t0);
  const config = {
    profile, keyDir, dataDir, host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900,
    logLevel: "trace", adminToken: ADMIN_TOKEN, insecureDev: false, ...overrides,
  };
  const app = await buildServer({ config, clock: clock.now, logStream: sink.stream });
  const token = config.adminToken;
  /** An admin request carrying `Authorization: Bearer <tok>` (tok null = no header). */
  const admin = (method, url, body, tok = token) => {
    const headers = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (tok !== null && tok !== undefined) headers.authorization = `Bearer ${tok}`;
    return app.inject({ method, url, headers, payload: body === undefined ? undefined : JSON.stringify(body) });
  };
  return { app, sink, clock, keyDir, dataDir, config, token, admin };
}

/** D6 labels ("engineer", "it") to the integers issuer.admin v1.1 takes; integers pass through. */
function encodeAttrs(attrs) {
  const out = { ...attrs };
  if (typeof out.role === "string" && out.role in zk.ROLES) out.role = zk.ROLES[out.role];
  if (typeof out.dept === "string" && out.dept in zk.DEPTS) out.dept = zk.DEPTS[out.dept];
  return out;
}

let employeeSeq = 0;
/**
 * issuer.admin v1.1 POST /admin/enrolments with the bearer token (or `token`; null = none).
 * Resolves {res, status, body, employeeId, enrolmentId, code, expiresAt}; never throws on a refusal.
 */
async function adminEnrol(iss, { employeeId, attributes, ttlSeconds, token } = {}) {
  const id = employeeId === undefined ? `safety-emp-${++employeeSeq}` : employeeId;
  const body = { employeeId: id, attributes: encodeAttrs(attributes) };
  if (ttlSeconds !== undefined) body.ttlSeconds = ttlSeconds;
  const res = await iss.admin("POST", "/admin/enrolments", body, token === undefined ? iss.token : token);
  let b = {};
  try { b = JSON.parse(res.body); } catch (_) { /* non-JSON refusal */ }
  return { res, status: res.statusCode, body: b, employeeId: id, enrolmentId: b.enrolmentId, code: b.code, expiresAt: b.expiresAt };
}

/**
 * The issuer.api v2 enrolment path end to end: the ADMIN creates the enrolment and assigns the
 * attributes, then the user's wallet redeems the one-time code through the real client library,
 * which sends only {commitment, enrolmentCode}. Resolves {summary, enrolment}.
 */
async function enrolViaAdmin({ iss, wallet, name, issuer, attributes, employeeId }) {
  const client = require(r("client", "src"));
  const e = await adminEnrol(iss, { employeeId, attributes });
  if (e.status !== 201) throw new Error(`admin enrolment refused: ${e.status} ${e.res.body}`);
  const summary = await client.requestCredential({ wallet, name, issuer, enrolmentCode: e.code });
  return { summary, enrolment: e };
}

/**
 * fetch() that serves the client library from an in-process issuer, recording every request
 * (method, url, body) the client sends. No sockets.
 */
function recordingFetch(app, sent = []) {
  const f = async (url, init = {}) => {
    sent.push({ method: init.method, url, body: init.body === undefined ? undefined : String(init.body) });
    const u = new URL(url);
    const res = await app.inject({ method: init.method, url: u.pathname + u.search, headers: init.headers, payload: init.body });
    return { status: res.statusCode, text: async () => res.body };
  };
  f.sent = sent;
  return f;
}

const challengeFor = (resource, nonce, now) => {
  const p = zk.policies[resource];
  return {
    nonce: String(nonce), resourceId: p.resourceId, epoch: Math.floor(now / 600), now,
    policy: { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice },
  };
};

const git = (...args) =>
  execFileSync("git", args, { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });

module.exports = {
  REPO, r, zk, verifier, snarkjs, readJson,
  V4_WASM, V4_VKEY, V3_VKEY, FIXTURES,
  vectorsV4, aliceWikiInput, fixtureIndex, fixture, v4Vkey,
  witnessV4, testOnlyIssuerPrv, signedCredential, rawInputV4,
  tmpDir, logSink, clockAt, makeIssuer, recordingFetch, challengeFor, git,
  ADMIN_TOKEN, encodeAttrs, adminEnrol, enrolViaAdmin,
};
