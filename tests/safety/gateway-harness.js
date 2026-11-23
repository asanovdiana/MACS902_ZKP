"use strict";
// In-process harness for the REAL P3 gateway (p3/gateway/src), used by the gateway half of floors
// 3, 4, 5 and 7 (F3.09, F4.06, F5.07, F7.05).
//
// What is real: the gateway's own TypeScript source loaded with tsx exactly as written, in its
// production v4 configuration: the built-in `integrated-access-v4` profile (ZK_PROFILE), the default
// artefact manifest (circuits/setup/integrated_access_v4.manifest.json, integrity-checked by the
// gateway's loader; ALLOW_DEMO_KEYS because the key is DEV/DEMO-ONLY), the pinned issuer, the
// snarkjs Groth16 verifier, the challenge/nullifier/session stores and the event bus. Requests take
// the path the team client takes: `GET /challenge?resource=` then
// `POST /access {resource, nonce, proof, publicSignals}` (p3/gateway/src/routes/teamAccess.ts), over
// HTTP (supertest). Proofs, public signals and fixtures.json are the committed
// circuits/fixtures/v4 files, read from disk at test time.
//
// Seams (nothing under p3/ is modified):
//   - createApp's `clock`, `registry` and `logger` deps (AppDeps); the registry double is the
//     gateway's own FakeRegistry (p3/gateway/tests/helpers.ts), which implements the issuer.api
//     staleness rule (insert keeps an old root acceptable, revoke does not);
//   - the challenge nonce: the gateway draws 128 random bits, and a committed proof is bound to the
//     fixture's nonce. After a REAL `GET /challenge`, the harness rebinds that stored challenge (and
//     the store's nonce index) to the fixture's nonce, i.e. "the RNG drew this nonce". Every other
//     challenge field (id, resource, now, epoch, TTL, single-use state) is the gateway's own.
//     fixtures/v4/README.md: "Treat each fixture's nonce as issued by the gateway". This touches the
//     ChallengeStore's private `byNonce` index; the harness fails loudly if its shape changes.
//
// Setup (once): `npm ci --prefix p3 && npm --prefix p3 run build -w shared`. Missing or stale
// setup FAILS the test with that instruction; it never skips.
const fs = require("fs");
const path = require("path");
const { createRequire } = require("module");
const { pathToFileURL } = require("url");
const h = require("./helpers");

const P3 = h.r("p3");
const GW = path.join(P3, "gateway");
const SETUP = "npm ci --prefix p3 && npm --prefix p3 run build -w shared";
const PROFILE_ID = "integrated-access-v4";
const OPERATOR_TOKEN = "safety-gateway-operator-token-0f1e2d3c";

/** Throw (never skip) when the P3 dependencies or the shared build are missing or stale. */
function assertP3Setup() {
  const missing = [];
  for (const dep of ["tsx", "express", "pino", "pino-http", "snarkjs", "supertest", "zod", "helmet", "express-rate-limit"]) {
    if (!fs.existsSync(path.join(P3, "node_modules", dep, "package.json"))) missing.push(`p3/node_modules/${dep}`);
  }
  if (!fs.existsSync(path.join(P3, "node_modules", "@zkag", "shared"))) missing.push("p3/node_modules/@zkag/shared");
  const dist = path.join(P3, "shared", "dist", "index.js");
  if (!fs.existsSync(dist)) missing.push("p3/shared/dist (the @zkag/shared build)");
  if (missing.length) {
    throw new Error(`P3 gateway is not set up for the safety tier; missing: ${missing.join(", ")}. Run once: ${SETUP}`);
  }
  const built = fs.statSync(dist).mtimeMs;
  const srcDir = path.join(P3, "shared", "src");
  const stale = fs.readdirSync(srcDir).filter((f) => f.endsWith(".ts") && fs.statSync(path.join(srcDir, f)).mtimeMs > built);
  if (stale.length) {
    throw new Error(`p3/shared/dist is older than p3/shared/src (${stale.join(", ")}); rebuild: npm --prefix p3 run build -w shared`);
  }
}

let loaded;
/** Load the gateway source (TypeScript, via tsx) once per process. */
async function loadGateway() {
  if (loaded) return loaded;
  assertP3Setup();
  const { tsImport } = require(path.join(P3, "node_modules", "tsx", "dist", "esm", "api", "index.cjs"));
  const imp = async (rel) => tsImport(pathToFileURL(path.join(GW, rel)).href, __filename);
  const [app, helpers] = await Promise.all([imp("src/app/createApp.ts"), imp("tests/helpers.ts")]);
  const p3require = createRequire(path.join(GW, "package.json"));
  loaded = {
    createApp: app.createApp,
    FakeClock: helpers.FakeClock,
    FakeRegistry: helpers.FakeRegistry,
    testConfig: helpers.testConfig,
    pino: p3require("pino"),
    request: p3require("supertest"),
  };
  return loaded;
}

/**
 * A fresh gateway (fresh challenge, nullifier and session state) in a fixture's `gateway_state`.
 * Options: `state` (a fixtures.json gateway_state), `root` (registry root), `nowS` (gateway clock).
 */
async function makeGateway({ state, root, nowS } = {}) {
  const gw = await loadGateway();
  const idx = h.fixtureIndex();
  const st = state || idx.fixtures.alice_wiki.gateway_state;
  const config = gw.testConfig({
    LOG_LEVEL: "trace",
    OPERATOR_TOKEN,
    ZK_PROFILE: PROFILE_ID,
    ALLOW_DEMO_KEYS: "true",
    TRUSTED_ISSUER_AX: idx.context.pinned_issuer.Ax,
    TRUSTED_ISSUER_AY: idx.context.pinned_issuer.Ay,
    CHALLENGE_TTL_SECONDS: String(idx.context.nonce_ttl_seconds),
    NULLIFIER_MAX_PER_EPOCH: "1",
    ZK_RATE_LIMIT_PER_MIN: "100000",
  });
  const clock = new gw.FakeClock(Number(nowS ?? st.now) * 1000);
  const registry = new gw.FakeRegistry(root ?? st.current_root);
  const sink = h.logSink();
  // No redaction: the floor must hold for the gateway's raw log output, not only after redaction.
  const logger = gw.pino({ level: "trace" }, sink.stream);
  const { app, ctx } = gw.createApp({ config, clock, registry, logger });
  if (ctx.profile.id !== PROFILE_ID) throw new Error(`gateway runs profile ${ctx.profile.id}, expected ${PROFILE_ID}`);
  if (ctx.profile.signals.join(",") !== idx.public_signals.join(",")) {
    throw new Error(`gateway v4 signal order [${ctx.profile.signals}] != fixtures.json [${idx.public_signals}]`);
  }
  const art = ctx.artifacts();
  if (art.status !== "ready") throw new Error(`gateway refused the v4 artefacts: ${art.status} ${art.detail || ""}`);
  const elig = ctx.pipeline.authorizationEligible();
  if (!elig.eligible) throw new Error(`gateway is not authorization-eligible: ${elig.missing.join("; ")}`);

  const http = () => gw.request(app);
  /** GET /challenge for a fixtures.json resource name; checks the challenge against the contract. */
  const challenge = async (resourceName) => {
    const res = await http().get(`/challenge?resource=${encodeURIComponent(resourceName)}`);
    if (res.status !== 200) throw new Error(`challenge refused: ${res.status} ${JSON.stringify(res.body)}`);
    const want = idx.context.resources[resourceName];
    const c = res.body;
    const bad = ["roleMask", "deptMask", "minClearance", "requireDevice"].filter((k) => c.policy[k] !== want[k]);
    if (c.resourceId !== want.resourceId || bad.length) {
      throw new Error(`gateway policy for ${resourceName} differs from fixtures.json context: ${bad.join(",")} resourceId ${c.resourceId}`);
    }
    return c;
  };
  /** Rebind the challenge the gateway issued with `issuedNonce` to `nonce` (see the header). */
  const plantNonce = (issuedNonce, nonce) => {
    const store = ctx.challenges;
    const id = store.idForNonce(issuedNonce);
    const stored = id && store.peek(id);
    if (!stored || stored.state !== "issued") throw new Error("no fresh challenge to bind the fixture nonce to");
    if (!(store.byNonce instanceof Map)) throw new Error("ChallengeStore has no byNonce index: update gateway-harness.js plantNonce");
    store.byNonce.delete(issuedNonce);
    stored.nonce = nonce;
    store.byNonce.set(nonce, id);
    return stored;
  };
  /** POST /access; resolves {res, status, admitted, code, reason, cid, event} (event: verification.completed). */
  const access = async (body) => {
    const res = await http().post("/access").set("content-type", "application/json").send(body);
    const cid = res.body && res.body.correlationId;
    const event = cid ? ctx.bus.recent(10_000).find((e) => e.type === "verification.completed" && e.correlationId === cid) : undefined;
    const err = (res.body && res.body.error) || {};
    return { res, status: res.status, admitted: res.body && res.body.admitted === true, code: err.code, reason: err.reason, cid, event };
  };
  /**
   * The client path for a committed fixture: GET /challenge for `presentedTo` (default: the
   * fixture's presented_to), bind the fixture's nonce to it, POST /access with the committed proof.
   */
  const present = async (name, { presentedTo, proof, publicSignals } = {}) => {
    const meta = idx.fixtures[name];
    const fx = h.fixture(meta.dir);
    const to = presentedTo || meta.presented_to;
    const c = await challenge(to);
    plantNonce(c.nonce, meta.nonce);
    const body = { resource: to, nonce: meta.nonce, proof: proof || fx.proof, publicSignals: publicSignals || fx.publicSignals };
    return { ...(await access(body)), body, challenge: c };
  };
  /** Let the gateway's async root-change handler (session revocation) run. */
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  return { app, ctx, clock, registry, sink, idx, challenge, plantNonce, access, present, settle, gw };
}

/** Stop the bn128 worker threads p3's snarkjs started (one curve per process). */
async function shutdown() {
  const c = globalThis.curve_bn128;
  if (c && typeof c.terminate === "function") await c.terminate();
  // ffjavascript rebuilds the curve on the next use when the global is empty (it is shared with
  // circuits/scripts/verify.js, which clears it the same way).
  delete globalThis.curve_bn128;
}

module.exports = { loadGateway, makeGateway, assertP3Setup, shutdown, SETUP, OPERATOR_TOKEN };
