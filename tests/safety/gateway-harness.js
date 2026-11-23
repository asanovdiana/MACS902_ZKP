"use strict";
// In-process harness for the REAL P3 gateway (p3/gateway/src), used by the gateway half of floors
// 3, 4, 5 and 7 (F3.09, F4.06, F5.07, F7.05).
//
// What is real: the gateway's own TypeScript source (createApp, routes, VerificationPipeline,
// ChallengeStore, NullifierStore, SessionStore, EventBus, artifact loader with its manifest/sha256
// integrity check, and the snarkjs Groth16 verifier), loaded with tsx exactly as written; the
// committed v4 fixtures and verification key (circuits/fixtures/v4), read from disk at test time.
// Requests go through the HTTP stack (supertest, as the gateway's own tests do).
//
// Seams (all of them exist in p3 today; nothing under p3/ is modified):
//   - `clock`, `registry`, `logger` and `testOverrides.profile` of createApp's AppDeps;
//   - the registry double is the gateway's own FakeRegistry (p3/gateway/tests/helpers.ts);
//   - the challenge nonce: the gateway draws a random nonce, and a committed proof is bound to the
//     fixture's nonce. After a REAL challenge issuance (POST /api/zk/challenges) the harness sets
//     the stored challenge's nonce to the fixture's (`ctx.challenges.peek(id)`), i.e. "the RNG drew
//     this nonce". Every other challenge field (id, resource, epoch, TTL, single-use state) is the
//     gateway's own. fixtures/v4/README.md: "Treat each fixture's nonce as issued by the gateway".
//   - the v4 profile: the gateway ships no `access.public_signals v4` profile yet (it has
//     p1-integrated-v3 and the proposed zkag-access-v1, whose order differs). The harness builds
//     one from fixtures.json `public_signals` (the contract order) with the gateway's own signal
//     vocabulary (`now` -> `currentTime`) and every REQUIRED_CAPABILITY the gateway defines.
//
// Setup (once): `npm ci --prefix p3 && npm --prefix p3 run build -w shared`. Missing or stale
// setup FAILS the test with that instruction; it never skips.
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { createRequire } = require("module");
const { pathToFileURL } = require("url");
const h = require("./helpers");

const P3 = h.r("p3");
const GW = path.join(P3, "gateway");
const SETUP = "npm ci --prefix p3 && npm --prefix p3 run build -w shared";
const PROFILE_ID = "access-v4";
const CIRCUIT_ID = "integrated_access_v4";
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
  const [app, helpers, profiles, groth16] = await Promise.all([
    imp("src/app/createApp.ts"),
    imp("tests/helpers.ts"),
    imp("src/verification/profiles.ts"),
    imp("src/verification/groth16.ts"),
  ]);
  const p3require = createRequire(path.join(GW, "package.json"));
  loaded = {
    createApp: app.createApp,
    FakeClock: helpers.FakeClock,
    FakeRegistry: helpers.FakeRegistry,
    testConfig: helpers.testConfig,
    REQUIRED_CAPABILITIES: profiles.REQUIRED_CAPABILITIES,
    SnarkjsGroth16Verifier: groth16.SnarkjsGroth16Verifier,
    pino: p3require("pino"),
    request: p3require("supertest"),
    p3snarkjs: p3require("snarkjs"),
  };
  return loaded;
}

const fixtureIndex = () => h.fixtureIndex();
const VKEY_FILE = path.join(h.FIXTURES, "verification_key.json");

/** fixtures.json resource names (file_share) -> gateway resource ids (file-share). */
const gatewayResource = (name) => name.replace(/_/g, "-");

/** The `access.public_signals v4` profile in the gateway's vocabulary, built from fixtures.json. */
function v4Profile(gw, idx) {
  const rename = { now: "currentTime" };
  return {
    id: PROFILE_ID,
    circuitId: CIRCUIT_ID,
    title: "access.public_signals v4 (safety tier)",
    signals: idx.public_signals.map((n) => rename[n] || n),
    capabilities: Object.fromEntries(gw.REQUIRED_CAPABILITIES.map((c) => [c, true])),
    policyCoverage: ["wiki", "file-share", "admin-panel"],
    notes: ["safety tier: committed v4 fixtures; DEV-ONLY key"],
  };
}

/** A temp artifact dir the gateway's own loader integrity-checks (manifest + vkey sha256). */
function v4ArtifactDir(profile) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zkgate-safety-gw-art-"));
  const raw = fs.readFileSync(VKEY_FILE);
  const vkey = JSON.parse(raw.toString("utf8"));
  fs.writeFileSync(path.join(dir, "verification_key.json"), raw);
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify({
    circuitId: CIRCUIT_ID,
    profile: profile.id,
    version: "v4-fixtures",
    proofSystem: "groth16",
    curve: "bn128",
    nPublic: vkey.nPublic,
    publicSignals: profile.signals,
    securityStatus: "DEV-ONLY (TEST-ONLY fixtures)",
    securityReview: { status: "accepted", reviewer: "safety tier", reference: "tests/safety/gateway-harness.js" },
    files: { verificationKey: { path: "verification_key.json", sha256: crypto.createHash("sha256").update(raw).digest("hex") } },
  }));
  return dir;
}

/**
 * A fresh gateway (fresh challenge, nullifier and session state) in a fixture's `gateway_state`.
 * Options: `root` (registry root), `nowS` (unix seconds on the gateway clock).
 * Returns {app, ctx, clock, registry, sink, idx, challenge, present, verify, nowS}.
 */
async function makeGateway({ state, root, nowS } = {}) {
  const gw = await loadGateway();
  const idx = fixtureIndex();
  const st = state || idx.fixtures.alice_wiki.gateway_state;
  const profile = v4Profile(gw, idx);
  const config = gw.testConfig({
    LOG_LEVEL: "trace",
    OPERATOR_TOKEN,
    ZK_PROFILE: "zkag-access-v1",
    ARTIFACT_DIR: v4ArtifactDir(profile),
    TRUSTED_ISSUER_AX: idx.context.pinned_issuer.Ax,
    TRUSTED_ISSUER_AY: idx.context.pinned_issuer.Ay,
    CHALLENGE_TTL_SECONDS: String(idx.context.nonce_ttl_seconds),
    CLOCK_SKEW_SECONDS: String(idx.context.nonce_ttl_seconds),
    EPOCH_SECONDS: "600",
    NULLIFIER_MAX_PER_EPOCH: "1",
  });
  const clock = new gw.FakeClock(Number(nowS ?? st.now) * 1000);
  const registry = new gw.FakeRegistry(root ?? st.current_root);
  const sink = h.logSink();
  // No redaction: the floor must hold for the gateway's raw log output, not only after redaction.
  const logger = gw.pino({ level: "trace" }, sink.stream);
  const { app, ctx } = gw.createApp({ config, clock, registry, logger, testOverrides: { profile } });
  const art = ctx.artifacts();
  if (art.status !== "ready" || !art.reviewed) throw new Error(`gateway refused the v4 artefacts: ${art.status} ${art.detail || ""}`);
  if (!ctx.pipeline.authorizationEligible().eligible) {
    throw new Error(`gateway is not authorization-eligible: ${ctx.pipeline.authorizationEligible().missing.join("; ")}`);
  }

  /** POST /api/zk/challenges for a fixtures.json resource name; checks the policy against the contract. */
  const challenge = async (resourceName) => {
    const res = await gw.request(app).post("/api/zk/challenges").set("content-type", "application/json").send({ resource: gatewayResource(resourceName) });
    if (res.status !== 201) throw new Error(`challenge refused: ${res.status} ${JSON.stringify(res.body)}`);
    const want = idx.context.resources[resourceName];
    const got = res.body;
    const mismatch = ["roleMask", "deptMask", "minClearance", "requireDevice"].filter((k) => got.policy[k] !== String(want[k]));
    if (got.resourceField !== String(want.resourceId) || mismatch.length) {
      throw new Error(`gateway policy for ${resourceName} differs from fixtures.json context: ${mismatch.join(",")} resourceField ${got.resourceField}`);
    }
    return got;
  };
  /** The gateway issued `nonce` with this challenge (see the header: the RNG drew it). */
  const plantNonce = (challengeId, nonce) => {
    const stored = ctx.challenges.peek(challengeId);
    if (!stored || stored.state !== "issued") throw new Error("no fresh challenge to bind the fixture nonce to");
    stored.nonce = nonce;
  };
  const verify = (body) => gw.request(app).post("/api/zk/verify").set("content-type", "application/json").send(body);
  /**
   * Issue a challenge for `presentedTo` (default: the fixture's presented_to), bind the fixture's
   * nonce to it, and submit the committed proof. Resolves {res, body, challengeId}.
   */
  const present = async (name, { presentedTo, proof, publicSignals } = {}) => {
    const meta = idx.fixtures[name];
    const fx = h.fixture(meta.dir);
    const c = await challenge(presentedTo || meta.presented_to);
    plantNonce(c.challengeId, meta.nonce);
    const body = { challengeId: c.challengeId, proof: proof || fx.proof, publicSignals: publicSignals || fx.publicSignals };
    const res = await verify(body);
    return { res, body, challengeId: c.challengeId };
  };
  return { app, ctx, clock, registry, sink, idx, profile, challenge, plantNonce, verify, present, gw };
}

/** Stop the bn128 worker threads p3's snarkjs started (one curve per process). */
async function shutdown() {
  const c = globalThis.curve_bn128;
  if (c && typeof c.terminate === "function") await c.terminate();
  // ffjavascript rebuilds the curve on the next use when the global is empty (it is shared with
  // circuits/scripts/verify.js, which clears it the same way).
  delete globalThis.curve_bn128;
}

module.exports = { loadGateway, makeGateway, assertP3Setup, gatewayResource, shutdown, SETUP, OPERATOR_TOKEN };
