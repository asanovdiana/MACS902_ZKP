"use strict";
// issuer.api v1 over Fastify (ADR 0003). One profile per process. Structured JSON logs carry
// route, method, status, leafIndex, latency and error code only: never a commitment, attribute,
// signature, request body or key material (contract logging rule, floors 6, 7, 9).
const crypto = require("crypto");
const Fastify = require("fastify");
const { LogController } = require("fastify");
const { loadOrCreateKey } = require("./keys");
const { createSigner, validateCommitment, validateAttributes } = require("./signer");
const { createRegistry } = require("./registry");
const { createStore } = require("./store");
const { createEnrolments } = require("./enrolments");
const { ApiError, err } = require("./errors");

const EVENT_BUFFER = 256; // root-changed events kept for Last-Event-ID replay
const LEAVES_DEFAULT_LIMIT = 1000;
const LEAVES_MAX_LIMIT = 5000;
const INDEX = /^(0|[1-9][0-9]*)$/;
const FORBIDDEN_KEYS = new Set(["credentialsecret", "credentialsalt", "secret", "salt"]);

/** True if any key at any depth names a secret or salt (case/underscore/hyphen-insensitive). */
function hasForbiddenKey(v) {
  if (v === null || typeof v !== "object") return false;
  if (Array.isArray(v)) return v.some(hasForbiddenKey);
  for (const k of Object.keys(v)) {
    if (FORBIDDEN_KEYS.has(k.toLowerCase().replace(/[_-]/g, ""))) return true;
    if (hasForbiddenKey(v[k])) return true;
  }
  return false;
}

function parseIndex(s, code) {
  if (typeof s !== "string" || !INDEX.test(s) || !Number.isSafeInteger(Number(s))) throw err(400, code, "invalid integer");
  return Number(s);
}

const sha256 = (s) => crypto.createHash("sha256").update(s).digest();

/** True iff `header` is exactly "Bearer <token>" (constant-time compare of digests). */
function bearerMatches(header, token) {
  if (typeof header !== "string") return false;
  const m = /^Bearer (.+)$/.exec(header);
  return m !== null && crypto.timingSafeEqual(sha256(m[1]), sha256(token));
}

function createMetrics() {
  return { issued: 0, revoked: 0, enrolmentsCreated: 0, enrolmentsRedeemed: 0, rootChanges: 0, sseClients: 0, sseEvents: 0, errors: {}, requests: {} };
}

/**
 * buildServer({config, clock, logStream}) -> Fastify instance (not listening) with
 * .registry, .signer, .metrics. `clock()` returns unix seconds (injectable for tests).
 */
async function buildServer({ config, clock = () => Math.floor(Date.now() / 1000), logStream }) {
  const metrics = createMetrics();
  // SR-04: fail closed. Without a token the revoke and admin routes would be open and nobody could
  // create an enrolment; only an explicit development switch allows that. Checked before any key
  // material is created.
  const adminToken = typeof config.adminToken === "string" && config.adminToken !== "" ? config.adminToken : null;
  if (adminToken === null && config.insecureDev !== true) {
    throw new Error("ISSUER_ADMIN_TOKEN is required; set ISSUER_INSECURE_DEV=1 only for local development");
  }
  const prv = loadOrCreateKey(config.keyDir);
  const signer = await createSigner({ profile: config.profile, prv });
  // ---- admin events (issuer.admin v1): in-memory ring buffer + live subscribers -----------------
  const heartbeatMs = config.sseHeartbeatMs || 15000;
  const events = []; // {seq, data}
  let seq = 0;
  const clients = new Set(); // raw ServerResponse
  const frame = (res, text) => {
    res.write(text);
    metrics.sseEvents += 1;
  };
  const eventFrame = (e) => `id: ${e.seq}\nevent: root-changed\ndata: ${JSON.stringify(e)}\n\n`;
  function publish(info, kind) {
    seq += 1;
    const e = { seq, root: info.root, prevRoot: info.prevRoot, kind, leafIndex: info.leafIndex, at: info.at };
    events.push(e);
    if (events.length > EVENT_BUFFER) events.shift();
    for (const res of clients) frame(res, eventFrame(e));
  }

  const registry = await createRegistry({
    profile: config.profile,
    store: createStore(config.dataDir),
    clock,
    historyRetentionSeconds: config.historyRetentionSeconds,
    onChange: (kind, info) => {
      metrics.rootChanges += 1;
      if (kind === "insert") metrics.issued += 1;
      else metrics.revoked += 1;
      publish(info, kind);
    },
  });

  const enrolments = createEnrolments({ dir: config.dataDir, clock, defaultTtlSeconds: config.enrolmentTtlSeconds || 3600 });

  const app = Fastify({
    logController: new LogController({ disableRequestLogging: true }),
    logger: { level: config.logLevel || "info", stream: logStream || process.stdout },
  });

  // JSON parser: empty body -> undefined (revoke has none); a non-object is rejected per route.
  app.addContentTypeParser("application/json", { parseAs: "string" }, (req, body, done) => {
    if (body === "") return done(null, undefined);
    try {
      done(null, JSON.parse(body));
    } catch (_) {
      done(err(400, "invalid_json", "body is not valid JSON"));
    }
  });

  const countError = (code) => {
    metrics.errors[code] = (metrics.errors[code] || 0) + 1;
  };

  app.setErrorHandler((e, req, reply) => {
    let status, code, message;
    if (e instanceof ApiError) {
      ({ status, code, message } = e);
    } else if (e && typeof e.statusCode === "number" && e.statusCode >= 400 && e.statusCode < 500) {
      status = 400; // Fastify body/media-type problems
      code = "invalid_json";
      message = "body is not valid JSON";
    } else {
      status = 500;
      code = "internal";
      message = "internal error";
    }
    req.errorCode = code;
    countError(code);
    reply.code(status).send({ error: { code, message } });
  });

  app.setNotFoundHandler((req, reply) => {
    req.errorCode = "not_found";
    countError("not_found");
    reply.code(404).send({ error: { code: "not_found", message: "no such route" } });
  });

  app.addHook("onRequest", async (req) => {
    req.startedAt = process.hrtime.bigint();
  });

  app.addHook("onResponse", async (req, reply) => {
    const latencyMs = Number(process.hrtime.bigint() - req.startedAt) / 1e6;
    const route = req.routeOptions.url || "unmatched";
    const key = `${req.method} ${route}`;
    const m = (metrics.requests[key] ||= { count: 0, latencyMsSum: 0, latencyMsMax: 0 });
    m.count += 1;
    m.latencyMsSum += latencyMs;
    m.latencyMsMax = Math.max(m.latencyMsMax, latencyMs);
    const fields = { route, method: req.method, status: reply.statusCode, latencyMs: Math.round(latencyMs * 1000) / 1000 };
    const li = req.params && req.params.leafIndex;
    if (typeof li === "string" && INDEX.test(li) && Number.isSafeInteger(Number(li))) fields.leafIndex = Number(li);
    if (req.errorCode) fields.code = req.errorCode;
    req.log.info(fields, "request");
  });

  // ---- routes --------------------------------------------------------------------------------
  app.get("/issuer", async () => ({ profile: registry.profile, depth: registry.depth, issuer: { Ax: signer.publicKey.Ax, Ay: signer.publicKey.Ay } }));

  let chain = Promise.resolve(); // serialises issue (async signing) so indices follow insert order
  const exclusive = (fn) => {
    const run = chain.then(fn);
    chain = run.catch(() => {});
    return run;
  };

  // issuer.api v2: the user supplies a commitment and the admin-issued one-time code; the issuer
  // signs the attributes the ADMIN assigned. The legacy open form {commitment, attributes} survives
  // only for the v3 baseline under ISSUER_INSECURE_DEV=1.
  const legacyOpen = config.insecureDev === true && registry.profile === "v3";

  app.post("/credentials", async (req, reply) => {
    const body = req.body;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw err(400, "invalid_json", "body must be a JSON object");
    if (hasForbiddenKey(body)) throw err(400, "forbidden_field", "the request carries a secret or salt field");
    const commitment = validateCommitment(body.commitment);
    const legacy = legacyOpen && body.enrolmentCode === undefined && Object.prototype.hasOwnProperty.call(body, "attributes");
    if (!legacy && Object.prototype.hasOwnProperty.call(body, "attributes")) {
      throw err(400, "attributes_not_accepted", "attributes are assigned by the admin enrolment, not by the client");
    }
    if (Object.keys(body).some((k) => k !== "commitment" && k !== "enrolmentCode" && !(legacy && k === "attributes"))) {
      throw err(400, "invalid_request", "unknown request field");
    }
    if (legacy) validateAttributes(registry.profile, body.attributes, clock());
    const credential = await exclusive(async () => {
      const rec = legacy ? null : enrolments.lookup(body.enrolmentCode);
      registry.assertCanInsert(commitment);
      const now = clock();
      const attributes = legacy ? body.attributes : rec.attributes;
      if (!legacy && typeof attributes.expiry === "number" && attributes.expiry <= now) {
        throw err(410, "enrolment_expired", "the credential expiry assigned by the admin has passed");
      }
      const issued = await signer.issue(commitment, attributes, now);
      const leafIndex = registry.size();
      const prev = rec ? enrolments.markRedeemed(rec, leafIndex) : null; // consume before the leaf exists: fail safe
      try {
        registry.insert({ commitment, leaf: issued.leaf });
      } catch (e) {
        if (rec) enrolments.revertRedeemed(rec, prev);
        throw e;
      }
      if (rec) metrics.enrolmentsRedeemed += 1;
      return {
        profile: registry.profile,
        attributes: issued.attributes,
        signature: issued.signature,
        issuer: { Ax: signer.publicKey.Ax, Ay: signer.publicKey.Ay },
        leafIndex,
      };
    });
    reply.code(201);
    return { credential };
  });

  const adminAuth = async (req, reply) => {
    if (adminToken === null || bearerMatches(req.headers.authorization, adminToken)) return;
    reply.header("www-authenticate", "Bearer");
    throw err(401, "unauthorized", "missing or invalid admin token");
  };

  app.post("/credentials/:leafIndex/revoke", { preHandler: adminAuth }, async (req) => {
    const i = parseIndex(req.params.leafIndex, "invalid_leaf_index");
    return { root: registry.revoke(i) };
  });

  app.get("/root", async () => ({ root: registry.root(), updatedAt: registry.updatedAt(), profile: registry.profile, depth: registry.depth }));

  app.get("/root/history", async (req) => {
    const s = req.query.since;
    const since = s === undefined ? 0 : parseIndex(s, "invalid_since");
    return { now: clock(), current: registry.root(), roots: registry.history(since) };
  });

  app.get("/path/:leafIndex", async (req) => registry.path(parseIndex(req.params.leafIndex, "invalid_leaf_index")));

  // ---- issuer.admin v1 -------------------------------------------------------------------------
  const queryInt = (v, dflt, min, max) => {
    if (v === undefined) return dflt;
    if (typeof v !== "string" || !INDEX.test(v) || Number(v) < min || Number(v) > max) throw err(400, "invalid_query", "invalid query parameter");
    return Number(v);
  };

  app.get("/admin/leaves", { preHandler: adminAuth }, async (req) => {
    const from = queryInt(req.query.from, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = queryInt(req.query.limit, LEAVES_DEFAULT_LIMIT, 1, LEAVES_MAX_LIMIT);
    return { profile: registry.profile, depth: registry.depth, total: registry.size(), from, leaves: registry.adminLeaves(from, limit) };
  });

  // issuer.admin v1.1. employeeId and the pending attributes stay in this process and its state
  // file; no response here, and no log line, carries a code, attribute or commitment.
  app.post("/admin/enrolments", { preHandler: adminAuth }, async (req, reply) => {
    const body = req.body;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw err(400, "invalid_json", "body must be a JSON object");
    if (Object.keys(body).some((k) => k !== "employeeId" && k !== "attributes" && k !== "ttlSeconds")) throw err(400, "invalid_request", "unknown request field");
    const employeeId = enrolments.validateEmployeeId(body.employeeId);
    const ttlSeconds = enrolments.validateTtl(body.ttlSeconds);
    const attributes = validateAttributes(registry.profile, body.attributes, clock());
    const e = enrolments.create({ employeeId, attributes, ttlSeconds, isLive: (i) => registry.leafStatus(i) === "issued" });
    metrics.enrolmentsCreated += 1;
    reply.code(201);
    return { enrolmentId: e.id, code: e.code, expiresAt: e.expiresAt };
  });

  app.get("/admin/enrolments", { preHandler: adminAuth }, async (req) => {
    const from = queryInt(req.query.from, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = queryInt(req.query.limit, LEAVES_DEFAULT_LIMIT, 1, LEAVES_MAX_LIMIT);
    return { total: enrolments.total(), from, enrolments: enrolments.list(from, limit) };
  });

  app.delete("/admin/enrolments/:enrolmentId", { preHandler: adminAuth }, async (req) => enrolments.cancel(req.params.enrolmentId));

  app.get("/admin/tree", { preHandler: adminAuth }, async () => registry.adminTree());

  app.get("/admin/events", { preHandler: adminAuth }, (req, reply) => {
    const res = reply.raw;
    reply.hijack();
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive", "x-accel-buffering": "no" });
    frame(res, `event: hello\ndata: ${JSON.stringify({ profile: registry.profile, root: registry.root(), seq })}\n\n`);
    const last = req.headers["last-event-id"];
    if (typeof last === "string" && INDEX.test(last) && Number(last) < seq && events.length > 0 && Number(last) >= events[0].seq - 1) {
      for (const e of events) if (e.seq > Number(last)) frame(res, eventFrame(e));
    }
    clients.add(res);
    metrics.sseClients = clients.size;
    req.log.info({ route: "/admin/events", sseClients: clients.size }, "sse connected");
    const beat = setInterval(() => frame(res, ": hb\n\n"), heartbeatMs);
    res.on("close", () => {
      clearInterval(beat);
      clients.delete(res);
      metrics.sseClients = clients.size;
      req.log.info({ route: "/admin/events", sseClients: clients.size }, "sse disconnected");
    });
  });

  // issuer.api v1.1 addition: counters and latency.
  app.get("/metrics", async () => ({
    profile: registry.profile,
    leaves: registry.size(),
    issued: metrics.issued,
    revoked: metrics.revoked,
    enrolmentsCreated: metrics.enrolmentsCreated,
    enrolmentsRedeemed: metrics.enrolmentsRedeemed,
    enrolmentsPending: enrolments.pending(),
    rootChanges: metrics.rootChanges,
    sseClients: metrics.sseClients,
    sseEvents: metrics.sseEvents,
    errors: metrics.errors,
    requests: metrics.requests,
  }));

  app.addHook("preClose", async () => {
    for (const res of clients) res.destroy();
  });

  if (adminToken === null) {
    app.log.warn("INSECURE: ISSUER_INSECURE_DEV=1 and no ISSUER_ADMIN_TOKEN; the admin and revoke routes are open. Local development only.");
  }
  app.decorate("registry", registry);
  app.decorate("signer", signer);
  app.decorate("metrics", metrics);
  await app.ready();
  return app;
}

module.exports = { buildServer, hasForbiddenKey };
