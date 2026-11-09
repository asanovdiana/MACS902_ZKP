"use strict";
// Configuration from the environment. The key directory is configuration, not a hard-coded path,
// so tests (and deployments) point it elsewhere: ISSUER_KEY_DIR (default issuer/keys).
const path = require("path");

const ROOT = path.resolve(__dirname, "..");

/**
 * loadConfig(env, overrides) -> {profile, keyDir, dataDir, host, port, stalenessSeconds,
 * historyRetentionSeconds, logLevel}
 *
 * ISSUER_PROFILE      v3 | v4                       (default v3)
 * ISSUER_KEY_DIR      directory of the private key  (default <issuer>/keys, gitignored, 0700)
 * ISSUER_DATA_DIR     registry state directory      (default <issuer>/data, gitignored)
 * ISSUER_HOST / ISSUER_PORT                         (default 127.0.0.1 / 8100)
 * ISSUER_ADMIN_TOKEN bearer token for /admin/* and revoke (never logged). Required: the issuer
 *                     refuses to start without it unless ISSUER_INSECURE_DEV=1 (SR-04).
 * ISSUER_INSECURE_DEV 1 = local development only: no token needed (admin surface open), v3 may use
 *                     the legacy open enrolment. Logs a warning at start. Any other value: off.
 * ISSUER_ENROLMENT_TTL_SECONDS default lifetime of an enrolment code, 60..604800 (default 3600)
 * ISSUER_SSE_HEARTBEAT_SECONDS                      (default 15)
 * ISSUER_LOG_LEVEL    pino level                    (default info)
 */
function loadConfig(env = process.env, overrides = {}) {
  const profile = env.ISSUER_PROFILE || "v3";
  if (profile !== "v3" && profile !== "v4") throw new Error("ISSUER_PROFILE must be v3 or v4");
  const portRaw = env.ISSUER_PORT === undefined ? "8100" : env.ISSUER_PORT;
  if (!/^[0-9]{1,5}$/.test(portRaw) || Number(portRaw) > 65535) throw new Error("ISSUER_PORT must be 0..65535");
  const ttlRaw = env.ISSUER_ENROLMENT_TTL_SECONDS === undefined ? "3600" : env.ISSUER_ENROLMENT_TTL_SECONDS;
  if (!/^[0-9]{1,7}$/.test(ttlRaw) || Number(ttlRaw) < 60 || Number(ttlRaw) > 604800) throw new Error("ISSUER_ENROLMENT_TTL_SECONDS must be 60..604800");
  return {
    profile,
    keyDir: path.resolve(env.ISSUER_KEY_DIR || path.join(ROOT, "keys")),
    dataDir: path.resolve(env.ISSUER_DATA_DIR || path.join(ROOT, "data")),
    host: env.ISSUER_HOST || "127.0.0.1",
    port: Number(portRaw),
    stalenessSeconds: 30, // issuer.api v1 staleness window
    historyRetentionSeconds: 900, // contract: retained >= 10 minutes
    adminToken: env.ISSUER_ADMIN_TOKEN || null,
    insecureDev: env.ISSUER_INSECURE_DEV === "1",
    enrolmentTtlSeconds: Number(ttlRaw),
    sseHeartbeatMs: Number(env.ISSUER_SSE_HEARTBEAT_SECONDS || 15) * 1000,
    logLevel: env.ISSUER_LOG_LEVEL || "info",
    ...overrides,
  };
}

module.exports = { loadConfig };
