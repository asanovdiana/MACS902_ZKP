"use strict";
// Gateway challenge client (v4). The gateway (P3) is not built yet: this is written against the
// contract (access.public_signals v4, obligation 5; D-ruling: the challenge carries `now`) and the
// endpoint shapes below are ASSUMPTIONS to be confirmed by G1-S1-GATE:
//   GET  {gateway}/challenge?resource=<wiki|file_share|admin_panel>
//        -> 200 {nonce, resourceId, epoch, now, policy:{roleMask,deptMask,minClearance,requireDevice}}
//   POST {gateway}/access  {resource, nonce, proof, publicSignals}
//        -> 2xx admitted, 4xx {error:{code}}
// The client never invents `now`, `epoch` or `nonce`; it proves exactly what the gateway issued.
const zk = require("../../circuits/lib");
const { ClientError } = require("./errors");
const { requestJson, stripSlash } = require("./http");

const bad = (why) => new ClientError("INVALID_CHALLENGE", `invalid challenge: ${why}`);

/** Non-negative safe integer from a JSON number or a canonical decimal string. */
function int(name, v, max) {
  const n = typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) ? Number(v) : v;
  if (!Number.isSafeInteger(n) || n < 0 || (max !== undefined && n > max)) throw bad(`${name} out of range`);
  return n;
}

function parseChallenge(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) throw bad("not an object");
  const allowed = ["nonce", "resourceId", "epoch", "now", "policy"];
  for (const k of Object.keys(c)) if (!allowed.includes(k)) throw bad(`unexpected field ${JSON.stringify(k)}`);
  for (const k of allowed) if (c[k] === undefined) throw bad(`missing ${k}`);
  // nonce is 128 random bits: a JSON number would lose precision, so strings only.
  if (typeof c.nonce !== "string" || !zk.isCanonical(c.nonce)) throw bad("nonce must be a canonical decimal string");
  const resourceId = int("resourceId", c.resourceId, 3);
  if (resourceId < 1) throw bad("resourceId out of range");
  const now = int("now", c.now);
  const epoch = int("epoch", c.epoch);
  if (epoch !== Math.floor(now / 600)) throw bad("epoch is not floor(now / 600)");
  const p = c.policy;
  if (!p || typeof p !== "object" || Array.isArray(p)) throw bad("policy missing");
  const pk = ["roleMask", "deptMask", "minClearance", "requireDevice"];
  for (const k of Object.keys(p)) if (!pk.includes(k)) throw bad(`unexpected policy field ${JSON.stringify(k)}`);
  const policy = {
    roleMask: int("policy.roleMask", p.roleMask, 15),
    deptMask: int("policy.deptMask", p.deptMask, 15),
    minClearance: int("policy.minClearance", p.minClearance, 3),
    requireDevice: int("policy.requireDevice", p.requireDevice, 1),
  };
  return { nonce: c.nonce, resourceId, epoch, now, policy };
}

function checkResource(resource) {
  if (typeof resource !== "string" || !Object.prototype.hasOwnProperty.call(zk.policies, resource)) {
    throw new ClientError("INVALID_REQUEST", `resource must be one of ${Object.keys(zk.policies).join(", ")}`);
  }
}

async function fetchChallenge({ gatewayUrl, resource, fetch = globalThis.fetch, timeoutMs = 10000 }) {
  checkResource(resource);
  const { json } = await requestJson({
    fetch, method: "GET", url: `${stripSlash(gatewayUrl)}/challenge?resource=${resource}`, timeoutMs, who: "GATEWAY",
  });
  return parseChallenge(json);
}

/** Send the proof. Only the nonce, proof and public signals leave the client (floor 6). */
async function submitProof({ gatewayUrl, resource, nonce, proof, publicSignals, fetch = globalThis.fetch, timeoutMs = 20000 }) {
  checkResource(resource);
  const { json } = await requestJson({
    fetch, method: "POST", url: `${stripSlash(gatewayUrl)}/access`, body: { resource, nonce, proof, publicSignals }, timeoutMs, who: "GATEWAY",
  });
  return json;
}

module.exports = { parseChallenge, fetchChallenge, submitProof };
