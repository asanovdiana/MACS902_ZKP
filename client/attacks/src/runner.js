"use strict";
// Sending attack requests to a gateway and comparing actual with expected.
//
// Assumed gateway endpoints (client/README.md "Assumptions for the gateway", to confirm in P3):
//   GET  {gateway}/challenge?resource=<wiki|file_share|admin_panel> -> {nonce, resourceId, epoch, now, policy}
//   POST {gateway}/access {resource, nonce, proof, publicSignals}   -> 2xx admitted | 4xx {error:{code}}
const { buildAttack, ATTACK_IDS } = require("./attacks");

const strip = (u) => u.replace(/\/+$/, "");

/** send(request) -> {status, body}: POST the request's JSON body to `gatewayUrl` + request.path. */
function httpSender(gatewayUrl) {
  return async (req) => {
    const res = await fetch(strip(gatewayUrl) + req.path, {
      method: req.method, headers: { "content-type": "application/json" }, body: JSON.stringify(req.body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}

/** A challenge source for World.setChallengeSource that asks the gateway. */
function httpChallengeSource(gatewayUrl) {
  return async (resource) => {
    const res = await fetch(`${strip(gatewayUrl)}/challenge?resource=${encodeURIComponent(resource)}`);
    if (!res.ok) throw new Error(`gateway refused a challenge for ${resource} (status ${res.status})`);
    return res.json();
  };
}

/**
 * Send the request steps of a built attack and compare. `wait(seconds)` is called before a step
 * that carries `waitSeconds`; with `skipWaits` such steps are reported as skipped.
 * A step passes when the outcome (admit = 2xx) matches and, for a denial, the code matches
 * (`lenientCodes`: outcome only).
 */
async function runAttack(built, { send, wait, skipWaits = false, lenientCodes = false }) {
  const steps = [];
  for (const req of built.requests) {
    const step = { label: req.label, expect: req.expect };
    if (req.waitSeconds && skipWaits) {
      steps.push({ ...step, skipped: true, pass: true, actual: null });
      continue;
    }
    if (req.waitSeconds && wait) await wait(req.waitSeconds);
    try {
      const r = await send(req);
      const outcome = r.status >= 200 && r.status < 300 ? "admit" : "deny";
      const code = r.body && r.body.error && typeof r.body.error.code === "string" ? r.body.error.code : null;
      const pass = outcome === req.expect.outcome && (outcome === "admit" || lenientCodes || code === req.expect.code);
      steps.push({ ...step, actual: { status: r.status, outcome, code }, pass });
    } catch (e) {
      steps.push({ ...step, actual: { status: null, outcome: "error", code: null, error: String(e && e.message) }, pass: false });
    }
  }
  return { id: built.id, steps, pass: steps.every((s) => s.pass) };
}

module.exports = { httpSender, httpChallengeSource, runAttack, ATTACK_IDS, buildAttack };
