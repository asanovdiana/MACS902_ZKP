"use strict";
// Minimal gateway stand-in for client tests: issues challenges per the contract and accepts a
// proof only if it verifies and matches an issued, unused nonce. NOT the gateway (P3).
const http = require("http");
const crypto = require("crypto");
const path = require("path");
const zk = require("../../../circuits/lib");
const verifier = require("../../../circuits/scripts/verify.js");

const VKEY = path.resolve(__dirname, "..", "..", "..", "circuits", "setup", "integrated_access_v4.verification_key.json");

async function startChallengeStub({ now = 1794128400 } = {}) {
  const clock = { now };
  const issued = new Map(); // nonce -> resource
  const log = [];
  const vkey = verifier.loadVerificationKey(VKEY);
  const send = (res, s, o) => { res.writeHead(s, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
  const challenge = (resource) => {
    const p = zk.policies[resource];
    const nonce = BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString();
    issued.set(nonce, resource);
    return {
      nonce, resourceId: p.resourceId, epoch: Math.floor(clock.now / 600), now: clock.now,
      policy: { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice },
    };
  };
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      const url = new URL(req.url, "http://x");
      log.push({ method: req.method, path: url.pathname, body: raw });
      if (req.method === "GET" && url.pathname === "/challenge") {
        const r = url.searchParams.get("resource");
        if (!Object.prototype.hasOwnProperty.call(zk.policies, r)) return send(res, 400, { error: { code: "unknown_resource" } });
        return send(res, 200, challenge(r));
      }
      if (req.method === "POST" && url.pathname === "/access") {
        try {
          const b = JSON.parse(raw);
          const resource = issued.get(b.nonce);
          if (!resource || resource !== b.resource) return send(res, 403, { error: { code: "bad_nonce" } });
          if (b.publicSignals[9] !== b.nonce) return send(res, 403, { error: { code: "nonce_mismatch" } });
          if (!(await verifier.verify(vkey, b.publicSignals, b.proof))) return send(res, 403, { error: { code: "bad_proof" } });
          issued.delete(b.nonce);
          return send(res, 200, { admitted: true, resource });
        } catch (_) {
          return send(res, 400, { error: { code: "bad_request" } });
        }
      }
      return send(res, 404, { error: { code: "not_found" } });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${server.address().port}`, clock, log, challenge,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}

module.exports = { startChallengeStub };
