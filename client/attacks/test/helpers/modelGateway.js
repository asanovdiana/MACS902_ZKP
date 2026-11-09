"use strict";
// Reference "model gateway" for the Attack Lab tests: a minimal in-test implementation of
// obligations 1-8 of access.public_signals v4 (docs/CONTRACTS.md) so the attack requests can be
// checked end to end. It is NOT the P3 gateway. The check order (cheap before expensive; a nonce
// is burned only on admission) is the proposal documented in client/attacks/README.md.
const http = require("http");
const crypto = require("crypto");
const zk = require("../../../../circuits/lib");
const verifier = require("../../../../circuits/scripts/verify.js");

const TTL = 120;
const RESOURCES = ["wiki", "file_share", "admin_panel"];
const rand128 = () => BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString();

class ModelGateway {
  /** @param {{vkey, pinned:{Ax,Ay}, clock:()=>number, root:()=>Promise<string>|string}} o */
  constructor({ vkey, pinned, clock, root }) {
    Object.assign(this, { vkey, pinned, clock, root });
    this.nonces = new Map(); // canonical nonce -> stored challenge
    this.nullifiers = new Set(); // `${nullifier}:${epoch}`
    this.log = []; // public values and decisions only (obligation 8)
  }

  challenge(resource) {
    const p = zk.policies[resource];
    if (!p) return { status: 404, body: { error: { code: "UNKNOWN_RESOURCE" } } };
    const now = this.clock();
    const policy = { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice };
    const c = { nonce: rand128(), resourceId: p.resourceId, epoch: Math.floor(now / 600), now, policy };
    this.nonces.set(c.nonce, { ...c, used: false });
    return { status: 200, body: c };
  }

  async access(body) {
    const deny = (status, code) => {
      this.log.push({ status, code });
      return { status, body: { error: { code } } };
    };
    if (!body || typeof body !== "object" || typeof body.resource !== "string" || typeof body.nonce !== "string" ||
        !body.proof || typeof body.proof !== "object" || !Array.isArray(body.publicSignals) ||
        Object.keys(body).sort().join() !== "nonce,proof,publicSignals,resource") return deny(400, "MALFORMED_REQUEST");
    if (body.publicSignals.length !== 12 || !body.publicSignals.every((s) => typeof s === "string" && zk.isCanonical(s))) return deny(400, "MALFORMED_REQUEST");
    if (!RESOURCES.includes(body.resource)) return deny(404, "UNKNOWN_RESOURCE");
    const s = zk.decodePublicSignals("v4", body.publicSignals);
    if (s.nonce !== body.nonce) return deny(400, "MALFORMED_REQUEST");
    // obligation 6: nonce issued, unused, unexpired
    const ch = this.nonces.get(s.nonce);
    if (!ch) return deny(403, "NONCE_UNKNOWN");
    if (ch.used) return deny(403, "NONCE_USED");
    if (this.clock() - ch.now > TTL) return deny(403, "NONCE_EXPIRED");
    // obligation 4: policy and resource of the service actually requested
    const p = zk.policies[body.resource];
    if (s.resourceId !== String(p.resourceId) || s.roleMask !== String(p.roleMask) || s.deptMask !== String(p.deptMask) ||
        s.minClearance !== String(p.minClearance) || s.requireDevice !== String(p.requireDevice)) return deny(403, "POLICY_MISMATCH");
    // obligation 5: now / epoch / resource equal the stored challenge
    if (s.now !== String(ch.now) || s.epoch !== String(ch.epoch) || s.resourceId !== String(ch.resourceId)) return deny(403, "CHALLENGE_MISMATCH");
    // obligation 2: pinned issuer key
    if (s.issuerAx !== this.pinned.Ax || s.issuerAy !== this.pinned.Ay) return deny(403, "ISSUER_NOT_PINNED");
    // obligation 3: current root (strict: read per request)
    if (s.root !== (await this.root())) return deny(403, "ROOT_NOT_CURRENT");
    // obligation 1: Groth16
    if (!(await verifier.verify(this.vkey, body.publicSignals, body.proof))) return deny(403, "PROOF_INVALID");
    // obligation 7: one (nullifier, epoch)
    const key = `${s.nullifier}:${s.epoch}`;
    if (this.nullifiers.has(key)) return deny(429, "RATE_LIMITED");
    this.nullifiers.add(key);
    ch.used = true;
    this.log.push({ status: 200, resourceId: s.resourceId, nullifier: s.nullifier, epoch: s.epoch });
    return { status: 200, body: { admitted: true } };
  }
}

/** Serve the model gateway on 127.0.0.1:0: GET /challenge?resource=, POST /access. */
async function serve(gw) {
  const server = http.createServer(async (req, res) => {
    const send = (r) => { res.writeHead(r.status, { "content-type": "application/json" }); res.end(JSON.stringify(r.body)); };
    const u = new URL(req.url, "http://x");
    if (req.method === "GET" && u.pathname === "/challenge") return send(gw.challenge(u.searchParams.get("resource")));
    if (req.method === "POST" && u.pathname === "/access") {
      let raw = "";
      for await (const c of req) raw += c;
      let body;
      try { body = JSON.parse(raw); } catch { return send({ status: 400, body: { error: { code: "MALFORMED_REQUEST" } } }); }
      return send(await gw.access(body));
    }
    return send({ status: 404, body: { error: { code: "not_found" } } });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)) };
}

module.exports = { ModelGateway, serve, TTL };
