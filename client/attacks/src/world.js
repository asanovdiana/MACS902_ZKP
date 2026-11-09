"use strict";
// The Attack Lab "world": an issuer (in-process by default, or a running one by URL), fresh
// throw-away personas enrolled on it the way real employees are (issuer.api v2: the admin creates an
// enrolment with the persona's attributes, the persona redeems the one-time code with its
// commitment; the world plays both roles, the admin with ISSUER_ADMIN_TOKEN), a challenge source (the gateway's, or a local stand-in), and
// proving. Everything private (secrets, salts, signatures, Merkle paths, forger keys) lives in
// memory here and is never put into an attack result (floor 6); `secretsForTests()` exposes the
// values only so tests can scan outputs for them.
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");
const zk = require("../../../circuits/lib");
const verifier = require("../../../circuits/scripts/verify.js");

const SETUP = path.resolve(__dirname, "..", "..", "..", "circuits", "setup");
const WASM = path.join(SETUP, "integrated_access_v4.wasm");
const ZKEY = path.join(SETUP, "integrated_access_v4.zkey");
const VKEY = path.join(SETUP, "integrated_access_v4.verification_key.json");

const A = zk.ROLES, D = zk.DEPTS;
/** The three demo personas (docs/project-scope.md). Attributes are the user's own; they are local only. */
const PERSONAS = {
  alice: { role: A.engineer, dept: D.engineering, clearance: 2, deviceCompliant: 1, employeeActive: 1 },
  bob: { role: A.contractor, dept: D.operations, clearance: 1, deviceCompliant: 1, employeeActive: 1 },
  carol: { role: A.admin, dept: D.it, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
};
const YEAR = 365 * 86400;
const SHORT_TTL = 3; // seconds, for the expired-credential attack

const rnd31 = () => BigInt("0x" + crypto.randomBytes(31).toString("hex")).toString();
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));

class WorldError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/**
 * @param {{issuerUrl?: string, adminToken?: string, startNow?: number}} o  without issuerUrl an
 *   in-process issuer on temp directories (fresh key), a random admin token and a mutable clock is
 *   used. With issuerUrl, `adminToken` (the issuer's ISSUER_ADMIN_TOKEN) is required to enrol.
 */
async function createWorld({ issuerUrl, adminToken, startNow } = {}) {
  let call, closeIssuer, now, advance, tmp = null;
  if (issuerUrl) {
    const base = issuerUrl.replace(/\/+$/, "");
    call = async (method, url, body, auth) => {
      const headers = { "content-type": "application/json" };
      if (auth && adminToken) headers.authorization = `Bearer ${adminToken}`;
      const res = await fetch(base + url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: res.status, json: await res.json().catch(() => null) };
    };
    now = () => Math.floor(Date.now() / 1000);
    advance = sleep;
    closeIssuer = async () => {};
  } else {
    const { buildServer } = require("../../../issuer/src/server");
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "attack-lab-"));
    adminToken = crypto.randomBytes(24).toString("hex");
    const clock = { t: startNow || Math.floor(Date.now() / 1000) };
    const app = await buildServer({
      config: { profile: "v4", keyDir: path.join(tmp, "k"), dataDir: path.join(tmp, "d"), host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, logLevel: "silent", adminToken },
      clock: () => clock.t,
    });
    call = async (method, url, body, auth) => {
      const headers = { "content-type": "application/json" };
      if (auth) headers.authorization = `Bearer ${adminToken}`;
      const res = await app.inject({ method, url, headers, payload: body === undefined ? undefined : JSON.stringify(body) });
      return { status: res.statusCode, json: res.body ? JSON.parse(res.body) : null };
    };
    now = () => clock.t;
    advance = async (s) => { clock.t += s; };
    closeIssuer = async () => { await app.close(); };
  }

  const info = await call("GET", "/issuer");
  if (info.status !== 200 || info.json.profile !== "v4") throw new WorldError("ISSUER_UNAVAILABLE", "the issuer is not serving profile v4");
  const pinned = { Ax: info.json.issuer.Ax, Ay: info.json.issuer.Ay };

  const personas = [];
  const codes = [];
  let seq = 0;
  const paths = [];
  const forgerKeys = [];
  let challengeSource = async (resource) => {
    // local stand-in when no gateway is attached: shape of the gateway's challenge, never sent anywhere
    const p = zk.policies[resource];
    const t = now();
    return {
      nonce: BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString(), resourceId: p.resourceId, epoch: zk.epochOf(t), now: t,
      policy: { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice },
    };
  };

  const world = {
    pinned,
    now: () => now(),
    advance: (s) => advance(s),
    setChallengeSource(fn) { challengeSource = fn; },
    challenge: async (resource) => {
      const c = await challengeSource(resource);
      return { nonce: String(c.nonce), resourceId: Number(c.resourceId), epoch: Number(c.epoch), now: Number(c.now), policy: c.policy };
    },

    async root() {
      const r = await call("GET", "/root");
      return r.json.root;
    },

    /** Enrol a fresh credential (new secret and salt) for a demo persona; the issuer sees only the commitment. */
    async enrol(name, { attributes, ttl = YEAR } = {}) {
      const base = attributes || PERSONAS[name];
      if (!base) throw new WorldError("UNKNOWN_PERSONA", "unknown persona");
      const credentialSecret = rnd31(), credentialSalt = rnd31();
      const commitment = await zk.commitment(credentialSecret, credentialSalt);
      const attrs = { ...base, expiry: now() + ttl };
      // admin side: one enrolment per throw-away employee (a fresh id each time: one live credential per employee)
      const employeeId = `attack-${name}-${crypto.randomBytes(4).toString("hex")}-${++seq}`;
      const enrolment = await call("POST", "/admin/enrolments", { employeeId, attributes: attrs }, true);
      if (enrolment.status !== 201) throw new WorldError("ENROL_FAILED", `issuer refused the enrolment (${enrolment.json && enrolment.json.error && enrolment.json.error.code})`);
      codes.push(enrolment.json.code);
      // user side: only the commitment and the one-time code leave the wallet
      const res = await call("POST", "/credentials", { commitment, enrolmentCode: enrolment.json.code });
      if (res.status !== 201) throw new WorldError("ENROL_FAILED", `issuer refused the credential (${res.json && res.json.error && res.json.error.code})`);
      const c = res.json.credential;
      const p = { name, credentialSecret, credentialSalt, commitment, attributes: attrs, signature: c.signature, issuer: c.issuer, leafIndex: c.leafIndex, code: enrolment.json.code };
      personas.push(p);
      return p;
    },

    /**
     * The SR-03 attack, kept as a world primitive: a user who reaches the issuer tries to choose
     * their own attributes (and, with `code`, to combine them with an enrolment). Returns
     * {status, code}; the issuer must answer 400 attributes_not_accepted / 403 invalid_enrolment_code.
     */
    async selfEnrol(attributes, code) {
      const commitment = await zk.commitment(rnd31(), rnd31());
      const body = code === undefined ? { commitment, attributes } : { commitment, enrolmentCode: code, attributes };
      const r = await call("POST", "/credentials", body);
      return { status: r.status, code: r.json && r.json.error ? r.json.error.code : null };
    },

    /** Re-enrol a persona's replacement WITHOUT a new admin enrolment: reuse its (spent) code. */
    async reuseCode(persona, commitment) {
      const r = await call("POST", "/credentials", { commitment, enrolmentCode: persona.code });
      return { status: r.status, code: r.json && r.json.error ? r.json.error.code : null };
    },

    /** GET /path/:leafIndex -> {status, body}. */
    async path(persona) {
      const r = await call("GET", `/path/${persona.leafIndex}`);
      if (r.status === 200) paths.push(r.json);
      return { status: r.status, body: r.json };
    },

    /** Revoke through the issuer (admin route). Returns the new root. */
    async revoke(persona) {
      const r = await call("POST", `/credentials/${persona.leafIndex}/revoke`, undefined, true);
      if (r.status !== 200) throw new WorldError("REVOKE_FAILED", `issuer refused the revocation (${r.json && r.json.error && r.json.error.code})`);
      return r.json.root;
    },

    /**
     * Circuit input for `persona` -> `resource` (circuits/lib buildInputV4: the client's path).
     * Overrides: challenge, policy, issuer, signature, attributes, precheck.
     */
    async input(persona, resource, o = {}) {
      const challenge = o.challenge || (await world.challenge(resource));
      const mp = o.merkleProof || (await (async () => {
        const r = await world.path(persona);
        if (r.status !== 200) throw new WorldError("NO_PATH", `the registry has no path for this credential (status ${r.status})`);
        return r.body;
      })());
      const args = {
        credentialSecret: persona.credentialSecret, credentialSalt: persona.credentialSalt, commitment: persona.commitment,
        attributes: o.attributes || persona.attributes, signature: o.signature || persona.signature, issuer: o.issuer || persona.issuer,
        merkleProof: mp, policy: o.policy || resource,
        challenge: { nonce: challenge.nonce, resourceId: challenge.resourceId, epoch: challenge.epoch, now: challenge.now },
      };
      return zk.buildInputV4(args, { precheck: o.precheck !== false });
    },

    /** A verified Groth16 proof: {proof, publicSignals} (verified with circuits/scripts/verify.js). */
    async prove(input) {
      const res = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
      const vkey = verifier.loadVerificationKey(VKEY);
      if (!(await verifier.verify(vkey, res.publicSignals, res.proof))) throw new WorldError("PROOF_INVALID", "a freshly generated proof failed local verification");
      return { proof: res.proof, publicSignals: res.publicSignals };
    },

    /**
     * Assert that the circuit refuses `input` at witness generation. Resolves true when it does;
     * throws when a proof is produced (a floor violation) or when failure is not a circuit assertion.
     */
    async witnessRefuses(input) {
      let res;
      try {
        res = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
      } catch (e) {
        if (/Assert Failed/.test(String(e && e.message))) return true;
        throw new WorldError("PROVER_ERROR", "the prover failed for a reason other than a circuit assertion");
      }
      throw new WorldError("FLOOR_VIOLATION", `a proof was produced for an input the circuit must refuse (${res.publicSignals.length} signals)`);
    },

    /** A self-signed credential: a random forger key signs the persona's attrHash. */
    async forge(persona) {
      const prv = crypto.randomBytes(32);
      forgerKeys.push(prv.toString("hex"));
      const issuer = await zk.publicKey(prv);
      const M = await zk.profiles.v4.message({ commitment: persona.commitment, attributes: persona.attributes });
      return { issuer, signature: await zk.sign(prv, M) };
    },

    SHORT_TTL,

    /** Every private value created in this world (tests scan outputs for them; never print). */
    secretsForTests() {
      const out = [];
      for (const p of personas) out.push(p.credentialSecret, p.credentialSalt, p.commitment, p.signature.S, p.signature.R8x, p.signature.R8y);
      for (const k of forgerKeys) out.push(k, BigInt("0x" + k).toString());
      out.push(...codes);
      if (adminToken) out.push(adminToken);
      for (const pa of paths) for (const s of pa.pathElements) if (s !== "0") out.push(String(s));
      return [...new Set(out.map(String))].filter((s) => s.length >= 20);
    },

    async close() {
      await closeIssuer();
      if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
    },
  };
  return world;
}

module.exports = { createWorld, WorldError, PERSONAS };
