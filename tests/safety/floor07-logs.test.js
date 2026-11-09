"use strict";
// Floor 7: the gateway log and gateway state hold no username, email, role, department or
// clearance.
//
// The gateway is P3 and not in this repository (todo below). Applied here to the P2 services by
// extension: the issuer's structured log, metrics, admin listing and SSE events carry no
// attribute, commitment, leaf hash, signature, secret or admin token; client errors carry no
// secret. (The issuer legitimately knows the attributes at enrolment; it must not log them.)
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const h = require("./helpers");

const { zk } = h;
const client = require(h.r("client", "src"));

const T0 = 1_800_000_000;
const TOKEN = "safety-admin-token-5c1e0f";
const PERSONAS = {
  alice: { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 },
  carol: { role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: 4070908801 },
};

let iss, issuer, wallet, adminBodies = [];
const auth = { authorization: `Bearer ${TOKEN}` };
// issuer.api v2: the admin names the employee; an email-shaped id is the worst case for floor 7
const EMPLOYEE = { alice: "alice.smith@corp.example", carol: "carol.jones@corp.example" };
const codes = []; // every enrolment code handed out in this session

before(async () => {
  iss = await h.makeIssuer({ t0: T0, overrides: { adminToken: TOKEN, logLevel: "trace" } });
  issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });
  wallet = new client.Wallet({ home: h.tmpDir("wallet") });
  for (const [name, attributes] of Object.entries(PERSONAS)) {
    await wallet.keygen({ name, profile: "v4", issuerUrl: "http://issuer.test" });
    const { enrolment } = await h.enrolViaAdmin({ iss, wallet, name, issuer, attributes, employeeId: EMPLOYEE[name] });
    codes.push(enrolment.code);
    await client.prepareV4({ credential: wallet.load(name), issuer, challenge: h.challengeFor("wiki", "5", T0) });
  }
  const inj = (o) => iss.app.inject(o);
  // a busy session: reads, admin reads, revoke, every error path
  for (const url of ["/root", "/root/history?since=0", "/issuer", "/metrics", "/path/0", "/path/99", "/nope"]) await inj({ method: "GET", url });
  for (const url of ["/admin/leaves", "/admin/tree"]) adminBodies.push((await inj({ method: "GET", url, headers: auth })).body);
  await inj({ method: "GET", url: "/admin/leaves", headers: { authorization: "Bearer wrong" } });
  iss.clock.advance(3);
  await inj({ method: "POST", url: "/credentials/1/revoke", headers: auth });
  await inj({ method: "POST", url: "/credentials/1/revoke", headers: auth });
  const c = wallet.load("alice");
  const post = (payload) => inj({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload });
  await post(JSON.stringify({ commitment: c.commitment, attributes: { ...c.attributes } })); // v1 shape: attributes_not_accepted
  await post(JSON.stringify({ commitment: c.commitment, attributes: { ...c.attributes, clearance: 9 } }));
  await post(JSON.stringify({ commitment: c.commitment, attributes: c.attributes, credentialSecret: c.secrets.credentialSecret }));
  await post("{not json");
  // issuer.api v2 / admin v1.1 paths, success and every refusal
  await post(JSON.stringify({ commitment: c.commitment, enrolmentCode: codes[0] })); // enrolment_used
  await post(JSON.stringify({ commitment: c.commitment })); // invalid_enrolment_code
  const enrol = async (employeeId, attributes, headers = auth) => {
    const res = await inj({ method: "POST", url: "/admin/enrolments", headers: { "content-type": "application/json", ...headers }, payload: JSON.stringify({ employeeId, attributes: h.encodeAttrs(attributes) }) });
    if (res.statusCode === 201) codes.push(JSON.parse(res.body).code);
    return res;
  };
  await enrol(EMPLOYEE.alice, PERSONAS.alice); // employee_has_credential
  await enrol(EMPLOYEE.carol.toUpperCase(), PERSONAS.carol); // carol is revoked (leaf 1): allowed, pending
  await enrol(EMPLOYEE.carol, PERSONAS.carol); // enrolment_pending
  await enrol("dave@corp.example", { ...PERSONAS.alice, clearance: 9 }); // invalid_attributes
  await enrol("erin@corp.example", PERSONAS.alice, { authorization: "Bearer wrong" }); // 401
  const pending = JSON.parse((await inj({ method: "GET", url: "/admin/enrolments", headers: auth })).body).enrolments.find((x) => x.status === "pending");
  await inj({ method: "DELETE", url: `/admin/enrolments/${pending.enrolmentId}`, headers: auth });
  await inj({ method: "DELETE", url: `/admin/enrolments/${pending.enrolmentId}`, headers: auth }); // enrolment_not_pending
  adminBodies.push((await inj({ method: "GET", url: "/metrics" })).body);
});
after(async () => {
  await iss.app.close();
  await client.shutdown();
});

async function sensitiveValues() {
  // issuer.api v2 (G1-S1-SAFETY-021): the employee ids (username/email) and enrolment codes are
  // identity and credentials the issuer now holds; they join the list.
  const ids = [...Object.values(EMPLOYEE), EMPLOYEE.carol.toUpperCase(), "dave@corp.example", "erin@corp.example", "alice.smith", "corp.example"];
  const out = [TOKEN, ...ids, ...codes];
  for (const name of Object.keys(PERSONAS)) {
    const c = wallet.load(name);
    out.push(c.secrets.credentialSecret, c.secrets.credentialSalt, c.commitment, c.signature.R8x, c.signature.R8y, c.signature.S);
    out.push(await zk.attrHash(c.attributes, c.commitment));
  }
  return out;
}

describe("floor 7: logs and state hold no identity attributes", () => {
  test("F7.01 issuer log: no secret, salt, commitment, attrHash/leaf, signature or admin token", async () => {
    const log = iss.sink.text();
    assert.ok(iss.sink.lines.length >= 15, `expected a busy log, got ${iss.sink.lines.length} lines`);
    for (const v of await sensitiveValues()) assert.ok(!log.includes(v), `issuer log contains a sensitive value (${v.slice(0, 6)}...)`);
  });

  test("F7.02 issuer log lines carry only the documented fields (no attribute keys, no bodies, no headers)", () => {
    const allowed = new Set(["level", "time", "pid", "hostname", "reqId", "msg", "route", "method", "status", "latencyMs", "leafIndex", "code", "sseClients", "address", "profile"]);
    for (const line of iss.sink.lines) {
      const o = JSON.parse(line);
      for (const k of Object.keys(o)) assert.ok(allowed.has(k), `log field "${k}" is not on the allow-list: ${line.slice(0, 160)}`);
      for (const k of ["role", "dept", "clearance", "attributes", "body", "headers", "authorization", "commitment", "email", "username"]) {
        assert.ok(!line.includes(`"${k}"`), `log line has "${k}"`);
      }
    }
  });

  test("F7.03 admin listing, tree and metrics responses carry no attribute, commitment or signature", async () => {
    const text = adminBodies.join("\n");
    const leaves = JSON.parse(adminBodies[0]).leaves;
    for (const l of leaves) assert.deepEqual(Object.keys(l).sort(), ["issuedAt", "leaf", "leafIndex", "revokedAt", "status"]);
    for (const k of ["role", "dept", "clearance", "attributes", "commitment", "signature", "secret", "salt"]) {
      assert.ok(!text.includes(`"${k}"`), `admin/metrics output has "${k}"`);
    }
    const sens = await sensitiveValues();
    const commitments = Object.keys(PERSONAS).map((n) => wallet.load(n).commitment);
    for (const v of sens.filter((x) => commitments.includes(x) || x === TOKEN)) assert.ok(!text.includes(v));
    // issuer.api v2: no employee id (username/email) and no enrolment code in these outputs either
    const nonLeaf = sens.filter((x) => !/^\d+$/.test(x));
    for (const v of nonLeaf) assert.ok(!text.includes(v), `admin/metrics output contains ${v.slice(0, 8)}...`);
  });

  test("F7.04 client errors and messages do not echo secrets or issuer free text", async () => {
    const c = wallet.load("alice");
    const stub = async () => ({ status: 400, text: async () => JSON.stringify({ error: { code: "x\"<script>", message: c.secrets.credentialSecret } }) });
    const ic = new client.IssuerClient({ baseUrl: "http://x.test", fetch: stub });
    await assert.rejects(ic.getRoot(), (e) => {
      assert.ok(!e.message.includes(c.secrets.credentialSecret));
      assert.ok(!e.message.includes("<script>"));
      return true;
    });
    // a lib refusal on a bad secret names a code, not the value
    await assert.rejects(zk.buildInputV4({
      credentialSecret: c.secrets.credentialSecret + "0", credentialSalt: c.secrets.credentialSalt, commitment: c.commitment,
      attributes: c.attributes, signature: c.signature, issuer: c.issuer, merkleProof: { root: "1", pathElements: Array(16).fill("0"), pathIndices: Array(16).fill(0) },
      policy: "wiki", challenge: { nonce: "1", resourceId: 1, epoch: Math.floor(T0 / 600), now: T0 },
    }), (e) => {
      assert.ok(!e.message.includes(c.secrets.credentialSecret));
      return true;
    });
  });

  test("F7.05 gateway log and state hold no username, email, role, department or clearance", { todo: "gateway (P3) not in this repository" }, () => {});
});
