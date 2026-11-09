"use strict";
// Floor 6: private inputs (attributes, issuer signature, Merkle path, user secret) never leave the
// client; the issuer sees only secret_commitment.
//
// (The issuer necessarily sees the attributes at enrolment: it assigns them, scope M1 and
// CONTRACTS "Floor 6". What must never leave the client are the secret, the salt, and, towards the
// gateway, the attributes, signature and path.)
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const h = require("./helpers");

const { zk } = h;
const client = require(h.r("client", "src"));
const { hasForbiddenKey } = require(h.r("issuer", "src", "server.js"));

const T0 = 1_800_000_000;
const ATTRS = { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };

let iss, fetchRec, issuer, wallet, cred, prep;

before(async () => {
  iss = await h.makeIssuer({ t0: T0 });
  fetchRec = h.recordingFetch(iss.app);
  issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: fetchRec });
  wallet = new client.Wallet({ home: path.join(h.tmpDir("wallet"), "home") }); // not yet existing: the wallet creates it
  await wallet.keygen({ name: "alice", profile: "v4", issuerUrl: "http://issuer.test" });
  await h.enrolViaAdmin({ iss, wallet, name: "alice", issuer, attributes: ATTRS, employeeId: "alice" });
  cred = wallet.load("alice");
  prep = await client.prepareV4({ credential: cred, issuer, challenge: h.challengeFor("wiki", "991", T0) });
});
after(async () => {
  await iss.app.close();
  await client.shutdown();
});

/** Every private value the client holds for this credential. */
function privateValues() {
  return [
    cred.secrets.credentialSecret, cred.secrets.credentialSalt,
    cred.signature.R8x, cred.signature.R8y, cred.signature.S,
    ...prep.input.pathElements.filter((x) => x !== "0"),
  ];
}

const post = (app, body) =>
  app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });

describe("floor 6: private inputs stay on the client", () => {
  test("F6.01 issuer answers 400 forbidden_field to any secret/salt key, at any depth and spelling, without echoing it", async () => {
    const commitment = await zk.commitment("7", "8");
    const attributes = { role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: T0 + 3600 };
    const SECRET = "918273645546372819";
    const bodies = [
      { commitment, attributes, credentialSecret: SECRET },
      { commitment, attributes, credentialSalt: SECRET },
      { commitment, attributes, secret: SECRET },
      { commitment, attributes, salt: SECRET },
      { commitment, attributes, Credential_Secret: SECRET },
      { commitment, attributes, "credential-salt": SECRET },
      { commitment, attributes, SALT: SECRET },
      { commitment, attributes: { ...attributes, secret: SECRET } },
      { commitment, attributes, extra: [{ deep: { credentialSecret: SECRET } }] },
      // issuer.api v2 body shape: forbidden_field is still checked first, before the code
      { commitment, enrolmentCode: "C".repeat(32), credentialSecret: SECRET },
      { commitment, enrolmentCode: "C".repeat(32), Credential_Salt: SECRET },
      { commitment, enrolmentCode: { secret: SECRET } },
      { credentialSecret: SECRET },
    ];
    for (const b of bodies) {
      const res = await post(iss.app, b);
      assert.equal(res.statusCode, 400, JSON.stringify(Object.keys(b)));
      assert.equal(JSON.parse(res.body).error.code, "forbidden_field");
      assert.ok(!res.body.includes(SECRET), "error body echoes the secret");
    }
    assert.ok(!iss.sink.text().includes(SECRET), "issuer log contains a submitted secret");
    assert.equal(hasForbiddenKey({ a: { b: [{ c: { CREDENTIALSECRET: 1 } }] } }), true);
  });

  test("F6.02 the client's POST /credentials body is allow-listed: extra properties never reach the wire", async () => {
    const sent = [];
    const stub = async (url, init) => {
      sent.push(init.body);
      return { status: 201, text: async () => JSON.stringify({ credential: {} }) };
    };
    const ic = new client.IssuerClient({ baseUrl: "http://x.test", fetch: stub });
    // issuer.api v2 (G1-S1-SAFETY-021): the allow-list is now exactly {commitment, enrolmentCode};
    // attributes joined the properties that never reach the wire.
    const CODE = "Zk".repeat(16);
    await ic.requestCredential({
      commitment: "123", enrolmentCode: CODE, attributes: { role: 1, clearance: 3 },
      credentialSecret: "555", credentialSalt: "666", secrets: { credentialSecret: "555" }, signature: { S: "777" },
    });
    assert.equal(sent.length, 1);
    const body = JSON.parse(sent[0]);
    assert.deepEqual(Object.keys(body).sort(), ["commitment", "enrolmentCode"]);
    assert.deepEqual(body, { commitment: "123", enrolmentCode: CODE });
    for (const s of ["555", "666", "777", "clearance", "attributes"]) assert.ok(!sent[0].includes(s), s);
    // without a code (the v1 shape, or a secret slipped in) nothing is sent at all
    await assert.rejects(ic.requestCredential({ commitment: "123", attributes: { role: 0, secret: 5 } }), (e) => e.code === "INVALID_REQUEST");
    await assert.rejects(ic.requestCredential({ commitment: "123", enrolmentCode: { secret: "555" } }), (e) => e.code === "INVALID_REQUEST");
    assert.equal(sent.length, 1);
  });

  test("F6.03 a full enrol + prove-prepare session sends no secret, salt, signature or path to anyone", () => {
    assert.ok(fetchRec.sent.length >= 4);
    const wire = fetchRec.sent.map((s) => `${s.method} ${s.url} ${s.body || ""}`).join("\n");
    for (const x of privateValues()) assert.ok(!wire.includes(x), "a private value left the client");
    // and the only body the client ever sends is {commitment, enrolmentCode} (issuer.api v2; the
    // admin's enrolment request is not the client's and does not go through fetchRec)
    const bodies = fetchRec.sent.filter((x) => x.body !== undefined);
    assert.equal(bodies.length, 1);
    for (const s of bodies) {
      assert.deepEqual(Object.keys(JSON.parse(s.body)).sort(), ["commitment", "enrolmentCode"]);
      assert.ok(s.url.endsWith("/credentials"));
    }
    const paths = new Set(fetchRec.sent.map((s) => `${s.method} ${new URL(s.url).pathname.replace(/\/\d+$/, "/:i")}`));
    assert.deepEqual([...paths].sort(), ["GET /issuer", "GET /path/:i", "GET /root", "POST /credentials"]);
  });

  test("F6.04 towards the gateway only {resource, nonce, proof, publicSignals} is sent", async () => {
    const sent = [];
    const stub = async (url, init) => {
      sent.push({ url, body: init.body });
      return { status: 200, text: async () => "{}" };
    };
    const fx = h.fixture("alice_wiki");
    await client.submitProof({ gatewayUrl: "http://gw.test", resource: "wiki", nonce: fx.publicSignals[9], proof: fx.proof, publicSignals: fx.publicSignals, fetch: stub, credentialSecret: "999" });
    assert.equal(sent.length, 1);
    assert.deepEqual(Object.keys(JSON.parse(sent[0].body)).sort(), ["nonce", "proof", "publicSignals", "resource"]);
    // the public signals of a real proof hold none of the private values
    const ps = prep.expectedSignals;
    for (const x of privateValues()) assert.ok(!ps.includes(x));
    for (const k of ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry"]) {
      assert.ok(!zk.getProfile("v4").publicSignals.includes(k), `${k} is a public signal`);
    }
  });

  test("F6.05 committed fixtures hold no private value of any persona (secret, salt, commitment, attrHash, signature, path)", async () => {
    const v = h.vectorsV4();
    const banned = [];
    for (const c of v.credentials) {
      banned.push(c.credentialSecret, c.credentialSalt, c.commitment, c.attrHash, c.signature.R8x, c.signature.R8y, c.signature.S);
      banned.push(...c.merkle.pathElements);
    }
    banned.push(v.forged.signature.R8x, v.forged.signature.R8y, v.forged.signature.S);
    // zero-subtree hashes are public constants (every empty tree has them); they are not private
    const emptyTreeHashes = new Set((await zk.createTree("v4")).zeroes.map(String));
    const files = [];
    const walk = (d) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else files.push(p);
      }
    };
    walk(h.FIXTURES);
    const allowed = /(^|\/)(proof\.json|public\.json|README\.md|fixtures\.json|verification_key\.json)$/;
    for (const f of files) {
      assert.match(f, allowed, `unexpected file in fixtures: ${f}`);
      const text = fs.readFileSync(f, "utf8");
      for (const b of banned) if (!emptyTreeHashes.has(b)) assert.ok(!text.includes(b), `${path.relative(h.REPO, f)} contains a private vector value`);
    }
    assert.ok(files.length >= 20);
  });

  test("F6.06 issuer state on disk holds the commitment and leaf only: no attribute, signature or secret", () => {
    const state = fs.readFileSync(path.join(iss.dataDir, "registry.json"), "utf8");
    assert.ok(state.includes(cred.commitment), "registry should hold the commitment (duplicate check)");
    for (const x of privateValues()) assert.ok(!state.includes(x));
    for (const k of ["attributes", "role", "dept", "clearance", "signature", "secret", "salt"]) {
      assert.ok(!state.includes(`"${k}"`), `registry state has a "${k}" key`);
    }
  });

  test("F6.07 the wallet keeps secrets in 0600 files under a 0700 directory and refuses group/other-readable files", () => {
    const file = wallet.pathOf("alice");
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
    assert.equal(fs.statSync(wallet.home).mode & 0o777, 0o700);
    fs.chmodSync(file, 0o644);
    try {
      assert.throws(() => wallet.load("alice"), (e) => e.code === "WALLET_PERMISSIONS");
    } finally {
      fs.chmodSync(file, 0o600);
    }
    // the public summary carries no secret, salt, signature or attribute
    const s = JSON.stringify(wallet.summary("alice"));
    for (const x of privateValues()) assert.ok(!s.includes(x));
    assert.ok(!/"(attributes|secrets|signature)"/.test(s));
  });

  test("F6.08 the prover writes no input or witness file (in-memory fullProve only)", () => {
    const src = fs.readFileSync(h.r("client", "src", "prover.js"), "utf8");
    assert.ok(!/writeFile|createWriteStream|wtns\.calculate\([^)]*["'`]/.test(src), "prover.js writes files");
    assert.match(src, /groth16\.fullProve\(prep\.input, art\.wasm, art\.zkey\)/);
  });

  test("F6.09 SR-09: a corrupt pin file fails closed (PINS_CORRUPT) before the enrolment request is sent", async () => {
    const e = await h.adminEnrol(iss, { employeeId: "f609", attributes: ATTRS });
    assert.equal(e.status, 201, e.res.body);
    const leaves = async () => JSON.parse((await iss.admin("GET", "/admin/leaves")).body).total;
    const n0 = await leaves();
    const info = JSON.parse((await iss.app.inject({ method: "GET", url: "/issuer" })).body);
    for (const bad of ["{not json", "[]", JSON.stringify({ "http://issuer.test": { Ax: "01", Ay: "2" } }), "dir"]) {
      const w = new client.Wallet({ home: path.join(h.tmpDir("wallet-f609"), "home") });
      await w.keygen({ name: "u", profile: "v4", issuerUrl: "http://issuer.test" });
      const pins = path.join(w.home, "pins.json");
      if (bad === "dir") fs.mkdirSync(pins);
      else fs.writeFileSync(pins, bad, { mode: 0o600 });
      const rec = h.recordingFetch(iss.app);
      const ic = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: rec });
      await assert.rejects(client.requestCredential({ wallet: w, name: "u", issuer: ic, enrolmentCode: e.code }), (x) => x.code === "PINS_CORRUPT", bad);
      assert.deepEqual(rec.sent.filter((s) => s.method !== "GET"), [], `${bad}: a request with a body was sent`);
      assert.equal(w.load("u").status, "pending");
      if (bad !== "dir") assert.equal(fs.readFileSync(pins, "utf8"), bad, "the corrupt pin file was overwritten (silent TOFU re-pin)");
    }
    assert.equal(await leaves(), n0, "a refused enrolment changed the registry");
    // the documented way through: an explicit, out-of-band issuer key; the code was not spent
    const w = new client.Wallet({ home: path.join(h.tmpDir("wallet-f609"), "home") });
    await w.keygen({ name: "u", profile: "v4", issuerUrl: "http://issuer.test" });
    fs.writeFileSync(path.join(w.home, "pins.json"), "{not json", { mode: 0o600 });
    const ic = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });
    await client.requestCredential({ wallet: w, name: "u", issuer: ic, enrolmentCode: e.code, expectedIssuer: info.issuer });
    assert.equal(w.load("u").status, "issued");
    assert.equal(await leaves(), n0 + 1);
  });

  test("F6.10 issuer enrolment state: after redemption no attribute, code or commitment is kept, file 0600", () => {
    const file = path.join(iss.dataDir, "enrolments.json");
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    const text = fs.readFileSync(file, "utf8");
    const state = JSON.parse(text);
    const alice = state.enrolments.find((x) => String(x.employeeId).toLowerCase() === "alice");
    assert.ok(alice, "alice's enrolment record");
    assert.equal(alice.attributes == null, true, "redeemed enrolment still holds its attributes");
    assert.ok(!text.includes(cred.commitment), "enrolment state holds a commitment");
    for (const x of privateValues()) assert.ok(!text.includes(x));
    assert.ok(!/"code"\s*:/.test(text), "enrolment state holds a plaintext code");
  });
});
