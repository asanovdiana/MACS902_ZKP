"use strict";
// Floor 2: no valid proof exists for an unsatisfied policy, a tampered attribute, a forged issuer
// signature, or an expired credential.
//
// Method: the COMMITTED v4 witness calculator (circuits/setup/integrated_access_v4.wasm, the one
// the client prover ships) is run on attack inputs; no witness means no Groth16 proof. Where the
// circuit by design accepts the input (a self-signed credential under the forger's own key; a
// proof made for another policy), the test shows the resulting proof does not verify once the
// public signals are the pinned/required ones (gateway obligations 2 and 4).
// Constraint-level evidence (each constraint removed -> a negative test fails) is floor 1.
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const h = require("./helpers");

const { zk, witnessV4, verifier } = h;

const NOW = 1794128400; // the vectors' gateway clock
const ALICE = { role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };

let prv; // TEST-ONLY vector issuer key (public label; protects nothing)
let pinned;
let vkey;

before(async () => {
  prv = h.testOnlyIssuerPrv();
  pinned = await zk.publicKey(prv);
  vkey = h.v4Vkey();
});
after(async () => verifier.terminate());

describe("floor 2: no valid proof for tampered / forged / unsatisfied / expired", () => {
  test("F2.00 control: the TEST-ONLY issuer key reproduces the fixtures' pinned key and an honest input has a witness", async () => {
    const idx = h.fixtureIndex();
    assert.deepEqual(pinned, idx.context.pinned_issuer);
    const v = h.aliceWikiInput();
    const w = await witnessV4(v.input);
    assert.equal(w.ok, true, w.error);
    assert.equal(w.nullifier, v.expectedPublicSignals[0]);
  });

  test("F2.01 tampered attribute (each of the 6, signature and path kept) -> no witness", async () => {
    const base = h.aliceWikiInput().input;
    const tamper = { role: "1", dept: "1", clearance: "3", deviceCompliant: "0", employeeActive: "0", expiry: String(BigInt(base.expiry) + 1n) };
    for (const [k, v] of Object.entries(tamper)) {
      assert.notEqual(base[k], v);
      const w = await witnessV4({ ...base, [k]: v });
      assert.equal(w.ok, false, `${k}: ${base[k]} -> ${v} produced a witness`);
    }
  });

  test("F2.02 tampered attribute that WOULD satisfy the stricter policy (engineer claims admin, clearance 3) -> no witness", async () => {
    const base = h.aliceWikiInput().input;
    const ap = zk.policies.admin_panel;
    const forged = {
      ...base, role: "1", clearance: "3",
      roleMask: String(ap.roleMask), deptMask: String(ap.deptMask), minClearance: String(ap.minClearance),
      requireDevice: String(ap.requireDevice), resourceId: String(ap.resourceId),
    };
    const w = await witnessV4(forged);
    assert.equal(w.ok, false);
    // and the lib's pre-check agrees the honest attributes do not satisfy it
    assert.equal(zk.checkPolicyLocally(ALICE, "admin_panel", NOW).ok, false);
  });

  test("F2.03 forged signature under the PINNED key (attrHash signed by another key, pinned key claimed) -> no witness", async () => {
    const base = h.aliceWikiInput().input;
    const v = h.vectorsV4();
    // the vectors' forger signature over Alice's attrHash, presented with the pinned issuer key
    const w1 = await witnessV4({ ...base, R8x: v.forged.signature.R8x, R8y: v.forged.signature.R8y, S: v.forged.signature.S });
    assert.equal(w1.ok, false, "forger signature accepted under the pinned key");
    // a fresh random key signing a fresh credential, tree root honest, pinned key claimed
    const rogue = crypto.randomBytes(32);
    const cred = await h.signedCredential(rogue, ALICE);
    const w2 = await witnessV4(h.rawInputV4(cred, ALICE, { now: NOW, issuer: pinned }));
    assert.equal(w2.ok, false, "self-signed credential accepted under the pinned key");
    // S tweaked, S + l (non-canonical scalar) and S = 0
    const L = zk.L;
    for (const S of [String(BigInt(base.S) + 1n), String(BigInt(base.S) + L), "0"]) {
      const w = await witnessV4({ ...base, S });
      assert.equal(w.ok, false, `S variant accepted`);
    }
  });

  test("F2.04 self-signed credential under the FORGER's key: witness exists (by design) but the proof carries the forger key; with the pinned key substituted it does not verify", async () => {
    const rogue = crypto.randomBytes(32);
    const cred = await h.signedCredential(rogue, ALICE);
    const w = await witnessV4(h.rawInputV4(cred, ALICE, { now: NOW }));
    assert.equal(w.ok, true, "the circuit accepts any key it is given; the gateway pin is the defence");
    const fx = h.fixture("forged_issuer_alice_wiki");
    assert.equal(await verifier.verify(vkey, fx.publicSignals, fx.proof), true);
    assert.notDeepEqual([fx.publicSignals[2], fx.publicSignals[3]], [pinned.Ax, pinned.Ay], "forged fixture must not carry the pinned key");
    const swapped = [...fx.publicSignals];
    swapped[2] = pinned.Ax;
    swapped[3] = pinned.Ay;
    assert.equal(await verifier.verify(vkey, swapped, fx.proof), false, "forged proof re-labelled with the pinned key verified");
  });

  test("F2.05 off-curve issuer key or R8 -> no witness", async () => {
    const base = h.aliceWikiInput().input;
    for (const patch of [{ issuerAx: "1" }, { issuerAy: "1" }, { R8x: "1" }, { R8y: "1" }, { issuerAx: "0", issuerAy: "1" }]) {
      const w = await witnessV4({ ...base, ...patch });
      assert.equal(w.ok, false, `accepted ${JSON.stringify(patch)}`);
    }
  });

  test("F2.06 unsatisfied policy with honest, issuer-signed attributes -> no witness (each policy clause)", async () => {
    const cases = [
      // [attributes, policy, clause]
      [{ ...ALICE }, "admin_panel", "role not in roleMask + clearance"],
      [{ ...ALICE, role: 1, clearance: 2 }, "admin_panel", "clearance below minClearance only"],
      [{ ...ALICE, role: 2, clearance: 3 }, "file_share", "role not in roleMask only"],
      [{ ...ALICE, deviceCompliant: 0 }, "wiki", "device required, not compliant"],
      [{ ...ALICE, employeeActive: 0 }, "wiki", "inactive employee"],
      [{ ...ALICE, dept: 2 }, { roleMask: 15, deptMask: 0b1011, minClearance: 0, requireDevice: 0, resourceId: 1 }, "dept not in deptMask"],
    ];
    for (const [attrs, policy, clause] of cases) {
      const cred = await h.signedCredential(prv, attrs);
      const w = await witnessV4(h.rawInputV4(cred, attrs, { now: NOW, policy }));
      assert.equal(w.ok, false, `${clause}: witness exists`);
      assert.equal(zk.checkPolicyLocally(attrs, policy, NOW).ok, false, `${clause}: lib pre-check disagrees`);
    }
    // control: the same machinery admits a satisfied policy
    const cred = await h.signedCredential(prv, ALICE);
    const ok = await witnessV4(h.rawInputV4(cred, ALICE, { now: NOW, policy: "file_share" }));
    assert.equal(ok.ok, true, ok.error);
  });

  test("F2.07 a valid proof for one policy does not verify with another resource's policy signals", async () => {
    const fx = h.fixture("alice_wiki");
    assert.equal(await verifier.verify(vkey, fx.publicSignals, fx.proof), true);
    const ap = zk.policies.admin_panel;
    const relabelled = [...fx.publicSignals];
    [relabelled[4], relabelled[5], relabelled[6], relabelled[7], relabelled[10]] =
      [ap.roleMask, ap.deptMask, ap.minClearance, ap.requireDevice, ap.resourceId].map(String);
    assert.equal(await verifier.verify(vkey, relabelled, fx.proof), false);
  });

  test("F2.08 expired credential (expiry == now, expiry < now) -> no witness; expiry = now + 1 -> witness", async () => {
    for (const [delta, want] of [[0, false], [-1, false], [-86400, false], [1, true]]) {
      const attrs = { ...ALICE, expiry: NOW + delta };
      const cred = await h.signedCredential(prv, attrs);
      const w = await witnessV4(h.rawInputV4(cred, attrs, { now: NOW }));
      assert.equal(w.ok, want, `expiry = now ${delta >= 0 ? "+" : ""}${delta}: ${w.error || "witness"}`);
    }
  });

  test("F2.09 range wrap-arounds on expiry/now (expiry = now + 2^64, now = p - 1) -> no witness", async () => {
    const attrs = { ...ALICE, expiry: BigInt(NOW) + (1n << 64n) };
    // lib refuses to hash an out-of-contract expiry, so hash it the way a forger would (raw Poseidon)
    const secret = "11", salt = "22";
    const commitment = await zk.commitment(secret, salt);
    const ah = await zk.poseidon([attrs.role, attrs.dept, attrs.clearance, attrs.deviceCompliant, attrs.employeeActive, attrs.expiry, commitment]);
    const sig = await zk.sign(prv, ah);
    const tree = await zk.createTree("v4");
    tree.insert(BigInt(ah));
    const cred = { secret, salt, signature: sig, issuer: pinned, tree, leafIndex: 0 };
    const w = await witnessV4(h.rawInputV4(cred, attrs, { now: NOW }));
    assert.equal(w.ok, false, "expiry >= 2^64 accepted");
    const base = h.aliceWikiInput().input;
    const w2 = await witnessV4({ ...base, now: String(zk.P - 1n) });
    assert.equal(w2.ok, false, "now = p - 1 accepted");
  });

  test("F2.10 out-of-range attribute even when the issuer signed it (role 4, clearance 5, device 2) -> no witness", async () => {
    for (const patch of [{ role: 4 }, { dept: 4 }, { clearance: 5 }, { deviceCompliant: 2 }]) {
      const attrs = { ...ALICE, ...patch };
      const secret = "33", salt = "44";
      const commitment = await zk.commitment(secret, salt);
      const ah = await zk.poseidon([attrs.role, attrs.dept, attrs.clearance, attrs.deviceCompliant, attrs.employeeActive, attrs.expiry, commitment]);
      const tree = await zk.createTree("v4");
      tree.insert(BigInt(ah));
      const cred = { secret, salt, signature: await zk.sign(prv, ah), issuer: pinned, tree, leafIndex: 0 };
      const policy = { roleMask: 15, deptMask: 15, minClearance: 0, requireDevice: 0, resourceId: 1 };
      const w = await witnessV4(h.rawInputV4(cred, attrs, { now: NOW, policy }));
      assert.equal(w.ok, false, `${JSON.stringify(patch)} accepted`);
    }
  });

  test("F2.11 the real issuer refuses expired and out-of-range attributes (issuer.api v1)", async () => {
    const t0 = 1_800_000_000;
    // issuer.api v2 (G1-S1-SAFETY-021): attributes enter the issuer only through the admin's
    // enrolment, so that is where the same refusal must happen; the user path cannot carry them at
    // all, and an assigned expiry that passes before redemption is never signed.
    const iss = await h.makeIssuer({ t0 });
    const { app } = iss;
    const post = (body) => app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });
    const leaves = async () => JSON.parse((await app.inject({ method: "GET", url: "/metrics" })).body).leaves;
    try {
      const commitment = await zk.commitment("5", "6");
      const bad = [
        { ...ALICE, expiry: t0 }, { ...ALICE, expiry: t0 - 1 }, { ...ALICE, role: 4 }, { ...ALICE, clearance: 4 },
        { ...ALICE, deviceCompliant: 2 }, { ...ALICE, employeeActive: 2 }, { ...ALICE, role: "admin" },
      ];
      for (const attributes of bad) {
        const e = await iss.admin("POST", "/admin/enrolments", { employeeId: "f211", attributes });
        assert.equal(e.statusCode, 400, JSON.stringify(attributes));
        assert.equal(JSON.parse(e.body).error.code, "invalid_attributes");
        const res = await post({ commitment, attributes });
        assert.equal(res.statusCode, 400, JSON.stringify(attributes));
        assert.equal(JSON.parse(res.body).error.code, "attributes_not_accepted");
      }
      // valid when assigned, expired by the time the user redeems: refused, nothing signed or inserted
      const e = await h.adminEnrol(iss, { employeeId: "f211-late", attributes: { ...ALICE, expiry: t0 + 100 } });
      assert.equal(e.status, 201, e.res.body);
      iss.clock.advance(100);
      const late = await post({ commitment, enrolmentCode: e.code });
      assert.equal(late.statusCode, 410);
      assert.equal(JSON.parse(late.body).error.code, "enrolment_expired");
      assert.ok(!/"signature"/.test(late.body));
      assert.equal(await leaves(), 0);
    } finally {
      await app.close();
    }
  });

  test("F2.12 v3 proofs are not admissible under the v4 key (v3 binds no issuer/policy/time)", async () => {
    const v3 = h.readJson(h.V3_VKEY);
    assert.equal(v3.nPublic, 1);
    assert.equal(vkey.nPublic, 12);
    const fx = h.fixture("alice_wiki");
    assert.equal(await verifier.verify(vkey, [fx.publicSignals[1]], fx.proof), false);
    const contracts = require("fs").readFileSync(h.r("docs", "CONTRACTS.md"), "utf8");
    assert.match(contracts, /The gateway must not admit on v3\s+proofs/);
  });

  test("F2.13 every one of the 12 public signals tampered on a valid fixture -> verify false", async () => {
    for (const name of ["alice_wiki", "carol_admin_panel"]) {
      const fx = h.fixture(name);
      assert.equal(await verifier.verify(vkey, fx.publicSignals, fx.proof), true, name);
      for (let i = 0; i < 12; i++) {
        const t = [...fx.publicSignals];
        t[i] = (BigInt(t[i]) + 1n).toString();
        assert.equal(await verifier.verify(vkey, t, fx.proof), false, `${name}: slot ${i} tampered verified`);
      }
    }
  });

  test("F2.14 only an authenticated enrolment path can obtain issuer-signed attributes", async () => {
    // SR-03 closed by issuer.api v2 / issuer.admin v1.1 (G1-S1-IDEN-014); made real in G1-S1-SAFETY-021.
    const t0 = 1_800_000_000;
    const client = require(h.r("client", "src"));
    const ADMIN = { role: 1, dept: 1, clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };
    const ENGINEER = { role: 0, dept: 0, clearance: 1, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };
    const iss = await h.makeIssuer({ t0 });
    const { app } = iss;
    const post = (body) => app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });
    const errOf = (res) => JSON.parse(res.body).error.code;
    const leaves = async () => JSON.parse((await app.inject({ method: "GET", url: "/metrics" })).body).leaves;
    try {
      const commitment = await zk.commitment("11", "12");
      // (a) self-chosen attributes are refused outright, with or without a valid code
      const own = await h.adminEnrol(iss, { employeeId: "eve", attributes: ENGINEER });
      assert.equal(own.status, 201, own.res.body);
      for (const body of [{ commitment, attributes: ADMIN }, { commitment, enrolmentCode: own.code, attributes: ADMIN }]) {
        const res = await post(body);
        assert.equal(res.statusCode, 400);
        assert.equal(errOf(res), "attributes_not_accepted");
      }
      // (b) no code, unknown code, malformed code: 403 invalid_enrolment_code
      for (const enrolmentCode of [undefined, "A".repeat(32), "short", 12345, { $ne: 1 }]) {
        const res = await post(enrolmentCode === undefined ? { commitment } : { commitment, enrolmentCode });
        assert.equal(res.statusCode, 403, JSON.stringify(enrolmentCode));
        assert.equal(errOf(res), "invalid_enrolment_code");
      }
      assert.equal(await leaves(), 0, "a refused request inserted a leaf");
      // (c) the admin surface needs the bearer: no header, wrong token, token in the URL -> 401
      for (const tok of [null, "wrong-token", ""]) {
        const e = await h.adminEnrol(iss, { employeeId: "mallory", attributes: ADMIN, token: tok });
        assert.equal(e.status, 401, `token ${JSON.stringify(tok)}`);
        assert.equal(e.code, undefined);
      }
      const inUrl = await app.inject({ method: "POST", url: `/admin/enrolments?token=${iss.token}`, headers: { "content-type": "application/json" }, payload: JSON.stringify({ employeeId: "mallory", attributes: ADMIN }) });
      assert.equal(inUrl.statusCode, 401);
      // (d) the credential carries the ADMIN's attributes; the client has no way to name others
      const wallet = new client.Wallet({ home: h.tmpDir("wallet-f214") });
      const rec = h.recordingFetch(app);
      const issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: rec });
      await wallet.keygen({ name: "eve", profile: "v4", issuerUrl: "http://issuer.test" });
      await client.requestCredential({ wallet, name: "eve", issuer, enrolmentCode: own.code, attributes: ADMIN });
      const cred = wallet.load("eve");
      assert.deepEqual(cred.attributes, ENGINEER);
      assert.equal(await zk.verifySignature(await zk.attrHash(ENGINEER, cred.commitment), cred.signature, cred.issuer), true);
      for (const s of rec.sent.filter((x) => x.body !== undefined)) {
        assert.deepEqual(Object.keys(JSON.parse(s.body)).sort(), ["commitment", "enrolmentCode"]);
      }
      // ... and with those attributes the admin panel is unprovable (engineer, clearance 1)
      const prep = client.prepareV4({ credential: cred, issuer, challenge: h.challengeFor("admin_panel", "4242", t0) });
      await assert.rejects(prep);
      assert.equal(await leaves(), 1);
    } finally {
      await app.close();
    }
    // (e) fail closed: no token, no issuer (v4 and v3), and v4 has no open enrolment even in insecure-dev
    const { buildServer } = require(h.r("issuer", "src", "server.js"));
    for (const profile of ["v4", "v3"]) {
      for (const adminToken of [undefined, null, ""]) {
        const keyDir = require("path").join(h.tmpDir("f214-k"), "k");
        await assert.rejects(
          buildServer({ config: { profile, keyDir, dataDir: h.tmpDir("f214-d"), host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, logLevel: "silent", adminToken, insecureDev: false } }),
          /ISSUER_ADMIN_TOKEN/,
        );
      }
    }
    const dev = await h.makeIssuer({ t0, overrides: { adminToken: undefined, insecureDev: true, logLevel: "silent" } });
    try {
      const res = await dev.app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify({ commitment: await zk.commitment("13", "14"), attributes: ADMIN }) });
      assert.equal(res.statusCode, 400);
      assert.equal(errOf(res), "attributes_not_accepted");
    } finally {
      await dev.app.close();
    }
  });
});
