"use strict";
// Floor 3: a revoked credential is denied against the current root.
//
// Real issuer (issuer/src, in-process, temp dirs) + real client library (enrolment and prepareV4)
// + the committed v4 witness calculator. Gateway half: the staleness rule's reference
// implementation (issuer/src/registry.js isRootAcceptable) and the stale-root fixture; the
// gateway's own enforcement is P3 (todo below).
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const h = require("./helpers");

const { zk, witnessV4 } = h;
const client = require(h.r("client", "src"));
const { isRootAcceptable } = require(h.r("issuer", "src", "registry.js"));

const T0 = 1_800_000_000;
const EXPIRY = 4070908800;
const ATTRS = {
  alice: { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY },
  bob: { role: "contractor", dept: "operations", clearance: 1, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY },
};

let iss, issuer, wallet;
const before_ = {}; // inputs prepared before Bob's revocation
const enrolments = {}; // name -> the admin enrolment whose code that holder redeemed
let rootBefore, rootAfter;

before(async () => {
  iss = await h.makeIssuer({ t0: T0 });
  issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });
  wallet = new client.Wallet({ home: h.tmpDir("wallet") });
  for (const [name, attributes] of Object.entries(ATTRS)) {
    await wallet.keygen({ name, profile: "v4", issuerUrl: "http://issuer.test" });
    enrolments[name] = (await h.enrolViaAdmin({ iss, wallet, name, issuer, attributes, employeeId: name })).enrolment;
  }
  for (const name of Object.keys(ATTRS)) {
    const prep = await client.prepareV4({ credential: wallet.load(name), issuer, challenge: h.challengeFor("wiki", "777", T0) });
    before_[name] = prep.input;
  }
  rootBefore = JSON.parse((await iss.app.inject({ method: "GET", url: "/root" })).body).root;
  iss.clock.advance(5);
  const rv = await iss.admin("POST", `/credentials/${wallet.load("bob").leafIndex}/revoke`);
  assert.equal(rv.statusCode, 200);
  rootAfter = JSON.parse(rv.body).root;
});
after(async () => {
  await iss.app.close();
  await client.shutdown();
});

describe("floor 3: revoked credential vs current root", () => {
  test("F3.01 control: before revocation Bob's input had a witness against the then-current root", async () => {
    assert.equal(before_.bob.root, rootBefore);
    const w = await witnessV4(before_.bob);
    assert.equal(w.ok, true, w.error);
    assert.notEqual(rootBefore, rootAfter);
  });

  test("F3.02 revoked: GET /path is 410 and the client refuses to prepare a proof", async () => {
    const res = await iss.app.inject({ method: "GET", url: `/path/${wallet.load("bob").leafIndex}` });
    assert.equal(res.statusCode, 410);
    assert.equal(JSON.parse(res.body).error.code, "revoked");
    await assert.rejects(
      client.prepareV4({ credential: wallet.load("bob"), issuer, challenge: h.challengeFor("wiki", "778", T0 + 5) }),
      (e) => e.code === "revoked",
    );
  });

  test("F3.03 Bob's old path against the CURRENT root -> no witness", async () => {
    const w = await witnessV4({ ...before_.bob, root: rootAfter });
    assert.equal(w.ok, false);
  });

  test("F3.04 Bob's leaf with the CURRENT tree's siblings at his index -> no witness (his slot is 0 now)", async () => {
    // rebuild the issuer's current tree from the admin listing (revoked leaf = "0")
    const { leaves } = JSON.parse((await iss.admin("GET", "/admin/leaves")).body);
    const tree = await zk.createTree("v4");
    for (const l of leaves) tree.insert(BigInt(l.leaf));
    assert.equal(tree.root.toString(), rootAfter);
    const idx = wallet.load("bob").leafIndex;
    const p = zk.proofFor(tree, idx);
    assert.equal(p.leaf, "0");
    const w = await witnessV4({ ...before_.bob, pathElements: p.pathElements, pathIndices: p.pathIndices, root: rootAfter });
    assert.equal(w.ok, false);
  });

  test("F3.05 the zero leaf is a tree member, but v4 has no leaf/M input: the leaf is the in-circuit attrHash", async () => {
    // "0" at Bob's index reaches the current root: if the circuit took the leaf as an input, a
    // revoked slot would be provable. It does not: the committed wasm rejects a `leaf` or `M` signal.
    const { leaves } = JSON.parse((await iss.admin("GET", "/admin/leaves")).body);
    const tree = await zk.createTree("v4");
    for (const l of leaves) tree.insert(BigInt(l.leaf));
    const p = zk.proofFor(tree, wallet.load("bob").leafIndex);
    assert.equal(await zk.merkleRoot("0", p.pathElements, p.pathIndices), rootAfter);
    for (const extra of [{ leaf: "0" }, { M: "0" }]) {
      const w = await witnessV4({ ...before_.alice, ...extra });
      assert.equal(w.ok, false, `wasm accepted an extra ${Object.keys(extra)[0]} input`);
    }
  });

  test("F3.06 unrevoked Alice still proves against the current root (revocation is targeted)", async () => {
    const prep = await client.prepareV4({ credential: wallet.load("alice"), issuer, challenge: h.challengeFor("wiki", "779", T0 + 5) });
    assert.equal(prep.input.root, rootAfter);
    const w = await witnessV4(prep.input);
    assert.equal(w.ok, true, w.error);
  });

  test("F3.07 staleness rule: a root superseded by a revocation is never acceptable, even inside 30 s", async () => {
    const hist = JSON.parse((await iss.app.inject({ method: "GET", url: "/root/history" })).body);
    const now = iss.clock.now();
    assert.equal(isRootAcceptable(hist.roots, rootAfter, now), true);
    assert.equal(isRootAcceptable(hist.roots, rootBefore, now), false, "pre-revocation root accepted");
    assert.equal(isRootAcceptable(hist.roots, rootBefore, now + 1), false);
    // insert-only supersession stays acceptable for 30 s (enrolments do not break in-flight proofs)
    const rootR = rootAfter;
    await wallet.keygen({ name: "carol", profile: "v4", issuerUrl: "http://issuer.test" });
    iss.clock.advance(1);
    await h.enrolViaAdmin({ iss, wallet, name: "carol", issuer, attributes: { ...ATTRS.alice }, employeeId: "carol" });
    const hist2 = JSON.parse((await iss.app.inject({ method: "GET", url: "/root/history" })).body);
    const t = iss.clock.now();
    assert.equal(isRootAcceptable(hist2.roots, rootR, t + 30), true);
    assert.equal(isRootAcceptable(hist2.roots, rootR, t + 31), false);
    assert.equal(isRootAcceptable(hist2.roots, rootBefore, t), false, "revocation must still block after a later insert");
    assert.equal(isRootAcceptable(hist2.roots, "123", t), false);
  });

  test("F3.08 fixtures: stale_root_bob_wiki carries the pre-revocation root, which the vectors' tree loses on delete(1)", async () => {
    const idx = h.fixtureIndex();
    const v = h.vectorsV4();
    const fx = h.fixture("stale_root_bob_wiki");
    assert.equal(fx.publicSignals[1], idx.context.root_before_revocation);
    assert.notEqual(fx.publicSignals[1], idx.context.root_after_bob_revoked);
    assert.equal(idx.fixtures.stale_root_bob_wiki.gateway_state.current_root, idx.context.root_after_bob_revoked);
    const tree = await zk.createTree("v4");
    for (const c of v.credentials) tree.insert(BigInt(c.attrHash));
    assert.equal(tree.root.toString(), idx.context.root_before_revocation);
    tree.delete(idx.context.revoked.leafIndex);
    assert.equal(tree.root.toString(), idx.context.root_after_bob_revoked);
  });

  test("F3.10 a revoked holder cannot obtain a replacement credential without the admin", async () => {
    // SR-03 closed by issuer.api v2 (G1-S1-IDEN-014); made real in G1-S1-SAFETY-021.
    const post = (body) => iss.app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });
    const errOf = (res) => JSON.parse(res.body).error.code;
    const leafCount = async () => JSON.parse((await iss.admin("GET", "/admin/leaves")).body).total;
    const n0 = await leafCount();
    const fresh = await zk.commitment("424242", "434343");
    // Bob (revoked) on his own: his spent code, no code, a guessed code, self-chosen attributes
    const spent = await post({ commitment: fresh, enrolmentCode: enrolments.bob.code });
    assert.equal(spent.statusCode, 409);
    assert.equal(errOf(spent), "enrolment_used");
    for (const [body, status, code] of [
      [{ commitment: fresh }, 403, "invalid_enrolment_code"],
      [{ commitment: fresh, enrolmentCode: "B".repeat(32) }, 403, "invalid_enrolment_code"],
      [{ commitment: fresh, attributes: ATTRS.bob }, 400, "attributes_not_accepted"],
    ]) {
      const res = await post(body);
      assert.equal(res.statusCode, status, JSON.stringify(Object.keys(body)));
      assert.equal(errOf(res), code);
    }
    // the client library with the spent code: refused, the pending wallet entry stays pending
    await wallet.keygen({ name: "bob2", profile: "v4", issuerUrl: "http://issuer.test" });
    await assert.rejects(client.requestCredential({ wallet, name: "bob2", issuer, enrolmentCode: enrolments.bob.code }));
    assert.equal(wallet.load("bob2").status, "pending");
    assert.equal(await leafCount(), n0, "a refused re-enrolment changed the registry");
    // the admin cannot re-enrol a LIVE holder (no implicit replacement) ...
    const live = await h.adminEnrol(iss, { employeeId: "ALICE", attributes: ATTRS.alice });
    assert.equal(live.status, 409);
    assert.equal(live.body.error.code, "employee_has_credential");
    // ... and re-enrols Bob only because his old leaf is revoked: a deliberate, authenticated act
    const noBearer = await h.adminEnrol(iss, { employeeId: "bob", attributes: ATTRS.bob, token: null });
    assert.equal(noBearer.status, 401);
    const again = await h.adminEnrol(iss, { employeeId: "Bob", attributes: ATTRS.bob });
    assert.equal(again.status, 201, again.res.body);
    await client.requestCredential({ wallet, name: "bob2", issuer, enrolmentCode: again.code });
    const b2 = wallet.load("bob2");
    assert.notEqual(b2.leafIndex, wallet.load("bob").leafIndex);
    assert.equal(await leafCount(), n0 + 1);
    // the old leaf stays revoked: the old credential still cannot prepare a proof
    await assert.rejects(
      client.prepareV4({ credential: wallet.load("bob"), issuer, challenge: h.challengeFor("wiki", "780", iss.clock.now()) }),
      (e) => e.code === "revoked",
    );
  });

  test("F3.09 gateway denies a revoked credential against its current root", { todo: "gateway (P3) not in this repository; fixture stale_root_bob_wiki is its test input" }, () => {});
});
