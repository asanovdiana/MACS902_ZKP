"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { Wallet, IssuerClient, requestCredential } = require("../src");
const { startStubIssuer } = require("./helpers/stubIssuer");
const { mk, rm } = require("./helpers/tmp");

const ATTRS = { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 };
const dirs = [];
const newWallet = () => { const d = mk(); dirs.push(d); return new Wallet({ home: path.join(d, "h") }); };
const stubs = [];
const stubOf = async (o) => { const s = await startStubIssuer(o); stubs.push(s); return s; };
test.after(async () => { dirs.forEach(rm); await Promise.all(stubs.map((s) => s.close())); });

async function enrol(stub, { wallet = newWallet(), expectedIssuer, attributes = ATTRS } = {}) {
  await wallet.keygen({ name: "u", profile: stub.profile.name, issuerUrl: stub.url });
  const issuer = new IssuerClient({ baseUrl: stub.url });
  const enrolmentCode = stub.enrol(attributes);
  return { wallet, enrolmentCode, run: () => requestCredential({ wallet, name: "u", issuer, enrolmentCode, expectedIssuer }) };
}

test("honest issuer: credential is stored as issued, first-use pin recorded", async () => {
  const stub = await stubOf();
  const { wallet, run } = await enrol(stub);
  const r = await run();
  assert.equal(r.status, "issued");
  const c = wallet.load("u");
  assert.equal(c.status, "issued");
  assert.equal(c.leafIndex, 0);
  assert.equal(c.issuer.Ax, stub.pub.Ax);
  assert.deepEqual(c.attributes, ATTRS);
  assert.ok(c.signature.R8x && c.signature.S);
  assert.deepEqual(wallet.getPin(stub.url), { Ax: stub.pub.Ax, Ay: stub.pub.Ay });
});

test("the secret and salt never appear in any request body, URL or header the issuer saw", async () => {
  const stub = await stubOf();
  const seen = [];
  const spy = async (url, init) => { seen.push({ url: String(url), init }); return fetch(url, init); };
  const wallet = newWallet();
  await wallet.keygen({ name: "u", profile: "v3", issuerUrl: stub.url });
  const c = wallet.load("u");
  await requestCredential({ wallet, name: "u", issuer: new IssuerClient({ baseUrl: stub.url, fetch: spy }), enrolmentCode: stub.enrol(ATTRS) });
  const wire = JSON.stringify(seen) + JSON.stringify(stub.requests);
  assert.equal(wire.includes(c.secrets.credentialSecret), false);
  assert.equal(wire.includes(c.secrets.credentialSalt), false);
  assert.ok(wire.includes(c.commitment), "commitment is what the issuer is meant to see");
});

test("a credential signed by a different key than the issuer claims is refused and not stored", async () => {
  const stub = await stubOf({ mode: "bad-signature" });
  const { wallet, run } = await enrol(stub);
  await assert.rejects(run(), (e) => e.code === "BAD_SIGNATURE");
  assert.equal(wallet.load("u").status, "pending");
});

test("a self-signed credential (foreign issuer key) is refused against the issuer's own /issuer key", async () => {
  const stub = await stubOf({ mode: "foreign-issuer" });
  const { wallet, run } = await enrol(stub);
  await assert.rejects(run(), (e) => e.code === "ISSUER_KEY_MISMATCH");
  assert.equal(wallet.load("u").status, "pending");
});

test("an explicit expected key beats whatever the issuer advertises, and nothing is sent on mismatch", async () => {
  const stub = await stubOf();
  const { wallet, run } = await enrol(stub, { expectedIssuer: { Ax: "1", Ay: "2" } });
  await assert.rejects(run(), (e) => e.code === "ISSUER_KEY_MISMATCH");
  assert.equal(stub.requests.filter((r) => r.method === "POST").length, 0);
  assert.equal(wallet.getPin(stub.url), undefined);
});

test("a stored pin for the issuer URL is enforced on later enrolments", async () => {
  const stub = await stubOf();
  const wallet = newWallet();
  wallet.setPin(stub.url, { Ax: "5", Ay: "6" });
  const { run } = await enrol(stub, { wallet });
  await assert.rejects(run(), (e) => e.code === "ISSUER_KEY_MISMATCH");
});

test("an issuer that returns attributes other than the ones it signed is refused", async () => {
  // v4 only: in v3 the attributes are unsigned (credential v3 gap), in v4 they are inside the signed attrHash.
  const stub = await stubOf({ mode: "altered-attributes", profile: "v4" });
  const { wallet, run } = await enrol(stub, { attributes: { role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 } });
  await assert.rejects(run(), (e) => e.code === "BAD_SIGNATURE");
  assert.equal(wallet.load("u").status, "pending");
});

test("the stored attributes are the admin-assigned ones: the client chooses none and sends none", async () => {
  const stub = await stubOf();
  const assigned = { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 };
  const { wallet, run } = await enrol(stub, { attributes: assigned });
  await run();
  assert.deepEqual(wallet.load("u").attributes, assigned);
  const sent = JSON.parse(stub.requests.find((r) => r.method === "POST").body);
  assert.deepEqual(Object.keys(sent).sort(), ["commitment", "enrolmentCode"]);
  const summary = wallet.summary("u", { withAttributes: true });
  assert.deepEqual(summary.attributes, assigned);
  assert.equal("attributes" in wallet.summary("u"), false, "attributes only on request");
});

test("a missing, wrong or reused enrolment code is refused with the issuer's code and nothing is stored", async () => {
  const stub = await stubOf();
  const { wallet, enrolmentCode, run } = await enrol(stub);
  const issuer = new IssuerClient({ baseUrl: stub.url });
  await assert.rejects(requestCredential({ wallet, name: "u", issuer }), (e) => e.code === "INVALID_REQUEST");
  await assert.rejects(requestCredential({ wallet, name: "u", issuer, enrolmentCode: "short" }), (e) => e.code === "INVALID_REQUEST");
  await assert.rejects(requestCredential({ wallet, name: "u", issuer, enrolmentCode: "A".repeat(32) }), (e) => e.code === "invalid_enrolment_code");
  assert.equal(wallet.load("u").status, "pending");
  await run();
  const w2 = newWallet();
  await w2.keygen({ name: "u", profile: "v3", issuerUrl: stub.url });
  await assert.rejects(requestCredential({ wallet: w2, name: "u", issuer, enrolmentCode }), (e) => e.code === "enrolment_used");
  assert.equal(w2.load("u").status, "pending");
});

test("a malformed attribute set from the issuer is refused before it is stored", async () => {
  const stub = await stubOf();
  const { wallet, run } = await enrol(stub, { attributes: { role: 2, clearance: 2, deviceCompliant: 1 } });
  await assert.rejects(run(), (e) => e.code === "ISSUER_BAD_RESPONSE");
  assert.equal(wallet.load("u").status, "pending");
});

test("SR-09: a corrupt pins file fails closed before anything is sent; an explicit issuer key is the way around it", async () => {
  const stub = await stubOf();
  const { wallet, enrolmentCode } = await enrol(stub);
  fs.writeFileSync(path.join(wallet.home, "pins.json"), "{not json");
  const issuer = new IssuerClient({ baseUrl: stub.url });
  await assert.rejects(requestCredential({ wallet, name: "u", issuer, enrolmentCode }), (e) => e.code === "PINS_CORRUPT");
  assert.equal(stub.requests.filter((r) => r.method === "POST").length, 0, "the code was not spent");
  const expectedIssuer = { Ax: stub.pub.Ax, Ay: stub.pub.Ay };
  const r = await requestCredential({ wallet, name: "u", issuer, enrolmentCode, expectedIssuer });
  assert.equal(r.status, "issued");
});

test("profile mismatch between the pending credential and the issuer is refused before sending", async () => {
  const stub = await stubOf({ profile: "v3" });
  const wallet = newWallet();
  await wallet.keygen({ name: "u", profile: "v4", issuerUrl: stub.url });
  await assert.rejects(
    requestCredential({ wallet, name: "u", issuer: new IssuerClient({ baseUrl: stub.url }), enrolmentCode: stub.enrol(ATTRS) }),
    (e) => e.code === "PROFILE_MISMATCH",
  );
  assert.equal(stub.requests.filter((r) => r.method === "POST").length, 0);
});

test("requesting twice for an already issued credential is refused", async () => {
  const stub = await stubOf();
  const { run } = await enrol(stub);
  await run();
  await assert.rejects(run(), (e) => e.code === "ALREADY_ISSUED");
});

test("v4 enrolment: the attrHash signature over the admin-assigned attributes verifies", async () => {
  const stub = await stubOf({ profile: "v4" });
  const wallet = newWallet();
  await wallet.keygen({ name: "u", profile: "v4", issuerUrl: stub.url });
  const attributes = { role: 1, dept: 1, clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };
  await requestCredential({ wallet, name: "u", issuer: new IssuerClient({ baseUrl: stub.url }), enrolmentCode: stub.enrol(attributes) });
  assert.equal(wallet.load("u").status, "issued");
  assert.deepEqual(wallet.load("u").attributes, attributes);
});
