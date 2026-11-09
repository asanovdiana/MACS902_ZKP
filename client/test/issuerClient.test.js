"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { IssuerClient, ClientError } = require("../src");
const { startStubIssuer } = require("./helpers/stubIssuer");

let stub;
test.before(async () => { stub = await startStubIssuer({ profile: "v3" }); });
test.after(() => stub.close());

const ATTRS = { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 };

test("getIssuer and getRoot follow issuer.api v2", async () => {
  const c = new IssuerClient({ baseUrl: stub.url });
  const i = await c.getIssuer();
  assert.equal(i.profile, "v3");
  assert.equal(i.issuer.Ax, stub.pub.Ax);
  const r = await c.getRoot();
  assert.equal(r.profile, "v3");
  assert.ok(r.root);
});

test("requestCredential sends exactly {commitment, enrolmentCode} and nothing else", async () => {
  const seen = [];
  const spy = async (url, init) => { seen.push({ url: String(url), init }); return fetch(url, init); };
  const c = new IssuerClient({ baseUrl: stub.url, fetch: spy });
  const SECRET = "123456789012345678901234567890";
  await c.requestCredential({
    commitment: "777", enrolmentCode: stub.enrol(ATTRS), attributes: { ...ATTRS, role: 3 },
    // anything extra, such as a caller mistakenly passing secrets, must be dropped by the allow-list
    credentialSecret: SECRET, credentialSalt: "999888777", secrets: { credentialSecret: SECRET },
  });
  assert.equal(seen.length, 1);
  const body = JSON.parse(seen[0].init.body);
  assert.deepEqual(Object.keys(body).sort(), ["commitment", "enrolmentCode"]);
  const wire = JSON.stringify(seen);
  for (const needle of [SECRET, "999888777", "credentialSecret", "credentialSalt"]) {
    assert.equal(wire.includes(needle), false, `leaked ${needle}`);
  }
});

test("requestCredential refuses a missing or malformed code and a non-canonical commitment before any network call", async () => {
  let calls = 0;
  const c = new IssuerClient({ baseUrl: "http://x.test", fetch: async () => { calls++; return new Response("{}"); } });
  for (const enrolmentCode of [undefined, null, 5, "", "short", "a b".repeat(8), "x".repeat(129), { a: 1 }]) {
    await assert.rejects(c.requestCredential({ commitment: "5", enrolmentCode }), (e) => e instanceof ClientError && e.code === "INVALID_REQUEST");
  }
  await assert.rejects(c.requestCredential({ commitment: "0123", enrolmentCode: "x".repeat(32) }), (e) => e.code === "INVALID_REQUEST");
  await assert.rejects(c.requestCredential({ commitment: "0", enrolmentCode: "x".repeat(32) }), (e) => e.code === "INVALID_REQUEST");
  assert.equal(calls, 0);
});

test("path is cached per root and refreshed when the root changes", async () => {
  const c = new IssuerClient({ baseUrl: stub.url });
  await c.requestCredential({ commitment: "11", enrolmentCode: stub.enrol(ATTRS) });
  const idx = stub.tree.leaves.length - 1;
  const pathHits = () => stub.requests.filter((r) => r.url.startsWith("/path/")).length;
  const before = pathHits();
  const p1 = await c.getPath(idx);
  const p2 = await c.getPath(idx);
  assert.deepEqual(p1, p2);
  assert.equal(pathHits() - before, 1, "second call must come from the cache");
  await c.requestCredential({ commitment: "12", enrolmentCode: stub.enrol(ATTRS) }); // root moves
  await c.getPath(idx);
  assert.equal(pathHits() - before, 2, "root change must refresh the path");
});

test("410 revoked and 404 unknown_leaf become ClientErrors with the issuer's code", async () => {
  const c = new IssuerClient({ baseUrl: stub.url });
  const { credential } = await c.requestCredential({ commitment: "21", enrolmentCode: stub.enrol(ATTRS) });
  await stub.revoke(credential.leafIndex);
  await assert.rejects(c.getPath(credential.leafIndex), (e) =>
    e instanceof ClientError && e.code === "revoked" && e.status === 410 && /revoked/i.test(e.message));
  await assert.rejects(c.getPath(9999), (e) => e.code === "unknown_leaf" && e.status === 404);
});

test("network failure and non-JSON replies are clear errors", async () => {
  const dead = new IssuerClient({ baseUrl: "http://127.0.0.1:1", timeoutMs: 500 });
  await assert.rejects(dead.getRoot(), (e) => e.code === "ISSUER_UNREACHABLE");
  const bad = new IssuerClient({ baseUrl: "http://x.test", fetch: async () => new Response("<html>", { status: 502 }) });
  await assert.rejects(bad.getRoot(), (e) => e.code === "ISSUER_BAD_RESPONSE");
});

test("rejects a malformed leaf index before any network call", async () => {
  let calls = 0;
  const c = new IssuerClient({ baseUrl: "http://x.test", fetch: async () => { calls++; return new Response("{}"); } });
  for (const bad of [-1, 1.5, "a", "../x", NaN]) {
    await assert.rejects(c.getPath(bad), (e) => e.code === "INVALID_REQUEST");
  }
  assert.equal(calls, 0);
});
