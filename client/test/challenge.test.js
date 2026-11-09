"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { parseChallenge, fetchChallenge, submitProof } = require("../src");

const good = () => ({
  nonce: "188145448239764496473744807162415126743",
  resourceId: 2,
  epoch: 2990214,
  now: 1794128400,
  policy: { roleMask: 3, deptMask: 15, minClearance: 2, requireDevice: 0 },
});
const bad = (patch) => ({ ...good(), ...patch });
const code = (c) => (e) => e.code === c;

test("parseChallenge accepts the contract shape and returns canonical strings/numbers", () => {
  const c = parseChallenge(good());
  assert.equal(c.nonce, "188145448239764496473744807162415126743");
  assert.equal(c.resourceId, 2);
  assert.equal(c.policy.roleMask, 3);
});

test("parseChallenge accepts decimal strings for numeric fields", () => {
  const c = parseChallenge(bad({ resourceId: "2", epoch: "2990214", now: "1794128400" }));
  assert.equal(c.now, 1794128400);
});

test("parseChallenge rejects bad nonce, epoch/now inconsistency, resource, unknown keys, bad policy", () => {
  assert.throws(() => parseChallenge(bad({ nonce: "0123" })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ nonce: 12 })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ epoch: 5 })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ resourceId: 9 })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ extra: 1 })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ policy: { roleMask: 99, deptMask: 15, minClearance: 2, requireDevice: 0 } })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(bad({ policy: undefined })), code("INVALID_CHALLENGE"));
  assert.throws(() => parseChallenge(null), code("INVALID_CHALLENGE"));
  const { now, ...noNow } = good();
  assert.throws(() => parseChallenge(noNow), code("INVALID_CHALLENGE"));
});

test("fetchChallenge asks the gateway for a resource and parses the reply", async () => {
  const calls = [];
  const f = async (url, init) => { calls.push({ url: String(url), init }); return new Response(JSON.stringify(good()), { status: 200 }); };
  const c = await fetchChallenge({ gatewayUrl: "http://gw.test/", resource: "file_share", fetch: f });
  assert.equal(c.resourceId, 2);
  assert.equal(calls[0].url, "http://gw.test/challenge?resource=file_share");
});

test("fetchChallenge: gateway errors and garbage are clear ClientErrors", async () => {
  const f = (status, body) => async () => new Response(body, { status });
  await assert.rejects(fetchChallenge({ gatewayUrl: "http://g", resource: "wiki", fetch: f(503, "{}") }), code("GATEWAY_ERROR"));
  await assert.rejects(fetchChallenge({ gatewayUrl: "http://g", resource: "wiki", fetch: f(200, "nope") }), code("GATEWAY_BAD_RESPONSE"));
  await assert.rejects(fetchChallenge({ gatewayUrl: "http://g", resource: "wiki", fetch: f(200, "{}") }), code("INVALID_CHALLENGE"));
  await assert.rejects(fetchChallenge({ gatewayUrl: "http://g", resource: "nope" }), code("INVALID_REQUEST"));
});

test("submitProof sends only the nonce, proof and public signals", async () => {
  const seen = [];
  const f = async (url, init) => { seen.push({ url: String(url), body: JSON.parse(init.body) }); return new Response(JSON.stringify({ admitted: true }), { status: 200 }); };
  const r = await submitProof({ gatewayUrl: "http://gw.test", resource: "wiki", nonce: "5", proof: { pi_a: [] }, publicSignals: ["1"], fetch: f });
  assert.deepEqual(r, { admitted: true });
  assert.deepEqual(Object.keys(seen[0].body).sort(), ["nonce", "proof", "publicSignals", "resource"]);
});
