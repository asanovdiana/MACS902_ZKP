"use strict";
// v4 end to end: REAL issuer (in-process, temp dirs) + minimal challenge stub + real proving with
// the committed integrated_access_v4 artefacts. Personas as in issuer/scripts/seed-personas.js.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const zk = require("../../circuits/lib");
const verifier = require("../../circuits/scripts/verify.js");
const { Wallet, IssuerClient, requestCredential, prove, fetchChallenge, submitProof, shutdown } = require("../src");
const { startRealIssuer } = require("./helpers/realIssuer");
const { startChallengeStub } = require("./helpers/challengeStub");
const { mk, rm } = require("./helpers/tmp");

const NOW = 1794128400;
const EXPIRY = 4070908800;
const base = { deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY };
const PERSONAS = {
  alice: { role: "engineer", dept: "engineering", clearance: 2, ...base },
  bob: { role: "contractor", dept: "operations", clearance: 1, ...base },
  carol: { role: "admin", dept: "it", clearance: 3, ...base },
};
const VKEY = path.join(__dirname, "..", "..", "circuits", "setup", "integrated_access_v4.verification_key.json");

let iss, gw, dir, wallet, issuer, vkey;
const creds = {};
test.before(async () => {
  iss = await startRealIssuer({ profile: "v4", clock: () => NOW });
  gw = await startChallengeStub({ now: NOW });
  dir = mk();
  wallet = new Wallet({ home: path.join(dir, "h") });
  issuer = new IssuerClient({ baseUrl: iss.url });
  vkey = verifier.loadVerificationKey(VKEY);
  for (const [name, attrs] of Object.entries(PERSONAS)) {
    await wallet.keygen({ name, profile: "v4", issuerUrl: iss.url });
    await requestCredential({ wallet, name, issuer, enrolmentCode: await iss.enrol(attrs) });
    creds[name] = wallet.load(name);
  }
});
test.after(async () => { await gw.close(); await iss.close(); rm(dir); await shutdown(); });

const getChallenge = (resource) => fetchChallenge({ gatewayUrl: gw.url, resource });

for (const [who, resource] of [["alice", "wiki"], ["alice", "file_share"], ["carol", "admin_panel"], ["carol", "wiki"], ["bob", "wiki"]]) {
  test(`${who} -> ${resource}: proves, signals match the challenge, verifies, and the gateway admits`, async () => {
    const ch = await getChallenge(resource);
    const r = await prove({ credential: creds[who], issuer, challenge: ch });
    const p = zk.policies[resource];
    assert.equal(r.publicSignals.length, 12);
    assert.equal(r.publicSignals[0], await zk.nullifier(creds[who].secrets.credentialSecret, p.resourceId, ch.epoch));
    assert.equal(r.publicSignals[1], (await issuer.getRoot()).root);
    assert.deepEqual(r.publicSignals.slice(4), [p.roleMask, p.deptMask, p.minClearance, p.requireDevice, ch.now, ch.nonce, p.resourceId, ch.epoch].map(String));
    assert.equal(await verifier.verify(vkey, r.publicSignals, r.proof), true);
    const reply = await submitProof({ gatewayUrl: gw.url, resource, nonce: ch.nonce, proof: r.proof, publicSignals: r.publicSignals });
    assert.deepEqual(reply, { admitted: true, resource });
    // replay at the stub: the nonce is spent
    await assert.rejects(submitProof({ gatewayUrl: gw.url, resource, nonce: ch.nonce, proof: r.proof, publicSignals: r.publicSignals }), (e) => e.status === 403);
  });
}

for (const [who, resource, reasons] of [
  ["bob", "file_share", ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"]],
  ["bob", "admin_panel", ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"]],
  ["alice", "admin_panel", ["ROLE_NOT_ALLOWED", "CLEARANCE_TOO_LOW"]],
]) {
  test(`${who} -> ${resource} is refused locally with ${reasons.join(" + ")}; no proof is generated`, async () => {
    const ch = await getChallenge(resource);
    const before = gw.log.length;
    await assert.rejects(prove({ credential: creds[who], issuer, challenge: ch }), (e) => {
      assert.equal(e.code, "POLICY_NOT_SATISFIED");
      const codes = e.reasons.map((r) => r.code);
      for (const c of reasons) assert.ok(codes.includes(c), `${c} in ${codes}`);
      return true;
    });
    assert.equal(gw.log.length, before, "nothing was sent to the gateway");
  });
}

test("a revoked credential (issuer 410) fails at the path fetch", async () => {
  await wallet.keygen({ name: "dave", profile: "v4", issuerUrl: iss.url });
  await requestCredential({ wallet, name: "dave", issuer, enrolmentCode: await iss.enrol(PERSONAS.alice) });
  const dave = wallet.load("dave");
  await iss.revoke(dave.leafIndex);
  const ch = await getChallenge("wiki");
  await assert.rejects(prove({ credential: dave, issuer: new IssuerClient({ baseUrl: iss.url }), challenge: ch }), (e) => e.code === "revoked" && e.status === 410);
});

test("an expired credential is refused locally", async () => {
  await wallet.keygen({ name: "erin", profile: "v4", issuerUrl: iss.url });
  await requestCredential({ wallet, name: "erin", issuer, enrolmentCode: await iss.enrol({ ...PERSONAS.alice, expiry: NOW + 5 }) });
  const erin = wallet.load("erin");
  const ch = await getChallenge("wiki"); // gateway clock = NOW: still valid
  gw.clock.now = NOW + 10;
  try {
    const late = await getChallenge("wiki");
    assert.equal(late.now, NOW + 10);
    await assert.rejects(prove({ credential: erin, issuer, challenge: late }), (e) => e.code === "CREDENTIAL_EXPIRED");
  } finally { gw.clock.now = NOW; }
  assert.ok(ch.now === NOW);
});

test("a challenge whose epoch is not floor(now/600) is refused", async () => {
  const ch = { ...(await getChallenge("wiki")), epoch: 1 };
  await assert.rejects(prove({ credential: creds.alice, issuer, challenge: ch }), (e) => e.code === "INVALID_CHALLENGE");
});

test("nullifier: stable across nonces for the same resource+epoch, different across resources", async () => {
  const a = await prove({ credential: creds.carol, issuer, challenge: await getChallenge("wiki") });
  const b = await prove({ credential: creds.carol, issuer, challenge: await getChallenge("wiki") });
  const c = await prove({ credential: creds.carol, issuer, challenge: await getChallenge("file_share") });
  assert.notEqual(a.publicSignals[9], b.publicSignals[9]);
  assert.equal(a.publicSignals[0], b.publicSignals[0]);
  assert.notEqual(a.publicSignals[0], c.publicSignals[0]);
  // a different user, same resource: different nullifier
  const d = await prove({ credential: creds.alice, issuer, challenge: await getChallenge("wiki") });
  assert.notEqual(a.publicSignals[0], d.publicSignals[0]);
});

test("the gateway only ever saw nonce, proof and public signals (floor 6)", async () => {
  const ch = await getChallenge("wiki");
  const r = await prove({ credential: creds.alice, issuer, challenge: ch });
  await submitProof({ gatewayUrl: gw.url, resource: "wiki", nonce: ch.nonce, proof: r.proof, publicSignals: r.publicSignals });
  const wire = gw.log.map((l) => l.body).join("\n");
  for (const c of Object.values(creds)) {
    for (const v of [c.secrets.credentialSecret, c.secrets.credentialSalt, c.commitment, c.signature.R8x, c.signature.S]) {
      assert.ok(!wire.includes(String(v)));
    }
  }
  for (const w of ["engineer", "contractor", "engineering", "alice"]) assert.ok(!wire.includes(w));
});
