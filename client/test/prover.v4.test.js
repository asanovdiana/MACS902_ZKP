"use strict";
// v4: input building, local policy refusal and real proving with the committed v4 artefacts.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const zk = require("../../circuits/lib");
const verifier = require("../../circuits/scripts/verify.js");
const { Wallet, IssuerClient, requestCredential, prove, prepareV4, shutdown, ARTEFACT_DIR } = require("../src");
const { toInts } = require("./helpers/attrs");
const { startStubIssuer } = require("./helpers/stubIssuer");
const { mk, rm } = require("./helpers/tmp");

const NOW = 1794128400; // 2026-11-08T09:00:00Z, as in the lib vectors
const EXPIRY = 4070908800;
const ALICE = { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY };
const BOB = { role: "contractor", dept: "operations", clearance: 1, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY };
const ADMIN = { role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY };

const challengeFor = (resource, nonce = "188145448239764496473744807162415126743", now = NOW) => {
  const p = zk.policies[resource];
  return {
    nonce, resourceId: p.resourceId, epoch: Math.floor(now / 600), now,
    policy: { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice },
  };
};

let stub, dir, wallet, issuer;
test.before(async () => {
  stub = await startStubIssuer({ profile: "v4" });
  dir = mk();
  wallet = new Wallet({ home: path.join(dir, "h") });
  issuer = new IssuerClient({ baseUrl: stub.url });
});
test.after(async () => { await stub.close(); rm(dir); await shutdown(); });

async function enrol(name, attributes) {
  await wallet.keygen({ name, profile: "v4", issuerUrl: stub.url });
  await requestCredential({ wallet, name, issuer, enrolmentCode: stub.enrol(toInts("v4", attributes)) });
  return wallet.load(name);
}

test("prepareV4 builds the circuit input in access.public_signals v4 order and predicts the signals", async () => {
  const cred = await enrol("alice", ALICE);
  const ch = challengeFor("file_share");
  const { input, expectedSignals } = await prepareV4({ credential: cred, issuer, challenge: ch });
  assert.deepEqual(Object.keys(input).slice(-11), zk.PUBLIC_SIGNALS.v4.slice(1));
  assert.equal(input.nonce, ch.nonce);
  assert.equal(input.resourceId, "2");
  assert.equal(input.epoch, String(ch.epoch));
  assert.equal(input.now, String(NOW));
  assert.equal(input.issuerAx, stub.pub.Ax);
  assert.equal(input.root, (await issuer.getRoot()).root);
  assert.equal(input.pathElements.length, 16);
  assert.equal(expectedSignals.length, 12);
  assert.equal(expectedSignals[0], await zk.nullifier(cred.secrets.credentialSecret, 2, ch.epoch));
});

test("Bob (contractor) -> Admin Panel is refused locally with reasons, no proof attempted", async () => {
  const cred = await enrol("bob", BOB);
  await assert.rejects(prove({ credential: cred, issuer, challenge: challengeFor("admin_panel") }), (e) => {
    assert.equal(e.code, "POLICY_NOT_SATISFIED");
    const codes = e.reasons.map((r) => r.code);
    assert.ok(codes.includes("ROLE_NOT_ALLOWED"));
    assert.ok(codes.includes("CLEARANCE_TOO_LOW"));
    return true;
  });
});

test("an expired credential is refused locally", async () => {
  const cred = await enrol("old", { ...ALICE, expiry: NOW + 5 });
  await assert.rejects(
    prepareV4({ credential: cred, issuer, challenge: challengeFor("wiki", "5", NOW + 10) }),
    (e) => e.code === "CREDENTIAL_EXPIRED" && e.reasons.some((r) => r.code === "CREDENTIAL_EXPIRED"),
  );
});

test("a challenge whose epoch does not match its now is refused (client never invents now/epoch)", async () => {
  const cred = wallet.load("alice");
  const ch = { ...challengeFor("wiki"), epoch: 1 };
  await assert.rejects(prepareV4({ credential: cred, issuer, challenge: ch }), (e) => e.code === "INVALID_CHALLENGE");
});

test("v4 prove without a challenge is refused", async () => {
  await assert.rejects(prove({ credential: wallet.load("alice"), issuer }), (e) => e.code === "CHALLENGE_REQUIRED");
});

test("a revoked v4 credential fails at the path fetch with 'revoked'", async () => {
  const cred = await enrol("gone", ALICE);
  await stub.revoke(cred.leafIndex);
  await assert.rejects(prepareV4({ credential: cred, issuer, challenge: challengeFor("wiki") }), (e) => e.code === "revoked");
});

test("missing artefacts are reported after the local policy check passes", async () => {
  const empty = mk();
  try {
    await assert.rejects(prove({ credential: wallet.load("alice"), issuer, challenge: challengeFor("wiki"), artefactDir: empty }), (e) => {
      assert.equal(e.code, "ARTEFACTS_MISSING");
      assert.match(e.message, /integrated_access_v4/);
      return true;
    });
  } finally { rm(empty); }
});

test("v4 proof verifies with verify.js and carries the gateway's expected signals", async () => {
  const cred = wallet.load("alice");
  const ch = challengeFor("wiki");
  const r = await prove({ credential: cred, issuer, challenge: ch });
  assert.equal(r.profile, "v4");
  assert.equal(r.publicSignals.length, 12);
  assert.equal(r.publicSignals[0], await zk.nullifier(cred.secrets.credentialSecret, 1, ch.epoch));
  assert.equal(r.publicSignals[9], ch.nonce);
  const vkey = verifier.loadVerificationKey(path.join(ARTEFACT_DIR, "integrated_access_v4.verification_key.json"));
  assert.equal(await verifier.verify(vkey, r.publicSignals, r.proof), true);
  // public output never carries a private value
  const out = JSON.stringify(r);
  for (const v of [cred.secrets.credentialSecret, cred.secrets.credentialSalt, cred.commitment]) assert.ok(!out.includes(v));
});

test("a proof presented with a changed nonce does not verify", async () => {
  const r = await prove({ credential: wallet.load("alice"), issuer, challenge: challengeFor("wiki") });
  const vkey = verifier.loadVerificationKey(path.join(ARTEFACT_DIR, "integrated_access_v4.verification_key.json"));
  const tampered = r.publicSignals.slice();
  tampered[9] = "1";
  assert.equal(await verifier.verify(vkey, tampered, r.proof), false);
});
