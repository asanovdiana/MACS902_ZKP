"use strict";
// v3 end to end against a stub issuer: keygen -> request -> prove -> verify with circuits/scripts/verify.js
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { Wallet, IssuerClient, requestCredential, prove, shutdown, ARTEFACT_DIR } = require("../src");
const verifier = require("../../circuits/scripts/verify.js");
const { startStubIssuer } = require("./helpers/stubIssuer");
const { mk, rm } = require("./helpers/tmp");

const ALICE = { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 }; // File Share TEST credential (v3 opaque numbers)
const BOB = { role: 2, clearance: 1, deviceCompliant: 1, employeeActive: 1 }; // v3 FileShareAccess rejects
const vkey = verifier.loadVerificationKey(path.join(ARTEFACT_DIR, "integrated_access_v3.verification_key.json"));

let stub, dir, wallet, issuer;
test.before(async () => {
  stub = await startStubIssuer({ profile: "v3" });
  dir = mk();
  wallet = new Wallet({ home: path.join(dir, "h") });
  issuer = new IssuerClient({ baseUrl: stub.url });
});
test.after(async () => {
  await stub.close();
  rm(dir);
  await shutdown();
  await verifier.terminate();
});

async function enrol(name, attributes) {
  await wallet.keygen({ name, profile: "v3", issuerUrl: stub.url });
  await requestCredential({ wallet, name, issuer, enrolmentCode: stub.enrol(attributes) });
  return wallet.load(name);
}

test("keygen -> request -> prove -> verify.js accepts; the only public signal is the current root", async () => {
  const cred = await enrol("alice", ALICE);
  const out = await prove({ credential: cred, issuer });
  const root = (await issuer.getRoot()).root;
  assert.deepEqual(out.publicSignals, [root]);
  assert.equal(await verifier.verify(vkey, out.publicSignals, out.proof), true);
  // the result carries no private input
  const wire = JSON.stringify(out);
  for (const v of [cred.secrets.credentialSecret, cred.secrets.credentialSalt, cred.signature.S]) {
    assert.equal(wire.includes(v), false);
  }
  assert.deepEqual(Object.keys(out).sort(), ["profile", "proof", "publicSignals"]);
});

test("a tampered public signal fails verification", async () => {
  const cred = wallet.load("alice");
  const out = await prove({ credential: cred, issuer });
  const bad = [(BigInt(out.publicSignals[0]) + 1n).toString()];
  assert.equal(await verifier.verify(vkey, bad, out.proof), false);
});

test("proving writes no input or witness file next to the wallet or in the cwd", async () => {
  const before = new Set(fs.readdirSync(process.cwd()));
  const cred = wallet.load("alice");
  await prove({ credential: cred, issuer });
  const after = fs.readdirSync(process.cwd()).filter((f) => !before.has(f));
  assert.deepEqual(after, []);
  assert.deepEqual(fs.readdirSync(path.join(wallet.home, "credentials")), ["alice.json"]);
});

test("revoked credential: prove fails with a clear 'revoked' error and produces no proof", async () => {
  const cred = await enrol("carol", ALICE);
  await stub.revoke(cred.leafIndex);
  await assert.rejects(prove({ credential: cred, issuer }), (e) => {
    assert.equal(e.code, "revoked");
    assert.match(e.message, /revoked/i);
    return true;
  });
});

test("an unsatisfied v3 policy is refused locally with reasons, before the prover runs", async () => {
  const cred = await enrol("bob", BOB);
  await assert.rejects(prove({ credential: cred, issuer }), (e) => {
    assert.equal(e.code, "POLICY_NOT_SATISFIED");
    assert.ok(e.reasons.some((r) => r.code === "CLEARANCE_TOO_LOW"));
    return true;
  });
});

test("a pending credential cannot prove", async () => {
  await wallet.keygen({ name: "pending", profile: "v3", issuerUrl: stub.url });
  await assert.rejects(prove({ credential: wallet.load("pending"), issuer }), (e) => e.code === "NOT_ISSUED");
});

test("missing artefacts give an ARTEFACTS_MISSING error naming the file, not a stack trace", async () => {
  const cred = wallet.load("alice");
  await assert.rejects(prove({ credential: cred, issuer, artefactDir: dir }), (e) => {
    assert.equal(e.code, "ARTEFACTS_MISSING");
    assert.match(e.message, /integrated_access_v3/);
    return true;
  });
});
