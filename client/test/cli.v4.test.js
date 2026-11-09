"use strict";
// zkgate CLI, v4: child processes against the real issuer and the challenge stub.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const zk = require("../../circuits/lib");
const verifier = require("../../circuits/scripts/verify.js");
const { startRealIssuer } = require("./helpers/realIssuer");
const { startChallengeStub } = require("./helpers/challengeStub");
const { mk, rm } = require("./helpers/tmp");

const BIN = path.join(__dirname, "..", "bin", "zkgate");
const VKEY = path.join(__dirname, "..", "..", "circuits", "setup", "integrated_access_v4.verification_key.json");
const NOW = 1794128400;

let iss, gw, home, out;
test.before(async () => {
  iss = await startRealIssuer({ profile: "v4", clock: () => NOW });
  gw = await startChallengeStub({ now: NOW });
  home = mk();
  out = mk();
});
test.after(async () => { await gw.close(); await iss.close(); rm(home); rm(out); await verifier.terminate(); });

const zkgate = (args) =>
  new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, ZKGATE_HOME: path.join(home, "w") } });
    let so = "", se = "";
    p.stdout.on("data", (d) => (so += d));
    p.stderr.on("data", (d) => (se += d));
    p.on("close", (code) => resolve({ code, so, se }));
  });

async function enrol(name, role, dept, clearance) {
  let r = await zkgate(["keygen", "--name", name, "--issuer", iss.url]);
  assert.equal(r.code, 0, r.se);
  const code = await iss.enrol({ role, dept, clearance, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 });
  r = await zkgate(["request", "--name", name, "--issuer", iss.url, "--code", code]);
  assert.equal(r.code, 0, r.se);
  return JSON.parse(fs.readFileSync(path.join(home, "w", "credentials", `${name}.json`), "utf8"));
}

const noSecrets = (cred, text) => {
  for (const v of [cred.secrets.credentialSecret, cred.secrets.credentialSalt, cred.signature.S, cred.signature.R8x, ...(cred.merklePath || [])]) {
    assert.ok(!text.includes(String(v)), "secret value in output");
  }
};

test("prove --challenge FILE --out writes proof.json and public.json that verify", async () => {
  const cred = await enrol("alice", "engineer", "engineering", 2);
  const ch = gw.challenge("file_share");
  const f = path.join(out, "challenge.json");
  fs.writeFileSync(f, JSON.stringify(ch));
  const o = path.join(out, "alice");
  const r = await zkgate(["prove", "--name", "alice", "--challenge", f, "--out", o]);
  assert.equal(r.code, 0, r.se);
  noSecrets(cred, r.so + r.se);
  const proof = JSON.parse(fs.readFileSync(path.join(o, "proof.json"), "utf8"));
  const pub = JSON.parse(fs.readFileSync(path.join(o, "public.json"), "utf8"));
  assert.equal(pub.length, 12);
  assert.equal(pub[9], ch.nonce);
  assert.equal(pub[0], await zk.nullifier(cred.secrets.credentialSecret, 2, ch.epoch));
  assert.equal(await verifier.verify(verifier.loadVerificationKey(VKEY), pub, proof), true);
  noSecrets(cred, JSON.stringify(proof) + JSON.stringify(pub));
});

test("prove --challenge without --out prints {proof, publicSignals} only", async () => {
  const cred = wallet("alice");
  const f = path.join(out, "c2.json");
  fs.writeFileSync(f, JSON.stringify(gw.challenge("wiki")));
  const r = await zkgate(["prove", "--name", "alice", "--challenge", f]);
  assert.equal(r.code, 0, r.se);
  const j = JSON.parse(r.so);
  assert.deepEqual(Object.keys(j).sort(), ["proof", "publicSignals"]);
  noSecrets(cred, r.so);
});

test("prove --gateway URL --resource NAME --submit fetches the challenge, proves and is admitted", async () => {
  const cred = wallet("alice");
  const r = await zkgate(["prove", "--name", "alice", "--gateway", gw.url, "--resource", "wiki", "--submit"]);
  assert.equal(r.code, 0, r.se);
  assert.match(r.so, /gateway: \{"admitted":true,"resource":"wiki"\}/);
  noSecrets(cred, r.so + r.se);
  assert.ok(gw.log.some((l) => l.method === "GET" && l.path === "/challenge"));
  assert.ok(gw.log.some((l) => l.method === "POST" && l.path === "/access"));
});

test("--gateway without --submit prints the proof and sends nothing to /access", async () => {
  const before = gw.log.filter((l) => l.path === "/access").length;
  const r = await zkgate(["prove", "--name", "alice", "--gateway", gw.url, "--resource", "file_share"]);
  assert.equal(r.code, 0, r.se);
  assert.equal(JSON.parse(r.so).publicSignals.length, 12);
  assert.equal(gw.log.filter((l) => l.path === "/access").length, before);
});

test("policy refusal exits 1 with the reasons on stderr and no proof on stdout", async () => {
  const cred = await enrol("bob", "contractor", "operations", 1);
  const r = await zkgate(["prove", "--name", "bob", "--gateway", gw.url, "--resource", "admin_panel", "--submit"]);
  assert.equal(r.code, 1);
  assert.equal(r.so, "");
  assert.match(r.se, /ROLE_NOT_ALLOWED/);
  assert.match(r.se, /CLEARANCE_TOO_LOW/);
  noSecrets(cred, r.se);
});

test("an unknown resource and an invalid challenge file are refused without a stack trace", async () => {
  let r = await zkgate(["prove", "--name", "alice", "--gateway", gw.url, "--resource", "coffee"]);
  assert.equal(r.code, 1);
  assert.match(r.se, /resource must be one of/);
  const f = path.join(out, "bad.json");
  fs.writeFileSync(f, JSON.stringify({ ...gw.challenge("wiki"), epoch: 1 }));
  r = await zkgate(["prove", "--name", "alice", "--challenge", f]);
  assert.equal(r.code, 1);
  assert.match(r.se, /epoch/);
  assert.ok(!/\n\s+at /.test(r.se));
});

test("--submit without --gateway is a usage error", async () => {
  const f = path.join(out, "c3.json");
  fs.writeFileSync(f, JSON.stringify(gw.challenge("wiki")));
  const r = await zkgate(["prove", "--name", "alice", "--challenge", f, "--submit"]);
  assert.equal(r.code, 2);
});

function wallet(name) {
  return JSON.parse(fs.readFileSync(path.join(home, "w", "credentials", `${name}.json`), "utf8"));
}
