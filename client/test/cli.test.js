"use strict";
// CLI smoke tests: real child processes against the in-process stub issuer.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const verifier = require("../../circuits/scripts/verify.js");
const { startStubIssuer } = require("./helpers/stubIssuer");
const { mk, rm } = require("./helpers/tmp");

const BIN = path.join(__dirname, "..", "bin", "zkgate");
const VKEY = path.join(__dirname, "..", "..", "circuits", "setup", "integrated_access_v3.verification_key.json");

const ATTRS = { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 };
let stub, home, out;
test.before(async () => {
  stub = await startStubIssuer({ profile: "v3" });
  home = mk();
  out = mk();
});
test.after(async () => { await stub.close(); rm(home); rm(out); await verifier.terminate(); });

const zkgate = (args, env = {}) =>
  new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, ZKGATE_HOME: path.join(home, "w"), ...env } });
    let so = "", se = "";
    p.stdout.on("data", (d) => (so += d));
    p.stderr.on("data", (d) => (se += d));
    p.on("close", (code) => resolve({ code, so, se }));
  });

test("no arguments and --help print usage; unknown command exits 2", async () => {
  assert.equal((await zkgate(["--help"])).code, 0);
  assert.match((await zkgate(["--help"])).so, /zkgate keygen/);
  const r = await zkgate(["frobnicate"]);
  assert.equal(r.code, 2);
  assert.match(r.se, /unknown command/i);
});

test("keygen -> request -> status -> prove, output never contains secret, salt or signature", async () => {
  let r = await zkgate(["keygen", "--name", "alice", "--issuer", stub.url]);
  assert.equal(r.code, 0, r.se);
  const f = path.join(home, "w", "credentials", "alice.json");
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  const cred = JSON.parse(fs.readFileSync(f, "utf8"));
  assert.equal(cred.status, "pending");
  assert.ok(r.so.includes(cred.commitment));

  r = await zkgate(["request", "--name", "alice", "--issuer", stub.url, "--code", stub.enrol(ATTRS)]);
  assert.equal(r.code, 0, r.se);
  const issued = JSON.parse(fs.readFileSync(f, "utf8"));
  assert.equal(issued.status, "issued");

  const st = await zkgate(["status", "--name", "alice"]);
  assert.equal(st.code, 0, st.se);
  assert.match(st.so, /issued/);
  assert.match(st.so, /attributes \(assigned by your administrator\): role=2, clearance=2, deviceCompliant=1, employeeActive=1/);

  const pr = await zkgate(["prove", "--name", "alice", "--issuer", stub.url, "--out", out]);
  assert.equal(pr.code, 0, pr.se);

  const secrets = [issued.secrets.credentialSecret, issued.secrets.credentialSalt, issued.signature.S, issued.signature.R8x];
  for (const text of [r.so, r.se, st.so, st.se, pr.so, pr.se]) {
    for (const s of secrets) assert.equal(text.includes(s), false, "CLI output leaked a private value");
  }

  const proof = JSON.parse(fs.readFileSync(path.join(out, "proof.json"), "utf8"));
  const pub = JSON.parse(fs.readFileSync(path.join(out, "public.json"), "utf8"));
  assert.equal(await verifier.verify(verifier.loadVerificationKey(VKEY), pub, proof), true);
});

test("prove without --out prints {proof, publicSignals} JSON on stdout", async () => {
  const pr = await zkgate(["prove", "--name", "alice", "--issuer", stub.url]);
  assert.equal(pr.code, 0, pr.se);
  const j = JSON.parse(pr.so);
  assert.deepEqual(Object.keys(j).sort(), ["proof", "publicSignals"]);
});

test("a revoked credential: prove exits 1 with a clear message and no proof", async () => {
  await zkgate(["keygen", "--name", "dave", "--issuer", stub.url]);
  await zkgate(["request", "--name", "dave", "--issuer", stub.url, "--code", stub.enrol(ATTRS)]);
  const idx = JSON.parse(fs.readFileSync(path.join(home, "w", "credentials", "dave.json"), "utf8")).leafIndex;
  await stub.revoke(idx);
  const pr = await zkgate(["prove", "--name", "dave", "--issuer", stub.url]);
  assert.equal(pr.code, 1);
  assert.match(pr.se, /revoked/i);
  assert.equal(pr.so, "");
});

test("errors are one line, no stack trace; missing credential is explained", async () => {
  const r = await zkgate(["status", "--name", "nobody"]);
  assert.equal(r.code, 1);
  assert.match(r.se, /no credential named/i);
  assert.doesNotMatch(r.se, /\n\s+at /);
});

test("request without --issuer, without --code, or with attribute flags fails with a usage hint; nothing is sent", async () => {
  await zkgate(["keygen", "--name", "erin", "--issuer", stub.url]);
  const posts = () => stub.requests.filter((q) => q.method === "POST").length;
  const before = posts();
  let r = await zkgate(["request", "--name", "erin", "--issuer", stub.url]);
  assert.equal(r.code, 2);
  assert.match(r.se, /--code/);
  r = await zkgate(["request", "--name", "erin", "--issuer", stub.url, "--code", stub.enrol(ATTRS), "--role", "3", "--clearance", "3"]);
  assert.equal(r.code, 2);
  assert.match(r.se, /assigned by your administrator/);
  assert.equal(posts(), before);
});

test("ZKGATE_ENROLMENT_CODE works as the code; a used code is refused with the issuer's code", async () => {
  await zkgate(["keygen", "--name", "fay", "--issuer", stub.url]);
  const code = stub.enrol(ATTRS);
  let r = await zkgate(["request", "--name", "fay", "--issuer", stub.url], { ZKGATE_ENROLMENT_CODE: code });
  assert.equal(r.code, 0, r.se);
  await zkgate(["keygen", "--name", "gus", "--issuer", stub.url]);
  r = await zkgate(["request", "--name", "gus", "--issuer", stub.url, "--code", code]);
  assert.equal(r.code, 1);
  assert.match(r.se, /enrolment_used/);
  assert.ok(!r.se.includes(code), "the code is never echoed");
});

test("SR-09: a corrupt pins file makes request fail closed; --issuer-key is the documented way around it", async () => {
  await zkgate(["keygen", "--name", "hal", "--issuer", stub.url]);
  fs.writeFileSync(path.join(home, "w", "pins.json"), "garbage");
  const before = stub.requests.filter((q) => q.method === "POST").length;
  let r = await zkgate(["request", "--name", "hal", "--issuer", stub.url, "--code", stub.enrol(ATTRS)]);
  assert.equal(r.code, 1);
  assert.match(r.se, /pin file/);
  assert.equal(stub.requests.filter((q) => q.method === "POST").length, before);
  r = await zkgate(["request", "--name", "hal", "--issuer", stub.url, "--issuer-key", `${stub.pub.Ax}:${stub.pub.Ay}`, "--code", stub.enrol(ATTRS)]);
  assert.equal(r.code, 0, r.se);
  fs.rmSync(path.join(home, "w", "pins.json"));
});
