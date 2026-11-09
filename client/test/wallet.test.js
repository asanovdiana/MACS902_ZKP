"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const zk = require("../../circuits/lib");
const { Wallet, ClientError } = require("../src");
const { mk, rm } = require("./helpers/tmp");

const dirs = [];
const ISSUED = {
  attributes: { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 },
  issuer: { Ax: "1", Ay: "2" }, signature: { R8x: "3", R8y: "4", S: "5" }, leafIndex: 0,
};
const newWallet = () => {
  const d = mk();
  dirs.push(d);
  return { home: d, wallet: new Wallet({ home: path.join(d, "home") }) };
};
test.after(() => dirs.forEach(rm));

test("keygen: secret and salt are canonical 31-byte field elements, commitment is Poseidon(2)", async () => {
  const { wallet } = newWallet();
  const r = await wallet.keygen({ name: "alice", profile: "v3", issuerUrl: "http://issuer.test" });
  const c = wallet.load("alice");
  assert.equal(c.status, "pending");
  assert.equal(c.version, 1);
  assert.equal(c.format, "zk-access-gate/credential");
  for (const k of ["credentialSecret", "credentialSalt"]) {
    assert.ok(zk.isCanonical(c.secrets[k]), k);
    assert.ok(BigInt(c.secrets[k]) < 2n ** 248n && BigInt(c.secrets[k]) > 0n);
  }
  assert.notEqual(c.secrets.credentialSecret, c.secrets.credentialSalt);
  assert.equal(c.commitment, await zk.commitment(c.secrets.credentialSecret, c.secrets.credentialSalt));
  assert.equal(r.commitment, c.commitment);
  assert.equal(JSON.stringify(r).includes(c.secrets.credentialSecret), false, "keygen result leaks secret");
  assert.equal(JSON.stringify(r).includes(c.secrets.credentialSalt), false, "keygen result leaks salt");
});

test("two keygens never share secret or salt (ADR 0005)", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "a" });
  await wallet.keygen({ name: "b" });
  const a = wallet.load("a"), b = wallet.load("b");
  assert.notEqual(a.secrets.credentialSecret, b.secrets.credentialSecret);
  assert.notEqual(a.secrets.credentialSalt, b.secrets.credentialSalt);
  assert.notEqual(a.commitment, b.commitment);
});

test("credential file has mode 0600 and the wallet directories 0700", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  const f = wallet.pathOf("alice");
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(f)).mode & 0o777, 0o700);
  assert.equal(fs.statSync(wallet.home).mode & 0o777, 0o700);
});

test("default home honours ZKGATE_HOME, then falls back to ~/.zkgate", () => {
  assert.equal(Wallet.defaultHome({ ZKGATE_HOME: "/x/y" }), "/x/y");
  assert.match(Wallet.defaultHome({}), /\.zkgate$/);
});

test("keygen refuses to overwrite an existing credential (losing the secret would orphan the leaf)", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  const before = fs.readFileSync(wallet.pathOf("alice"), "utf8");
  await assert.rejects(wallet.keygen({ name: "alice" }), (e) => e instanceof ClientError && e.code === "WALLET_EXISTS");
  assert.equal(fs.readFileSync(wallet.pathOf("alice"), "utf8"), before);
});

test("atomic write: a failed rename leaves the old file intact and no temp file behind", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  const before = fs.readFileSync(wallet.pathOf("alice"), "utf8");
  const c = wallet.load("alice");
  const orig = fs.renameSync;
  fs.renameSync = () => { throw new Error("disk gone"); };
  try {
    assert.throws(() => wallet.save("alice", { ...c, ...ISSUED, status: "issued" }), /disk gone/);
  } finally {
    fs.renameSync = orig;
  }
  assert.equal(fs.readFileSync(wallet.pathOf("alice"), "utf8"), before);
  assert.deepEqual(fs.readdirSync(path.dirname(wallet.pathOf("alice"))), ["alice.json"]);
});

test("save replaces the file atomically with mode 0600 preserved", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  const c = wallet.load("alice");
  wallet.save("alice", { ...c, ...ISSUED, status: "issued" });
  assert.equal(wallet.load("alice").leafIndex, 0);
  assert.equal(fs.statSync(wallet.pathOf("alice")).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(path.dirname(wallet.pathOf("alice"))), ["alice.json"]);
});

test("load refuses a credential file readable by group or other", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  fs.chmodSync(wallet.pathOf("alice"), 0o640);
  assert.throws(() => wallet.load("alice"), (e) => e.code === "WALLET_PERMISSIONS" && !/credentialSecret/.test(e.message));
  fs.chmodSync(wallet.pathOf("alice"), 0o604);
  assert.throws(() => wallet.load("alice"), (e) => e.code === "WALLET_PERMISSIONS");
});

test("load rejects malformed files without echoing their content", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice" });
  const f = wallet.pathOf("alice");
  fs.writeFileSync(f, "{not json SECRETISH", { mode: 0o600 });
  assert.throws(() => wallet.load("alice"), (e) => e.code === "WALLET_CORRUPT" && !/SECRETISH/.test(e.message));
  fs.writeFileSync(f, JSON.stringify({ format: "other", version: 1 }), { mode: 0o600 });
  assert.throws(() => wallet.load("alice"), (e) => e.code === "WALLET_CORRUPT");
  assert.throws(() => wallet.load("nobody"), (e) => e.code === "WALLET_NOT_FOUND");
});

test("credential names cannot escape the wallet directory", async () => {
  const { wallet } = newWallet();
  for (const bad of ["../evil", "a/b", "", ".", "..", "x\0y", "a".repeat(100)]) {
    await assert.rejects(wallet.keygen({ name: bad }), (e) => e.code === "INVALID_NAME", JSON.stringify(bad));
  }
});

test("keygen rejects an unknown profile", async () => {
  const { wallet } = newWallet();
  await assert.rejects(wallet.keygen({ name: "a", profile: "v9" }), (e) => e.code === "INVALID_PROFILE");
});

test("summary shows ids and hashes only, never secrets", async () => {
  const { wallet } = newWallet();
  await wallet.keygen({ name: "alice", profile: "v3" });
  const c = wallet.load("alice");
  const s = JSON.stringify(wallet.summary("alice"));
  assert.ok(s.includes(c.commitment));
  assert.equal(s.includes(c.secrets.credentialSecret), false);
  assert.equal(s.includes(c.secrets.credentialSalt), false);
  assert.deepEqual(wallet.list().map((x) => x.name), ["alice"]);
});

test("issuer pins persist per issuer URL", () => {
  const { wallet } = newWallet();
  assert.equal(wallet.getPin("http://i.test"), undefined);
  wallet.setPin("http://i.test", { Ax: "1", Ay: "2" });
  assert.deepEqual(wallet.getPin("http://i.test"), { Ax: "1", Ay: "2" });
  assert.equal(wallet.getPin("http://other.test"), undefined);
  assert.equal(fs.statSync(path.join(wallet.home, "pins.json")).mode & 0o777, 0o600);
});

test("SR-09: an unparseable or malformed pins file fails closed on read and on write, and is left untouched", () => {
  const bad = ["{not json", "", "[]", "null", "42", '{"http://i.test":null}', '{"http://i.test":{"Ax":"1"}}', '{"http://i.test":{"Ax":"x","Ay":"2"}}', '{"http://i.test":{"Ax":"01","Ay":"2"}}'];
  for (const text of bad) {
    const { wallet } = newWallet();
    fs.mkdirSync(wallet.home, { recursive: true, mode: 0o700 });
    const f = path.join(wallet.home, "pins.json");
    fs.writeFileSync(f, text, { mode: 0o600 });
    assert.throws(() => wallet.getPin("http://i.test"), (e) => e instanceof ClientError && e.code === "PINS_CORRUPT", JSON.stringify(text));
    assert.throws(() => wallet.setPin("http://i.test", { Ax: "1", Ay: "2" }), (e) => e.code === "PINS_CORRUPT");
    assert.equal(fs.readFileSync(f, "utf8"), text, "a corrupt file is never overwritten");
  }
});

test("SR-09: an unreadable pins file (a directory) fails closed; a missing one is simply no pins", () => {
  const { wallet } = newWallet();
  assert.equal(wallet.getPin("http://i.test"), undefined);
  fs.mkdirSync(path.join(wallet.home, "pins.json"), { recursive: true });
  assert.throws(() => wallet.getPin("http://i.test"), (e) => e.code === "PINS_CORRUPT");
});

test("Poseidon cross-check: client commitment path uses the pinned circomlibjs vectors (floor 8)", async () => {
  const v = require("../../circuits/test/vectors/v3/poseidon.json");
  for (const s of v.samples["2"]) {
    assert.equal(await zk.commitment(s.inputs[0], s.inputs[1]), s.out);
  }
});
