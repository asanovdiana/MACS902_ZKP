"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { tmpDir, zk } = require("./helpers");
const { loadOrCreateKey } = require("../src/keys");
const { createSigner } = require("../src/signer");
const { loadConfig } = require("../src/config");

describe("keys (G0-S1-IDEN-001)", () => {
  it("generates a 32-byte key once, mode 0600, and returns the same key on reload", () => {
    const dir = path.join(tmpDir(), "nested", "keys");
    const a = loadOrCreateKey(dir);
    assert.strictEqual(a.length, 32);
    const files = fs.readdirSync(dir);
    assert.deepStrictEqual(files, ["issuer.key"]);
    const st = fs.statSync(path.join(dir, files[0]));
    assert.strictEqual(st.mode & 0o777, 0o600);
    assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700);
    const b = loadOrCreateKey(dir);
    assert.ok(a.equals(b));
  });

  it("leaves no temp files behind and two generations in one dir do not overwrite", () => {
    const dir = tmpDir();
    const a = loadOrCreateKey(dir);
    const b = loadOrCreateKey(dir);
    assert.ok(a.equals(b));
    assert.deepStrictEqual(fs.readdirSync(dir), ["issuer.key"]);
  });

  it("refuses a key file readable by group or other", () => {
    const dir = tmpDir();
    loadOrCreateKey(dir);
    fs.chmodSync(path.join(dir, "issuer.key"), 0o644);
    assert.throws(() => loadOrCreateKey(dir), /permissions/);
  });

  it("refuses a malformed key file without printing its content", () => {
    const dir = tmpDir();
    fs.writeFileSync(path.join(dir, "issuer.key"), "deadbeef-not-a-key\n", { mode: 0o600 });
    assert.throws(
      () => loadOrCreateKey(dir),
      (e) => /malformed/.test(e.message) && !e.message.includes("deadbeef")
    );
  });

  it("the signer exposes only the public key and signs reproducibly under the same key", async () => {
    const dir = tmpDir();
    const prv = loadOrCreateKey(dir);
    const s1 = await createSigner({ profile: "v3", prv });
    const s2 = await createSigner({ profile: "v3", prv: loadOrCreateKey(dir) });
    assert.deepStrictEqual(s1.publicKey, s2.publicKey);
    assert.deepStrictEqual(s1.publicKey, await zk.publicKey(prv));
    const dump = JSON.stringify(s1) + Object.keys(s1).join(",");
    assert.ok(!dump.includes(prv.toString("hex")));
    assert.ok(!Object.values(s1).some((v) => Buffer.isBuffer(v)));
  });
});

describe("key directory mode (SR-10)", () => {
  it("creates the directory 0700 whatever the umask, including parents it creates", () => {
    const old = process.umask(0o000);
    try {
      const dir = path.join(tmpDir(), "a", "b");
      loadOrCreateKey(dir);
      assert.strictEqual(fs.statSync(dir).mode & 0o777, 0o700);
    } finally {
      process.umask(old);
    }
  });

  it("refuses a pre-existing directory accessible by group or other, without creating a key", () => {
    for (const mode of [0o755, 0o750, 0o705, 0o770, 0o777]) {
      const dir = tmpDir();
      fs.chmodSync(dir, mode);
      assert.throws(() => loadOrCreateKey(dir), /directory.*group\/other/);
      assert.deepStrictEqual(fs.readdirSync(dir), [], mode.toString(8));
    }
  });

  it("accepts a pre-existing 0700 directory and a key written earlier", () => {
    const dir = tmpDir();
    fs.chmodSync(dir, 0o700);
    const a = loadOrCreateKey(dir);
    assert.ok(a.equals(loadOrCreateKey(dir)));
  });
});

describe("config", () => {
  it("defaults to v3 profile and issuer/keys + issuer/data under the package dir", () => {
    const c = loadConfig({});
    assert.strictEqual(c.profile, "v3");
    assert.strictEqual(c.keyDir, path.resolve(__dirname, "..", "keys"));
    assert.strictEqual(c.dataDir, path.resolve(__dirname, "..", "data"));
    assert.strictEqual(c.stalenessSeconds, 30);
  });
  it("reads ISSUER_PROFILE, ISSUER_KEY_DIR, ISSUER_DATA_DIR, ISSUER_PORT, ISSUER_HOST", () => {
    const c = loadConfig({ ISSUER_PROFILE: "v4", ISSUER_KEY_DIR: "/x/k", ISSUER_DATA_DIR: "/x/d", ISSUER_PORT: "9100", ISSUER_HOST: "0.0.0.0" });
    assert.deepStrictEqual([c.profile, c.keyDir, c.dataDir, c.port, c.host], ["v4", "/x/k", "/x/d", 9100, "0.0.0.0"]);
  });
  it("rejects an unknown profile and a bad port", () => {
    assert.throws(() => loadConfig({ ISSUER_PROFILE: "v5" }), /ISSUER_PROFILE/);
    assert.throws(() => loadConfig({ ISSUER_PORT: "abc" }), /ISSUER_PORT/);
  });
});
