"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { makeApp, tmpDir, json, zk, adminReq, ADMIN_TOKEN } = require("./helpers");
const { seedPersonas, PERSONAS, DEFAULT_EXPIRY, parseArgs } = require("../scripts/seed-personas");
const { Wallet } = require("../../client/src");

async function listening(profile) {
  const ctx = await makeApp({ profile, secure: true });
  const address = await ctx.app.listen({ host: "127.0.0.1", port: 0 });
  return { ...ctx, url: address };
}
const seed = (url, homeRoot, o = {}) => seedPersonas({ issuerUrl: url, adminToken: ADMIN_TOKEN, homeRoot, ...o });
const readWallet = (home, name) => JSON.parse(fs.readFileSync(path.join(home, "credentials", `${name}.json`), "utf8"));

describe("seed-personas (G2-S1-IDEN-022)", () => {
  it("v4: seeds Alice, Bob and Carol with the D6 attributes, one wallet home each", async () => {
    const { app, url, sink } = await listening("v4");
    const homeRoot = tmpDir("seed-");
    const out = await seed(url, homeRoot);
    assert.deepEqual(out.map((p) => p.name), ["alice", "bob", "carol"]);
    assert.deepEqual(out.map((p) => p.leafIndex), [0, 1, 2]);
    assert.ok(out.every((p) => p.status === "issued" && p.profile === "v4"));
    const want = {
      alice: { role: zk.ROLES.engineer, dept: zk.DEPTS.engineering, clearance: 2 },
      bob: { role: zk.ROLES.contractor, dept: zk.DEPTS.operations, clearance: 1 },
      carol: { role: zk.ROLES.admin, dept: zk.DEPTS.it, clearance: 3 },
    };
    for (const name of ["alice", "bob", "carol"]) {
      const home = path.join(homeRoot, name);
      const cred = readWallet(home, name);
      assert.deepEqual({ role: cred.attributes.role, dept: cred.attributes.dept, clearance: cred.attributes.clearance }, want[name]);
      assert.equal(cred.attributes.deviceCompliant, 1);
      assert.equal(cred.attributes.employeeActive, 1);
      assert.equal(cred.attributes.expiry, DEFAULT_EXPIRY);
      assert.equal(fs.readdirSync(path.join(home, "credentials")).length, 1, "one persona per home");
      assert.equal(fs.statSync(path.join(home, "credentials", `${name}.json`)).mode & 0o077, 0);
      assert.equal(new Wallet({ home }).summary(name).status, "issued");
    }
    assert.equal(json(await adminReq(app, "GET", "/admin/leaves")).total, 3);
    // The wallet secrets never reach the issuer; nothing of the wallet's secrets is in its log.
    for (const name of ["alice", "bob", "carol"]) {
      const c = readWallet(path.join(homeRoot, name), name);
      assert.ok(!sink.text().includes(c.secrets.credentialSecret));
      assert.ok(!sink.text().includes(c.secrets.credentialSalt));
    }
    await app.close();
  });

  it("is idempotent: a second run issues nothing new", async () => {
    const { app, url } = await listening("v4");
    const homeRoot = tmpDir("seed-");
    const first = await seed(url, homeRoot);
    const second = await seed(url, homeRoot);
    assert.deepEqual(second.map((p) => p.leafIndex), first.map((p) => p.leafIndex));
    assert.ok(second.every((p) => p.skipped === true));
    assert.equal(json(await adminReq(app, "GET", "/admin/leaves")).total, 3);
    assert.equal(json(await adminReq(app, "GET", "/admin/enrolments")).total, 3, "no second enrolment");
    await app.close();
  });

  it("honours a custom expiry and persona subset", async () => {
    const { app, url } = await listening("v4");
    const homeRoot = tmpDir("seed-");
    const out = await seed(url, homeRoot, { expiry: 1_900_000_000, only: ["bob"] });
    assert.deepEqual(out.map((p) => p.name), ["bob"]);
    assert.equal(readWallet(path.join(homeRoot, "bob"), "bob").attributes.expiry, 1_900_000_000);
    await app.close();
  });

  it("v3: seeds the same people by their D6 numbers; Alice can be made File-Share-provable", async () => {
    const { app, url } = await listening("v3");
    const homeRoot = tmpDir("seed-");
    await seed(url, homeRoot);
    const a = readWallet(path.join(homeRoot, "alice"), "alice").attributes;
    const b = readWallet(path.join(homeRoot, "bob"), "bob").attributes;
    const c = readWallet(path.join(homeRoot, "carol"), "carol").attributes;
    assert.deepEqual(a, { role: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1 });
    assert.deepEqual(b, { role: 2, clearance: 1, deviceCompliant: 1, employeeActive: 1 });
    assert.deepEqual(c, { role: 1, clearance: 3, deviceCompliant: 1, employeeActive: 1 });
    await app.close();

    const second = await listening("v3");
    const home2 = tmpDir("seed-");
    await seed(second.url, home2, { v3Provable: true });
    const a2 = readWallet(path.join(home2, "alice"), "alice").attributes;
    assert.equal(a2.role, 2);
    assert.equal(a2.clearance, 2);
    await second.app.close();
  });

  it("needs the admin token, and a wrong token enrols nobody", async () => {
    const { app, url } = await listening("v4");
    await assert.rejects(seedPersonas({ issuerUrl: url, homeRoot: tmpDir("seed-") }), /admin token is required/);
    await assert.rejects(seedPersonas({ issuerUrl: url, adminToken: "wrong", homeRoot: tmpDir("seed-") }), /HTTP 401 unauthorized/);
    assert.equal(app.registry.size(), 0);
    await app.close();
  });

  it("replaces a stale unredeemed enrolment left by an earlier run, and never re-enrols a revoked persona", async () => {
    const { app, url } = await listening("v4");
    const homeRoot = tmpDir("seed-");
    const stale = await adminReq(app, "POST", "/admin/enrolments", { employeeId: "alice", attributes: { role: 0, dept: 0, clearance: 0, deviceCompliant: 0, employeeActive: 1, expiry: 4070908800 } });
    assert.equal(stale.statusCode, 201);
    await seed(url, homeRoot);
    assert.equal(readWallet(path.join(homeRoot, "alice"), "alice").attributes.clearance, 2, "the persona's attributes, not the stale ones");
    assert.equal((await adminReq(app, "POST", "/credentials/0/revoke")).statusCode, 200);
    const again = await seed(url, homeRoot);
    assert.ok(again.every((p) => p.skipped), "an issued (even revoked) wallet is skipped: revoke and re-enrol are the admin's decision");
    await app.close();
  });

  it("refuses an unknown persona and parses CLI arguments", async () => {
    await assert.rejects(seedPersonas({ issuerUrl: "http://127.0.0.1:1", adminToken: "t", homeRoot: tmpDir("seed-"), only: ["mallory"] }), /unknown persona/);
    assert.deepEqual(
      parseArgs(["--issuer", "http://x:1", "--home", "/h", "--expiry", "123", "--only", "alice,bob", "--v3-provable", "--admin-token", "tok"], {}),
      { issuerUrl: "http://x:1", homeRoot: "/h", expiry: 123, only: ["alice", "bob"], v3Provable: true, adminToken: "tok" },
    );
    assert.equal(parseArgs([], { ISSUER_ADMIN_TOKEN: "envtok" }).adminToken, "envtok");
    assert.equal(parseArgs([], { ZKGATE_HOME: "/z" }).homeRoot, "/z");
    assert.throws(() => parseArgs(["--bogus"], {}), /unknown option/);
    assert.deepEqual(Object.keys(PERSONAS), ["alice", "bob", "carol"]);
  });
});
