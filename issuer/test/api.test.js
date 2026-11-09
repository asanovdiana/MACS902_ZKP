"use strict";
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const { zk, makeApp, json, post, newSecrets, issue, adminEnrol, adminReq, T0, V3_ATTRS, v4Attrs, attrsFor, tmpDir, vectors } = require("./helpers");

const CODE = "x".repeat(32);

const errOf = (res) => json(res).error;
const expectErr = (res, status, code) => {
  assert.strictEqual(res.statusCode, status, res.body);
  const e = errOf(res);
  assert.strictEqual(e.code, code);
  assert.strictEqual(typeof e.message, "string");
  assert.deepStrictEqual(Object.keys(json(res)), ["error"]);
};

for (const profile of ["v3", "v4"]) {
  const P = zk.profiles[profile];

  describe(`issuer.api v1, profile ${profile}`, () => {
    let ctx;
    beforeEach(async () => {
      ctx = await makeApp({ profile });
    });
    afterEach(() => ctx.app.close());

    it("GET /issuer returns profile, depth and the public key only", async () => {
      const res = await ctx.app.inject("/issuer");
      assert.strictEqual(res.statusCode, 200);
      const b = json(res);
      assert.deepStrictEqual(Object.keys(b).sort(), ["depth", "issuer", "profile"]);
      assert.strictEqual(b.profile, profile);
      assert.strictEqual(b.depth, P.depth);
      assert.deepStrictEqual(Object.keys(b.issuer), ["Ax", "Ay"]);
      assert.ok(zk.isCanonical(b.issuer.Ax) && zk.isCanonical(b.issuer.Ay));
    });

    it("POST /credentials signs the profile's message: the lib verifies the signature (M1 done)", async () => {
      const { res, secrets, cred } = await issue(ctx.app, profile);
      assert.strictEqual(res.statusCode, 201);
      assert.deepStrictEqual(Object.keys(json(res)), ["credential"]);
      assert.deepStrictEqual(Object.keys(cred).sort(), ["attributes", "issuer", "leafIndex", "profile", "signature"]);
      assert.strictEqual(cred.profile, profile);
      assert.strictEqual(cred.leafIndex, 0);
      assert.deepStrictEqual(cred.attributes, attrsFor(profile));
      for (const k of ["R8x", "R8y", "S"]) assert.ok(zk.isCanonical(cred.signature[k]));
      const M = await P.message({ commitment: secrets.commitment, attributes: cred.attributes });
      assert.strictEqual(await zk.verifySignature(M, cred.signature, cred.issuer), true);
      // the issuer key in the response is the one /issuer publishes
      assert.deepStrictEqual(cred.issuer, json(await ctx.app.inject("/issuer")).issuer);
      // a different message does not verify
      assert.strictEqual(await zk.verifySignature(String(BigInt(M) + 1n), cred.signature, cred.issuer), false);
    });

    it("the signed message is profile-specific (v3: commitment, v4: attrHash)", async () => {
      const { secrets, cred } = await issue(ctx.app, profile);
      const viaCommitment = await zk.verifySignature(secrets.commitment, cred.signature, cred.issuer);
      assert.strictEqual(viaCommitment, profile === "v3");
    });

    it("inserts the leaf: /root and /path reflect it and match the lib tree (floor 8)", async () => {
      const { secrets, cred } = await issue(ctx.app, profile);
      const leaf = await P.leaf({ commitment: secrets.commitment, attributes: cred.attributes });
      const tree = await zk.createTree(profile);
      tree.insert(BigInt(leaf));
      const root = json(await ctx.app.inject("/root"));
      assert.deepStrictEqual(Object.keys(root).sort(), ["depth", "profile", "root", "updatedAt"]);
      assert.strictEqual(root.root, tree.root.toString());
      assert.strictEqual(root.updatedAt, T0);
      assert.strictEqual(root.depth, P.depth);
      const pr = await ctx.app.inject("/path/0");
      assert.strictEqual(pr.statusCode, 200);
      const p = json(pr);
      assert.deepStrictEqual(Object.keys(p).sort(), ["leaf", "leafIndex", "pathElements", "pathIndices", "profile", "root"]);
      assert.strictEqual(p.leaf, leaf);
      assert.strictEqual(p.root, root.root);
      assert.strictEqual(p.pathElements.length, P.depth);
      assert.ok(p.pathIndices.every((b) => b === 0 || b === 1), "pathIndices are JSON integers");
      assert.strictEqual(await zk.merkleRoot(p.leaf, p.pathElements, p.pathIndices), p.root);
    });

    it("revoke: returns the new root, /path then answers 410 revoked, old path fails against the new root (floor 3)", async () => {
      await issue(ctx.app, profile);
      const second = await issue(ctx.app, profile);
      const oldPath = json(await ctx.app.inject("/path/1"));
      ctx.clock.advance(5);
      const res = await post(ctx.app, "/credentials/1/revoke", "");
      assert.strictEqual(res.statusCode, 200, res.body);
      const { root } = json(res);
      assert.deepStrictEqual(Object.keys(json(res)), ["root"]);
      const cur = json(await ctx.app.inject("/root"));
      assert.strictEqual(cur.root, root);
      assert.strictEqual(cur.updatedAt, T0 + 5);
      assert.notStrictEqual(root, oldPath.root);
      assert.notStrictEqual(await zk.merkleRoot(oldPath.leaf, oldPath.pathElements, oldPath.pathIndices), root);
      expectErr(await ctx.app.inject("/path/1"), 410, "revoked");
      assert.strictEqual((await ctx.app.inject("/path/0")).statusCode, 200);
      assert.ok(second.cred);
      expectErr(await post(ctx.app, "/credentials/1/revoke", ""), 409, "already_revoked");
    });

    it("revoke accepts an empty body with or without a JSON content type", async () => {
      await issue(ctx.app, profile);
      const a = await ctx.app.inject({ method: "POST", url: "/credentials/0/revoke" });
      assert.strictEqual(a.statusCode, 200);
    });

    it("GET /root/history: shape, change kinds, since filter", async () => {
      await issue(ctx.app, profile);
      ctx.clock.advance(10);
      await issue(ctx.app, profile);
      ctx.clock.advance(10);
      await post(ctx.app, "/credentials/0/revoke", "");
      ctx.clock.advance(1);
      const res = await ctx.app.inject("/root/history");
      assert.strictEqual(res.statusCode, 200);
      const h = json(res);
      assert.deepStrictEqual(Object.keys(h).sort(), ["current", "now", "roots"]);
      assert.strictEqual(h.now, ctx.clock.now());
      assert.strictEqual(h.current, json(await ctx.app.inject("/root")).root);
      assert.deepStrictEqual(h.roots.map((r) => r.supersededBy), ["insert", "insert", "revoke", null]);
      for (const r of h.roots) assert.deepStrictEqual(Object.keys(r), ["root", "validFrom", "supersededAt", "supersededBy"]);
      const since = json(await ctx.app.inject(`/root/history?since=${T0 + 10}`));
      assert.strictEqual(since.roots.length, 3);
      assert.strictEqual(since.roots.at(-1).root, h.current);
    });

    it("error: invalid_json", async () => {
      expectErr(await post(ctx.app, "/credentials", "{not json"), 400, "invalid_json");
      expectErr(await post(ctx.app, "/credentials", ""), 400, "invalid_json");
      expectErr(await post(ctx.app, "/credentials", "[1]"), 400, "invalid_json");
      expectErr(await post(ctx.app, "/credentials", "null"), 400, "invalid_json");
      const res = await ctx.app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "text/plain" }, payload: "x" });
      expectErr(res, 400, "invalid_json");
    });

    it("error: forbidden_field at any depth, for every secret-like key, and the value is never logged (floor 6)", async () => {
      const s = await newSecrets();
      const marker = "9".repeat(40);
      const shapes = [
        { commitment: s.commitment, enrolmentCode: CODE, credentialSecret: marker },
        { commitment: s.commitment, enrolmentCode: CODE, credentialSalt: marker },
        { commitment: s.commitment, enrolmentCode: CODE, secret: marker },
        { commitment: s.commitment, enrolmentCode: CODE, salt: marker },
        { commitment: s.commitment, attributes: { salt: marker } },
        { commitment: s.commitment, enrolmentCode: CODE, extra: { nested: [{ credentialSecret: marker }] } },
        { commitment: s.commitment, enrolmentCode: CODE, Credential_Secret: marker },
      ];
      for (const body of shapes) expectErr(await post(ctx.app, "/credentials", body), 400, "forbidden_field");
      assert.ok(!ctx.sink.text().includes(marker));
      assert.strictEqual(json(await ctx.app.inject("/root")).root, (await zk.createTree(profile)).root.toString(), "nothing inserted");
    });

    it("error: invalid_commitment", async () => {
      const P_ = zk.P.toString();
      const bad = ["0", "01", "-1", "0x10", " 5", "5 ", "1.5", "", P_, (zk.P + 1n).toString(), 5, null, undefined, {}, true];
      for (const c of bad) {
        const body = c === undefined ? { enrolmentCode: CODE } : { commitment: c, enrolmentCode: CODE };
        expectErr(await post(ctx.app, "/credentials", body), 400, "invalid_commitment");
      }
    });

    it("error: invalid_attributes at the admin enrolment (missing, extra, wrong type, out of range, wrong profile)", async () => {
      const a = attrsFor(profile);
      const cases = [
        undefined, null, [], "x", {},
        { ...a, bogus: 1 },
        { ...a, role: 4 }, { ...a, role: -1 }, { ...a, role: 1.5 }, { ...a, role: "1" }, { ...a, role: true },
        { ...a, clearance: 4 }, { ...a, deviceCompliant: 2 }, { ...a, employeeActive: 2 }, { ...a, deviceCompliant: true },
        profile === "v3" ? { ...a, dept: 0 } : (({ dept, ...rest }) => rest)(a),
        profile === "v3" ? { ...a, expiry: T0 + 10 } : { ...a, dept: 4 },
        (({ role, ...rest }) => rest)(a),
      ];
      for (const attributes of cases) {
        const res = await adminReq(ctx.app, "POST", "/admin/enrolments", { employeeId: `bad-${Math.random().toString(36).slice(2)}`, attributes });
        expectErr(res, 400, "invalid_attributes");
      }
    });

    it("error: invalid_leaf_index / unknown_leaf on revoke and path", async () => {
      for (const i of ["abc", "-1", "01", "1.5", "99999999999999999999", "0x1"]) {
        expectErr(await post(ctx.app, `/credentials/${i}/revoke`, ""), 400, "invalid_leaf_index");
        expectErr(await ctx.app.inject(`/path/${i}`), 400, "invalid_leaf_index");
      }
      expectErr(await post(ctx.app, "/credentials/0/revoke", ""), 404, "unknown_leaf");
      expectErr(await ctx.app.inject("/path/0"), 404, "unknown_leaf");
      await issue(ctx.app, profile);
      expectErr(await ctx.app.inject("/path/1"), 404, "unknown_leaf");
    });

    it("error: invalid_since", async () => {
      for (const s of ["abc", "-1", "01", "1.5", "", "0x1"]) {
        expectErr(await ctx.app.inject(`/root/history?since=${s}`), 400, "invalid_since");
      }
      assert.strictEqual((await ctx.app.inject("/root/history?since=0")).statusCode, 200);
    });

    it("error: duplicate_commitment", async () => {
      const s = await newSecrets();
      const first = await issue(ctx.app, profile, undefined, { commitmentOf: s.commitment });
      assert.strictEqual(first.res.statusCode, 201);
      const second = await adminEnrol(ctx.app, profile);
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: second.code }), 409, "duplicate_commitment");
      const retry = await post(ctx.app, "/credentials", { commitment: (await newSecrets()).commitment, enrolmentCode: second.code });
      assert.strictEqual(retry.statusCode, 201, "a refused redemption does not burn the code");
    });

    it("error: tree_full at 2^depth leaves (v3: 4)", async function () {
      if (profile !== "v3") return this.skip();
      for (let i = 0; i < 4; i++) assert.strictEqual((await issue(ctx.app, profile)).res.statusCode, 201);
      expectErr((await issue(ctx.app, profile)).res, 409, "tree_full");
    });

    it("error: not_found for unknown routes and 405-like methods", async () => {
      expectErr(await ctx.app.inject("/nope"), 404, "not_found");
      expectErr(await ctx.app.inject({ method: "DELETE", url: "/root" }), 404, "not_found");
    });

    it("error: internal carries no details", async () => {
      ctx.app.registry.insert = () => { throw new Error("SECRET-DETAIL /etc/passwd"); };
      const res = (await issue(ctx.app, profile)).res;
      expectErr(res, 500, "internal");
      assert.ok(!res.body.includes("SECRET-DETAIL"));
      assert.ok(!ctx.sink.text().includes("SECRET-DETAIL"));
    });

    it("error messages never echo request values", async () => {
      const marker = "7777777777777777777777777777";
      const res = await post(ctx.app, "/credentials", { commitment: marker + "x", enrolmentCode: CODE });
      assert.ok(!res.body.includes(marker));
      const res2 = await post(ctx.app, "/credentials", { commitment: (await newSecrets()).commitment, enrolmentCode: CODE, bogusKeyName123: 1 });
      assert.ok(!res2.body.includes("bogusKeyName123"));
      const res3 = await post(ctx.app, "/credentials", { commitment: (await newSecrets()).commitment, enrolmentCode: marker });
      assert.ok(!res3.body.includes(marker));
    });

    it("logs: structured JSON with route/status/leafIndex/latency and no commitment, attributes, signature or key (floor 6/7)", async () => {
      const { secrets, cred } = await issue(ctx.app, profile);
      await ctx.app.inject("/path/0");
      await post(ctx.app, "/credentials/0/revoke", "");
      await post(ctx.app, "/credentials", { commitment: "0", enrolmentCode: CODE });
      await ctx.app.inject("/root/history?since=0");
      const text = ctx.sink.text();
      const reqLogs = ctx.sink.lines.map((l) => JSON.parse(l)).filter((l) => l.route);
      assert.ok(reqLogs.length >= 5);
      const l0 = reqLogs.find((l) => l.route === "/credentials" && l.status === 201);
      assert.ok(l0 && typeof l0.latencyMs === "number" && l0.method === "POST");
      assert.ok(reqLogs.some((l) => l.route === "/path/:leafIndex" && l.leafIndex === 0));
      assert.ok(reqLogs.some((l) => l.route === "/credentials" && l.status === 400 && l.code === "invalid_commitment"));
      const forbidden = [
        secrets.commitment, secrets.credentialSecret, secrets.credentialSalt,
        cred.signature.R8x, cred.signature.R8y, cred.signature.S,
        '"role"', "deviceCompliant", "employeeActive", "clearance", "expiry",
      ];
      for (const f of forbidden) assert.ok(!text.includes(f), `log contains ${f.slice(0, 12)}`);
      const keyHex = fs.readFileSync(path.join(ctx.keyDir, "issuer.key"), "utf8").trim();
      assert.ok(!text.includes(keyHex));
    });

    it("GET /metrics counts issued, revoked, root changes, errors by code and request latency", async () => {
      await issue(ctx.app, profile);
      await issue(ctx.app, profile);
      await post(ctx.app, "/credentials/0/revoke", "");
      await post(ctx.app, "/credentials", { commitment: "0", enrolmentCode: CODE });
      const m = json(await ctx.app.inject("/metrics"));
      assert.strictEqual(m.issued, 2);
      assert.strictEqual(m.revoked, 1);
      assert.strictEqual(m.rootChanges, 3);
      assert.strictEqual(m.errors.invalid_commitment, 1);
      assert.strictEqual(m.leaves, 2);
      assert.strictEqual(m.requests["POST /credentials"].count, 3);
      assert.strictEqual(m.enrolmentsCreated, 2);
      assert.strictEqual(m.enrolmentsRedeemed, 2);
      assert.strictEqual(m.enrolmentsPending, 0);
      assert.ok(m.requests["POST /credentials"].latencyMsSum >= 0);
      assert.strictEqual(m.profile, profile);
    });

    it("private key is never reachable through any route", async () => {
      await issue(ctx.app, profile);
      const keyHex = fs.readFileSync(path.join(ctx.keyDir, "issuer.key"), "utf8").trim();
      for (const url of ["/issuer", "/root", "/root/history", "/path/0", "/metrics"]) {
        assert.ok(!(await ctx.app.inject(url)).body.includes(keyHex), url);
      }
    });
  });
}

describe("issuer.api v2, v4-only validation", () => {
  let ctx;
  beforeEach(async () => { ctx = await makeApp({ profile: "v4" }); });
  afterEach(() => ctx.app.close());
  const cases = {
    "expiry == now": T0,
    "expiry < now": T0 - 1,
    "expiry 0": 0,
    "expiry above 2^53-1": 2 ** 53,
    "expiry as string": String(T0 + 5),
    "expiry fractional": T0 + 0.5,
    "expiry negative": -5,
  };
  for (const [name, expiry] of Object.entries(cases)) {
    it(`rejects ${name}`, async () => {
      expectErr((await adminEnrol(ctx.app, "v4", v4Attrs(expiry))).res, 400, "invalid_attributes");
    });
  }
  it("accepts expiry = now + 1 and expiry = 2^53 - 1", async () => {
    for (const e of [T0 + 1, Number.MAX_SAFE_INTEGER]) {
      const r = await issue(ctx.app, "v4", v4Attrs(e));
      assert.strictEqual(r.res.statusCode, 201, r.res.body);
    }
  });
  it("accepts every enum extreme and rejects enum labels (integers only)", async () => {
    const r = await issue(ctx.app, "v4", v4Attrs(T0 + 5, { role: 3, dept: 3, clearance: 3 }));
    assert.strictEqual(r.res.statusCode, 201);
    expectErr((await adminEnrol(ctx.app, "v4", v4Attrs(T0 + 5, { role: "admin" }))).res, 400, "invalid_attributes");
  });
  it("tampering with an attribute after issue breaks the signature (attributes are signed in v4)", async () => {
    const { secrets, cred } = await issue(ctx.app, "v4");
    for (const k of ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry"]) {
      const changed = { ...cred.attributes, [k]: cred.attributes[k] === 1 ? 0 : cred.attributes[k] + 1 };
      const M = await zk.profiles.v4.message({ commitment: secrets.commitment, attributes: changed });
      assert.strictEqual(await zk.verifySignature(M, cred.signature, cred.issuer), false, k);
    }
  });
  it("reproduces the committed v4 vectors' root through the API (floor 8)", async () => {
    const v = vectors("v4");
    const clock = ctx.clock;
    clock.t = v.now;
    for (const c of v.credentials) {
      const { res } = await issue(ctx.app, "v4", c.attributes, { commitmentOf: c.commitment });
      assert.strictEqual(res.statusCode, 201, res.body);
      assert.strictEqual(json(res).credential.leafIndex, c.leafIndex);
    }
    assert.strictEqual(json(await ctx.app.inject("/root")).root, v.tree.root);
  });
});

describe("issuer.api v2, v3-only", () => {
  it("reproduces the committed v3 vectors' root through the API (floor 8)", async () => {
    const ctx = await makeApp({ profile: "v3" });
    const v = vectors("v3");
    for (const c of v.credentials) {
      const { res } = await issue(ctx.app, "v3", c.attributes, { commitmentOf: c.commitment });
      assert.strictEqual(res.statusCode, 201, res.body);
    }
    assert.strictEqual(json(await ctx.app.inject("/root")).root, v.tree.root);
    await ctx.app.close();
  });
});

describe("restart behaviour (IDEN-001/002/004)", () => {
  for (const profile of ["v3", "v4"]) {
    it(`${profile}: same issuer key, same tree, revocations and history after a restart`, async () => {
      const keyDir = tmpDir("issuer-keys-");
      const dataDir = tmpDir("issuer-data-");
      const a = await makeApp({ profile, keyDir, dataDir });
      const pub = json(await a.app.inject("/issuer")).issuer;
      const c0 = await issue(a.app, profile);
      await issue(a.app, profile);
      await post(a.app, "/credentials/0/revoke", "");
      const rootA = json(await a.app.inject("/root"));
      const histA = json(await a.app.inject("/root/history")).roots;
      await a.app.close();

      const b = await makeApp({ profile, keyDir, dataDir, clock: a.clock });
      assert.deepStrictEqual(json(await b.app.inject("/issuer")).issuer, pub);
      assert.deepStrictEqual(json(await b.app.inject("/root")), rootA);
      assert.deepStrictEqual(json(await b.app.inject("/root/history")).roots, histA);
      expectErr(await b.app.inject("/path/0"), 410, "revoked");
      assert.strictEqual((await b.app.inject("/path/1")).statusCode, 200);
      // the pre-restart credential still verifies under the post-restart key
      const M = await zk.profiles[profile].message({ commitment: c0.secrets.commitment, attributes: c0.cred.attributes });
      assert.strictEqual(await zk.verifySignature(M, c0.cred.signature, json(await b.app.inject("/issuer")).issuer), true);
      const c2 = await issue(b.app, profile);
      assert.strictEqual(c2.cred.leafIndex, 2);
      await b.app.close();
    });
  }

  it("refuses to start with a data dir written by another profile", async () => {
    const keyDir = tmpDir("issuer-keys-");
    const dataDir = tmpDir("issuer-data-");
    const a = await makeApp({ profile: "v3", keyDir, dataDir });
    await issue(a.app, "v3");
    await a.app.close();
    await assert.rejects(makeApp({ profile: "v4", keyDir, dataDir }), /profile/);
  });
});

describe("main entry", () => {
  it("start() listens on the configured port and serves /issuer", async () => {
    const { start } = require("../src/main");
    const keyDir = tmpDir("issuer-keys-");
    const dataDir = tmpDir("issuer-data-");
    const env = { ISSUER_PROFILE: "v3", ISSUER_KEY_DIR: keyDir, ISSUER_DATA_DIR: dataDir, ISSUER_PORT: "0", ISSUER_HOST: "127.0.0.1", ISSUER_LOG_LEVEL: "silent" };
    await assert.rejects(start(env), /ISSUER_ADMIN_TOKEN/, "SR-04: no token, no start");
    const { app, address } = await start({ ...env, ISSUER_ADMIN_TOKEN: "t".repeat(24) });
    const res = await fetch(`${address}/issuer`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual((await res.json()).profile, "v3");
    await app.close();
  });
});
