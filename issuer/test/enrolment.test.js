"use strict";
// issuer.api v2 / issuer.admin v1.1 (G1-S1-IDEN-014): admin-approved enrolment (SR-03), fail-closed
// start (SR-04). Everything here runs in the production posture (admin token set, insecureDev off)
// unless a test says otherwise.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { makeApp, json, post, newSecrets, adminReq, adminEnrol, ADMIN_TOKEN, attrsFor, v4Attrs, T0, tmpDir, zk } = require("./helpers");
const { buildServer } = require("../src/server");
const { loadConfig } = require("../src/config");

const errCode = (res) => json(res).error.code;
const expectErr = (res, status, code) => {
  assert.strictEqual(res.statusCode, status, res.body);
  assert.strictEqual(errCode(res), code);
};
const redeem = async (app, code, commitment) =>
  post(app, "/credentials", { commitment: commitment || (await newSecrets()).commitment, enrolmentCode: code });

for (const profile of ["v4", "v3"]) {
  describe(`enrolment (${profile}, production posture)`, () => {
    let ctx;
    beforeEach(async () => { ctx = await makeApp({ profile, secure: true }); });
    afterEach(async () => { await ctx.app.close(); });

    it("admin enrolment then redemption issues a credential carrying the ADMIN-assigned attributes", async () => {
      const attrs = profile === "v4" ? v4Attrs(T0 + 5000, { role: 1, clearance: 3 }) : { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 };
      const e = await adminEnrol(ctx.app, profile, attrs, "alice@example.test");
      assert.strictEqual(e.res.statusCode, 201, e.res.body);
      assert.match(e.code, /^[A-Za-z0-9_-]{32}$/);
      assert.ok(e.expiresAt > T0);
      const s = await newSecrets();
      const res = await redeem(ctx.app, e.code, s.commitment);
      assert.strictEqual(res.statusCode, 201, res.body);
      const c = json(res).credential;
      assert.deepStrictEqual(c.attributes, attrs);
      const M = await zk.profiles[profile].message({ commitment: s.commitment, attributes: attrs });
      assert.ok(await zk.verifySignature(M, c.signature, c.issuer));
    });

    it("enrolling without a code, with a wrong code, or with a malformed code is refused and inserts nothing", async () => {
      const s = await newSecrets();
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment }), 403, "invalid_enrolment_code");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: "A".repeat(32) }), 403, "invalid_enrolment_code");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: "short" }), 403, "invalid_enrolment_code");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: 12345 }), 403, "invalid_enrolment_code");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: { $ne: 1 } }), 403, "invalid_enrolment_code");
      assert.strictEqual(ctx.app.registry.size(), 0);
    });

    it("a client-chosen attributes field is rejected (attributes_not_accepted), with or without a valid code", async () => {
      const e = await adminEnrol(ctx.app, profile, attrsFor(profile));
      const s = await newSecrets();
      const greedy = profile === "v4" ? v4Attrs(T0 + 99999, { role: 1, clearance: 3 }) : { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 };
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, attributes: greedy }), 400, "attributes_not_accepted");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: e.code, attributes: greedy }), 400, "attributes_not_accepted");
      assert.strictEqual(ctx.app.registry.size(), 0);
      const ok = await redeem(ctx.app, e.code, s.commitment);
      assert.strictEqual(ok.statusCode, 201, "the code was not burned by the refused attempt");
      assert.deepStrictEqual(json(ok).credential.attributes, attrsFor(profile));
    });

    it("unknown top-level keys are invalid_request; secret/salt keys are forbidden_field first", async () => {
      const e = await adminEnrol(ctx.app, profile);
      const s = await newSecrets();
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: e.code, extra: 1 }), 400, "invalid_request");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment, enrolmentCode: e.code, credentialSecret: "5" }), 400, "forbidden_field");
    });

    it("a code is single use (enrolment_used), even for a different commitment", async () => {
      const e = await adminEnrol(ctx.app, profile);
      assert.strictEqual((await redeem(ctx.app, e.code)).statusCode, 201);
      expectErr(await redeem(ctx.app, e.code), 409, "enrolment_used");
      assert.strictEqual(ctx.app.registry.size(), 1);
    });

    it("concurrent redemptions of one code issue exactly one credential", async () => {
      const e = await adminEnrol(ctx.app, profile);
      const rs = await Promise.all([redeem(ctx.app, e.code), redeem(ctx.app, e.code), redeem(ctx.app, e.code)]);
      assert.deepStrictEqual(rs.map((r) => r.statusCode).sort(), [201, 409, 409]);
      assert.strictEqual(ctx.app.registry.size(), 1);
    });

    it("an expired code is refused (enrolment_expired) and an expired pending enrolment no longer blocks the employee", async () => {
      const e = await adminEnrol(ctx.app, profile, undefined, "dora", { ttlSeconds: 60 });
      ctx.clock.advance(61);
      expectErr(await redeem(ctx.app, e.code), 410, "enrolment_expired");
      const again = await adminEnrol(ctx.app, profile, profile === "v4" ? v4Attrs(T0 + 100000) : undefined, "dora");
      assert.strictEqual(again.res.statusCode, 201, again.res.body);
    });

    it("the default code lifetime is 3600 s", async () => {
      const e = await adminEnrol(ctx.app, profile);
      assert.strictEqual(e.expiresAt, T0 + 3600);
      ctx.clock.advance(3599);
      assert.strictEqual((await redeem(ctx.app, e.code)).statusCode, 201);
    });

    it("rejects invalid ttlSeconds and employeeId", async () => {
      for (const ttlSeconds of [0, 59, 604801, 1.5, "60", -1, null]) {
        expectErr((await adminEnrol(ctx.app, profile, undefined, "e1", { ttlSeconds })).res, 400, "invalid_ttl");
      }
      for (const id of ["", " a", "a b", "-a", "x".repeat(129), 5, null, "a/b", "a\nb"]) {
        expectErr((await adminEnrol(ctx.app, profile, undefined, id)).res, 400, "invalid_employee_id");
      }
      assert.strictEqual((await adminEnrol(ctx.app, profile, undefined, "x".repeat(128))).res.statusCode, 201);
    });

    it("at most one live credential per employee: a second enrolment is refused while pending and while live (case-insensitive)", async () => {
      const first = await adminEnrol(ctx.app, profile, undefined, "Erin");
      expectErr((await adminEnrol(ctx.app, profile, undefined, "erin")).res, 409, "enrolment_pending");
      assert.strictEqual((await redeem(ctx.app, first.code)).statusCode, 201);
      expectErr((await adminEnrol(ctx.app, profile, undefined, "ERIN")).res, 409, "employee_has_credential");
      assert.strictEqual(ctx.app.registry.size(), 1);
    });

    it("a revoked employee cannot self re-enrol: old code is used, no code is refused, a new enrolment needs the admin", async () => {
      const first = await adminEnrol(ctx.app, profile, undefined, "frank");
      assert.strictEqual((await redeem(ctx.app, first.code)).statusCode, 201);
      assert.strictEqual((await adminReq(ctx.app, "POST", "/credentials/0/revoke")).statusCode, 200);
      const s = await newSecrets();
      expectErr(await redeem(ctx.app, first.code, s.commitment), 409, "enrolment_used");
      expectErr(await post(ctx.app, "/credentials", { commitment: s.commitment }), 403, "invalid_enrolment_code");
      assert.strictEqual(ctx.app.registry.size(), 1, "no second leaf");
      // the admin decides: a fresh enrolment is allowed once the old leaf is revoked
      const second = await adminEnrol(ctx.app, profile, undefined, "frank");
      assert.strictEqual(second.res.statusCode, 201, second.res.body);
      const r = await redeem(ctx.app, second.code, s.commitment);
      assert.strictEqual(json(r).credential.leafIndex, 1);
      // and now frank is live again
      expectErr((await adminEnrol(ctx.app, profile, undefined, "frank")).res, 409, "employee_has_credential");
    });

    it("cancel: a cancelled code is dead, cancelling frees the employee, redeemed/cancelled/unknown cannot be cancelled", async () => {
      const e = await adminEnrol(ctx.app, profile, undefined, "gina");
      const del = await adminReq(ctx.app, "DELETE", `/admin/enrolments/${e.enrolmentId}`);
      assert.strictEqual(del.statusCode, 200);
      assert.deepStrictEqual(json(del), { enrolmentId: e.enrolmentId, status: "cancelled" });
      expectErr(await redeem(ctx.app, e.code), 403, "invalid_enrolment_code");
      expectErr(await adminReq(ctx.app, "DELETE", `/admin/enrolments/${e.enrolmentId}`), 409, "enrolment_not_pending");
      expectErr(await adminReq(ctx.app, "DELETE", "/admin/enrolments/deadbeefdeadbeef"), 404, "unknown_enrolment");
      const again = await adminEnrol(ctx.app, profile, undefined, "gina");
      assert.strictEqual(again.res.statusCode, 201);
      await redeem(ctx.app, again.code);
      expectErr(await adminReq(ctx.app, "DELETE", `/admin/enrolments/${again.enrolmentId}`), 409, "enrolment_not_pending");
    });

    it("every admin enrolment route requires the bearer token", async () => {
      const e = await adminEnrol(ctx.app, profile);
      const body = JSON.stringify({ employeeId: "x1", attributes: attrsFor(profile) });
      const calls = [
        ["POST", "/admin/enrolments", body],
        ["GET", "/admin/enrolments", undefined],
        ["DELETE", `/admin/enrolments/${e.enrolmentId}`, undefined],
      ];
      for (const [method, url, payload] of calls) {
        for (const authorization of [undefined, "Bearer wrong", `Bearer ${ADMIN_TOKEN}x`, ADMIN_TOKEN, `Basic ${ADMIN_TOKEN}`]) {
          const headers = {};
          if (payload) headers["content-type"] = "application/json";
          if (authorization) headers.authorization = authorization;
          const res = await ctx.app.inject({ method, url, headers, payload });
          expectErr(res, 401, "unauthorized");
          assert.strictEqual(res.headers["www-authenticate"], "Bearer");
        }
      }
      assert.strictEqual(json(await adminReq(ctx.app, "GET", "/admin/enrolments")).total, 1, "the unauthenticated POST created nothing");
    });

    it("the listing shows employeeId and status, never the code, hash, attributes or commitment", async () => {
      const a = await adminEnrol(ctx.app, profile, undefined, "hank");
      const b = await adminEnrol(ctx.app, profile, undefined, "iris");
      const s = await newSecrets();
      await redeem(ctx.app, a.code, s.commitment);
      const res = await adminReq(ctx.app, "GET", "/admin/enrolments");
      const body = json(res);
      assert.strictEqual(body.total, 2);
      assert.deepStrictEqual(body.enrolments.map((x) => [x.employeeId, x.status, x.leafIndex]), [["hank", "redeemed", 0], ["iris", "pending", null]]);
      for (const x of body.enrolments) {
        assert.deepStrictEqual(Object.keys(x), ["enrolmentId", "employeeId", "status", "createdAt", "expiresAt", "redeemedAt", "leafIndex"]);
      }
      for (const secret of [a.code, b.code, s.commitment, "role", "clearance", "attributes", "deviceCompliant"]) {
        assert.ok(!res.body.includes(secret), secret);
      }
      ctx.clock.advance(7200);
      assert.deepStrictEqual(json(await adminReq(ctx.app, "GET", "/admin/enrolments")).enrolments.map((x) => x.status), ["redeemed", "expired"]);
      assert.strictEqual(json(await adminReq(ctx.app, "GET", "/admin/enrolments?from=1&limit=1")).enrolments.length, 1);
      expectErr(await adminReq(ctx.app, "GET", "/admin/enrolments?limit=0"), 400, "invalid_query");
    });

    it("the identity-free routes stay identity-free", async () => {
      const a = await adminEnrol(ctx.app, profile, undefined, "jane.doe@corp.test");
      await redeem(ctx.app, a.code);
      for (const url of ["/admin/leaves", "/admin/tree", "/root", "/root/history", "/path/0", "/metrics", "/issuer"]) {
        const res = url.startsWith("/admin") ? await adminReq(ctx.app, "GET", url) : await ctx.app.inject(url);
        assert.ok(!res.body.includes("jane"), url);
        assert.ok(!res.body.includes(a.code), url);
      }
    });

    it("state on disk: code stored hashed, attributes erased at redemption, mode 0600, no commitment or secret", async () => {
      const e = await adminEnrol(ctx.app, profile, undefined, "kate");
      const file = path.join(ctx.dataDir, "enrolments.json");
      assert.strictEqual(fs.statSync(file).mode & 0o777, 0o600);
      let text = fs.readFileSync(file, "utf8");
      assert.ok(!text.includes(e.code));
      assert.ok(text.includes("clearance"), "pending attributes are held for signing");
      const s = await newSecrets();
      await redeem(ctx.app, e.code, s.commitment);
      text = fs.readFileSync(file, "utf8");
      assert.ok(!text.includes(e.code));
      assert.ok(!text.includes(s.commitment));
      assert.ok(!text.includes("clearance"), "attributes erased once redeemed");
      assert.ok(text.includes("kate"));
      assert.strictEqual(JSON.parse(text).enrolments[0].leafIndex, 0);
    });

    it("state survives a restart: a used code stays used, a pending code stays redeemable, liveness is kept", async () => {
      const used = await adminEnrol(ctx.app, profile, undefined, "liam");
      await redeem(ctx.app, used.code);
      const pending = await adminEnrol(ctx.app, profile, undefined, "mona");
      await ctx.app.close();
      const next = await makeApp({ profile, secure: true, keyDir: ctx.keyDir, dataDir: ctx.dataDir, clock: ctx.clock });
      ctx = next;
      expectErr(await redeem(next.app, used.code), 409, "enrolment_used");
      expectErr((await adminEnrol(next.app, profile, undefined, "liam")).res, 409, "employee_has_credential");
      expectErr((await adminEnrol(next.app, profile, undefined, "mona")).res, 409, "enrolment_pending");
      assert.strictEqual((await redeem(next.app, pending.code)).statusCode, 201);
    });

    it("a failed insert leaves the enrolment pending (code not burned)", async () => {
      const e = await adminEnrol(ctx.app, profile, undefined, "nina");
      const real = ctx.app.registry.insert;
      ctx.app.registry.insert = () => { throw new Error("disk"); };
      expectErr(await redeem(ctx.app, e.code), 500, "internal");
      ctx.app.registry.insert = real;
      assert.strictEqual((await redeem(ctx.app, e.code)).statusCode, 201);
    });

    it("logs and metrics carry no employeeId, code, attribute value or commitment", async () => {
      const e = await adminEnrol(ctx.app, profile, undefined, "olivia.private@corp.test");
      const s = await newSecrets();
      await redeem(ctx.app, e.code, s.commitment);
      await redeem(ctx.app, e.code, s.commitment);
      await adminReq(ctx.app, "GET", "/admin/enrolments");
      const text = ctx.sink.text() + (await ctx.app.inject("/metrics")).body;
      for (const secret of [e.code, "olivia", s.commitment, ADMIN_TOKEN, "deviceCompliant", "clearance", e.enrolmentId]) {
        assert.ok(!text.includes(secret), secret);
      }
      const m = json(await ctx.app.inject("/metrics"));
      assert.deepStrictEqual([m.enrolmentsCreated, m.enrolmentsRedeemed, m.enrolmentsPending], [1, 1, 0]);
      assert.strictEqual(m.errors.enrolment_used, 1);
    });
  });
}

describe("enrolment (v4 specifics)", () => {
  it("an assigned expiry that has passed by redemption time is enrolment_expired, not a signature", async () => {
    const { app, clock } = await makeApp({ profile: "v4", secure: true });
    const e = await adminEnrol(app, "v4", v4Attrs(T0 + 100));
    clock.advance(200); // code (3600 s) still valid, credential expiry not
    expectErr(await redeem(app, e.code), 410, "enrolment_expired");
    assert.strictEqual(app.registry.size(), 0);
    await app.close();
  });
});

describe("fail-closed start and open enrolment (SR-03, SR-04)", () => {
  const base = () => ({ keyDir: tmpDir("k-"), dataDir: tmpDir("d-"), host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, logLevel: "silent" });

  for (const profile of ["v4", "v3"]) {
    it(`${profile}: refuses to start without ISSUER_ADMIN_TOKEN unless insecureDev`, async () => {
      for (const adminToken of [undefined, null, ""]) {
        await assert.rejects(buildServer({ config: { ...base(), profile, adminToken } }), /ISSUER_ADMIN_TOKEN/);
      }
      const cfg = { ...base(), profile };
      await assert.rejects(buildServer({ config: cfg }), /ISSUER_INSECURE_DEV/);
      assert.deepStrictEqual(fs.readdirSync(cfg.keyDir), [], "no key is created by a refused start");
    });
  }

  it("SR-20: only a boolean true enables insecure-dev; truthy strings and numbers do not", async () => {
    for (const profile of ["v4", "v3"]) {
      for (const insecureDev of ["0", "false", "1", "yes", 1, {}]) {
        const cfg = { ...base(), profile, insecureDev };
        await assert.rejects(buildServer({ config: cfg }), /ISSUER_ADMIN_TOKEN/, `${profile} insecureDev=${JSON.stringify(insecureDev)}`);
        assert.deepStrictEqual(fs.readdirSync(cfg.keyDir), [], "no key is created by a refused start");
      }
    }
    // with a token, a non-boolean insecureDev still leaves admin auth on
    const { app } = await makeApp({ profile: "v4", overrides: { adminToken: "t-0123456789abcdef", insecureDev: "0" } });
    assert.strictEqual((await app.inject({ method: "GET", url: "/admin/leaves" })).statusCode, 401);
    await app.close();
  });

  it("starts with a token, and warns loudly (once, no token) in insecure-dev mode", async () => {
    const ok = await makeApp({ profile: "v4", secure: true });
    assert.ok(!ok.sink.text().includes("INSECURE"));
    await ok.app.close();
    const dev = await makeApp({ profile: "v4" });
    const warn = dev.sink.lines.map((l) => JSON.parse(l)).filter((l) => l.level === 40);
    assert.strictEqual(warn.length, 1);
    assert.match(warn[0].msg, /INSECURE/);
    await dev.app.close();
  });

  it("loadConfig reads ISSUER_INSECURE_DEV only when exactly '1' and ISSUER_ENROLMENT_TTL_SECONDS", () => {
    assert.strictEqual(loadConfig({}).insecureDev, false);
    for (const v of ["0", "true", "yes", ""]) assert.strictEqual(loadConfig({ ISSUER_INSECURE_DEV: v }).insecureDev, false);
    assert.strictEqual(loadConfig({ ISSUER_INSECURE_DEV: "1" }).insecureDev, true);
    assert.strictEqual(loadConfig({}).enrolmentTtlSeconds, 3600);
    assert.strictEqual(loadConfig({ ISSUER_ENROLMENT_TTL_SECONDS: "600" }).enrolmentTtlSeconds, 600);
    assert.throws(() => loadConfig({ ISSUER_ENROLMENT_TTL_SECONDS: "5" }), /ISSUER_ENROLMENT_TTL_SECONDS/);
  });

  it("open enrolment is gone for v4 even in insecure-dev mode", async () => {
    const { app } = await makeApp({ profile: "v4" });
    const s = await newSecrets();
    expectErr(await post(app, "/credentials", { commitment: s.commitment, attributes: v4Attrs() }), 400, "attributes_not_accepted");
    assert.strictEqual(app.registry.size(), 0);
    await app.close();
  });

  it("open enrolment of v3 exists only with insecureDev", async () => {
    const s = await newSecrets();
    const dev = await makeApp({ profile: "v3" });
    assert.strictEqual((await post(dev.app, "/credentials", { commitment: s.commitment, attributes: attrsFor("v3") })).statusCode, 201);
    await dev.app.close();
    const prod = await makeApp({ profile: "v3", secure: true });
    expectErr(await post(prod.app, "/credentials", { commitment: s.commitment, attributes: attrsFor("v3") }), 400, "attributes_not_accepted");
    assert.strictEqual(prod.app.registry.size(), 0);
    await prod.app.close();
  });
});
