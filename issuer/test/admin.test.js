"use strict";
const assert = require("assert");
const { makeApp, json, post, issue, T0, v4Attrs, zk } = require("./helpers");
const { connectSse } = require("./sse");

const TOKEN = "test-admin-token-0123456789";
const auth = { authorization: `Bearer ${TOKEN}` };

async function listening(opts) {
  const ctx = await makeApp(opts);
  const address = await ctx.app.listen({ host: "127.0.0.1", port: 0 });
  return { ...ctx, base: address };
}
const revoke = (app, i, headers = {}) => app.inject({ method: "POST", url: `/credentials/${i}/revoke`, headers });
const get = (app, url, headers = {}) => app.inject({ method: "GET", url, headers });

describe("issuer.admin v1", () => {
  describe("GET /admin/leaves", () => {
    it("lists issued then revoked leaves with hash 0 and timestamps, and no attributes or commitments", async () => {
      const { app, clock } = await makeApp({ profile: "v4" });
      const a = await issue(app, "v4");
      clock.advance(5);
      const b = await issue(app, "v4");
      clock.advance(5);
      assert.equal((await revoke(app, 0)).statusCode, 200);
      const res = await get(app, "/admin/leaves");
      assert.equal(res.statusCode, 200);
      const body = json(res);
      assert.equal(body.profile, "v4");
      assert.equal(body.depth, 16);
      assert.equal(body.total, 2);
      assert.deepEqual(body.leaves.map((l) => [l.leafIndex, l.status]), [[0, "revoked"], [1, "issued"]]);
      assert.equal(body.leaves[0].leaf, "0");
      assert.equal(body.leaves[0].issuedAt, T0);
      assert.equal(body.leaves[0].revokedAt, T0 + 10);
      assert.equal(body.leaves[1].revokedAt, null);
      assert.equal(body.leaves[1].issuedAt, T0 + 5);
      assert.equal(body.leaves[1].leaf, json(await get(app, "/path/1")).leaf);
      for (const l of body.leaves) assert.deepEqual(Object.keys(l).sort(), ["issuedAt", "leaf", "leafIndex", "revokedAt", "status"]);
      for (const secret of [a.secrets.commitment, b.secrets.commitment, a.cred.signature.S, a.secrets.credentialSecret]) {
        assert.ok(!res.body.includes(secret));
      }
      assert.ok(!/"(role|dept|clearance|attributes|commitment)"/.test(res.body));
    });

    it("paginates with from and limit and rejects bad values", async () => {
      const { app } = await makeApp();
      for (let i = 0; i < 3; i++) await issue(app, "v3");
      const r = json(await get(app, "/admin/leaves?from=1&limit=1"));
      assert.equal(r.from, 1);
      assert.equal(r.total, 3);
      assert.deepEqual(r.leaves.map((l) => l.leafIndex), [1]);
      for (const q of ["from=-1", "from=x", "limit=0", "limit=5001", "limit=1.5"]) {
        const bad = await get(app, `/admin/leaves?${q}`);
        assert.equal(bad.statusCode, 400, q);
        assert.equal(json(bad).error.code, "invalid_query");
      }
    });

    it("an empty registry lists nothing", async () => {
      const { app } = await makeApp();
      const r = json(await get(app, "/admin/leaves"));
      assert.deepEqual(r.leaves, []);
      assert.equal(r.total, 0);
    });
  });

  describe("GET /admin/tree", () => {
    it("root equals /root, levels are path-compressed, and every parent hashes its children", async () => {
      const { app } = await makeApp({ profile: "v4" });
      for (let i = 0; i < 3; i++) await issue(app, "v4");
      await revoke(app, 1);
      const t = json(await get(app, "/admin/tree"));
      const root = json(await get(app, "/root")).root;
      assert.equal(t.root, root);
      assert.equal(t.depth, 16);
      assert.equal(t.leafCount, 3);
      assert.equal(t.zeros.length, 17);
      assert.equal(t.zeros[0], "0");
      assert.equal(t.levels.length, 17);
      t.levels.forEach((lv, l) => {
        assert.equal(lv.level, l);
        assert.equal(lv.nodes.length, Math.ceil(3 / 2 ** l));
      });
      assert.equal(t.levels[16].nodes[0], root);
      assert.equal(t.levels[0].nodes[1], "0", "revoked leaf has hash 0");
      const node = (l, i) => (i < t.levels[l].nodes.length ? t.levels[l].nodes[i] : t.zeros[l]);
      for (let l = 0; l < 16; l++) {
        for (let i = 0; i < t.levels[l + 1].nodes.length; i++) {
          assert.equal(await zk.poseidon([node(l, 2 * i), node(l, 2 * i + 1)]), t.levels[l + 1].nodes[i], `level ${l + 1} pos ${i}`);
        }
      }
      for (let l = 0; l < 16; l++) assert.equal(await zk.poseidon([t.zeros[l], t.zeros[l]]), t.zeros[l + 1]);
    });

    it("an empty tree has no nodes and root == zeros[depth]", async () => {
      const { app } = await makeApp();
      const t = json(await get(app, "/admin/tree"));
      assert.equal(t.leafCount, 0);
      assert.ok(t.levels.slice(0, t.depth).every((lv) => lv.nodes.length === 0));
      assert.equal(t.root, t.zeros[t.depth]);
      assert.equal(t.root, json(await get(app, "/root")).root);
    });
  });

  describe("auth", () => {
    it("with a token set, /admin/* and revoke need the bearer token; other routes stay open", async () => {
      const { app, sink } = await makeApp({ overrides: { adminToken: TOKEN } });
      await issue(app, "v3");
      for (const url of ["/admin/leaves", "/admin/tree", "/admin/events"]) {
        for (const headers of [{}, { authorization: "Bearer wrong" }, { authorization: TOKEN }, { authorization: "Basic " + TOKEN }]) {
          const r = await get(app, url, headers);
          assert.equal(r.statusCode, 401, `${url} ${JSON.stringify(headers)}`);
          assert.equal(json(r).error.code, "unauthorized");
          assert.equal(r.headers["www-authenticate"], "Bearer");
        }
      }
      assert.equal((await revoke(app, 0)).statusCode, 401);
      assert.equal((await get(app, "/root")).statusCode, 200);
      assert.equal((await get(app, "/admin/leaves", auth)).statusCode, 200);
      assert.equal((await get(app, "/admin/tree", auth)).statusCode, 200);
      assert.equal((await revoke(app, 0, auth)).statusCode, 200);
      assert.ok(!sink.text().includes(TOKEN), "token never logged");
      assert.ok(json(await get(app, "/metrics")).errors.unauthorized >= 13);
    });

    it("without a token the admin surface is open", async () => {
      const { app } = await makeApp();
      assert.equal((await get(app, "/admin/tree")).statusCode, 200);
    });

    it("an empty token counts as unset", async () => {
      const { app } = await makeApp({ overrides: { adminToken: "" } });
      assert.equal((await get(app, "/admin/leaves")).statusCode, 200);
    });
  });

  describe("GET /admin/events (SSE)", () => {
    it("sends hello, then root-changed for issue and revoke in order with correct prev/new roots", async () => {
      const { app, base, clock } = await listening({ profile: "v3" });
      const c = connectSse(`${base}/admin/events`);
      const r = await c.ready;
      assert.equal(r.status, 200);
      assert.match(r.headers["content-type"], /text\/event-stream/);
      const hello = await c.waitFor((f) => f.event === "hello");
      const root0 = json(await get(app, "/root")).root;
      assert.equal(hello.data.root, root0);
      assert.equal(hello.data.profile, "v3");
      assert.equal(hello.data.seq, 0);

      await issue(app, "v3");
      clock.advance(3);
      await issue(app, "v3");
      clock.advance(3);
      await revoke(app, 0);
      const rootNow = json(await get(app, "/root")).root;
      await c.waitFor((f) => f.event === "root-changed" && f.data.seq === 3);
      const ev = c.frames.filter((f) => f.event === "root-changed");
      assert.deepEqual(ev.map((f) => [f.id, f.data.seq, f.data.kind, f.data.leafIndex]), [["1", 1, "insert", 0], ["2", 2, "insert", 1], ["3", 3, "revoke", 0]]);
      assert.equal(ev[0].data.prevRoot, root0);
      assert.equal(ev[1].data.prevRoot, ev[0].data.root);
      assert.equal(ev[2].data.prevRoot, ev[1].data.root);
      assert.equal(ev[2].data.root, rootNow);
      assert.deepEqual(ev.map((f) => f.data.at), [T0, T0 + 3, T0 + 6]);
      assert.deepEqual(Object.keys(ev[0].data).sort(), ["at", "kind", "leafIndex", "prevRoot", "root", "seq"]);
      c.close();
      await app.close();
    });

    it("a reconnect with Last-Event-ID replays only the missed events; an unknown id gets hello only", async () => {
      const { app, base } = await listening();
      const c1 = connectSse(`${base}/admin/events`);
      await c1.ready;
      await issue(app, "v3");
      await c1.waitFor((f) => f.event === "root-changed" && f.data.seq === 1);
      c1.close();
      await issue(app, "v3");
      await issue(app, "v3");
      const c2 = connectSse(`${base}/admin/events`, { headers: { "last-event-id": "1" } });
      await c2.ready;
      await c2.waitFor((f) => f.event === "root-changed" && f.data.seq === 3);
      assert.deepEqual(c2.frames.map((f) => f.event), ["hello", "root-changed", "root-changed"]);
      assert.deepEqual(c2.frames.filter((f) => f.event === "root-changed").map((f) => f.data.seq), [2, 3]);
      assert.equal(c2.frames[0].data.seq, 3);
      await issue(app, "v3");
      await c2.waitFor((f) => f.data && f.data.seq === 4);
      const c3 = connectSse(`${base}/admin/events`, { headers: { "last-event-id": "999" } });
      await c3.ready;
      await c3.waitFor((f) => f.event === "hello");
      await new Promise((r) => setTimeout(r, 100));
      assert.deepEqual(c3.frames.map((f) => f.event), ["hello"]);
      c2.close();
      c3.close();
      await app.close();
    });

    it("requires the token when set, and the stream carries it as a header only", async () => {
      const { app, base, sink } = await listening({ overrides: { adminToken: TOKEN } });
      const bad = connectSse(`${base}/admin/events`);
      assert.equal((await bad.ready).status, 401);
      const ok = connectSse(`${base}/admin/events`, { headers: auth });
      assert.equal((await ok.ready).status, 200);
      await ok.waitFor((f) => f.event === "hello");
      ok.close();
      bad.close();
      await app.close();
      assert.ok(!sink.text().includes(TOKEN));
    });

    it("sends heartbeats and counts clients and frames in /metrics", async () => {
      const { app, base } = await listening({ overrides: { sseHeartbeatMs: 40 } });
      const c = connectSse(`${base}/admin/events`);
      await c.ready;
      await c.waitFor((f) => f.comment === "hb");
      const m = json(await get(app, "/metrics"));
      assert.equal(m.sseClients, 1);
      assert.ok(m.sseEvents >= 1);
      c.close();
      for (let i = 0; i < 50 && json(await get(app, "/metrics")).sseClients !== 0; i++) await new Promise((r) => setTimeout(r, 20));
      assert.equal(json(await get(app, "/metrics")).sseClients, 0);
      await app.close();
    });

    it("closing the app ends open streams", async () => {
      const { app, base } = await listening();
      const c = connectSse(`${base}/admin/events`);
      await c.ready;
      await Promise.race([app.close(), new Promise((_, rej) => setTimeout(() => rej(new Error("close hung")), 3000))]);
    });

    it("an event is not sent when the issue fails validation", async () => {
      const { app, base } = await listening({ profile: "v4" });
      const c = connectSse(`${base}/admin/events`);
      await c.ready;
      await c.waitFor((f) => f.event === "hello");
      const res = await post(app, "/credentials", { commitment: "0", enrolmentCode: "x".repeat(32) });
      assert.equal(res.statusCode, 400);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(c.frames.filter((f) => f.event === "root-changed").length, 0);
      c.close();
      await app.close();
    });
  });

  it("logs hold no attribute, commitment or token across admin traffic", async () => {
    const { app, sink } = await makeApp({ profile: "v4", overrides: { adminToken: TOKEN } });
    const { secrets, cred } = await issue(app, "v4");
    await get(app, "/admin/leaves", auth);
    await get(app, "/admin/tree", auth);
    const text = sink.text();
    for (const s of [TOKEN, secrets.commitment, cred.signature.S, String(cred.attributes.expiry)]) assert.ok(!text.includes(s), s);
  });

  it("persisted leaf timestamps survive a restart", async () => {
    const first = await makeApp();
    await issue(first.app, "v3");
    await revoke(first.app, 0);
    const second = await makeApp({ keyDir: first.keyDir, dataDir: first.dataDir, clock: first.clock });
    const l = json(await get(second.app, "/admin/leaves")).leaves[0];
    assert.deepEqual([l.status, l.issuedAt, l.revokedAt], ["revoked", T0, T0]);
  });
});
