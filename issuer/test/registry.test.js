"use strict";
const assert = require("assert");
const { zk, tmpDir, vectors, mutableClock, T0 } = require("./helpers");
const { createStore } = require("../src/store");
const { createRegistry, isRootAcceptable } = require("../src/registry");

const leafOf = (n) => String(1000 + n);

async function reg(profile = "v3", { dir = tmpDir("issuer-data-"), clock = mutableClock(), store } = {}) {
  store = store || createStore(dir);
  const r = await createRegistry({ profile, store, clock: clock.now, historyRetentionSeconds: 900 });
  return { r, clock, dir, store };
}

describe("registry (G0-S1-IDEN-002 / G1-S1-IDEN-011)", () => {
  for (const profile of ["v3", "v4"]) {
    const depth = zk.profiles[profile].depth;

    describe(`profile ${profile}`, () => {
      it("starts at the lib's empty root and matches the lib root for the same leaves (floor 8)", async () => {
        const { r } = await reg(profile);
        const tree = await zk.createTree(profile);
        assert.strictEqual(r.root(), tree.root.toString());
        for (let i = 0; i < 3; i++) {
          r.insert({ commitment: String(500 + i), leaf: leafOf(i) });
          tree.insert(BigInt(leafOf(i)));
        }
        assert.strictEqual(r.root(), tree.root.toString());
        assert.strictEqual(r.size(), 3);
      });

      it("path equals zk.proofFor and reproduces the root through zk.merkleRoot", async () => {
        const { r } = await reg(profile);
        const tree = await zk.createTree(profile);
        for (let i = 0; i < 3; i++) {
          r.insert({ commitment: String(500 + i), leaf: leafOf(i) });
          tree.insert(BigInt(leafOf(i)));
        }
        for (let i = 0; i < 3; i++) {
          const p = r.path(i);
          const ref = zk.proofFor(tree, i);
          assert.strictEqual(p.pathElements.length, depth);
          assert.deepStrictEqual(p.pathElements, ref.pathElements);
          assert.deepStrictEqual(p.pathIndices, ref.pathIndices.map(Number));
          assert.ok(p.pathIndices.every((b) => b === 0 || b === 1));
          assert.strictEqual(await zk.merkleRoot(p.leaf, p.pathElements, p.pathIndices), r.root());
        }
      });

      it("revoke sets the leaf to zero, changes the root and the old path no longer reproduces it (floor 3)", async () => {
        const { r } = await reg(profile);
        for (let i = 0; i < 3; i++) r.insert({ commitment: String(500 + i), leaf: leafOf(i) });
        const old = r.path(1);
        const before = r.root();
        const after = r.revoke(1);
        assert.notStrictEqual(after, before);
        assert.strictEqual(r.root(), after);
        assert.strictEqual(await zk.merkleRoot(old.leaf, old.pathElements, old.pathIndices), before);
        assert.notStrictEqual(await zk.merkleRoot(old.leaf, old.pathElements, old.pathIndices), r.root());
        // the registry equals a lib tree with leaf 1 deleted
        const tree = await zk.createTree(profile);
        for (let i = 0; i < 3; i++) tree.insert(BigInt(leafOf(i)));
        tree.delete(1);
        assert.strictEqual(r.root(), tree.root.toString());
        // indices are not reused
        assert.strictEqual(r.insert({ commitment: "900", leaf: leafOf(9) }), 3);
        assert.throws(() => r.path(1), (e) => e.status === 410 && e.code === "revoked");
      });

      it("errors: unknown leaf, already revoked, duplicate commitment", async () => {
        const { r } = await reg(profile);
        r.insert({ commitment: "500", leaf: leafOf(0) });
        assert.throws(() => r.path(5), (e) => e.status === 404 && e.code === "unknown_leaf");
        assert.throws(() => r.revoke(5), (e) => e.status === 404 && e.code === "unknown_leaf");
        assert.throws(() => r.insert({ commitment: "500", leaf: leafOf(1) }), (e) => e.status === 409 && e.code === "duplicate_commitment");
        r.revoke(0);
        assert.throws(() => r.revoke(0), (e) => e.status === 409 && e.code === "already_revoked");
        // a revoked commitment cannot be re-issued either
        assert.throws(() => r.insert({ commitment: "500", leaf: leafOf(1) }), (e) => e.code === "duplicate_commitment");
      });

      it("persists across restart: same leaves, same root, same history", async () => {
        const dir = tmpDir("issuer-data-");
        const clock = mutableClock();
        const a = (await reg(profile, { dir, clock })).r;
        a.insert({ commitment: "500", leaf: leafOf(0) });
        clock.advance(5);
        a.insert({ commitment: "501", leaf: leafOf(1) });
        clock.advance(5);
        a.revoke(0);
        const b = (await reg(profile, { dir, clock })).r;
        assert.strictEqual(b.root(), a.root());
        assert.strictEqual(b.size(), 2);
        assert.deepStrictEqual(b.history(0), a.history(0));
        assert.deepStrictEqual(b.path(1), a.path(1));
        assert.throws(() => b.path(0), (e) => e.code === "revoked");
        assert.throws(() => b.insert({ commitment: "500", leaf: "1" }), (e) => e.code === "duplicate_commitment");
        assert.strictEqual(b.insert({ commitment: "502", leaf: leafOf(2) }), 2);
      });
    });
  }

  it("v3 tree is full after 4 leaves (tree_full)", async () => {
    const { r } = await reg("v3");
    for (let i = 0; i < 4; i++) r.insert({ commitment: String(500 + i), leaf: leafOf(i) });
    assert.throws(() => r.insert({ commitment: "600", leaf: leafOf(9) }), (e) => e.status === 409 && e.code === "tree_full");
    assert.strictEqual(r.size(), 4);
  });

  for (const profile of ["v3", "v4"]) {
    it(`reproduces the committed ${profile} vectors' root from the same leaves (floor 8)`, async () => {
      const v = vectors(profile);
      const { r } = await reg(profile);
      assert.strictEqual(r.root(), v.tree.emptyRoot);
      for (const c of v.credentials) {
        const leaf = profile === "v3" ? c.commitment : c.attrHash;
        assert.strictEqual(r.insert({ commitment: c.commitment, leaf }), c.leafIndex);
      }
      assert.strictEqual(r.root(), v.tree.root);
      for (const c of v.credentials) {
        const p = r.path(c.leafIndex);
        assert.deepStrictEqual(p.pathElements, c.merkle.pathElements);
        assert.deepStrictEqual(p.pathIndices.map(String), c.merkle.pathIndices.map(String));
      }
    });
  }

  describe("state integrity", () => {
    it("refuses to start when the stored root does not match the rebuilt tree", async () => {
      const dir = tmpDir("issuer-data-");
      const { r, store } = await reg("v3", { dir });
      r.insert({ commitment: "500", leaf: leafOf(0) });
      const st = store.load();
      st.leaves[0].leaf = "12345"; // tamper
      store.save(st);
      await assert.rejects(reg("v3", { dir }), /root/);
    });
    it("refuses to start when the stored profile differs from the configured one", async () => {
      const dir = tmpDir("issuer-data-");
      const { r } = await reg("v3", { dir });
      r.insert({ commitment: "500", leaf: leafOf(0) });
      await assert.rejects(reg("v4", { dir }), /profile/);
    });
    it("fails stop when persisting fails: the registry halts and a restart returns the last persisted state", async () => {
      const dir = tmpDir("issuer-data-");
      const inner = createStore(dir);
      let fail = false;
      const store = { load: () => inner.load(), save: (s) => { if (fail) throw new Error("disk full"); inner.save(s); } };
      const { r } = await reg("v3", { store });
      r.insert({ commitment: "500", leaf: leafOf(0) });
      const root = r.root();
      fail = true;
      assert.throws(() => r.insert({ commitment: "501", leaf: leafOf(1) }), /disk full/);
      fail = false;
      for (const f of [() => r.root(), () => r.insert({ commitment: "502", leaf: leafOf(2) }), () => r.revoke(0), () => r.path(0)]) {
        assert.throws(f, (e) => e.status === 500 && e.code === "internal");
      }
      const again = (await reg("v3", { dir })).r;
      assert.strictEqual(again.root(), root);
      assert.strictEqual(again.size(), 1);
    });
    it("the data file is mode 0600 and holds no private material, only commitments/leaves/roots", async () => {
      const fs = require("fs");
      const path = require("path");
      const { r, dir } = await reg("v3");
      r.insert({ commitment: "500", leaf: leafOf(0) });
      const f = path.join(dir, "registry.json");
      assert.strictEqual(fs.statSync(f).mode & 0o777, 0o600);
      const st = JSON.parse(fs.readFileSync(f, "utf8"));
      assert.deepStrictEqual(Object.keys(st).sort(), ["history", "leaves", "profile", "updatedAt", "version"]);
    });
  });

  describe("root history and the staleness rule (issuer.api v1)", () => {
    // timeline: t0 empty root R0; t0+10 insert -> R1; t0+20 insert -> R2; t0+30 revoke -> R3
    async function timeline() {
      const ctx = await reg("v3");
      const { r, clock } = ctx;
      const R = [r.root()];
      clock.advance(10); r.insert({ commitment: "500", leaf: leafOf(0) }); R.push(r.root());
      clock.advance(10); r.insert({ commitment: "501", leaf: leafOf(1) }); R.push(r.root());
      clock.advance(10); r.revoke(0); R.push(r.root());
      return { ...ctx, R };
    }

    it("records timestamps and change kinds, oldest first", async () => {
      const { r, R } = await timeline();
      const h = r.history(0);
      assert.deepStrictEqual(h.map((e) => e.root), R);
      assert.deepStrictEqual(h.map((e) => e.supersededBy), ["insert", "insert", "revoke", null]);
      assert.deepStrictEqual(h.map((e) => e.validFrom), [T0, T0 + 10, T0 + 20, T0 + 30]);
      assert.deepStrictEqual(h.map((e) => e.supersededAt), [T0 + 10, T0 + 20, T0 + 30, null]);
      assert.strictEqual(r.updatedAt(), T0 + 30);
    });

    it("since filters to roots that were current at some time >= since", async () => {
      const { r, R } = await timeline();
      assert.deepStrictEqual(r.history(T0 + 21).map((e) => e.root), [R[2], R[3]]);
      assert.deepStrictEqual(r.history(T0 + 20).map((e) => e.root), [R[1], R[2], R[3]]);
      assert.deepStrictEqual(r.history(T0 + 31).map((e) => e.root), [R[3]]);
    });

    it("accepts the current root", async () => {
      const { r, R, clock } = await timeline();
      assert.strictEqual(isRootAcceptable(r.history(0), R[3], clock.now() + 1000, 30), true);
    });

    it("accepts an older root within 30 s when every change since was an insert", async () => {
      const { r, R, clock } = await timeline();
      const h = r.history(0);
      // R1 -> R2 insert, R2 -> R3 revoke: R2 was superseded by a revoke: never acceptable
      assert.strictEqual(isRootAcceptable(h, R[2], clock.now() + 1, 30), false);
      // before the revoke happened the same root was acceptable: use a registry with inserts only
      const { r: r2, R: R2, clock: c2 } = await (async () => {
        const x = await reg("v3");
        const out = [x.r.root()];
        x.clock.advance(1); x.r.insert({ commitment: "1", leaf: "11" }); out.push(x.r.root());
        x.clock.advance(1); x.r.insert({ commitment: "2", leaf: "12" }); out.push(x.r.root());
        return { r: x.r, R: out, clock: x.clock };
      })();
      const h2 = r2.history(0);
      assert.strictEqual(isRootAcceptable(h2, R2[0], c2.now() + 10, 30), true);
      assert.strictEqual(isRootAcceptable(h2, R2[1], c2.now() + 10, 30), true);
    });

    it("rejects an insert-superseded root older than 30 s", async () => {
      const x = await reg("v3");
      const r0 = x.r.root();
      x.clock.advance(1); x.r.insert({ commitment: "1", leaf: "11" });
      const supersededAt = x.clock.now();
      const h = x.r.history(0);
      assert.strictEqual(isRootAcceptable(h, r0, supersededAt + 30, 30), true); // boundary: <= 30
      assert.strictEqual(isRootAcceptable(h, r0, supersededAt + 31, 30), false);
    });

    it("rejects a root with a revoke anywhere between it and the current root, even inside 30 s", async () => {
      const x = await reg("v3");
      x.r.insert({ commitment: "1", leaf: "11" });
      x.clock.advance(1); x.r.insert({ commitment: "2", leaf: "12" });
      const rBefore = x.r.root();
      x.clock.advance(1); x.r.revoke(0);
      x.clock.advance(1); x.r.insert({ commitment: "3", leaf: "13" });
      const h = x.r.history(0);
      assert.strictEqual(isRootAcceptable(h, rBefore, x.clock.now() + 1, 30), false);
    });

    it("rejects an unknown root", async () => {
      const x = await reg("v3");
      assert.strictEqual(isRootAcceptable(x.r.history(0), "123", x.clock.now(), 30), false);
    });

    it("prunes history older than the retention window but keeps the current root", async () => {
      const x = await reg("v3");
      const r0 = x.r.root();
      x.r.insert({ commitment: "1", leaf: "11" });
      x.clock.advance(901);
      x.r.insert({ commitment: "2", leaf: "12" });
      const h = x.r.history(0);
      assert.ok(!h.some((e) => e.root === r0));
      assert.strictEqual(h[h.length - 1].supersededAt, null);
    });
  });
});
