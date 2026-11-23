// G1-S1-CIRC-037: committed v4 Groth16 fixtures (circuits/fixtures/v4/) for the gateway (P3), the
// client and the Attack Lab. Every fixture is a REAL proof under the committed v4 key; the attack
// fixtures verify cryptographically and carry exactly the property the gateway obligation
// (access.public_signals v4, obligations 1-8) must reject them on. Floor 6: no private value on disk.
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const zk = require("../lib");
const verifyLib = require("../scripts/verify.js");

const CIRCUITS = path.resolve(__dirname, "..");
const REPO = path.resolve(CIRCUITS, "..");
const SETUP = path.join(CIRCUITS, "setup");
const FIX = path.join(CIRCUITS, "fixtures", "v4");
const SCRIPT = path.join(CIRCUITS, "scripts", "access-fixtures.js");
const NAME = "integrated_access_v4";

const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const sha256 = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");

const VALID = ["alice_wiki", "alice_file_share", "carol_admin_panel", "carol_wiki", "bob_wiki"];
const ATTACKS = [
  "stale_root_bob_wiki",
  "forged_issuer_alice_wiki",
  "stale_now_alice_wiki",
  "same_epoch_a",
  "same_epoch_b",
  "wrong_service_alice_wiki_as_admin",
];
const ALL = [...VALID, ...ATTACKS];
const NONCE_TTL = 120n; // access.public_signals v4 obligation 5: skew bound = nonce TTL

const VEC = readJson(path.join(CIRCUITS, "test", "vectors", "v4", "credentials.json"));
const VEC_INPUT = readJson(path.join(CIRCUITS, "test", "vectors", "v4", "input.alice.wiki.json"));
const persona = Object.fromEntries(VEC.credentials.map((c) => [c.persona, c]));

let index;
let vkey;
const fx = {}; // name -> { proof, pub, sig (decoded by name), meta }

after(async () => {
  await verifyLib.terminate();
});

describe("G1-S1-CIRC-037 v4 fixtures (circuits/fixtures/v4)", function () {
  this.timeout(300000);

  before(() => {
    index = readJson(path.join(FIX, "fixtures.json"));
    vkey = readJson(path.join(SETUP, `${NAME}.verification_key.json`));
    for (const n of ALL) {
      const pub = readJson(path.join(FIX, n, "public.json"));
      fx[n] = { proof: readJson(path.join(FIX, n, "proof.json")), pub, sig: zk.decodePublicSignals("v4", pub), meta: index.fixtures[n] };
    }
  });

  describe("index (fixtures.json) and layout", () => {
    it("lists exactly the valid set and the attack set, each with kind, expect, obligation and description", () => {
      assert.deepEqual(Object.keys(index.fixtures).sort(), [...ALL].sort());
      for (const n of ALL) {
        const m = index.fixtures[n];
        assert.equal(m.dir, n);
        assert.equal(m.kind, VALID.includes(n) ? "valid" : "attack", n);
        assert.ok(["accept", "reject"].includes(m.expect), n);
        assert.ok(Array.isArray(m.gateway_obligations) && m.gateway_obligations.length > 0, n);
        for (const o of m.gateway_obligations) assert.ok(Number.isInteger(o) && o >= 1 && o <= 8, `${n} obligation ${o}`);
        assert.ok(typeof m.description === "string" && m.description.length > 20, n);
        assert.ok(zk.policies[m.resource], `${n} resource`);
        assert.ok(zk.policies[m.presented_to], `${n} presented_to`);
        assert.ok(persona[m.persona], `${n} persona`);
      }
      for (const n of VALID) assert.equal(index.fixtures[n].expect, "accept", n);
      for (const n of ATTACKS.filter((x) => x !== "same_epoch_a")) assert.equal(index.fixtures[n].expect, "reject", n);
      assert.equal(index.fixtures.same_epoch_a.expect, "accept");
      assert.equal(index.documented.replay.reuse, "alice_wiki");
      assert.equal(index.documented.replay.expect, "reject");
      assert.deepEqual(index.documented.replay.gateway_obligations, [6]);
    });

    it("binds to the committed v4 setup (vkey sha256, zkey sha256, public-signal order) and its vkey copy is identical", () => {
      const man = readJson(path.join(SETUP, `${NAME}.manifest.json`));
      assert.equal(index.verification_key_sha256, man.verification_key_sha256);
      assert.equal(index.zkey_sha256, man.zkey_sha256);
      assert.deepEqual(index.public_signals, man.public_signals);
      assert.equal(sha256(path.join(FIX, "verification_key.json")), man.verification_key_sha256);
      assert.match(index.TEST_ONLY, /TEST-ONLY/);
      // G2-S1-FINAL-001: the key comes from the simulated 3-party ceremony (DEMO-ONLY, never production)
      assert.equal(man.status, "DEMO-ONLY");
      assert.match(index.TEST_ONLY, /a DEMO-ONLY key \(phase 1 PSE ppot 0080; multi-party phase 2, 3 contributors \+ public beacon;/);
      assert.match(index.TEST_ONLY, /simulated by separate agents on one machine under one operator, so the multi-party guarantee does not hold/);
      assert.match(index.TEST_ONLY, /docs\/ceremony\/v4-ceremony-log\.md/);
      assert.match(index.TEST_ONLY, /Not for production\. Never use outside tests\./);
      assert.doesNotMatch(index.TEST_ONLY, /single-party|DEV-ONLY/);
    });

    it("contains only README.md, fixtures.json, verification_key.json and <name>/{proof,public}.json", () => {
      const top = fs.readdirSync(FIX).sort();
      assert.deepEqual(top, ["README.md", "fixtures.json", "verification_key.json", ...ALL].sort());
      for (const n of ALL) assert.deepEqual(fs.readdirSync(path.join(FIX, n)).sort(), ["proof.json", "public.json"], n);
    });

    it("README maps every fixture (and the replay) to a gateway obligation", () => {
      const readme = fs.readFileSync(path.join(FIX, "README.md"), "utf8");
      for (const n of ALL) assert.match(readme, new RegExp("`" + n + "`"), n);
      assert.match(readme, /replay/i);
      for (const o of [1, 2, 3, 4, 5, 6, 7]) assert.match(readme, new RegExp(`obligation ${o}\\b`), `obligation ${o}`);
      assert.match(readme, /\*\*DEMO-ONLY\*\* key/);
      assert.match(readme, /simulated\*\* by separate agents on one machine/);
      assert.match(readme, /not for production/);
      assert.doesNotMatch(readme, /single-party|DEV-ONLY/);
    });
  });

  describe("floor 6: no private value on disk", () => {
    it("no fixture file contains a secret, salt, commitment, attrHash, signature or Merkle sibling of any persona or the forger", () => {
      const secrets = new Set();
      for (const c of VEC.credentials) {
        for (const v of [c.credentialSecret, c.credentialSalt, c.commitment, c.attrHash, c.signature.R8x, c.signature.R8y, c.signature.S]) secrets.add(v);
        for (const v of c.merkle.pathElements) secrets.add(v);
      }
      for (const v of Object.values(VEC.forged.signature)) secrets.add(v);
      for (const v of Object.values(VEC_INPUT.input).flat()) secrets.add(String(v));
      // Short values (attributes 0..3, pathIndices, "0" empty siblings) and the public signals
      // themselves (root, issuer key, policy, now, nonce, resourceId, epoch) are not secrets.
      const pubVals = new Set(ALL.flatMap((n) => fx[n].pub));
      const scan = [...secrets].filter((v) => v.length > 12 && !pubVals.has(v));
      assert.ok(scan.length >= 30, `the scan list is not trivially empty (${scan.length})`);
      const files = [path.join(FIX, "fixtures.json"), path.join(FIX, "README.md"), ...ALL.flatMap((n) => [path.join(FIX, n, "proof.json"), path.join(FIX, n, "public.json")])];
      for (const f of files) {
        const text = fs.readFileSync(f, "utf8");
        for (const v of scan) assert.ok(!text.includes(v), `${path.relative(REPO, f)} contains a private value`);
        // no private-input key in any JSON (the README may name them in prose)
        if (f.endsWith(".json")) assert.doesNotMatch(text, /credentialSecret|credentialSalt|pathElements|pathIndices|"R8x"|"S"\s*:/, path.relative(REPO, f));
      }
    });
  });

  describe("cryptography: every fixture verifies under the committed v4 key (obligation 1)", () => {
    for (const n of ALL) {
      it(`${n} verifies; any public signal + 1 does not`, async () => {
        const { proof, pub } = fx[n];
        assert.equal(await verifyLib.verify(vkey, pub, proof), true);
        const i = (n.length * 7) % 12; // one tampered signal per fixture (setup_v4 tests all 12)
        assert.equal(await verifyLib.verify(vkey, pub.map((x, j) => (j === i ? (BigInt(x) + 1n).toString() : x)), proof), false);
      });
    }
  });

  describe("valid fixtures: every gateway obligation holds in the scenario context", () => {
    for (const n of VALID) {
      it(`${n}: pinned issuer, current root, the requested resource's policy, gateway now/epoch, lib nullifier`, async () => {
        const { sig, meta } = fx[n];
        const ctx = index.context;
        const pol = zk.policies[meta.resource];
        assert.equal(meta.presented_to, meta.resource);
        assert.equal(sig.issuerAx, ctx.pinned_issuer.Ax);
        assert.equal(sig.issuerAy, ctx.pinned_issuer.Ay);
        assert.equal(sig.root, ctx.root_before_revocation);
        assert.equal(sig.now, ctx.gateway_now);
        assert.equal(sig.epoch, ctx.epoch);
        assert.equal(sig.epoch, zk.epochOf(sig.now));
        for (const k of ["roleMask", "deptMask", "minClearance", "requireDevice", "resourceId"]) assert.equal(sig[k], String(pol[k]), k);
        assert.equal(sig.nullifier, await zk.nullifier(persona[meta.persona].credentialSecret, pol.resourceId, sig.epoch));
        assert.equal(sig.nonce, meta.nonce);
        assert.ok(BigInt(sig.nonce) < 1n << 128n, "128-bit nonce");
        assert.equal(persona[meta.persona].expectedAccess[meta.resource].ok, true);
      });
    }

    it("alice_wiki's public.json equals the vector's expectedPublicSignals", () => {
      assert.deepEqual(fx.alice_wiki.pub, VEC_INPUT.expectedPublicSignals);
    });

    it("every fixture nonce is distinct (each is a separately issued challenge)", () => {
      const nonces = ALL.map((n) => fx[n].sig.nonce);
      assert.equal(new Set(nonces).size, nonces.length);
    });

    it("unlinkability: Alice's Wiki and File Share nullifiers differ; Alice's and Carol's Wiki nullifiers differ", () => {
      assert.notEqual(fx.alice_wiki.sig.nullifier, fx.alice_file_share.sig.nullifier);
      assert.notEqual(fx.alice_wiki.sig.nullifier, fx.carol_wiki.sig.nullifier);
      assert.notEqual(fx.carol_wiki.sig.nullifier, fx.carol_admin_panel.sig.nullifier);
    });
  });

  describe("scenario context", () => {
    it("pinned issuer = vector issuer; root_before = vector root; root_after = the same tree with Bob's leaf deleted", async () => {
      const ctx = index.context;
      assert.deepEqual(ctx.pinned_issuer, { Ax: VEC.issuer.Ax, Ay: VEC.issuer.Ay });
      assert.equal(ctx.root_before_revocation, VEC.tree.root);
      const tree = await zk.createTree("v4");
      for (const c of VEC.credentials) tree.insert(BigInt(c.attrHash));
      assert.equal(tree.root.toString(), ctx.root_before_revocation);
      tree.delete(persona.bob.leafIndex);
      assert.equal(tree.root.toString(), ctx.root_after_bob_revoked);
      assert.notEqual(ctx.root_after_bob_revoked, ctx.root_before_revocation);
      assert.deepEqual(ctx.revoked, { persona: "bob", leafIndex: persona.bob.leafIndex });
      assert.equal(ctx.gateway_now, VEC.now);
      assert.equal(ctx.epoch, VEC.epoch);
      assert.equal(ctx.nonce_ttl_seconds, Number(NONCE_TTL));
      assert.deepEqual(ctx.resources, JSON.parse(JSON.stringify(zk.policies)));
    });
  });

  describe("attack fixtures carry the property the gateway must reject them on", () => {
    it("stale_root_bob_wiki (obligation 3, floor 3): Bob's valid proof on the pre-revocation root, which is not the current root", () => {
      const { sig, meta } = fx.stale_root_bob_wiki;
      const ctx = index.context;
      assert.equal(meta.persona, "bob");
      assert.deepEqual(meta.gateway_obligations, [3]);
      assert.equal(sig.root, ctx.root_before_revocation);
      assert.notEqual(sig.root, ctx.root_after_bob_revoked);
      assert.equal(meta.gateway_state.current_root, ctx.root_after_bob_revoked);
      // everything else would pass: pinned key, Wiki policy, gateway now/epoch
      assert.equal(sig.issuerAx, ctx.pinned_issuer.Ax);
      assert.equal(sig.now, ctx.gateway_now);
      assert.equal(sig.resourceId, "1");
    });

    it("forged_issuer_alice_wiki (obligation 2, floor 2): issuer key is the TEST-ONLY forger's, not the pinned key", () => {
      const { sig, meta } = fx.forged_issuer_alice_wiki;
      const ctx = index.context;
      assert.deepEqual(meta.gateway_obligations, [2]);
      assert.equal(sig.issuerAx, VEC.forged.publicKey.Ax);
      assert.equal(sig.issuerAy, VEC.forged.publicKey.Ay);
      assert.notEqual(sig.issuerAx, ctx.pinned_issuer.Ax);
      assert.equal(sig.root, ctx.root_before_revocation, "real root and path: only the pin stops it");
      assert.equal(sig.nullifier, fx.alice_wiki.sig.nullifier);
    });

    it("stale_now_alice_wiki (obligation 5, floor 2): now far behind the gateway clock (beyond the 120 s skew), credential still unexpired then", () => {
      const { sig, meta } = fx.stale_now_alice_wiki;
      const ctx = index.context;
      assert.deepEqual(meta.gateway_obligations, [5]);
      assert.ok(BigInt(sig.now) < BigInt(ctx.gateway_now) - NONCE_TTL);
      assert.ok(BigInt(sig.now) < BigInt(persona.alice.attributes.expiry));
      assert.equal(sig.epoch, zk.epochOf(sig.now));
      assert.notEqual(sig.epoch, ctx.epoch);
      assert.equal(sig.issuerAx, ctx.pinned_issuer.Ax);
      assert.equal(sig.root, ctx.root_before_revocation);
    });

    it("same_epoch_a / same_epoch_b (obligation 7, floor 5): different nonces, same resource and epoch, equal nullifiers", () => {
      const a = fx.same_epoch_a;
      const b = fx.same_epoch_b;
      assert.deepEqual(a.meta.gateway_obligations, [7]);
      assert.deepEqual(b.meta.gateway_obligations, [7]);
      assert.notEqual(a.sig.nonce, b.sig.nonce);
      assert.equal(a.sig.resourceId, b.sig.resourceId);
      assert.equal(a.sig.epoch, b.sig.epoch);
      assert.equal(a.sig.epoch, index.context.epoch);
      assert.equal(a.sig.nullifier, b.sig.nullifier);
      assert.equal(a.sig.nullifier, fx.alice_wiki.sig.nullifier);
      assert.deepEqual(b.meta.present_after, ["same_epoch_a"]);
    });

    it("wrong_service_alice_wiki_as_admin (obligation 4, floor 2): a Wiki proof presented for Admin Panel; policy and resourceId mismatch", () => {
      const { sig, meta } = fx.wrong_service_alice_wiki_as_admin;
      assert.deepEqual(meta.gateway_obligations, [4]);
      assert.equal(meta.resource, "wiki");
      assert.equal(meta.presented_to, "admin_panel");
      const want = zk.policies.admin_panel;
      assert.notEqual(sig.resourceId, String(want.resourceId));
      const mismatched = ["roleMask", "minClearance", "resourceId"].filter((k) => sig[k] !== String(want[k]));
      assert.deepEqual(mismatched, ["roleMask", "minClearance", "resourceId"]);
      assert.equal(persona.alice.expectedAccess.admin_panel.ok, false, "Alice cannot prove Admin Panel at all");
    });
  });

  describe("circuits/scripts/access-fixtures.js", () => {
    it("plan() reproduces every committed public.json from circuits/lib (no proving)", async () => {
      const { plan } = require(SCRIPT);
      const p = await plan();
      assert.deepEqual(Object.keys(p.fixtures).sort(), [...ALL].sort());
      for (const n of ALL) assert.deepEqual(await zk.expectedPublicSignals("v4", p.fixtures[n].input), fx[n].pub, n);
      assert.deepEqual(p.context, index.context);
    });

    for (const [what, file] of [["zkey", `${NAME}.zkey`], ["wasm", `${NAME}.wasm`]]) {
      it(`refuses (exit 2, writes nothing) when the ${what} hash differs from the manifest`, () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zkag-fx-"));
        try {
          const setup = path.join(dir, "setup");
          fs.mkdirSync(setup);
          for (const f of [`${NAME}.zkey`, `${NAME}.wasm`, `${NAME}.verification_key.json`, `${NAME}.manifest.json`]) {
            fs.copyFileSync(path.join(SETUP, f), path.join(setup, f));
          }
          const buf = fs.readFileSync(path.join(setup, file));
          buf[buf.length - 64] ^= 0xff;
          fs.writeFileSync(path.join(setup, file), buf);
          const out = path.join(dir, "out");
          const r = spawnSync(process.execPath, [SCRIPT, "--out", out], { cwd: REPO, env: { ...process.env, SETUP_OUT: setup }, encoding: "utf8", timeout: 120000 });
          assert.equal(r.status, 2, r.stderr);
          assert.match(r.stderr, new RegExp(`${what}_sha256`));
          assert.equal(fs.existsSync(out), false);
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      });
    }

    it("rejects unknown arguments with exit 2", () => {
      const r = spawnSync(process.execPath, [SCRIPT, "--bogus"], { cwd: REPO, encoding: "utf8", timeout: 60000 });
      assert.equal(r.status, 2, r.stderr);
    });
  });
});
