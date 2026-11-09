"use strict";
// G1-S1-IDEN-013, floor 8: issuer, registry, client and circuit agree on Poseidon parameters and
// encodings. One suite drives the REAL issuer (in-process Fastify, temp dirs), the REAL client
// library (Wallet, IssuerClient, requestCredential, prepareV3/prepareV4) over an inject-backed
// fetch, the shared lib (circuits/lib) and the compiled circuits (v3 depth 2, v4 depth 16; --O0 so
// signals keep their names). Nothing here proves with snarkjs (no v4 keys needed): the witness is
// calculated from the input the client built, and named signals are read back.
//
// Every checked value is recorded in ROWS and printed as a table at the end. Only public values are
// ever printed (truncated); secrets, salts, signatures and attributes never reach the output.
const path = require("path");
const assert = require("assert/strict");
const { makeApp, adminEnrol, post, json, mutableClock, tmpDir, T0, V3_ATTRS, zk } = require("./helpers");
const client = require("../../client/src");
const { compileCached, compileV3, NamedWitness, CIRCUITS } = require("../../circuits/test/helpers");

const EXPIRY = 4070908800;
const ATTRS_V4 = {
  alice: { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY },
  bob: { role: "contractor", dept: "operations", clearance: 1, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY },
  carol: { role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: EXPIRY },
};
// resources each persona satisfies (policy table, circuits/lib/policy.js)
const RESOURCES = { alice: ["wiki", "file_share"], bob: ["wiki"], carol: ["wiki", "admin_panel"] };
const NONCES = ["188145448239764496473744807162415126743", "109744069262759769149197779815633506376"];

const ROWS = [];
const short = (v) => { const s = String(v); return s.length > 14 ? `${s.slice(0, 6)}..${s.slice(-6)}` : s; };
/** Assert a === b (as strings) and record the pair as one checked value. */
function eq(profile, persona, id, label, a, b, show = true) {
  assert.equal(String(a), String(b), `${profile}/${persona}: ${label}`);
  ROWS.push({ id, profile, persona, label, value: show ? short(a) : "(not shown)" });
}
function ok(profile, persona, id, label, cond) {
  assert.ok(cond, `${profile}/${persona}: ${label}`);
  ROWS.push({ id, profile, persona, label, value: "true" });
}

const V4_SOURCES = ["integrated_access_v4_gate", "attribute_hash", "eddsa_verifier", "issuer_key", "merkle_membership_n",
  "access_policy_v4", "expiry", "challenge_binding"].map((f) => path.join(CIRCUITS, "components", `${f}.circom`));
const V4_MAIN = path.join(CIRCUITS, "integrated_access_v4.circom");
const compileV4O0 = () => compileCached("v4-d16-O0", V4_MAIN, [V4_MAIN, ...V4_SOURCES], { O: 0 });

/** fetch() that serves IssuerClient from an in-process Fastify app (no sockets). */
const injectFetch = (app) => async (url, init) => {
  const u = new URL(url);
  const r = await app.inject({ method: init.method, url: u.pathname + u.search, headers: init.headers, payload: init.body });
  return { status: r.statusCode, text: async () => r.body };
};

const challengeFor = (resource, nonce, now = T0) => {
  const p = zk.policies[resource];
  return {
    nonce, resourceId: p.resourceId, epoch: Math.floor(now / 600), now,
    policy: { roleMask: p.roleMask, deptMask: p.deptMask, minClearance: p.minClearance, requireDevice: p.requireDevice },
  };
};

/** Root rebuilt from the issuer's public leaf listing with a fresh lib tree (revoked leaf = 0). */
async function libRootFromListing(app, profile) {
  const res = await app.inject({ method: "GET", url: "/admin/leaves?limit=5000" });
  const { leaves } = json(res);
  const tree = await zk.createTree(profile);
  for (const l of leaves) tree.insert(BigInt(l.leaf));
  return { root: tree.root.toString(), leaves };
}

describe("floor 8: cross-component Poseidon and encoding cross-check (G1-S1-IDEN-013)", function () {
  this.timeout(900000);
  after(() => {
    const w = (s, n) => String(s).padEnd(n);
    console.log("\nCROSS-CHECK TABLE (public values only, truncated)");
    console.log(`${w("id", 6)} ${w("profile", 7)} ${w("persona", 8)} ${w("value checked", 78)} value`);
    for (const r of ROWS) console.log(`${w(r.id, 6)} ${w(r.profile, 7)} ${w(r.persona, 8)} ${w(r.label, 78)} ${r.value}`);
    console.log(`total checked values: ${ROWS.length}`);
  });

  for (const profile of ["v3", "v4"]) {
    describe(`profile ${profile}`, function () {
      let ctx, tester, issuer, wallet, personas, home;

      before(async function () {
        tester = profile === "v3" ? await compileV3(0) : await compileV4O0();
        ctx = await makeApp({ profile, clock: mutableClock() });
        issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: injectFetch(ctx.app) });
        home = tmpDir("zkgate-home-");
        wallet = new client.Wallet({ home });
        personas = profile === "v3" ? { alice: V3_ATTRS, bob: { ...V3_ATTRS } } : ATTRS_V4;
        for (const [name, attributes] of Object.entries(personas)) {
          await wallet.keygen({ name, profile, issuerUrl: "http://issuer.test" });
          const ints = { ...attributes, ...(profile === "v4" ? { role: zk.ROLES[attributes.role], dept: zk.DEPTS[attributes.dept] } : {}) }; // the admin assigns integers
          const e = await adminEnrol(ctx.app, profile, ints, name);
          assert.strictEqual(e.res.statusCode, 201, e.res.body);
          await client.requestCredential({ wallet, name, issuer, enrolmentCode: e.code });
        }
      });
      after(async () => {
        await ctx.app.close();
        await client.shutdown();
      });

      /** Circuit input via the client library, plus the named witness. */
      async function prepare(name, resource, nonce) {
        const credential = wallet.load(name);
        let prep;
        if (profile === "v3") prep = await client.prepareV3({ credential, issuer });
        else prep = await client.prepareV4({ credential, issuer, challenge: challengeFor(resource, nonce) });
        const w = await tester.calculateWitness(prep.input, true);
        await tester.checkConstraints(w);
        return { credential, ...prep, w, nw: new NamedWitness(tester, w) };
      }

      const pub = (name) => ({ ...wallet.load(name) });

      it("1. commitment: client == issuer leaf derivation == lib == circuit witness", async () => {
        const issuerInfo = json(await ctx.app.inject({ method: "GET", url: "/issuer" }));
        const tree = json(await ctx.app.inject({ method: "GET", url: "/admin/tree" }));
        for (const name of Object.keys(personas)) {
          const c = pub(name);
          const viaLib = await zk.commitment(c.secrets.credentialSecret, c.secrets.credentialSalt);
          const viaPoseidon = await zk.poseidon([c.secrets.credentialSecret, c.secrets.credentialSalt]);
          eq(profile, name, "C1.1", "client wallet commitment == lib commitment(secret, salt)", c.commitment, viaLib);
          eq(profile, name, "C1.2", "lib commitment == raw lib poseidon([secret, salt])", viaLib, viaPoseidon);
          // the issuer never sees secrets, so its side is the leaf it stored for the client's commitment
          const p = zk.profiles[profile];
          const leafFromClientInputs = await p.leaf({ commitment: c.commitment, attributes: c.attributes });
          eq(profile, name, "C1.3", "issuer tree level-0 node at leafIndex == leaf derived from client commitment + issuer-returned attributes",
            tree.levels[0].nodes[c.leafIndex], leafFromClientInputs);
          ok(profile, name, "C1.4", "issuer signature (from API response) verifies over the message derived from the client commitment",
            await zk.verifySignature(await p.message({ commitment: c.commitment, attributes: c.attributes }), c.signature, c.issuer));
          eq(profile, name, "C1.5", "issuer key in credential == GET /issuer key (Ax)", c.issuer.Ax, issuerInfo.issuer.Ax);
          eq(profile, name, "C1.6", "issuer key in credential == GET /issuer key (Ay)", c.issuer.Ay, issuerInfo.issuer.Ay);
          const r = await prepare(name, RESOURCES[name] ? RESOURCES[name][0] : undefined, NONCES[0]);
          eq(profile, name, "C1.7", "circuit witness credentialCommitment == client commitment", r.nw.get("main.credentialCommitment"), c.commitment);
          eq(profile, name, "C1.8", "circuit witness commitmentHasher.out == client commitment", r.nw.get("main.commitmentHasher.out"), c.commitment);
        }
      });

      if (profile === "v4") {
        it("2. attrHash: client lib == issuer-signed message == circuit AttributeHash == issuer tree leaf", async () => {
          const tree = json(await ctx.app.inject({ method: "GET", url: "/admin/tree" }));
          const leaves = json(await ctx.app.inject({ method: "GET", url: "/admin/leaves" })).leaves;
          for (const name of Object.keys(personas)) {
            const c = pub(name);
            const ah = await zk.attrHash(c.attributes, c.commitment);
            const direct = await zk.poseidon([c.attributes.role, c.attributes.dept, c.attributes.clearance, c.attributes.deviceCompliant,
              c.attributes.employeeActive, c.attributes.expiry, c.commitment]);
            eq(profile, name, "A2.1", "lib attrHash == Poseidon(7)(role,dept,clearance,device,active,expiry,commitment) written out", ah, direct);
            ok(profile, name, "A2.2", "issuer signature verifies over the lib attrHash", await zk.verifySignature(ah, c.signature, c.issuer));
            ok(profile, name, "A2.3", "(sanity) the same signature does NOT verify over attrHash+1", !(await zk.verifySignature((BigInt(ah) + 1n).toString(), c.signature, c.issuer)));
            eq(profile, name, "A2.4", "issuer /admin/tree level 0 at leafIndex == lib attrHash", tree.levels[0].nodes[c.leafIndex], ah);
            eq(profile, name, "A2.5", "issuer /admin/leaves leaf == lib attrHash", leaves[c.leafIndex].leaf, ah);
            const r = await prepare(name, RESOURCES[name][0], NONCES[0]);
            eq(profile, name, "A2.6", "circuit AttributeHash output (main.attr.attrHash) == lib attrHash", r.nw.get("main.attr.attrHash"), ah);
            eq(profile, name, "A2.7", "merkle leaf in the circuit == lib attrHash", r.nw.get("main.merkle.leaf"), ah);
          }
        });
      }

      async function rootChecks(phase, names, base) {
        const rootRes = json(await ctx.app.inject({ method: "GET", url: "/root" }));
        const { root: rebuilt, leaves } = await libRootFromListing(ctx.app, profile);
        const tree = json(await ctx.app.inject({ method: "GET", url: "/admin/tree" }));
        eq(profile, "(all)", `${base}.1`, `${phase}: issuer /root == lib tree rebuilt from /admin/leaves`, rootRes.root, rebuilt);
        eq(profile, "(all)", `${base}.2`, `${phase}: issuer /root == /admin/tree top node`, rootRes.root, tree.root);
        for (const name of names) {
          const c = pub(name);
          const path_ = await issuer.getPath(c.leafIndex);
          const viaClient = await zk.merkleRoot(path_.leaf, path_.pathElements, path_.pathIndices);
          eq(profile, name, `${base}.3`, `${phase}: client path-recomputed root == issuer /root`, viaClient, rootRes.root);
          eq(profile, name, `${base}.4`, `${phase}: issuer /path root == issuer /root`, path_.root, rootRes.root);
          const leaf = await zk.profiles[profile].leaf({ commitment: c.commitment, attributes: c.attributes });
          eq(profile, name, `${base}.5`, `${phase}: lib merkleRoot(own leaf, path) == issuer /root`, await zk.merkleRoot(leaf, path_.pathElements, path_.pathIndices), rootRes.root);
          eq(profile, name, `${base}.6`, `${phase}: issuer /path leaf == own leaf`, path_.leaf, leaf);
          const r = await prepare(name, RESOURCES[name] ? RESOURCES[name][0] : undefined, NONCES[0]);
          eq(profile, name, `${base}.7`, `${phase}: circuit root input (main.root) == issuer /root`, r.nw.get("main.root"), rootRes.root);
          eq(profile, name, `${base}.8`, `${phase}: circuit public signal slot for root == issuer /root`,
            profile === "v3" ? r.w[1] : r.w[2], rootRes.root);
          ok(profile, name, `${base}.9`, `${phase}: circuit constraints satisfied against the issuer's current root`, true);
        }
        return { rootRes, leaves };
      }

      it("3. root: issuer == client == lib == circuit, before and after a revoke", async () => {
        const before = await rootChecks("before revoke", Object.keys(personas), "R3");
        const bob = pub("bob");
        const rev = await post(ctx.app, `/credentials/${bob.leafIndex}/revoke`, undefined);
        assert.equal(rev.statusCode, 200);
        const after_ = await rootChecks("after revoke ", profile === "v3" ? ["alice"] : ["alice", "carol"], "R3r");
        assert.notEqual(after_.rootRes.root, before.rootRes.root, "the revoke moved the root");
        ROWS.push({ id: "R3r.0", profile, persona: "(all)", label: "revoke changed the root", value: `${short(before.rootRes.root)} -> ${short(after_.rootRes.root)}` });
        eq(profile, "bob", "R3r.10", "issuer /admin/leaves shows the revoked leaf as 0 (the value hashed into the root)", after_.leaves[bob.leafIndex].leaf, "0");
        await assert.rejects(issuer.getPath(bob.leafIndex), (e) => e.code === "revoked");
        ROWS.push({ id: "R3r.11", profile, persona: "bob", label: "client getPath for the revoked leaf is refused (410 revoked)", value: "true" });
      });

      if (profile === "v4") {
        it("4. nullifier: lib == circuit slot 0; differs across resources; stable across nonces", async () => {
          const pubNames = ["alice", "carol"]; // bob revoked in test 3; his path no longer issues
          const seen = new Map(); // `${name}|${resource}` -> nullifier
          for (const name of pubNames) {
            const c = pub(name);
            const sec = c.secrets.credentialSecret;
            for (const resource of RESOURCES[name]) {
              const ch = challengeFor(resource, NONCES[0]);
              const lib = await zk.nullifier(sec, ch.resourceId, ch.epoch);
              const direct = await zk.poseidon([sec, ch.resourceId, ch.epoch]);
              eq(profile, name, "N4.1", `lib nullifier(${resource}) == raw poseidon([secret, resourceId, epoch])`, lib, direct);
              const r0 = await prepare(name, resource, NONCES[0]);
              const r1 = await prepare(name, resource, NONCES[1]);
              eq(profile, name, "N4.2", `circuit output slot 0 (${resource}, nonce 0) == lib nullifier`, r0.w[1], lib);
              eq(profile, name, "N4.3", `client expectedPublicSignals[0] (${resource}) == lib nullifier`, r0.expectedSignals[0], lib);
              eq(profile, name, "N4.4", `circuit named output main.nullifier == slot 0 (${resource})`, r0.nw.get("main.nullifier"), r0.w[1]);
              eq(profile, name, "N4.5", `nullifier stable across nonces (${resource}): nonce 0 == nonce 1`, r0.w[1], r1.w[1]);
              ok(profile, name, "N4.6", `the two nonces really differ in the circuit (${resource})`, r0.nw.get("main.nonce") !== r1.nw.get("main.nonce"));
              seen.set(`${name}|${resource}`, lib);
            }
            const [r1, r2] = RESOURCES[name];
            ok(profile, name, "N4.7", `nullifiers differ across resources (${r1} vs ${r2})`, seen.get(`${name}|${r1}`) !== seen.get(`${name}|${r2}`));
            const later = challengeFor(r1, NONCES[0], T0 + 600);
            ok(profile, name, "N4.8", "nullifier differs across epochs (same resource)", (await zk.nullifier(sec, later.resourceId, later.epoch)) !== seen.get(`${name}|${r1}`));
          }
          ok(profile, "alice,carol", "N4.9", "different users on the same resource have different nullifiers (wiki)", seen.get("alice|wiki") !== seen.get("carol|wiki"));
        });
      }

      it("5. public signals: client expectedPublicSignals == witness slots, decoded with decodePublicSignals", async () => {
        const names = profile === "v3" ? ["alice"] : ["alice", "carol"];
        for (const name of names) {
          for (const resource of profile === "v3" ? [undefined] : RESOURCES[name]) {
            const r = await prepare(name, resource, NONCES[0]);
            const n = zk.PUBLIC_SIGNALS[profile].length;
            const fromWitness = r.w.slice(1, 1 + n).map(String);
            const expected = profile === "v3" ? await zk.expectedPublicSignals("v3", r.input) : r.expectedSignals;
            eq(profile, name, "S5.1", `expectedPublicSignals has ${n} signal(s)`, expected.length, n);
            const dw = zk.decodePublicSignals(profile, fromWitness);
            const de = zk.decodePublicSignals(profile, expected);
            for (const k of zk.PUBLIC_SIGNALS[profile]) {
              eq(profile, name, "S5.2", `${resource || "-"}: signal ${k}: witness == client expected`, dw[k], de[k]);
            }
            if (profile === "v4") {
              const ch = challengeFor(resource, NONCES[0]);
              const info = json(await ctx.app.inject({ method: "GET", url: "/issuer" })).issuer;
              const want = { issuerAx: info.Ax, issuerAy: info.Ay, roleMask: ch.policy.roleMask, deptMask: ch.policy.deptMask,
                minClearance: ch.policy.minClearance, requireDevice: ch.policy.requireDevice, now: ch.now, nonce: ch.nonce,
                resourceId: ch.resourceId, epoch: ch.epoch };
              for (const [k, v] of Object.entries(want)) eq(profile, name, "S5.3", `${resource}: witness signal ${k} == issuer/challenge value`, dw[k], v);
              eq(profile, name, "S5.4", `${resource}: witness root slot == issuer /root`, dw.root, json(await ctx.app.inject({ method: "GET", url: "/root" })).root);
            }
            eq(profile, name, "S5.5", "client JSON round trip of the witness slots equals expectedSignals", JSON.stringify(fromWitness), JSON.stringify(expected), false);
          }
        }
      });
    });
  }
});
