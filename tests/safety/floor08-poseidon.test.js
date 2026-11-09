"use strict";
// Floor 8: circuit, issuer and client use identical Poseidon parameters (cross-check test).
//
// Two layers: (1) an independent safety cross-check: the real issuer signs and stores, the real
// client builds the input, the COMMITTED v4 wasm (the prover's circuit) recomputes commitment,
// attrHash, Merkle root and nullifier, and everything must agree, anchored on published circomlib
// Poseidon outputs; (2) the identity team's cross-check suite (issuer/test/crosscheck.v4.test.js,
// G1-S1-IDEN-013) is run as-is and must pass.
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { spawnSync } = require("child_process");
const h = require("./helpers");

const { zk, witnessV4 } = h;
const client = require(h.r("client", "src"));

const T0 = 1_800_000_000;
const ATTRS = { role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };

let iss, issuer, wallet;
before(async () => {
  iss = await h.makeIssuer({ t0: T0 });
  issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });
  wallet = new client.Wallet({ home: h.tmpDir("wallet") });
  await wallet.keygen({ name: "carol", profile: "v4", issuerUrl: "http://issuer.test" });
  await h.enrolViaAdmin({ iss, wallet, name: "carol", issuer, attributes: ATTRS, employeeId: "carol" });
});
after(async () => {
  await iss.app.close();
  await client.shutdown();
});

/** Index of a named signal in the witness, from the committed setup's symbol-free layout: the
 * output nullifier is w[1], then the 11 public inputs in declaration order (w[2..12]). */
const PUB = ["nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance", "requireDevice", "now", "nonce", "resourceId", "epoch"];

describe("floor 8: one Poseidon across circuit, issuer, client", () => {
  test("F8.01 lib Poseidon matches published circomlib/circomlibjs reference outputs", async () => {
    // Values from circomlibjs' own test suite and the zk-kit zero hash (Poseidon(2)(0,0)).
    assert.equal(await zk.poseidon([1, 2]), "7853200120776062878684798364095072458815029376092732009249414926327459813530");
    assert.equal(await zk.poseidon([0, 0]), "14744269619966411208579211824598458697587494354926760081771325075741142829156");
    assert.equal(await zk.poseidon([1]), "18586133768512220936620570745912940619677854269274689475585506675881198879027");
  });

  test("F8.02 issuer-signed leaf == lib attrHash(client commitment) == registry leaf, and the issuer's signature verifies", async () => {
    const c = wallet.load("carol");
    const ah = await zk.attrHash(c.attributes, c.commitment);
    const leaves = JSON.parse((await iss.admin("GET", "/admin/leaves")).body).leaves;
    assert.equal(leaves[c.leafIndex].leaf, ah);
    const p = JSON.parse((await iss.app.inject({ method: "GET", url: `/path/${c.leafIndex}` })).body);
    assert.equal(p.leaf, ah);
    assert.equal(await zk.verifySignature(ah, c.signature, c.issuer), true);
    const info = JSON.parse((await iss.app.inject({ method: "GET", url: "/issuer" })).body);
    assert.deepEqual(c.issuer, info.issuer);
  });

  test("F8.03 the committed circuit accepts the client-built input and recomputes the registry root and the lib nullifier", async () => {
    const c = wallet.load("carol");
    const prep = await client.prepareV4({ credential: c, issuer, challenge: h.challengeFor("admin_panel", "31337", T0) });
    const w = await witnessV4(prep.input);
    assert.equal(w.ok, true, w.error);
    const pub = w.witness.slice(1, 13).map(String);
    const root = JSON.parse((await iss.app.inject({ method: "GET", url: "/root" })).body).root;
    assert.equal(pub[PUB.indexOf("root")], root, "circuit root != registry root");
    assert.equal(pub[0], await zk.nullifier(c.secrets.credentialSecret, 3, Math.floor(T0 / 600)), "circuit nullifier != lib nullifier");
    assert.deepEqual(pub, prep.expectedSignals, "witness public signals != client's expected signals");
    // and a wrong-commitment variant (salt + 1) is refused by the circuit: the commitment Poseidon is the same one
    const bad = await witnessV4({ ...prep.input, credentialSalt: (BigInt(prep.input.credentialSalt) + 1n).toString() });
    assert.equal(bad.ok, false);
  });

  test("F8.04 one encoder: issuer and client import circuits/lib, and carry no Poseidon of their own", () => {
    const fs = require("fs");
    const scan = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith(".js")).map((f) => [f, fs.readFileSync(path.join(dir, f), "utf8")]);
    for (const dir of [h.r("issuer", "src"), h.r("client", "src")]) {
      for (const [f, src] of scan(dir)) {
        assert.ok(!/require\(["'](circomlibjs|poseidon-lite|@iden3\/js-crypto)/.test(src), `${dir}/${f} imports its own Poseidon`);
      }
    }
    assert.match(fs.readFileSync(h.r("issuer", "src", "signer.js"), "utf8"), /require\("\.\.\/\.\.\/circuits\/lib"\)/);
    assert.match(fs.readFileSync(h.r("client", "src", "enrol.js"), "utf8"), /require\("\.\.\/\.\.\/circuits\/lib"\)/);
  });

  test("F8.05 identity's cross-check suite (G1-S1-IDEN-013) passes", () => {
    const mocha = h.r("issuer", "node_modules", "mocha", "bin", "mocha.js");
    const res = spawnSync(process.execPath, [mocha, "--no-config", "--timeout", "900000", "--exit", "test/crosscheck.v4.test.js"], {
      cwd: h.r("issuer"), encoding: "utf8", timeout: 900000,
    });
    const tail = `${res.stdout}\n${res.stderr}`.split("\n").slice(-15).join("\n");
    assert.equal(res.status, 0, tail);
    const m = /(\d+) passing/.exec(res.stdout);
    assert.ok(m && Number(m[1]) >= 8, `cross-check suite shrank below its 8 tests at review time\n${tail}`);
    assert.ok(!/\d+ failing/.test(res.stdout), tail);
  });
});
