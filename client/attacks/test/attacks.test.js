"use strict";
// Attack Lab (G2-S1-IDEN-021): every attack builds well-formed gateway requests, the cryptographic
// expectations hold, and the reference model gateway (test/helpers/modelGateway.js, obligations
// 1-8 of access.public_signals v4) rejects each attack with the expected reason code while
// admitting the honest baseline.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const zk = require("../../../circuits/lib");
const verifier = require("../../../circuits/scripts/verify.js");
const lab = require("../src");
const { ModelGateway } = require("./helpers/modelGateway");

const VKEY = verifier.loadVerificationKey(path.join(__dirname, "..", "..", "..", "circuits", "setup", "integrated_access_v4.verification_key.json"));

let world, gw;
const cache = new Map();
let chain = Promise.resolve();

test.before(async () => {
  world = await lab.createWorld();
  gw = new ModelGateway({ vkey: VKEY, pinned: world.pinned, clock: () => world.now(), root: () => world.root() });
  world.setChallengeSource((resource) => gw.challenge(resource).body);
});
test.after(async () => {
  await world.close();
  await verifier.terminate();
  await lab.shutdown();
});

const send = async (req) => gw.access(JSON.parse(JSON.stringify(req.body)));
/** Build and run one attack at a time: a revocation moves the root under proofs built earlier. */
function result(id) {
  if (!cache.has(id)) {
    const p = chain.then(async () => {
      const built = await lab.buildAttack(id, world);
      const run = await lab.runAttack(built, { send, wait: (s) => world.advance(s) });
      return { built, run };
    });
    chain = p.catch(() => {});
    cache.set(id, p);
  }
  return cache.get(id);
}

const EXPECTED = {
  baseline: ["admit"],
  replay: ["admit", "NONCE_USED"],
  replay_expired: ["NONCE_EXPIRED"],
  revoked: ["ROOT_NOT_CURRENT"],
  tamper: ["PROOF_INVALID"],
  forged: ["ISSUER_NOT_PINNED"],
  wrong_service: ["POLICY_MISMATCH"],
  spam: ["admit", "RATE_LIMITED"],
  expired: ["CHALLENGE_MISMATCH"],
};

test("the attack catalogue covers the scope table plus an honest baseline", () => {
  assert.deepEqual([...lab.ATTACK_IDS].sort(), Object.keys(EXPECTED).sort());
  for (const id of lab.ATTACK_IDS) {
    const a = lab.ATTACKS[id];
    assert.ok(a.title && a.scope && Array.isArray(a.obligations), id);
  }
});

test("reason codes: every code has an obligation, an HTTP status and text; proposal marked", () => {
  for (const [code, c] of Object.entries(lab.CODES)) {
    assert.match(code, /^[A-Z_]+$/);
    assert.ok(Number.isInteger(c.status) && c.status >= 400 && c.status < 500, code);
    assert.ok(c.text.length > 5, code);
    assert.ok(c.obligation === null || (c.obligation >= 1 && c.obligation <= 8), code);
  }
  for (const code of Object.values(EXPECTED).flat()) if (code !== "admit") assert.ok(lab.CODES[code], code);
});

for (const id of Object.keys(EXPECTED)) {
  test(`${id}: well-formed requests, expected outcomes, model gateway agrees`, async () => {
    const { built, run } = await result(id);
    assert.equal(built.id, id);
    assert.ok(built.requests.length >= 1);
    for (const r of built.requests) {
      assert.equal(r.method, "POST");
      assert.equal(r.path, "/access");
      assert.deepEqual(Object.keys(r.body).sort(), ["nonce", "proof", "publicSignals", "resource"]);
      assert.ok(["wiki", "file_share", "admin_panel"].includes(r.body.resource));
      assert.equal(r.body.publicSignals.length, 12);
      for (const s of r.body.publicSignals) assert.ok(typeof s === "string" && zk.isCanonical(s));
      assert.equal(r.body.nonce, r.body.publicSignals[9]);
      assert.ok(r.body.proof.pi_a && r.body.proof.pi_b && r.body.proof.pi_c);
      assert.ok(["admit", "deny"].includes(r.expect.outcome));
      if (r.expect.outcome === "deny") {
        assert.ok(lab.CODES[r.expect.code], r.expect.code);
        assert.equal(r.expect.status, lab.CODES[r.expect.code].status);
        assert.equal(r.expect.obligation, lab.CODES[r.expect.code].obligation);
      }
    }
    assert.deepEqual(built.requests.map((r) => (r.expect.outcome === "admit" ? "admit" : r.expect.code)), EXPECTED[id]);
    assert.ok(run.steps.every((s) => s.pass), JSON.stringify(run.steps.map((s) => [s.label, s.expect, s.actual])));
    assert.equal(run.pass, true);
  });
}

test("honest baseline: the model gateway admits and its log holds no identity", async () => {
  await result("baseline");
  const log = JSON.stringify(gw.log);
  assert.ok(!/alice|bob|carol|engineer|contractor|admin|clearance|@/i.test(log.replace(/admin_panel/g, "")));
});

test("forged: the proof verifies cryptographically; only the issuer pin stops it", async () => {
  const { built } = await result("forged");
  const body = built.requests[0].body;
  assert.equal(await verifier.verify(VKEY, body.publicSignals, body.proof), true);
  const s = zk.decodePublicSignals("v4", body.publicSignals);
  assert.notEqual(s.issuerAx, world.pinned.Ax);
});

test("revoked: the stale-root proof verifies, its root is the pre-revocation one, the path is now gone", async () => {
  const { built } = await result("revoked");
  const body = built.requests[0].body;
  assert.equal(await verifier.verify(VKEY, body.publicSignals, body.proof), true);
  const s = zk.decodePublicSignals("v4", body.publicSignals);
  assert.notEqual(s.root, await world.root());
  assert.equal(built.evidence.revokedPathStatus, 410);
  assert.equal(built.evidence.rootBefore, s.root);
  assert.notEqual(built.evidence.rootAfter, built.evidence.rootBefore);
  assert.equal(s.issuerAx, world.pinned.Ax);
});

test("tamper: edited role/clearance cannot be proved; the patched-signals request fails verify", async () => {
  const { built } = await result("tamper");
  const stages = built.local.map((l) => [l.stage, l.code, l.refused]);
  assert.deepEqual(stages, [["client-input", "BAD_SIGNATURE", true], ["witness", "WITNESS_REFUSED", true]]);
  const body = built.requests[0].body;
  assert.equal(await verifier.verify(VKEY, body.publicSignals, body.proof), false);
  // the patch is consistent with the Admin Panel challenge, so only verify can catch it
  const s = zk.decodePublicSignals("v4", body.publicSignals);
  assert.equal(s.roleMask, String(zk.policies.admin_panel.roleMask));
  assert.equal(s.resourceId, String(zk.policies.admin_panel.resourceId));
  assert.equal(body.resource, "admin_panel");
});

test("wrong_service: Bob -> Admin Panel is refused before proving; Alice's Wiki proof is a valid proof for the wrong policy", async () => {
  const { built } = await result("wrong_service");
  const refusal = built.local.find((l) => l.stage === "client-precheck");
  assert.equal(refusal.refused, true);
  assert.equal(refusal.code, "POLICY_NOT_SATISFIED");
  assert.ok(refusal.reasons.includes("ROLE_NOT_ALLOWED") && refusal.reasons.includes("CLEARANCE_TOO_LOW"));
  const witness = built.local.find((l) => l.stage === "witness");
  assert.equal(witness.code, "WITNESS_REFUSED");
  // the only request is Alice's genuine Wiki proof presented for the Admin Panel
  assert.equal(built.requests.length, 1);
  const body = built.requests[0].body;
  assert.equal(body.resource, "admin_panel");
  assert.equal(await verifier.verify(VKEY, body.publicSignals, body.proof), true);
  assert.equal(zk.decodePublicSignals("v4", body.publicSignals).resourceId, "1");
});

test("expired: no proof for an expired credential; a stale-now proof verifies but violates the challenge", async () => {
  const { built } = await result("expired");
  assert.deepEqual(built.local.map((l) => [l.stage, l.code]), [["client-precheck", "CREDENTIAL_EXPIRED"], ["witness", "WITNESS_REFUSED"]]);
  const body = built.requests[0].body;
  assert.equal(await verifier.verify(VKEY, body.publicSignals, body.proof), true);
  const s = zk.decodePublicSignals("v4", body.publicSignals);
  assert.ok(Number(s.now) < world.now(), "now lies in the past of the gateway clock");
  assert.equal(s.epoch, String(Math.floor(Number(s.now) / 600)));
});

test("spam: two valid proofs share one nullifier and epoch", async () => {
  const { built } = await result("spam");
  const [a, b] = built.requests.map((r) => zk.decodePublicSignals("v4", r.body.publicSignals));
  assert.equal(a.nullifier, b.nullifier);
  assert.equal(a.epoch, b.epoch);
  assert.notEqual(a.nonce, b.nonce);
});

test("replay: the second request is byte-identical to the first", async () => {
  const { built } = await result("replay");
  assert.deepEqual(built.requests[0].body, built.requests[1].body);
});

test("outputs hold no secrets: secret, salt, commitment, signature, path, forger key", async () => {
  for (const id of lab.ATTACK_IDS) await result(id);
  const all = JSON.stringify([...cache.values()].length ? await Promise.all([...cache.values()]) : []);
  assert.ok(all.length > 1000);
  const needles = world.secretsForTests();
  assert.ok(needles.length > 20);
  for (const n of needles) assert.ok(!all.includes(`"${n}"`) && !all.includes(n), "a private value appears in an attack output");
});

test("SR-03: a user cannot choose attributes, enrol without an admin code, or re-enrol after a revocation", async () => {
  for (const id of lab.ATTACK_IDS) await result(id); // earlier attacks finish first: this test moves the root
  const adminAttrs = { role: zk.ROLES.admin, dept: zk.DEPTS.it, clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: world.now() + 86400 };
  // an engineer asks for admin / clearance 3 with no code, and with a (valid, spent) code of someone else
  assert.deepEqual(await world.selfEnrol(adminAttrs), { status: 400, code: "attributes_not_accepted" });
  const bob = await world.enrol("bob");
  assert.deepEqual(await world.selfEnrol(adminAttrs, bob.code), { status: 400, code: "attributes_not_accepted" });
  // a revoked user holds only a spent code: no replacement without the admin
  await world.revoke(bob);
  const fresh = await zk.commitment("11".repeat(10), "22".repeat(10));
  assert.deepEqual(await world.reuseCode(bob, fresh), { status: 409, code: "enrolment_used" });
  assert.equal((await world.path(bob)).status, 410);
});

test("a malformed attack id and a missing world are refused", async () => {
  await assert.rejects(lab.buildAttack("nope", world), /unknown attack/);
  await assert.rejects(lab.buildAttack("replay", null), /world/);
});

test("the library and CLI never reference the committed issuer key directory", () => {
  const dir = path.join(__dirname, "..");
  for (const f of ["src", "bin"]) {
    for (const name of fs.readdirSync(path.join(dir, f))) {
      assert.ok(!/issuer\/keys/.test(fs.readFileSync(path.join(dir, f, name), "utf8")), name);
    }
  }
});
