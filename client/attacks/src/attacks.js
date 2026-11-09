"use strict";
// The Attack Lab catalogue (docs/project-scope.md, "Attack Lab buttons"). Each attack builds the
// exact requests the gateway would receive plus the expected outcome and reason code, and records
// what the client itself refuses to do ("local" evidence). Reason codes: ./codes.js (proposal).
const zk = require("../../../circuits/lib");
const { CODES } = require("./codes");

const mkExpect = (code) =>
  code
    ? { outcome: "deny", status: CODES[code].status, code, obligation: CODES[code].obligation }
    : { outcome: "admit", status: 200, code: null, obligation: null };

/** POST /access request (method, path, JSON body {resource, nonce, proof, publicSignals}). */
function request(label, resource, { proof, publicSignals }, code, extra = {}) {
  return {
    label, method: "POST", path: "/access",
    body: { resource, nonce: publicSignals[9], proof, publicSignals },
    expect: mkExpect(code),
    ...extra,
  };
}

/** Run `fn`, which must throw a circuits/lib AccessInputError; record the refusal. */
async function clientRefuses(stage, fn) {
  try {
    await fn();
  } catch (e) {
    if (e instanceof zk.AccessInputError) {
      return { stage, refused: true, code: e.code, reasons: (e.reasons || []).map((r) => r.code) };
    }
    throw e;
  }
  throw new Error(`FLOOR VIOLATION: the client built an input it must refuse (${stage})`);
}

const witnessRefusal = async (world, input) => {
  await world.witnessRefuses(input);
  return { stage: "witness", refused: true, code: "WITNESS_REFUSED", reasons: [] };
};

const prove = async (world, persona, resource, o) => world.prove(await world.input(persona, resource, o));

const ATTACKS = {
  baseline: {
    title: "Honest baseline (control)",
    scope: "Admitted: Alice opens the Wiki with a valid proof",
    floor: null, obligations: [1, 2, 3, 4, 5, 6, 7],
    async build(w) {
      const alice = await w.enrol("alice");
      return { local: [], requests: [request("alice -> wiki", "wiki", await prove(w, alice, "wiki"), null)] };
    },
  },

  replay: {
    title: "Replay a captured proof",
    scope: "Denied: nonce already used / expired",
    floor: 4, obligations: [6],
    async build(w) {
      const alice = await w.enrol("alice");
      const p = await prove(w, alice, "wiki");
      return {
        local: [],
        requests: [
          request("original presentation", "wiki", p, null),
          request("captured proof presented again", "wiki", JSON.parse(JSON.stringify(p)), "NONCE_USED"),
        ],
      };
    },
  },

  replay_expired: {
    title: "Replay a proof after its nonce expired",
    scope: "Denied: nonce expired",
    floor: 4, obligations: [6],
    async build(w) {
      const alice = await w.enrol("alice");
      const p = await prove(w, alice, "wiki");
      return { local: [], requests: [request("proof held past the nonce TTL", "wiki", p, "NONCE_EXPIRED", { waitSeconds: 125 })] };
    },
  },

  revoked: {
    title: "Revoked user tries again",
    scope: "Denied: root mismatch, not in tree",
    floor: 3, obligations: [3],
    async build(w) {
      const bob = await w.enrol("bob");
      const rootBefore = await w.root();
      // Bob proves while still registered: a valid proof against the pre-revocation root.
      const p = await prove(w, bob, "wiki");
      const rootAfter = await w.revoke(bob);
      const gone = await w.path(bob);
      return {
        local: [{ stage: "registry", refused: true, code: gone.body && gone.body.error ? gone.body.error.code : "revoked", reasons: [] }],
        requests: [request("pre-revocation proof presented after the revocation", "wiki", p, "ROOT_NOT_CURRENT")],
        evidence: { rootBefore, rootAfter, revokedPathStatus: gone.status },
      };
    },
  },

  tamper: {
    title: "Tamper attributes (contractor edits role to admin)",
    scope: "Denied: issuer signature invalid",
    floor: 2, obligations: [1],
    async build(w) {
      const bob = await w.enrol("bob");
      const local = [];
      // 1. the client's input builder: edited attributes no longer match the issuer signature
      local.push(await clientRefuses("client-input", () =>
        w.input(bob, "admin_panel", { attributes: { ...bob.attributes, role: zk.ROLES.admin, clearance: 3 } })));
      // 2. the circuit: the same edit applied to a raw input fails at witness generation
      const raw = await w.input(bob, "admin_panel", { precheck: false });
      local.push(await witnessRefusal(w, { ...raw, role: String(zk.ROLES.admin), clearance: "3" }));
      // 3. the only request left: Bob's genuine Wiki proof with its public signals patched to the
      //    Admin Panel challenge. Every cheap gateway check passes; Groth16 verify fails.
      const adminCh = await w.challenge("admin_panel");
      const honest = await prove(w, bob, "wiki");
      const s = zk.decodePublicSignals("v4", honest.publicSignals);
      const ap = zk.policies.admin_panel;
      const patched = zk.encodePublicSignals("v4", {
        ...s, roleMask: ap.roleMask, deptMask: ap.deptMask, minClearance: ap.minClearance, requireDevice: ap.requireDevice,
        resourceId: ap.resourceId, nonce: adminCh.nonce, now: adminCh.now, epoch: adminCh.epoch,
      });
      return {
        local,
        requests: [request("Wiki proof with public signals patched to Admin Panel", "admin_panel", { proof: honest.proof, publicSignals: patched }, "PROOF_INVALID")],
      };
    },
  },

  forged: {
    title: "Forged credential (self-signed)",
    scope: "Denied: signature not from issuer",
    floor: 2, obligations: [2],
    async build(w) {
      const alice = await w.enrol("alice");
      const { issuer, signature } = await w.forge(alice);
      const p = await prove(w, alice, "wiki", { issuer, signature });
      return { local: [], requests: [request("valid proof under the forger's key", "wiki", p, "ISSUER_NOT_PINNED")] };
    },
  },

  wrong_service: {
    title: "Valid user, wrong service (Bob to Admin Panel)",
    scope: "Denied: policy not satisfied (proof can't be generated)",
    floor: 2, obligations: [4],
    async build(w) {
      const bob = await w.enrol("bob");
      const local = [];
      local.push(await clientRefuses("client-precheck", () => w.input(bob, "admin_panel")));
      local.push(await witnessRefusal(w, await w.input(bob, "admin_panel", { precheck: false })));
      // Alice's genuine Wiki proof (under a nonce the gateway issued for the Admin Panel)
      const alice = await w.enrol("alice");
      const ch = await w.challenge("admin_panel");
      const wiki = zk.policies.wiki;
      const p = await prove(w, alice, "wiki", { challenge: { nonce: ch.nonce, resourceId: wiki.resourceId, epoch: ch.epoch, now: ch.now } });
      return { local, requests: [request("Wiki proof presented for the Admin Panel", "admin_panel", p, "POLICY_MISMATCH")] };
    },
  },

  spam: {
    title: "Spam requests",
    scope: "Rate-limited: same nullifier in this epoch",
    floor: 5, obligations: [7],
    async build(w) {
      const alice = await w.enrol("alice");
      // two fresh nonces, two valid proofs, one nullifier (Poseidon(secret, resourceId, epoch))
      const [c1, c2] = [await w.challenge("wiki"), await w.challenge("wiki")];
      const p1 = await prove(w, alice, "wiki", { challenge: c1 });
      const p2 = await prove(w, alice, "wiki", { challenge: c2 });
      return {
        local: [],
        requests: [request("first proof of the epoch", "wiki", p1, null), request("second proof, fresh nonce, same nullifier", "wiki", p2, "RATE_LIMITED")],
      };
    },
  },

  expired: {
    title: "Expired credential",
    scope: "Denied: expiry check fails",
    floor: 2, obligations: [5],
    async build(w) {
      const alice = await w.enrol("alice", { ttl: w.SHORT_TTL });
      const expiry = alice.attributes.expiry;
      await w.advance(w.SHORT_TTL + 1); // the credential is now expired
      const fresh = await w.challenge("wiki");
      const local = [];
      local.push(await clientRefuses("client-precheck", () => w.input(alice, "wiki", { challenge: fresh })));
      local.push(await witnessRefusal(w, await w.input(alice, "wiki", { challenge: fresh, precheck: false })));
      // The attacker's remaining move: prove with an old `now` (the last second the credential was
      // valid) under a fresh nonce. The proof verifies; the stored challenge's `now` does not match.
      const staleNow = expiry - 1;
      const stale = { nonce: fresh.nonce, resourceId: fresh.resourceId, epoch: zk.epochOf(staleNow), now: staleNow };
      const p = await prove(w, alice, "wiki", { challenge: stale });
      return { local, requests: [request("proof with a stale now", "wiki", p, "CHALLENGE_MISMATCH")] };
    },
  },
};

const ATTACK_IDS = Object.keys(ATTACKS);

/** Build one attack against `world`. Side effects: enrols throw-away personas; `revoked` revokes one of them. */
async function buildAttack(id, world) {
  if (!world) throw new Error("buildAttack needs a world (createWorld())");
  const a = ATTACKS[id];
  if (!a) throw new Error(`unknown attack ${JSON.stringify(id)} (known: ${ATTACK_IDS.join(", ")})`);
  const out = await a.build(world);
  const denied = out.requests.filter((r) => r.expect.outcome === "deny");
  return {
    id, title: a.title, scope: a.scope, floor: a.floor, obligations: a.obligations,
    display: denied.length ? denied.map((r) => ({ code: r.expect.code, text: CODES[r.expect.code].text })) : [],
    local: out.local, requests: out.requests, evidence: out.evidence || {},
  };
}

module.exports = { ATTACKS, ATTACK_IDS, buildAttack };
