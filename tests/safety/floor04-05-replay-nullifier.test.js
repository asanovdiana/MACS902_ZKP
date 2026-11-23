"use strict";
// Floor 4: a replayed proof (used or expired nonce) is denied.
// Floor 5: the same nullifier twice in one epoch is rate-limited; nullifiers from one user to
//          different services are unlinkable.
//
// The circuit half is tested here: nonce, now, epoch and resourceId are bound into the proof;
// the nullifier is Poseidon(3)(credentialSecret, resourceId, epoch), stable within (resource,
// epoch), independent of nonce, different across resources and epochs. The fixtures must carry
// exactly the properties the gateway checks. The gateway half (nonce store, nullifier store) is
// P3 and is marked todo.
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const h = require("./helpers");

const { zk, witnessV4, verifier } = h;
const FQ = verifier.FIELD_Q;
let vkey, idx, v;

before(() => {
  vkey = h.v4Vkey();
  idx = h.fixtureIndex();
  v = h.vectorsV4();
});
after(async () => verifier.terminate());

const secretOf = (persona) => v.credentials.find((c) => c.persona === persona).credentialSecret;

describe("floor 4: replay (circuit and fixture half)", () => {
  test("F4.01 the nonce is bound: a valid proof with any other nonce does not verify", async () => {
    const fx = h.fixture("alice_wiki");
    assert.equal(fx.publicSignals[9], idx.fixtures.alice_wiki.nonce);
    for (const n of ["0", "1", (BigInt(fx.publicSignals[9]) + 1n).toString(), idx.fixtures.alice_file_share.nonce]) {
      const t = [...fx.publicSignals];
      t[9] = n;
      assert.equal(await verifier.verify(vkey, t, fx.proof), false, `nonce ${n} verified`);
    }
  });

  test("F4.02 non-canonical spellings of a used nonce do not verify (replay state keyed on the canonical value)", async () => {
    const fx = h.fixture("alice_wiki");
    const n = fx.publicSignals[9];
    for (const spelt of ["0" + n, " " + n, n + " ", "+" + n, (BigInt(n) + zk.P).toString(), "0x" + BigInt(n).toString(16)]) {
      const t = [...fx.publicSignals];
      t[9] = spelt;
      assert.equal(await verifier.verify(vkey, t, fx.proof), false, `spelling ${JSON.stringify(spelt)} verified`);
    }
    assert.deepEqual(verifier.canonicalizeSignals(["0" + n]), [n]);
  });

  test("F4.03 Groth16 malleability: (-A, -B, C) verifies, so replay/rate-limit state must never key on proof bytes", async () => {
    const fx = h.fixture("alice_wiki");
    const neg = (y) => ((FQ - BigInt(y)) % FQ).toString();
    const p = JSON.parse(JSON.stringify(fx.proof));
    p.pi_a[1] = neg(p.pi_a[1]);
    p.pi_b[1] = [neg(p.pi_b[1][0]), neg(p.pi_b[1][1])];
    assert.notDeepEqual(p, fx.proof);
    assert.equal(await verifier.verify(vkey, fx.publicSignals, p), true, "if this fails, the malleability note is obsolete, not the floor");
    const contracts = require("fs").readFileSync(h.r("docs", "CONTRACTS.md"), "utf8");
    assert.match(contracts, /replay state on `nonce`, rate-limit state on `\(nullifier, epoch\)`, never on proof bytes/);
  });

  test("F4.04 now/epoch bound: the stale_now fixture carries an old now (outside the 120 s TTL) and its own epoch", () => {
    const fx = h.fixture("stale_now_alice_wiki");
    const gnow = BigInt(idx.context.gateway_now);
    const now = BigInt(fx.publicSignals[8]);
    assert.ok(gnow - now > BigInt(idx.context.nonce_ttl_seconds));
    assert.equal(fx.publicSignals[11], (now / 600n).toString());
    assert.notEqual(fx.publicSignals[11], idx.context.epoch);
  });

  test("F4.05 the circuit binds now and epoch: changing either in the witness input changes or breaks the proof statement", async () => {
    const base = h.aliceWikiInput().input;
    const w0 = await witnessV4(base);
    const wEpoch = await witnessV4({ ...base, epoch: String(BigInt(base.epoch) + 1n) });
    assert.equal(wEpoch.ok, true);
    assert.notEqual(wEpoch.nullifier, w0.nullifier, "epoch must feed the nullifier");
    const fx = h.fixture("alice_wiki");
    for (const slot of [8, 11]) {
      const t = [...fx.publicSignals];
      t[slot] = (BigInt(t[slot]) - 1n).toString();
      assert.equal(await verifier.verify(vkey, t, fx.proof), false, `slot ${slot}`);
    }
  });

  test("F4.06 gateway denies a used nonce and an expired nonce (TTL 120 s)", async () => {
    // Real P3 gateway in-process (tests/safety/gateway-harness.js): integrated-access-v4 profile,
    // real Groth16, the client path GET /challenge + POST /access, injectable clock.
    const gwh = require("./gateway-harness");
    const TTL = idx.context.nonce_ttl_seconds;
    assert.equal(TTL, 120);
    const fx = h.fixture("alice_wiki");
    const N = idx.fixtures.alice_wiki.nonce;
    const granted = (r, what) => {
      assert.equal(r.status, 200, `${what}: ${JSON.stringify(r.res.body)}`);
      assert.equal(r.admitted, true, what);
      assert.equal(r.event.groth16Valid, true, what);
    };
    const refused = (r, status, code, reason, what) => {
      assert.equal(r.status, status, `${what}: ${JSON.stringify(r.res.body)}`);
      assert.equal(r.code, code, what);
      if (reason) assert.equal(r.reason, reason, what);
      assert.notEqual(r.admitted, true, what);
    };
    try {
      // used nonce: replay of alice_wiki
      const gw = await gwh.makeGateway({ state: idx.fixtures.alice_wiki.gateway_state });
      const first = await gw.present("alice_wiki");
      granted(first, "first presentation");
      const replay = await gw.access(first.body);
      refused(replay, 403, "NONCE_USED", "CHALLENGE_REPLAYED", "replay");
      assert.equal(replay.event.groth16Valid, null, "a replay must be refused before verification");
      // re-randomised proof (-A, -B, C) with the used nonce: still a replay (state not keyed on proof bytes)
      const neg = (y) => ((FQ - BigInt(y)) % FQ).toString();
      const p = JSON.parse(JSON.stringify(fx.proof));
      p.pi_a[1] = neg(p.pi_a[1]);
      p.pi_b[1] = [neg(p.pi_b[1][0]), neg(p.pi_b[1][1])];
      refused(await gw.access({ ...first.body, proof: p }), 403, "NONCE_USED", "CHALLENGE_REPLAYED", "re-randomised replay");
      // the used proof against a NEW challenge's (fresh, gateway-drawn) nonce: not bound to it
      const c = await gw.challenge("wiki");
      assert.notEqual(c.nonce, N);
      refused(await gw.access({ ...first.body, nonce: c.nonce }), 403, "CHALLENGE_MISMATCH", "NONCE_MISMATCH", "old proof, new nonce");
      // a non-canonical spelling of the used nonce is refused before any state lookup
      refused(await gw.access({ ...first.body, nonce: "0" + N }), 400, "MALFORMED_REQUEST", null, "non-canonical nonce");
      const spelt = [...fx.publicSignals];
      spelt[9] = "0" + spelt[9];
      const c2 = await gw.challenge("wiki");
      refused(await gw.access({ ...first.body, nonce: c2.nonce, publicSignals: spelt }), 400, "MALFORMED_REQUEST", null, "non-canonical signal");
      // a nonce this gateway never issued
      refused(await gw.access({ ...first.body, nonce: "123456789" }), 403, "NONCE_UNKNOWN", null, "unknown nonce");
      assert.equal(gw.ctx.sessions.size, 1, "only the first presentation may hold a session");
      assert.ok(gw.ctx.bus.recent().some((e) => e.type === "replay.rejected"));

      // expired nonce: the challenge TTL is the contract's 120 s
      const exp = await gwh.makeGateway({ state: idx.fixtures.alice_wiki.gateway_state });
      const ch = await exp.challenge("wiki");
      const stored = exp.plantNonce(ch.nonce, N);
      assert.equal(stored.expiresAt - stored.createdAt, TTL * 1000);
      assert.equal(String(ch.now), idx.fixtures.alice_wiki.gateway_state.now);
      exp.clock.advance((TTL + 1) * 1000);
      const body = { resource: "wiki", nonce: N, proof: fx.proof, publicSignals: fx.publicSignals };
      refused(await exp.access(body), 403, "NONCE_EXPIRED", "CHALLENGE_EXPIRED", "TTL + 1 s");
      assert.equal(exp.ctx.sessions.size, 0);
      // an expired nonce is burnt: presenting it again is a replay, not a second chance
      refused(await exp.access(body), 403, "NONCE_USED", "CHALLENGE_REPLAYED", "expired, again");
      // control: within the TTL (TTL - 1 s) the same proof is admitted, so the denial above is the TTL's
      const inTime = await gwh.makeGateway({ state: idx.fixtures.alice_wiki.gateway_state });
      inTime.plantNonce((await inTime.challenge("wiki")).nonce, N);
      inTime.clock.advance((TTL - 1) * 1000);
      granted(await inTime.access(body), "within TTL");

      // expired now: stale_now_alice_wiki (now/epoch 90 days old) at gateway_now
      const meta = idx.fixtures.stale_now_alice_wiki;
      const stale = await gwh.makeGateway({ state: meta.gateway_state });
      const s = await stale.present("stale_now_alice_wiki");
      refused(s, 403, "CHALLENGE_MISMATCH", null, "stale now");
      assert.ok(["EPOCH_MISMATCH", "TIME_MISMATCH"].includes(s.reason), s.reason);
      assert.equal(stale.ctx.sessions.size, 0);
      assert.equal(stale.ctx.nullifiers.size, 0);
      // now must EQUAL the challenge's now: one second off, in the same epoch, is denied
      const off = await gwh.makeGateway({ state: idx.fixtures.alice_wiki.gateway_state, nowS: Number(idx.fixtures.alice_wiki.gateway_state.now) + 1 });
      const o = await off.present("alice_wiki");
      refused(o, 403, "CHALLENGE_MISMATCH", "TIME_MISMATCH", "now off by 1 s");
      // control: at the proof's own (old) clock it would be admitted, so only freshness stops it
      const oldNow = h.fixture(meta.dir).publicSignals[8];
      const past = await gwh.makeGateway({ state: meta.gateway_state, nowS: oldNow });
      granted(await past.present("stale_now_alice_wiki"), "stale_now at its own clock");
    } finally {
      await gwh.shutdown();
    }
  });
});

describe("floor 5: nullifier (circuit and fixture half)", () => {
  test("F5.01 nullifier = Poseidon(3)(credentialSecret, resourceId, epoch): lib == fixture == witness", async () => {
    const fx = h.fixture("alice_wiki");
    const n = await zk.nullifier(secretOf("alice"), fx.publicSignals[10], fx.publicSignals[11]);
    assert.equal(fx.publicSignals[0], n);
    const w = await witnessV4(h.aliceWikiInput().input);
    assert.equal(w.nullifier, n);
  });

  test("F5.02 same user, same resource, same epoch, different nonces -> equal nullifiers (rate-limitable)", () => {
    const a = h.fixture("same_epoch_a").publicSignals;
    const b = h.fixture("same_epoch_b").publicSignals;
    assert.notEqual(a[9], b[9], "nonces must differ");
    assert.equal(a[0], b[0], "nullifiers must be equal");
    assert.equal(a[11], b[11]);
    assert.equal(a[10], b[10]);
  });

  test("F5.03 nullifier independent of nonce and of now within the epoch (witness level)", async () => {
    const base = h.aliceWikiInput().input;
    const w0 = await witnessV4(base);
    const w1 = await witnessV4({ ...base, nonce: "42" });
    const epochStart = BigInt(base.epoch) * 600n;
    const w2 = await witnessV4({ ...base, now: (epochStart + 599n).toString() });
    for (const w of [w0, w1, w2]) assert.equal(w.ok, true, w.error);
    assert.equal(w1.nullifier, w0.nullifier);
    assert.equal(w2.nullifier, w0.nullifier);
  });

  test("F5.04 unlinkable across services: same user, different resourceId -> different nullifiers", async () => {
    const wiki = h.fixture("alice_wiki").publicSignals;
    const fs_ = h.fixture("alice_file_share").publicSignals;
    assert.equal(wiki[11], fs_[11]);
    assert.notEqual(wiki[10], fs_[10]);
    assert.notEqual(wiki[0], fs_[0]);
    const s = secretOf("alice");
    const ns = await Promise.all([1, 2, 3].map((r) => zk.nullifier(s, r, idx.context.epoch)));
    assert.equal(new Set(ns).size, 3);
    // carol: wiki vs admin panel
    assert.notEqual(h.fixture("carol_wiki").publicSignals[0], h.fixture("carol_admin_panel").publicSignals[0]);
  });

  test("F5.05 nothing in the public signals links one user's proofs across services except shared policy/root/issuer", () => {
    const wiki = h.fixture("alice_wiki").publicSignals;
    const fs_ = h.fixture("alice_file_share").publicSignals;
    const carolWiki = h.fixture("carol_wiki").publicSignals;
    // slots that differ between Alice@wiki and Alice@file_share must not be user-specific: compare
    // with Carol@wiki, which shares every non-user slot with Alice@wiki except nonce and nullifier
    const userSpecific = [];
    for (let i = 0; i < 12; i++) if (wiki[i] !== carolWiki[i] && i !== 9) userSpecific.push(i);
    assert.deepEqual(userSpecific, [0], "only the nullifier may differ between two users on the same service");
    assert.notEqual(wiki[0], fs_[0]);
    // the nullifier is not the commitment, the attrHash, or the secret
    const a = v.credentials.find((c) => c.persona === "alice");
    for (const x of [a.commitment, a.attrHash, a.credentialSecret]) assert.ok(!wiki.includes(x) && !fs_.includes(x));
  });

  test("F5.06 different epochs -> different nullifiers (sessions do not link across epochs)", async () => {
    const s = secretOf("alice");
    const e = BigInt(idx.context.epoch);
    assert.notEqual(await zk.nullifier(s, 1, e), await zk.nullifier(s, 1, e + 1n));
    assert.equal(h.fixture("stale_now_alice_wiki").publicSignals[0], await zk.nullifier(s, 1, h.fixture("stale_now_alice_wiki").publicSignals[11]));
  });

  test("F5.07 gateway rate-limits (nullifier, epoch) to one admission per epoch", async () => {
    // Real P3 gateway in-process (tests/safety/gateway-harness.js): integrated-access-v4 profile,
    // real Groth16, the client path GET /challenge + POST /access.
    const gwh = require("./gateway-harness");
    const A = idx.fixtures.same_epoch_a;
    const B = idx.fixtures.same_epoch_b;
    assert.equal(A.expect, "accept");
    assert.equal(B.expect, "reject");
    assert.deepEqual(B.present_after, ["same_epoch_a"]);
    const limited = (r, what) => {
      assert.equal(r.status, 429, `${what}: ${JSON.stringify(r.res.body)}`);
      assert.equal(r.code, "RATE_LIMITED", what);
      assert.equal(r.reason, "NULLIFIER_RATE_LIMITED", what);
      assert.notEqual(r.admitted, true, what);
    };
    try {
      const gw = await gwh.makeGateway({ state: A.gateway_state });
      const a = await gw.present("same_epoch_a");
      assert.equal(a.status, 200, JSON.stringify(a.res.body));
      assert.equal(a.admitted, true);
      assert.equal(gw.ctx.nullifiers.size, 1);
      const b = await gw.present("same_epoch_b");
      limited(b, "same_epoch_b");
      assert.equal(b.event.groth16Valid, true, "b is a valid proof: the denial is the rate limit's");
      assert.equal(gw.ctx.sessions.size, 1, "the second proof must not get a session");
      assert.ok(gw.ctx.bus.recent().some((e) => e.type === "nullifier.rate_limited" && e.nullifier === h.fixture("same_epoch_b").publicSignals[0]));
      // every other Alice -> Wiki proof of this epoch shares the nullifier and is rate-limited too
      limited(await gw.present("alice_wiki"), "alice_wiki");
      // a different service is a different nullifier: Alice -> File Share is still admitted
      const fsh = await gw.present("alice_file_share");
      assert.equal(fsh.status, 200, JSON.stringify(fsh.res.body));
      // another user on the same service is unaffected
      const carol = await gw.present("carol_wiki");
      assert.equal(carol.status, 200, JSON.stringify(carol.res.body));

      // concurrent submission of a and b: exactly one admission (the check-and-record is atomic)
      const race = await gwh.makeGateway({ state: A.gateway_state });
      const rs = await Promise.all(["same_epoch_a", "same_epoch_b"].map((n) => race.present(n)));
      assert.deepEqual(rs.map((r) => r.status).sort(), [200, 429]);
      assert.equal(race.ctx.sessions.size, 1);
      // order does not matter: b first is admitted, then a is rate-limited
      const rev = await gwh.makeGateway({ state: A.gateway_state });
      assert.equal((await rev.present("same_epoch_b")).status, 200);
      limited(await rev.present("same_epoch_a"), "a after b");
    } finally {
      await gwh.shutdown();
    }
  });

  test("F5.08 one person cannot hold two live credentials (else N credentials = N nullifiers per epoch): enrolment_pending / employee_has_credential", async () => {
    // SR-03 (system level of floor 5), issuer.api v2 / issuer.admin v1.1, G1-S1-SAFETY-021.
    const ATTRS = { role: 0, dept: 0, clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 };
    const iss = await h.makeIssuer({ overrides: { logLevel: "silent" } });
    const post = (body) => iss.app.inject({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload: JSON.stringify(body) });
    const total = async () => JSON.parse((await iss.admin("GET", "/admin/leaves")).body).total;
    try {
      const first = await h.adminEnrol(iss, { employeeId: "Grace.Hopper@corp.example", attributes: ATTRS });
      assert.equal(first.status, 201, first.res.body);
      // pending: a second enrolment for the same person (any case) is refused
      for (const id of ["grace.hopper@corp.example", "GRACE.HOPPER@CORP.EXAMPLE"]) {
        const e = await h.adminEnrol(iss, { employeeId: id, attributes: ATTRS });
        assert.equal(e.status, 409, id);
        assert.equal(e.body.error.code, "enrolment_pending");
      }
      // one code, two commitments: only the first is issued
      const a = await post({ commitment: await zk.commitment("501", "502"), enrolmentCode: first.code });
      assert.equal(a.statusCode, 201, a.body);
      const b = await post({ commitment: await zk.commitment("503", "504"), enrolmentCode: first.code });
      assert.equal(b.statusCode, 409);
      assert.equal(JSON.parse(b.body).error.code, "enrolment_used");
      // live: refused while the credential is unrevoked
      const live = await h.adminEnrol(iss, { employeeId: "GRACE.hopper@corp.example", attributes: ATTRS });
      assert.equal(live.status, 409);
      assert.equal(live.body.error.code, "employee_has_credential");
      // concurrent redemptions of one fresh code (another person) issue exactly one credential
      const other = await h.adminEnrol(iss, { employeeId: "ada", attributes: ATTRS });
      const rs = await Promise.all([1, 2, 3].map(async (i) => post({ commitment: await zk.commitment(String(600 + i), "1"), enrolmentCode: other.code })));
      assert.deepEqual(rs.map((x) => x.statusCode).sort(), [201, 409, 409]);
      assert.equal(await total(), 2, "one leaf per person");
      // a restart keeps the one-live-credential rule (state on disk, not in memory)
      await iss.app.close();
      const { buildServer } = require(h.r("issuer", "src", "server.js"));
      const again = await buildServer({ config: iss.config, clock: iss.clock.now });
      try {
        const res = await again.inject({ method: "POST", url: "/admin/enrolments", headers: { "content-type": "application/json", authorization: `Bearer ${iss.token}` }, payload: JSON.stringify({ employeeId: "grace.hopper@corp.example", attributes: ATTRS }) });
        assert.equal(res.statusCode, 409);
        assert.equal(JSON.parse(res.body).error.code, "employee_has_credential");
      } finally {
        await again.close();
      }
    } finally {
      await iss.app.close().catch(() => {});
    }
  });
});
