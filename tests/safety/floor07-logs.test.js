"use strict";
// Floor 7: the gateway log and gateway state hold no username, email, role, department or
// clearance.
//
// The gateway is P3 and not in this repository (todo below). Applied here to the P2 services by
// extension: the issuer's structured log, metrics, admin listing and SSE events carry no
// attribute, commitment, leaf hash, signature, secret or admin token; client errors carry no
// secret. (The issuer legitimately knows the attributes at enrolment; it must not log them.)
const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const h = require("./helpers");

const { zk } = h;
const client = require(h.r("client", "src"));

const T0 = 1_800_000_000;
const TOKEN = "safety-admin-token-5c1e0f";
const PERSONAS = {
  alice: { role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1, expiry: 4070908800 },
  carol: { role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1, expiry: 4070908801 },
};

let iss, issuer, wallet, adminBodies = [];
const auth = { authorization: `Bearer ${TOKEN}` };
// issuer.api v2: the admin names the employee; an email-shaped id is the worst case for floor 7
const EMPLOYEE = { alice: "alice.smith@corp.example", carol: "carol.jones@corp.example" };
const codes = []; // every enrolment code handed out in this session

before(async () => {
  iss = await h.makeIssuer({ t0: T0, overrides: { adminToken: TOKEN, logLevel: "trace" } });
  issuer = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });
  wallet = new client.Wallet({ home: h.tmpDir("wallet") });
  for (const [name, attributes] of Object.entries(PERSONAS)) {
    await wallet.keygen({ name, profile: "v4", issuerUrl: "http://issuer.test" });
    const { enrolment } = await h.enrolViaAdmin({ iss, wallet, name, issuer, attributes, employeeId: EMPLOYEE[name] });
    codes.push(enrolment.code);
    await client.prepareV4({ credential: wallet.load(name), issuer, challenge: h.challengeFor("wiki", "5", T0) });
  }
  const inj = (o) => iss.app.inject(o);
  // a busy session: reads, admin reads, revoke, every error path
  for (const url of ["/root", "/root/history?since=0", "/issuer", "/metrics", "/path/0", "/path/99", "/nope"]) await inj({ method: "GET", url });
  for (const url of ["/admin/leaves", "/admin/tree"]) adminBodies.push((await inj({ method: "GET", url, headers: auth })).body);
  await inj({ method: "GET", url: "/admin/leaves", headers: { authorization: "Bearer wrong" } });
  iss.clock.advance(3);
  await inj({ method: "POST", url: "/credentials/1/revoke", headers: auth });
  await inj({ method: "POST", url: "/credentials/1/revoke", headers: auth });
  const c = wallet.load("alice");
  const post = (payload) => inj({ method: "POST", url: "/credentials", headers: { "content-type": "application/json" }, payload });
  await post(JSON.stringify({ commitment: c.commitment, attributes: { ...c.attributes } })); // v1 shape: attributes_not_accepted
  await post(JSON.stringify({ commitment: c.commitment, attributes: { ...c.attributes, clearance: 9 } }));
  await post(JSON.stringify({ commitment: c.commitment, attributes: c.attributes, credentialSecret: c.secrets.credentialSecret }));
  await post("{not json");
  // issuer.api v2 / admin v1.1 paths, success and every refusal
  await post(JSON.stringify({ commitment: c.commitment, enrolmentCode: codes[0] })); // enrolment_used
  await post(JSON.stringify({ commitment: c.commitment })); // invalid_enrolment_code
  const enrol = async (employeeId, attributes, headers = auth) => {
    const res = await inj({ method: "POST", url: "/admin/enrolments", headers: { "content-type": "application/json", ...headers }, payload: JSON.stringify({ employeeId, attributes: h.encodeAttrs(attributes) }) });
    if (res.statusCode === 201) codes.push(JSON.parse(res.body).code);
    return res;
  };
  await enrol(EMPLOYEE.alice, PERSONAS.alice); // employee_has_credential
  await enrol(EMPLOYEE.carol.toUpperCase(), PERSONAS.carol); // carol is revoked (leaf 1): allowed, pending
  await enrol(EMPLOYEE.carol, PERSONAS.carol); // enrolment_pending
  await enrol("dave@corp.example", { ...PERSONAS.alice, clearance: 9 }); // invalid_attributes
  await enrol("erin@corp.example", PERSONAS.alice, { authorization: "Bearer wrong" }); // 401
  const pending = JSON.parse((await inj({ method: "GET", url: "/admin/enrolments", headers: auth })).body).enrolments.find((x) => x.status === "pending");
  await inj({ method: "DELETE", url: `/admin/enrolments/${pending.enrolmentId}`, headers: auth });
  await inj({ method: "DELETE", url: `/admin/enrolments/${pending.enrolmentId}`, headers: auth }); // enrolment_not_pending
  adminBodies.push((await inj({ method: "GET", url: "/metrics" })).body);
});
after(async () => {
  await iss.app.close();
  await client.shutdown();
});

async function sensitiveValues() {
  // issuer.api v2 (G1-S1-SAFETY-021): the employee ids (username/email) and enrolment codes are
  // identity and credentials the issuer now holds; they join the list.
  const ids = [...Object.values(EMPLOYEE), EMPLOYEE.carol.toUpperCase(), "dave@corp.example", "erin@corp.example", "alice.smith", "corp.example"];
  const out = [TOKEN, ...ids, ...codes];
  for (const name of Object.keys(PERSONAS)) {
    const c = wallet.load(name);
    out.push(c.secrets.credentialSecret, c.secrets.credentialSalt, c.commitment, c.signature.R8x, c.signature.R8y, c.signature.S);
    out.push(await zk.attrHash(c.attributes, c.commitment));
  }
  return out;
}

describe("floor 7: logs and state hold no identity attributes", () => {
  test("F7.01 issuer log: no secret, salt, commitment, attrHash/leaf, signature or admin token", async () => {
    const log = iss.sink.text();
    assert.ok(iss.sink.lines.length >= 15, `expected a busy log, got ${iss.sink.lines.length} lines`);
    for (const v of await sensitiveValues()) assert.ok(!log.includes(v), `issuer log contains a sensitive value (${v.slice(0, 6)}...)`);
  });

  test("F7.02 issuer log lines carry only the documented fields (no attribute keys, no bodies, no headers)", () => {
    const allowed = new Set(["level", "time", "pid", "hostname", "reqId", "msg", "route", "method", "status", "latencyMs", "leafIndex", "code", "sseClients", "address", "profile"]);
    for (const line of iss.sink.lines) {
      const o = JSON.parse(line);
      for (const k of Object.keys(o)) assert.ok(allowed.has(k), `log field "${k}" is not on the allow-list: ${line.slice(0, 160)}`);
      for (const k of ["role", "dept", "clearance", "attributes", "body", "headers", "authorization", "commitment", "email", "username"]) {
        assert.ok(!line.includes(`"${k}"`), `log line has "${k}"`);
      }
    }
  });

  test("F7.03 admin listing, tree and metrics responses carry no attribute, commitment or signature", async () => {
    const text = adminBodies.join("\n");
    const leaves = JSON.parse(adminBodies[0]).leaves;
    for (const l of leaves) assert.deepEqual(Object.keys(l).sort(), ["issuedAt", "leaf", "leafIndex", "revokedAt", "status"]);
    for (const k of ["role", "dept", "clearance", "attributes", "commitment", "signature", "secret", "salt"]) {
      assert.ok(!text.includes(`"${k}"`), `admin/metrics output has "${k}"`);
    }
    const sens = await sensitiveValues();
    const commitments = Object.keys(PERSONAS).map((n) => wallet.load(n).commitment);
    for (const v of sens.filter((x) => commitments.includes(x) || x === TOKEN)) assert.ok(!text.includes(v));
    // issuer.api v2: no employee id (username/email) and no enrolment code in these outputs either
    const nonLeaf = sens.filter((x) => !/^\d+$/.test(x));
    for (const v of nonLeaf) assert.ok(!text.includes(v), `admin/metrics output contains ${v.slice(0, 8)}...`);
  });

  test("F7.04 client errors and messages do not echo secrets or issuer free text", async () => {
    const c = wallet.load("alice");
    const stub = async () => ({ status: 400, text: async () => JSON.stringify({ error: { code: "x\"<script>", message: c.secrets.credentialSecret } }) });
    const ic = new client.IssuerClient({ baseUrl: "http://x.test", fetch: stub });
    await assert.rejects(ic.getRoot(), (e) => {
      assert.ok(!e.message.includes(c.secrets.credentialSecret));
      assert.ok(!e.message.includes("<script>"));
      return true;
    });
    // a lib refusal on a bad secret names a code, not the value
    await assert.rejects(zk.buildInputV4({
      credentialSecret: c.secrets.credentialSecret + "0", credentialSalt: c.secrets.credentialSalt, commitment: c.commitment,
      attributes: c.attributes, signature: c.signature, issuer: c.issuer, merkleProof: { root: "1", pathElements: Array(16).fill("0"), pathIndices: Array(16).fill(0) },
      policy: "wiki", challenge: { nonce: "1", resourceId: 1, epoch: Math.floor(T0 / 600), now: T0 },
    }), (e) => {
      assert.ok(!e.message.includes(c.secrets.credentialSecret));
      return true;
    });
  });

  test("F7.05 gateway log and state hold no username, email, role, department or clearance", async () => {
    // Real P3 gateway in-process (tests/safety/gateway-harness.js), real Groth16, a run of admits
    // and denials over every committed v4 fixture; then its raw (unredacted) log output and its
    // whole in-memory state (challenges, nullifiers, sessions, event history, root history) are
    // scanned for the fixture personas' identity and attributes.
    const gwh = require("./gateway-harness");
    const idx = h.fixtureIndex();
    const vec = h.vectorsV4();
    try {
      const gw = await gwh.makeGateway({ state: idx.fixtures.alice_wiki.gateway_state });
      const st = {};
      const run = async (name, opts) => {
        const r = await gw.present(name, opts);
        st[name] = r.res.status;
        return r;
      };
      // admits
      for (const n of ["alice_wiki", "alice_file_share", "carol_admin_panel", "carol_wiki", "bob_wiki"]) await run(n);
      // denials: replay, forged issuer, stale now, same nullifier, wrong service, malformed, unknown challenge
      const first = await gw.present("alice_file_share"); // same nullifier, same epoch
      st.dup_file_share = first.res.status;
      const replay = await gw.verify(first.body);
      st.replay = replay.status;
      await run("forged_issuer_alice_wiki");
      await run("stale_now_alice_wiki");
      await run("same_epoch_a");
      await run("same_epoch_b");
      await run("wrong_service_alice_wiki_as_admin");
      st.malformed = (await gw.verify({ challengeId: "x", proof: {}, publicSignals: ["01"] })).status;
      st.unknown = (await gw.verify({ ...first.body, challengeId: "A".repeat(24) })).status;
      // revocation, then a revoked credential's proof
      gw.registry.setRoot(idx.context.root_after_bob_revoked);
      await run("stale_root_bob_wiki");

      assert.deepEqual(
        { ...st },
        {
          alice_wiki: 200, alice_file_share: 200, carol_admin_panel: 200, carol_wiki: 200, bob_wiki: 200,
          dup_file_share: 429, replay: 409, forged_issuer_alice_wiki: 403, stale_now_alice_wiki: 403,
          same_epoch_a: 429, same_epoch_b: 429, wrong_service_alice_wiki_as_admin: 403, malformed: 400,
          unknown: 403, stale_root_bob_wiki: 403,
        },
        "the run must mix admissions and every denial path",
      );

      // ---- what must never appear ----
      const personas = vec.credentials.map((c) => c.persona);
      assert.deepEqual([...personas].sort(), ["alice", "bob", "carol"]);
      const labels = new Set();
      for (const c of vec.credentials) for (const v of Object.values(c.labels)) labels.add(String(v).toLowerCase());
      for (const k of Object.keys(zk.ROLES)) labels.add(k);
      for (const k of Object.keys(zk.DEPTS)) labels.add(k);
      const secretVals = [];
      for (const c of vec.credentials) {
        secretVals.push(c.credentialSecret, c.credentialSalt, c.commitment, c.attrHash, c.signature.R8x, c.signature.R8y, c.signature.S);
        for (const e of c.merkle.pathElements) if (e !== "0") secretVals.push(e);
      }
      // identity keys (username, email, role, department, clearance and their usual spellings)
      const IDENTITY_KEY = /^(user(name)?|user_?id|email|e-?mail|name_?id|subject|sub|persona|employee(_?id)?|role|roles|dept|department|clearance|attributes?|device_?compliant|employee_?active|expiry|credential_?secret|credential_?salt|commitment|attr_?hash|signature|path_?elements|path_?indices|leaf)$/i;
      const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/;
      const word = (w) => new RegExp(`(^|[^A-Za-z0-9])${w.replace(/[^A-Za-z0-9]/g, "\\$&")}([^A-Za-z0-9]|$)`, "i");
      // resource and route names that share a word with a label ("admin" in admin-panel, "finance" none)
      const RESOURCE_WORDS = new Set(["admin"]);
      // labels too short to scan as free text ("it", "bob" is a persona) are checked as whole values
      // The service policies' own summaries ("Engineer or admin, clearance >= 2") are the SERVICE's
      // configuration, identical for every user (contract obligation 8: "the policy fields are the
      // service's, not the user's"). Taken from the gateway itself and cut out before the label scan.
      const summaries = [];
      for (const r of Object.keys(idx.context.resources)) summaries.push((await gw.challenge(r)).policy.summary);
      assert.equal(summaries.length, 3);
      const unpolicy = (s) => summaries.reduce((acc, x) => acc.split(x).join(" "), s);

      /** Walk every value reachable from `root`, yielding [path, key, value] for keys and leaves. */
      function* walk(root, base) {
        const seen = new Set();
        const stack = [[root, base]];
        while (stack.length) {
          const [v, p] = stack.pop();
          if (v === null || v === undefined) continue;
          if (typeof v === "function") continue;
          if (typeof v !== "object") { yield [p, null, v]; continue; }
          if (seen.has(v)) continue;
          seen.add(v);
          if (Buffer.isBuffer(v) || ArrayBuffer.isView(v)) continue;
          if (v instanceof Map) {
            for (const [k, x] of v) { yield [p, String(k), undefined]; yield [`${p}[${String(k).slice(0, 24)}]`, null, k]; stack.push([x, `${p}[${String(k).slice(0, 24)}]`]); }
            continue;
          }
          if (v instanceof Set) { for (const x of v) stack.push([x, `${p}{}`]); continue; }
          for (const k of Object.keys(v)) { yield [p, k, undefined]; stack.push([v[k], `${p}.${k}`]); }
        }
      }
      function check(where, items) {
        let n = 0;
        for (const [p, k, v] of items) {
          n += 1;
          if (k !== null) {
            assert.ok(!IDENTITY_KEY.test(k), `${where}: identity key "${k}" at ${p}`);
            continue;
          }
          const s = String(v);
          assert.ok(!EMAIL.test(s), `${where}: email-shaped value at ${p}`);
          for (const name of personas) assert.ok(!word(name).test(s), `${where}: persona name "${name}" at ${p}`);
          for (const l of labels) {
            assert.notEqual(s.toLowerCase(), l, `${where}: attribute label "${l}" as a value at ${p}`);
            if (l.length >= 5 && !RESOURCE_WORDS.has(l)) assert.ok(!word(l).test(unpolicy(s)), `${where}: attribute label "${l}" at ${p}`);
          }
          for (const x of secretVals) assert.ok(!s.includes(x), `${where}: private credential value ${x.slice(0, 8)}... at ${p}`);
        }
        return n;
      }

      // ---- the log: raw pino output of the whole run ----
      const lines = gw.sink.lines;
      assert.ok(lines.length >= 25, `expected a busy log, got ${lines.length} lines`);
      const parsed = lines.map((l) => JSON.parse(l));
      assert.ok(parsed.some((o) => o.res && o.res.statusCode === 429) && parsed.some((o) => o.res && o.res.statusCode === 200));
      const logItems = check("gateway log", walk(parsed, "log"));
      assert.ok(logItems > 100);
      // free-text scan of the raw lines as well (catches anything a structured walk would split)
      check("gateway log text", lines.map((l, i) => [`line ${i}`, null, l]));

      // ---- the state: everything the gateway holds in memory after the run ----
      const ctx = gw.ctx;
      const state = {
        challenges: ctx.challenges,
        nullifiers: ctx.nullifiers,
        sessions: ctx.sessions,
        events: ctx.bus.recent(10_000),
        rootHistory: ctx.rootHistory,
        registry: ctx.registry,
        operator: ctx.operator,
      };
      assert.ok(ctx.challenges.size >= 12 && ctx.nullifiers.size >= 5 && ctx.sessions.size === 0 && state.events.length >= 30,
        `state too small to be meaningful: ${ctx.challenges.size}/${ctx.nullifiers.size}/${ctx.sessions.size}/${state.events.length}`);
      const stateItems = check("gateway state", walk(state, "state"));
      assert.ok(stateItems > 200);
      check("gateway state text", [["state", null, JSON.stringify(state.events)]]);

      // the event history carries public signals only: every signal name is a contract name
      const allowedSignals = new Set(gw.profile.signals);
      for (const e of state.events) for (const s of e.publicSignals || []) assert.ok(allowedSignals.has(s.name), `event signal ${s.name}`);
    } finally {
      await gwh.shutdown();
    }
  });
});
