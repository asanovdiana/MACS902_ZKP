#!/usr/bin/env node
// Regenerate the committed v4 Groth16 fixtures in circuits/fixtures/v4/ (G1-S1-CIRC-037):
//
//   npm run prove:fixtures:v4                                # = node circuits/scripts/access-fixtures.js
//   node circuits/scripts/access-fixtures.js --out <dir>     # write elsewhere (e.g. to compare)
//
// Proves with the COMMITTED pair $SETUP_OUT/integrated_access_v4.{wasm,zkey} (default
// circuits/setup/) and refuses (exit 2, nothing written) unless their sha256 equal wasm_sha256 /
// zkey_sha256 in integrated_access_v4.manifest.json: proofs from any other key would not verify
// under the committed verification key.
//
// Inputs come from the TEST-ONLY vectors (circuits/test/vectors/v4/credentials.json) and are built
// by circuits/lib buildInputV4, the client's path, which checks schema, policy, expiry, epoch,
// secret/commitment, signature and Merkle root before proving. Every proof's public signals are
// checked against lib expectedPublicSignals and verified with verify.js before anything is
// written. Witnesses are built in memory by snarkjs.groth16.fullProve: no input or witness file
// is ever written (floor 6); only proof.json + public.json per fixture are.
//
// Writes <name>/proof.json, <name>/public.json, fixtures.json (scenario context + per-fixture
// gateway obligation) and verification_key.json (copy of the committed key). README.md is
// hand-written. Proofs are randomised, so every run rewrites every proof.json; public.json and
// fixtures.json are deterministic.
//
// require()-ing this file proves nothing: it exports { plan, nonceFor, STALE_NOW_SECONDS }.
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zk = require("../lib");

const CIRCUITS = path.resolve(__dirname, "..");
const NAME = "integrated_access_v4";
const SETUP = process.env.SETUP_OUT ? path.resolve(process.env.SETUP_OUT) : path.join(CIRCUITS, "setup");
const WASM = path.join(SETUP, `${NAME}.wasm`);
const ZKEY = path.join(SETUP, `${NAME}.zkey`);
const VKEY = path.join(SETUP, `${NAME}.verification_key.json`);
const MANIFEST = path.join(SETUP, `${NAME}.manifest.json`);
const DEFAULT_OUT = path.join(CIRCUITS, "fixtures", "v4");
const VECTORS = path.join(CIRCUITS, "test", "vectors", "v4", "credentials.json");

const NONCE_TTL_SECONDS = 120; // access.public_signals v4, obligation 5
const STALE_NOW_SECONDS = 90n * 86400n; // 90 days behind the gateway clock; credential still unexpired

const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
const sha256 = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const log = (...a) => console.error("[access-fixtures]", ...a);
class Refusal extends Error {}
const refuse = (m) => {
  throw new Refusal(m);
};

/** Deterministic, distinct 128-bit nonce per fixture (the gateway issues 128 random bits). */
const nonceFor = (label) =>
  BigInt("0x" + crypto.createHash("sha256").update(`zk-access-gate TEST-ONLY v4 fixture nonce: ${label}`).digest().subarray(0, 16).toString("hex")).toString();

/**
 * The fixture plan: scenario context and, per fixture, the circuit input (in memory only) and the
 * metadata committed in fixtures.json. Deterministic; proves nothing.
 * @returns {Promise<{context: object, fixtures: Object<string, {input: object, meta: object}>}>}
 */
async function plan() {
  const vec = readJson(VECTORS);
  const persona = Object.fromEntries(vec.credentials.map((c) => [c.persona, c]));
  const pinned = { Ax: vec.issuer.Ax, Ay: vec.issuer.Ay };

  const tree = await zk.createTree("v4");
  for (const c of vec.credentials) tree.insert(BigInt(c.attrHash));
  const rootBefore = tree.root.toString();
  if (rootBefore !== vec.tree.root) throw new Error("vector tree root mismatch (regenerate the vectors?)");
  tree.delete(persona.bob.leafIndex);
  const rootAfter = tree.root.toString();

  const context = {
    pinned_issuer: pinned,
    root_before_revocation: rootBefore,
    root_after_bob_revoked: rootAfter,
    revoked: { persona: "bob", leafIndex: persona.bob.leafIndex },
    gateway_now: vec.now,
    epoch: vec.epoch,
    nonce_ttl_seconds: NONCE_TTL_SECONDS,
    resources: JSON.parse(JSON.stringify(zk.policies)),
  };
  const stateBefore = { current_root: rootBefore, now: vec.now, epoch: vec.epoch };

  const fixtures = {};
  const add = async (name, who, resource, over, meta) => {
    const k = persona[who];
    const pol = zk.policies[resource];
    const now = over.now ?? vec.now;
    const nonce = over.nonce ?? nonceFor(name);
    const input = await zk.buildInputV4({
      credentialSecret: k.credentialSecret,
      credentialSalt: k.credentialSalt,
      commitment: k.commitment,
      attributes: k.attributes,
      signature: over.signature || k.signature,
      issuer: over.issuer || pinned,
      merkleProof: { root: rootBefore, leaf: k.attrHash, ...k.merkle },
      policy: resource,
      challenge: { nonce, resourceId: pol.resourceId, epoch: zk.epochOf(now), now },
    });
    fixtures[name] = {
      input,
      meta: {
        dir: name,
        persona: who,
        resource,
        presented_to: meta.presented_to || resource,
        nonce,
        gateway_state: meta.gateway_state || stateBefore,
        ...meta,
      },
    };
  };

  const valid = (name, who, resource, nonce) =>
    add(name, who, resource, { nonce }, {
      kind: "valid",
      expect: "accept",
      gateway_obligations: [1, 2, 3, 4, 5, 6, 7],
      description: `${who} -> ${resource}: satisfies the policy; fresh nonce issued with the challenge; every obligation passes in gateway_state.`,
    });

  // alice_wiki keeps the vector nonce: its public.json equals vectors/v4/input.alice.wiki.json.
  await valid("alice_wiki", "alice", "wiki", vec.nonces[0].value);
  await valid("alice_file_share", "alice", "file_share");
  await valid("carol_admin_panel", "carol", "admin_panel");
  await valid("carol_wiki", "carol", "wiki");
  await valid("bob_wiki", "bob", "wiki");

  await add("stale_root_bob_wiki", "bob", "wiki", {}, {
    kind: "attack",
    expect: "reject",
    floor: 3,
    gateway_obligations: [3],
    gateway_state: { current_root: rootAfter, now: vec.now, epoch: vec.epoch },
    description:
      "Bob -> Wiki proved against root_before_revocation. Bob is then revoked (leaf deleted), so the gateway's current root is root_after_bob_revoked: root is not current. Bob cannot prove against the new root at all.",
  });
  // A forger signs Alice's attrHash with its own key (vectors `forged`) and proves with the real
  // root and Alice's real Merkle path: the circuit accepts any issuer key it is given.
  await add("forged_issuer_alice_wiki", "alice", "wiki", { issuer: vec.forged.publicKey, signature: vec.forged.signature }, {
    kind: "attack",
    expect: "reject",
    floor: 2,
    gateway_obligations: [2],
    description:
      "Alice's attributes self-signed by the TEST-ONLY forger key, real root and path. The proof verifies; only the pin of issuerAx/issuerAy to context.pinned_issuer stops it.",
  });
  await add("stale_now_alice_wiki", "alice", "wiki", { now: (BigInt(vec.now) - STALE_NOW_SECONDS).toString() }, {
    kind: "attack",
    expect: "reject",
    floor: 2,
    gateway_obligations: [5],
    description:
      "Alice -> Wiki with now (and epoch = floor(now / 600)) 90 days behind the gateway clock, credential unexpired then. An old now would revive an expired credential: now/epoch must equal the challenge the gateway stored with the nonce (skew bound 120 s).",
  });
  await add("same_epoch_a", "alice", "wiki", {}, {
    kind: "attack",
    expect: "accept",
    floor: 5,
    gateway_obligations: [7],
    description: "Alice -> Wiki, epoch E, nonce A. Present first: first use of (nullifier, epoch), admitted and recorded.",
  });
  await add("same_epoch_b", "alice", "wiki", {}, {
    kind: "attack",
    expect: "reject",
    floor: 5,
    gateway_obligations: [7],
    present_after: ["same_epoch_a"],
    description:
      "Alice -> Wiki, same resource and epoch, different fresh nonce B: same nullifier as same_epoch_a (and alice_wiki). Present after same_epoch_a: rate-limited.",
  });
  await add("wrong_service_alice_wiki_as_admin", "alice", "wiki", {}, {
    kind: "attack",
    expect: "reject",
    floor: 2,
    gateway_obligations: [4],
    presented_to: "admin_panel",
    description:
      "A valid Alice -> Wiki proof presented on a request for Admin Panel: resourceId 1 != 3 and the policy fields (roleMask, minClearance) are Wiki's, not Admin Panel's. Alice cannot prove Admin Panel's policy at all.",
  });

  return { context, fixtures };
}

/** --out <dir> (default circuits/fixtures/v4). */
function parseArgs(argv) {
  let out = DEFAULT_OUT;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--out") {
      if (!argv[i + 1]) refuse("--out needs a directory");
      out = path.resolve(argv[++i]);
    } else if (argv[i].startsWith("--out=")) {
      out = path.resolve(argv[i].slice("--out=".length));
    } else {
      refuse(`unknown argument ${argv[i]} (usage: access-fixtures.js [--out <dir>])`);
    }
  }
  return { out };
}

/** The committed pair must be the manifest's, or the proofs would not verify under the vkey. */
function checkArtefacts() {
  for (const p of [WASM, ZKEY, VKEY, MANIFEST]) if (!fs.existsSync(p)) refuse(`missing ${p}`);
  const man = readJson(MANIFEST);
  if (sha256(ZKEY) !== man.zkey_sha256) refuse(`${ZKEY} is not the zkey of the committed setup (zkey_sha256 mismatch)`);
  if (sha256(WASM) !== man.wasm_sha256) refuse(`${WASM} does not match the committed setup (wasm_sha256 mismatch)`);
  if (sha256(VKEY) !== man.verification_key_sha256) refuse(`${VKEY} does not match the manifest (verification_key_sha256 mismatch)`);
  return man;
}

// The fixtures' TEST_ONLY line follows the committed manifest (tests/safety F9.12): a multi-party
// DEMO-ONLY key never reads "single-party", a single-party key always does. The G2-S1-FINAL-001
// ceremony was simulated (separate agents on one machine, one operator; every contributor name says
// "simulated"), so its line also says the multi-party guarantee does not hold.
function testOnlyText(man) {
  const head = `TEST-ONLY fixtures built from circuits/test/vectors/v4. Proofs are valid under circuits/setup/${NAME}.verification_key.json`;
  const p2 = man.phase2 || {};
  if (typeof p2.contributions === "number" && p2.contributions >= 2) {
    const contributors = Array.isArray(p2.contributors) ? p2.contributors : [];
    const simulated = contributors.length > 0 && contributors.every((c) => /simulated/i.test(c.participant));
    const why = simulated
      ? "; all contributions simulated by separate agents on one machine under one operator, so the multi-party guarantee does not hold: docs/ceremony/v4-ceremony-log.md"
      : "";
    const status = man.status === "DEMO-ONLY" ? "DEMO-ONLY" : "DEV-ONLY";
    return `${head}, a ${status} key (phase 1 PSE ppot 0080; multi-party phase 2, ${p2.contributions} contributors + ${p2.beacon_public ? "public" : "local"} beacon${why}). Not for production. Never use outside tests.`;
  }
  return `${head}, a DEV-ONLY / DEMO-ONLY key (phase 1 PSE ppot 0080; single-party phase 2, so whoever ran setup could forge proofs). Never use outside tests.`;
}

async function main() {
  const { out: OUT } = parseArgs(process.argv.slice(2));
  const man = checkArtefacts();
  const vkey = readJson(VKEY);
  const snarkjs = require("snarkjs");
  const { verify } = require("./verify.js");

  const { context, fixtures } = await plan();
  const results = {};
  for (const [name, { input }] of Object.entries(fixtures)) {
    const t0 = process.hrtime.bigint();
    const res = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const expected = await zk.expectedPublicSignals("v4", input);
    if (JSON.stringify(res.publicSignals) !== JSON.stringify(expected)) throw new Error(`${name}: public signals differ from circuits/lib expectedPublicSignals`);
    zk.decodePublicSignals("v4", res.publicSignals); // canonical + ranged
    if (!(await verify(vkey, res.publicSignals, res.proof))) throw new Error(`${name}: proof does not verify under ${VKEY}`);
    results[name] = res;
    log(`${name}: prove ${ms.toFixed(0)} ms`);
  }

  // Write only after every proof is made and verified.
  fs.mkdirSync(OUT, { recursive: true });
  const index = {
    TEST_ONLY: testOnlyText(man),
    circuit: man.circuit,
    setup_manifest: `circuits/setup/${NAME}.manifest.json`,
    verification_key: `circuits/setup/${NAME}.verification_key.json`,
    verification_key_sha256: man.verification_key_sha256,
    zkey_sha256: man.zkey_sha256,
    public_signals: man.public_signals,
    context,
    fixtures: Object.fromEntries(Object.entries(fixtures).map(([n, f]) => [n, f.meta])),
    documented: {
      replay: {
        reuse: "alice_wiki",
        expect: "reject",
        floor: 4,
        gateway_obligations: [6],
        description: "Present alice_wiki twice: the second presentation reuses a consumed nonce and must be denied. No separate file.",
      },
      forged_signature_under_pinned_issuer: {
        expect: "no proof exists",
        description:
          "A proof whose issuerAx/issuerAy IS the pinned key but whose credential the issuer never signed cannot be generated (witness generation fails in the EdDSA verifier; circuits/test/v4.test.js). Its gateway-level form is forged_issuer_alice_wiki.",
      },
    },
  };
  for (const [name, res] of Object.entries(results)) {
    const dir = path.join(OUT, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "proof.json"), JSON.stringify(res.proof, null, 1) + "\n");
    fs.writeFileSync(path.join(dir, "public.json"), JSON.stringify(res.publicSignals, null, 1) + "\n");
  }
  fs.writeFileSync(path.join(OUT, "fixtures.json"), JSON.stringify(index, null, 2) + "\n");
  fs.copyFileSync(VKEY, path.join(OUT, "verification_key.json"));
  log(`wrote ${Object.keys(results).length} fixtures to ${OUT}`);
}

module.exports = { plan, nonceFor, STALE_NOW_SECONDS, NONCE_TTL_SECONDS };

if (require.main === module) {
  main()
    .then(async () => {
      await require("./verify.js").terminate();
    })
    .catch(async (e) => {
      log(e instanceof Refusal ? `ERROR: ${e.message}` : e.stack || e);
      try {
        await require("./verify.js").terminate();
      } catch (_) {
        /* nothing to release */
      }
      process.exit(e instanceof Refusal ? 2 : 1);
    });
}
