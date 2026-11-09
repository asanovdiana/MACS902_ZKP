#!/usr/bin/env node
"use strict";
/**
 * TEST-ONLY reference vectors for circuits/lib profiles v3 and v4 (ADR 0004; G0-S1-CIRC-021,
 * G1-S1-CIRC-038). Consumers: circuits/test/lib.test.js, identity's cross-check suite.
 *
 *   node circuits/scripts/gen-vectors.js           # (re)write circuits/test/vectors/{v3,v4}/*.json
 *   node circuits/scripts/gen-vectors.js --check   # exit 0 iff the committed vectors are up to date
 *
 * Every key and secret is sha256 of a public label containing "TEST-ONLY": they protect nothing
 * and must never be used by a running issuer or client. The issuer private key is stored only as
 * its label (floor 9). The clock is fixed so the output is deterministic. All encodings come from
 * circuits/lib; the tree is the lib's zk-kit wrapper.
 */
const fs = require("fs");
const path = require("path");
const nodeCrypto = require("crypto");
const lib = require("../lib");

const VDIR = path.join(__dirname, "..", "test", "vectors");

const BANNER =
  "TEST-ONLY reference vectors for ZK Access Gate. All keys and secrets are sha256 of public " +
  "labels and protect nothing. Never use them outside tests.";

const ISSUER_LABEL = "zk-access-gate TEST-ONLY issuer key (circuits/lib vectors) - never use outside tests";
const FORGER_LABEL = "zk-access-gate TEST-ONLY forger key (circuits/lib vectors) - a non-issuer self-signer";
const secretLabel = (profile, who) => `zk-access-gate TEST-ONLY ${profile} credentialSecret: ${who}`;
const saltLabel = (profile, who) => `zk-access-gate TEST-ONLY ${profile} credentialSalt: ${who}`;
const nonceLabel = (i) => `zk-access-gate TEST-ONLY gateway nonce sample ${i}`;

const NOW = Date.UTC(2026, 10, 8, 9, 0, 0) / 1000; // 2026-11-08T09:00:00Z
const EXPIRY = Date.UTC(2099, 0, 1, 0, 0, 0) / 1000; // 2099-01-01T00:00:00Z (<= 2^53 - 1)

const sha256 = (s) => nodeCrypto.createHash("sha256").update(s, "utf8").digest();
/** 31 bytes (< 2^248), as the client's CSPRNG secrets (credential v3/v4). */
const secret31 = (label) => BigInt("0x" + sha256(label).subarray(0, 31).toString("hex")).toString();
/** 128-bit gateway nonce. */
const nonce128 = (label) => BigInt("0x" + sha256(label).subarray(0, 16).toString("hex")).toString();

const V3_PERSONAS = [
  // v3 role/clearance are opaque (ADR 0008). Alice carries the v3 File Share TEST values 2/2 so a
  // v3 proof exists; Bob and Carol carry their D6 numbers, which v3 FileShareAccess rejects.
  { persona: "alice", attributes: { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 } },
  { persona: "bob", attributes: { role: 2, clearance: 1, deviceCompliant: 1, employeeActive: 1 } },
  { persona: "carol", attributes: { role: 1, clearance: 3, deviceCompliant: 1, employeeActive: 1 } },
];

const V4_PERSONAS = [
  { persona: "alice", role: "engineer", dept: "engineering", clearance: 2, deviceCompliant: 1, employeeActive: 1 },
  { persona: "bob", role: "contractor", dept: "operations", clearance: 1, deviceCompliant: 1, employeeActive: 1 },
  { persona: "carol", role: "admin", dept: "it", clearance: 3, deviceCompliant: 1, employeeActive: 1 },
];

const verdict = (v) => ({ ok: v.ok, reasons: v.reasons.map((r) => r.code) });

async function poseidonSamples(sets) {
  const out = {};
  for (const [n, list] of Object.entries(sets)) {
    out[n] = [];
    for (const inputs of list) out[n].push({ inputs: inputs.map(String), out: await lib.poseidon(inputs) });
  }
  return out;
}

async function issuerKey(label) {
  const prv = sha256(label);
  return { prv, pub: await lib.publicKey(prv) };
}

async function generateV3(issuer) {
  const profile = lib.profiles.v3;
  const tree = await lib.createTree(profile);
  const emptyRoot = tree.root.toString();
  const creds = [];
  for (const p of V3_PERSONAS) {
    const credentialSecret = secret31(secretLabel("v3", p.persona));
    const credentialSalt = secret31(saltLabel("v3", p.persona));
    const commitment = await lib.commitment(credentialSecret, credentialSalt);
    const M = await profile.message({ commitment, attributes: p.attributes });
    const signature = await lib.sign(issuer.prv, M);
    tree.insert(BigInt(await profile.leaf({ commitment, attributes: p.attributes })));
    creds.push({ p, credentialSecret, credentialSalt, commitment, signature });
  }
  const credentials = creds.map(({ p, credentialSecret, credentialSalt, commitment, signature }, i) => {
    const pr = lib.proofFor(tree, i);
    return {
      persona: p.persona,
      secretLabel: secretLabel("v3", p.persona),
      saltLabel: saltLabel("v3", p.persona),
      credentialSecret,
      credentialSalt,
      commitment,
      attributes: p.attributes,
      signature,
      leafIndex: i,
      merkle: { pathElements: pr.pathElements, pathIndices: pr.pathIndices },
      expectedAccess: { file_share_v3: verdict(lib.checkFileShareV3(p.attributes)) },
    };
  });
  const root = tree.root.toString();
  const credentialsJson = {
    TEST_ONLY: BANNER,
    profile: "v3",
    depth: profile.depth,
    note:
      "v3 role and clearance are opaque integers (ADR 0008), not D6 names. Alice carries the v3 " +
      "File Share TEST values role 2, clearance 2 so that a v3 proof exists; Bob (2/1) and Carol (1/3) " +
      "carry their D6 numbers and v3 FileShareAccess rejects them. v3 attributes are unsigned.",
    issuer: { seedLabel: ISSUER_LABEL, ...issuer.pub },
    tree: {
      description: "@zk-kit/incremental-merkle-tree 1.1.0, Poseidon(2), arity 2, zero leaf 0; leaves = commitments in leafIndex order",
      emptyRoot,
      root,
    },
    credentials,
  };

  const a = credentials[0];
  const input = await lib.buildInputV3({
    credentialSecret: a.credentialSecret,
    credentialSalt: a.credentialSalt,
    commitment: a.commitment,
    attributes: a.attributes,
    signature: a.signature,
    issuer: issuer.pub,
    merkleProof: { root, leaf: a.commitment, ...a.merkle },
  });
  const inputJson = {
    TEST_ONLY: BANNER,
    profile: "v3",
    circuit: "circuits/integrated_access_v3.circom (IntegratedAccessGate)",
    persona: "alice",
    input,
    expectedPublicSignals: await lib.expectedPublicSignals("v3", input),
  };
  const poseidonJson = {
    TEST_ONLY: BANNER,
    implementation: "circomlibjs 0.1.7 buildPoseidon, F.toObject(poseidon([...])) == circomlib 2.0.5 Poseidon(n)",
    samples: await poseidonSamples({ 2: [[0, 0], [1, 2], [11, 22]] }),
  };
  return { "v3/credentials.json": credentialsJson, "v3/input.alice.json": inputJson, "v3/poseidon.json": poseidonJson };
}

async function generateV4(issuer) {
  const profile = lib.profiles.v4;
  const now = String(NOW);
  const epoch = lib.epochOf(NOW);
  const nonces = [0, 1, 2].map((i) => ({ label: nonceLabel(i), value: nonce128(nonceLabel(i)) }));
  const tree = await lib.createTree(profile);
  const emptyRoot = tree.root.toString();
  const creds = [];
  for (const p of V4_PERSONAS) {
    const credentialSecret = secret31(secretLabel("v4", p.persona));
    const credentialSalt = secret31(saltLabel("v4", p.persona));
    const commitment = await lib.commitment(credentialSecret, credentialSalt);
    const attributes = {
      role: lib.ROLES[p.role],
      dept: lib.DEPTS[p.dept],
      clearance: p.clearance,
      deviceCompliant: p.deviceCompliant,
      employeeActive: p.employeeActive,
      expiry: EXPIRY,
    };
    const attrHash = await lib.attrHash(attributes, commitment);
    const signature = await lib.sign(issuer.prv, await profile.message({ commitment, attributes }));
    tree.insert(BigInt(await profile.leaf({ commitment, attributes })));
    creds.push({ p, credentialSecret, credentialSalt, commitment, attributes, attrHash, signature });
  }
  const root = tree.root.toString();
  const credentials = [];
  for (const [i, c] of creds.entries()) {
    const pr = lib.proofFor(tree, i);
    const nullifiers = {};
    const expectedAccess = {};
    for (const [name, pol] of Object.entries(lib.policies)) {
      nullifiers[name] = await lib.nullifier(c.credentialSecret, pol.resourceId, epoch);
      expectedAccess[name] = verdict(lib.checkPolicyLocally(c.attributes, pol, now));
    }
    credentials.push({
      persona: c.p.persona,
      labels: { role: c.p.role, dept: c.p.dept },
      secretLabel: secretLabel("v4", c.p.persona),
      saltLabel: saltLabel("v4", c.p.persona),
      credentialSecret: c.credentialSecret,
      credentialSalt: c.credentialSalt,
      commitment: c.commitment,
      attributes: c.attributes,
      attrHash: c.attrHash,
      signature: c.signature,
      leafIndex: i,
      merkle: { pathElements: pr.pathElements, pathIndices: pr.pathIndices },
      nullifiers,
      expectedAccess,
    });
  }

  const forger = await issuerKey(FORGER_LABEL);
  const aliceHash = credentials[0].attrHash;
  const credentialsJson = {
    TEST_ONLY: BANNER,
    profile: "v4",
    depth: profile.depth,
    now,
    nowIso: new Date(NOW * 1000).toISOString(),
    epoch,
    expiry: EXPIRY,
    expiryIso: new Date(EXPIRY * 1000).toISOString(),
    issuer: { seedLabel: ISSUER_LABEL, ...issuer.pub },
    tree: {
      description: "@zk-kit/incremental-merkle-tree 1.1.0, Poseidon(2), arity 2, zero leaf 0; leaves = attrHash in leafIndex order",
      emptyRoot,
      root,
    },
    nonces,
    resources: lib.policies,
    credentials,
    forged: {
      note: "alice's attrHash self-signed by a non-issuer key: verifies under publicKey, not under issuer",
      seedLabel: FORGER_LABEL,
      publicKey: forger.pub,
      message: aliceHash,
      signature: await lib.sign(forger.prv, aliceHash),
    },
  };

  const a = credentials[0];
  const input = await lib.buildInputV4({
    credentialSecret: a.credentialSecret,
    credentialSalt: a.credentialSalt,
    commitment: a.commitment,
    attributes: a.attributes,
    signature: a.signature,
    issuer: issuer.pub,
    merkleProof: { root, leaf: a.attrHash, ...a.merkle },
    policy: "wiki",
    challenge: { nonce: nonces[0].value, resourceId: lib.policies.wiki.resourceId, epoch, now },
  });
  const expectedPublicSignals = await lib.expectedPublicSignals("v4", input);
  const inputJson = {
    TEST_ONLY: BANNER,
    profile: "v4",
    circuit: "circuits/integrated_access_v4.circom (depth 16; lands with G1-S1-CIRC-036)",
    persona: "alice",
    resource: "wiki",
    challenge: { nonce: input.nonce, resourceId: input.resourceId, epoch: input.epoch, now: input.now },
    input,
    expectedPublicSignals,
    expectedPublicSignalsByName: lib.decodePublicSignals("v4", expectedPublicSignals),
  };
  const poseidonJson = {
    TEST_ONLY: BANNER,
    implementation: "circomlibjs 0.1.7 buildPoseidon, F.toObject(poseidon([...])) == circomlib 2.0.5 Poseidon(n)",
    samples: await poseidonSamples({
      2: [[0, 0], [1, 2]],
      3: [[1, 2, 3], [a.credentialSecret, 1, epoch]],
      7: [[0, 0, 0, 0, 0, 0, 0], [0, 0, 2, 1, 1, EXPIRY, a.commitment]],
    }),
  };
  return { "v4/credentials.json": credentialsJson, "v4/input.alice.wiki.json": inputJson, "v4/poseidon.json": poseidonJson };
}

async function generate() {
  const issuer = await issuerKey(ISSUER_LABEL);
  return { ...(await generateV3(issuer)), ...(await generateV4(issuer)) };
}

const serialise = (obj) => JSON.stringify(obj, null, 2) + "\n";

async function main() {
  const check = process.argv.includes("--check");
  const out = await generate();
  let drift = 0;
  for (const [f, obj] of Object.entries(out)) {
    const p = path.join(VDIR, f);
    const fresh = serialise(obj);
    if (check) {
      if (!fs.existsSync(p) || fs.readFileSync(p, "utf8") !== fresh) {
        console.error("drift:", f);
        drift++;
      }
    } else {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, fresh);
      console.log("wrote", path.relative(process.cwd(), p));
    }
  }
  if (check) {
    if (drift) {
      console.error(`${drift} vector file(s) out of date; run node circuits/scripts/gen-vectors.js`);
      return 1;
    }
    console.log("vectors up to date");
  }
  return 0;
}

module.exports = { generate, serialise };

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (e) => {
      console.error(e);
      process.exit(1);
    }
  );
}
