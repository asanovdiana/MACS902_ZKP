"use strict";
// G1-S1-CIRC-036: the v4 access circuit (circuits/integrated_access_v4.circom, template in
// components/integrated_access_v4_gate.circom). Contracts: docs/CONTRACTS.md `credential v4`,
// `access.public_signals v4` (authoritative); ADR 0006, 0007. Floors 1-5, 8.
//
// Tiers inside this file:
//   1. layout      - R1CS header, public slots 0..11 by .sym name in contract order, counts for
//                    depth 8/16/20 at --O1/--O2 (and depth 16 at --O0)
//   2. positives   - the lib vector input.alice.wiki.json; 9 persona x policy combinations per the
//                    contract (allowed ones prove, denied ones fail witness generation); lib parity
//                    (commitment, attrHash, root, nullifier); nullifier rate-limit / unlinkability
//   3. negatives, input level (--O2): tampered attributes, self-signed, off-curve, revoked, wrong
//                    root, expired, each policy denial
//   4. negatives, public slots (--O1, --O2): every one of the 12 public signals changed after
//                    witness generation fails checkConstraints. Needed because a public input bound
//                    only linearly leaves no R1CS row at --O2 (memory: linear-binding-vanishes-at-o2)
//   5. negatives, witness level (--O0): one test per `<==` wiring line of the v4 gate; a valid
//                    witness is edited so that EXACTLY ONE R1CS row (that link) is violated, so
//                    weakening the line to `<--` makes the edit acceptable (floor 1)
//
// Every test title that kills a mutant contains "negatives" (scripts/MUTATION.md: --grep).
// All keys and secrets are TEST-ONLY (circuits/test/vectors/v4, sha256 of public labels).
const nodeCrypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { expect } = require("chai");
const zk = require("../lib");
const { CIRCUITS, compileCached, compilePoseidon2, expectReject, r1csInfo, NamedWitness, mod } = require("./helpers");

const ASSERT = /Assert Failed/;
const CONSTRAINT = /Constraint doesn't match/;

const COMPONENTS = path.join(CIRCUITS, "components");
const TEST_MAINS = path.join(__dirname, "circuits");
const MAINS = {
  8: path.join(CIRCUITS, "integrated_access_v4_d8.circom"),
  16: path.join(CIRCUITS, "integrated_access_v4.circom"),
  20: path.join(CIRCUITS, "integrated_access_v4_d20.circom"),
};
const V4_SOURCES = [
  "integrated_access_v4_gate.circom",
  "attribute_hash.circom",
  "eddsa_verifier.circom",
  "issuer_key.circom",
  "merkle_membership_n.circom",
  "access_policy_v4.circom",
  "expiry.circom",
  "challenge_binding.circom",
].map((f) => path.join(COMPONENTS, f));

const compileV4 = (O, depth = 16) => compileCached(`v4-d${depth}-O${O}`, MAINS[depth], [MAINS[depth], ...V4_SOURCES], { O });

/** Standalone component mains at --O0, for honest sub-witnesses (harness `main.X` = v4 `main.<comp>.X`). */
function harness(name, file, sources) {
  const f = path.join(TEST_MAINS, file);
  return compileCached(`v4-h-${name}-O0`, f, [f, ...sources.map((s) => path.join(COMPONENTS, s))], { O: 0 });
}
const harnesses = () =>
  Promise.all([
    harness("attribute-hash", "attribute_hash.circom", ["attribute_hash.circom"]),
    harness("issuer-signature", "issuer_signature_check.circom", ["eddsa_verifier.circom"]),
    harness("signature-points", "signature_points.circom", ["issuer_key.circom"]),
    harness("merkle-16", "merkle_n_16.circom", ["merkle_membership_n.circom"]),
    compilePoseidon2(),
  ]).then(([attr, signature, points, merkle, poseidon2]) => ({ attr, signature, points, merkle, poseidon2 }));

// Measured with circom 2.2.3 + circomlib 2.0.5. Any change to the v4 circuit must update these
// deliberately (and circuits/README.md).
const EXPECTED_COUNTS = {
  8: { 0: [10490, 20801], 1: [10474, 4231], 2: [7264, 0] },
  16: { 0: [12458, 25017], 1: [12442, 6423], 2: [9208, 0] },
  20: { 0: [13442, 27125], 1: [13426, 7519], 2: [10180, 0] },
};

// access.public_signals v4: output first, then the public inputs in declaration order.
const PUBLIC = [
  "nullifier", "root", "issuerAx", "issuerAy", "roleMask", "deptMask", "minClearance",
  "requireDevice", "now", "nonce", "resourceId", "epoch",
];
const ATTRS = ["role", "dept", "clearance", "deviceCompliant", "employeeActive", "expiry"];

// Contract verdicts (access.public_signals v4 "Demo policies", ADR 0008 personas).
const VERDICTS = {
  alice: { wiki: true, file_share: true, admin_panel: false },
  bob: { wiki: true, file_share: false, admin_panel: false },
  carol: { wiki: true, file_share: true, admin_panel: true },
};

const VEC_DIR = path.join(__dirname, "vectors", "v4");
const vec = JSON.parse(fs.readFileSync(path.join(VEC_DIR, "credentials.json"), "utf8"));
const vecInput = JSON.parse(fs.readFileSync(path.join(VEC_DIR, "input.alice.wiki.json"), "utf8"));
const persona = (name) => vec.credentials.find((c) => c.persona === name);
const sha256 = (s) => nodeCrypto.createHash("sha256").update(s, "utf8").digest();
const ISSUER_PRV = sha256(vec.issuer.seedLabel); // TEST-ONLY: sha256 of a public label
const PINNED = { Ax: vec.issuer.Ax, Ay: vec.issuer.Ay };
const NOW = BigInt(vec.now);
const CHALLENGE = (resource, over = {}) => ({
  nonce: vec.nonces[0].value,
  resourceId: String(vec.resources[resource] ? vec.resources[resource].resourceId : 1),
  epoch: vec.epoch,
  now: vec.now,
  ...over,
});

/** Builder arguments for a vector persona against the vector tree (as the client assembles them). */
function vecArgs(name, policy, over = {}) {
  const c = persona(name);
  return {
    credentialSecret: c.credentialSecret,
    credentialSalt: c.credentialSalt,
    commitment: c.commitment,
    attributes: { ...c.attributes },
    signature: { ...c.signature },
    issuer: { ...PINNED },
    merkleProof: { root: vec.tree.root, leaf: c.attrHash, ...c.merkle },
    policy,
    challenge: CHALLENGE(typeof policy === "string" ? policy : "wiki"),
    ...over,
  };
}

/** The gateway's pin (obligation 2) on publicSignals[2..3]; modelled here only to state the G-2 fix. */
const gatewayPinsIssuer = (pub) => pub[2] === PINNED.Ax && pub[3] === PINNED.Ay;

/**
 * TEST-ONLY registry: the three vector personas at leaves 0..2 (reproducing the vector root before
 * the variants go in), then issuer-signed variants of Alice that differ from her in ONE attribute.
 * Every credential here is genuinely signed by the pinned issuer and is a member of the same tree.
 */
async function buildWorld() {
  const tree = await zk.createTree(zk.profiles.v4);
  const creds = {};
  for (const c of vec.credentials) {
    tree.insert(BigInt(c.attrHash));
    creds[c.persona] = {
      credentialSecret: c.credentialSecret,
      credentialSalt: c.credentialSalt,
      commitment: c.commitment,
      attributes: { ...c.attributes },
      attrHash: c.attrHash,
      signature: { ...c.signature },
      leafIndex: c.leafIndex,
    };
  }
  const vectorRoot = tree.root.toString();
  const alice = creds.alice;
  const variants = {
    role: { role: 1 },
    dept: { dept: 1 },
    clearance: { clearance: 3 },
    deviceCompliant: { deviceCompliant: 0 },
    employeeActive: { employeeActive: 0 },
    expiry: { expiry: alice.attributes.expiry - 1 },
    expired: { expiry: Number(NOW) - 600 },
  };
  for (const [k, over] of Object.entries(variants)) {
    const attributes = { ...alice.attributes, ...over };
    const attrHash = await zk.attrHash(attributes, alice.commitment);
    tree.insert(BigInt(attrHash));
    creds[`alice.${k}`] = {
      ...alice,
      attributes,
      attrHash,
      signature: await zk.sign(ISSUER_PRV, attrHash),
      leafIndex: tree.leaves.length - 1,
    };
  }
  return { tree, creds, vectorRoot, root: tree.root.toString() };
}

/** Builder arguments for a world credential (path from the world tree). */
function worldArgs(world, name, policy, over = {}) {
  const c = world.creds[name];
  return {
    credentialSecret: c.credentialSecret,
    credentialSalt: c.credentialSalt,
    commitment: c.commitment,
    attributes: { ...c.attributes },
    signature: { ...c.signature },
    issuer: { ...PINNED },
    merkleProof: zk.proofFor(world.tree, c.leafIndex),
    policy,
    challenge: CHALLENGE(typeof policy === "string" ? policy : "wiki"),
    ...over,
  };
}

const pubOf = (w) => w.slice(1, 1 + PUBLIC.length).map((x) => x.toString());

let world;
before(async function () {
  this.timeout(120000);
  const pk = await zk.publicKey(ISSUER_PRV);
  expect(pk, "vector issuer key derives from its seed label").to.deep.equal(PINNED);
  world = await buildWorld();
  expect(world.vectorRoot, "personas at leaves 0..2 reproduce the vector root").to.equal(vec.tree.root);
});

// ---------------------------------------------------------------------------------------------
// 1. layout
// ---------------------------------------------------------------------------------------------
describe("v4 layout (access.public_signals v4)", function () {
  it("the lib's PUBLIC_SIGNALS.v4 is the contract order this suite asserts", function () {
    expect(zk.PUBLIC_SIGNALS.v4).to.deep.equal(PUBLIC);
  });

  for (const O of [0, 1, 2]) {
    describe(`depth 16, --O${O}`, function () {
      let t;
      before(async function () {
        t = await compileV4(O);
      });

      it("R1CS header: 11 public inputs, 1 output, 43 private inputs", async function () {
        const info = await r1csInfo(t);
        expect(info.nPubInputs).to.equal(11);
        expect(info.nOutputs).to.equal(1);
        expect(info.nPrvInputs).to.equal(43);
      });

      it("witness slots 1..12 are main.<name> in contract order (.sym)", function () {
        PUBLIC.forEach((name, i) => {
          expect(t.symbols[`main.${name}`], name).to.not.equal(undefined);
          expect(t.symbols[`main.${name}`].varIdx, name).to.equal(i + 1);
        });
        const bySlot = Object.entries(t.symbols)
          .filter(([, s]) => s.varIdx >= 1 && s.varIdx <= 12)
          .sort((a, b) => a[1].varIdx - b[1].varIdx)
          .map(([n]) => n);
        expect(bySlot).to.deep.equal(PUBLIC.map((n) => `main.${n}`));
      });

      it("no M, leaf, Ax or Ay input exists (credential v4)", function () {
        for (const n of ["main.M", "main.leaf", "main.Ax", "main.Ay"]) expect(t.symbols[n], n).to.equal(undefined);
      });
    });
  }

  for (const depth of [8, 16, 20]) {
    for (const O of depth === 16 ? [0, 1, 2] : [1, 2]) {
      const [nl, lin] = EXPECTED_COUNTS[depth][O];
      it(`constraint count depth ${depth} --O${O}: ${nl} non-linear + ${lin} linear`, async function () {
        const info = await r1csInfo(await compileV4(O, depth));
        expect({ nonLinear: info.nonLinear, linear: info.linear }).to.deep.equal({ nonLinear: nl, linear: lin });
        expect(info.nPubInputs).to.equal(11);
        expect(info.nPrvInputs).to.equal(11 + 2 * depth);
      });
    }
  }
});

// ---------------------------------------------------------------------------------------------
// 2. positives
// ---------------------------------------------------------------------------------------------
for (const O of [1, 2]) {
  describe(`v4 positives (--O${O})`, function () {
    let t;
    before(async function () {
      t = await compileV4(O);
    });

    it("the lib vector input.alice.wiki.json satisfies v4; public slots = expectedPublicSignals (array and by name)", async function () {
      const w = await t.calculateWitness(vecInput.input, true);
      await t.checkConstraints(w);
      expect(pubOf(w)).to.deep.equal(vecInput.expectedPublicSignals);
      const byName = Object.fromEntries(PUBLIC.map((n) => [n, w[t.symbols[`main.${n}`].varIdx].toString()]));
      expect(byName).to.deep.equal(vecInput.expectedPublicSignalsByName);
      expect(Object.keys(vecInput.expectedPublicSignalsByName)).to.deep.equal(PUBLIC);
    });

    it("buildInputV4 reproduces the vector input exactly (key order = circuit declaration order)", async function () {
      const input = await zk.buildInputV4(vecArgs("alice", "wiki"));
      expect(input).to.deep.equal(vecInput.input);
      expect(Object.keys(input)).to.deep.equal(Object.keys(vecInput.input));
    });

    for (const [who, row] of Object.entries(VERDICTS)) {
      for (const [policy, allow] of Object.entries(row)) {
        it(`${who} -> ${policy}: ${allow ? "admitted (witness satisfies v4)" : "denied (witness generation fails)"} per the contract`, async function () {
          expect(persona(who).expectedAccess[policy].ok, "vector agrees with the contract table").to.equal(allow);
          if (allow) {
            const input = await zk.buildInputV4(vecArgs(who, policy));
            const w = await t.calculateWitness(input, true);
            await t.checkConstraints(w);
            expect(pubOf(w)).to.deep.equal(await zk.expectedPublicSignals("v4", input));
            expect(pubOf(w)[0]).to.equal(persona(who).nullifiers[policy]);
          } else {
            const input = await zk.buildInputV4(vecArgs(who, policy), { precheck: false });
            await expectReject(t.calculateWitness(input, true), ASSERT);
          }
        });
      }
    }

    it("rate limit: the same user, resource and epoch give the same nullifier under a fresh nonce", async function () {
      const a = await t.calculateWitness(await zk.buildInputV4(vecArgs("alice", "wiki")), true);
      const b = await t.calculateWitness(
        await zk.buildInputV4(vecArgs("alice", "wiki", { challenge: CHALLENGE("wiki", { nonce: vec.nonces[1].value }) })),
        true
      );
      expect(b[1].toString()).to.equal(a[1].toString());
      expect(b[10].toString()).to.not.equal(a[10].toString());
    });

    it("unlinkability: one user's nullifiers differ across resources and across epochs", async function () {
      const ns = new Set();
      for (const policy of ["wiki", "file_share"]) {
        const w = await t.calculateWitness(await zk.buildInputV4(vecArgs("alice", policy)), true);
        ns.add(w[1].toString());
      }
      const nextEpoch = { now: String(NOW + 600n), epoch: String(BigInt(vec.epoch) + 1n) };
      const w = await t.calculateWitness(
        await zk.buildInputV4(vecArgs("alice", "wiki", { challenge: CHALLENGE("wiki", nextEpoch) })),
        true
      );
      ns.add(w[1].toString());
      expect(ns.size).to.equal(3);
    });

    it("every issuer-signed single-attribute variant that satisfies its policy is admitted (controls for the negatives)", async function () {
      for (const [name, policy] of [
        ["alice.role", "wiki"],
        ["alice.dept", "wiki"],
        ["alice.clearance", "wiki"],
        ["alice.deviceCompliant", "file_share"],
        ["alice.expiry", "wiki"],
      ]) {
        const w = await t.calculateWitness(await zk.buildInputV4(worldArgs(world, name, policy)), true);
        await t.checkConstraints(w);
        expect(w[2].toString(), name).to.equal(world.root);
      }
    });
  });
}

describe("v4 lib parity (--O0: every internal signal is addressable)", function () {
  let t;
  let W;
  before(async function () {
    t = await compileV4(0);
    W = new NamedWitness(t, await t.calculateWitness(vecInput.input, true));
  });

  it("credentialCommitment equals lib commitment(secret, salt)", async function () {
    const c = persona("alice");
    expect(W.get("main.credentialCommitment").toString()).to.equal(await zk.commitment(c.credentialSecret, c.credentialSalt));
    expect(W.get("main.credentialCommitment").toString()).to.equal(c.commitment);
  });

  it("AttributeHash output equals lib attrHash (and is the signed M and the Merkle leaf)", async function () {
    const c = persona("alice");
    const h = await zk.attrHash(c.attributes, c.commitment);
    expect(h).to.equal(c.attrHash);
    expect(W.get("main.attr.attrHash").toString()).to.equal(h);
    expect(W.get("main.signature.M").toString()).to.equal(h);
    expect(W.get("main.merkle.leaf").toString()).to.equal(h);
  });

  it("nullifier equals lib nullifier(secret, resourceId, epoch)", async function () {
    const c = persona("alice");
    const n = await zk.nullifier(c.credentialSecret, vecInput.input.resourceId, vecInput.input.epoch);
    expect(W.get("main.nullifier").toString()).to.equal(n);
    expect(n).to.equal(c.nullifiers.wiki);
  });

  it("the circuit's recomputed root equals the lib (zk-kit) tree root", async function () {
    const tree = await zk.createTree(zk.profiles.v4);
    for (const c of vec.credentials) tree.insert(BigInt(c.attrHash));
    expect(W.get("main.merkle.hashes[16]").toString()).to.equal(tree.root.toString());
    expect(W.get("main.root").toString()).to.equal(vec.tree.root);
  });
});

// ---------------------------------------------------------------------------------------------
// 3. negatives, input level
// ---------------------------------------------------------------------------------------------
describe("v4 negatives, input level (--O2)", function () {
  let t;
  let alice; // valid input: alice -> wiki in the world tree
  let aliceFs; // valid input: alice -> file_share in the world tree
  const witness = (input) => t.calculateWitness(input, true);
  const reject = (input) => expectReject(witness(input), ASSERT);

  before(async function () {
    t = await compileV4(2);
    alice = await zk.buildInputV4(worldArgs(world, "alice", "wiki"));
    aliceFs = await zk.buildInputV4(worldArgs(world, "alice", "file_share"));
    await t.checkConstraints(await witness(alice));
    await t.checkConstraints(await witness(aliceFs));
  });

  // G-1 closed: each of the 7 attrHash inputs changed, ORIGINAL signature and path.
  for (const [f, base, to] of [
    ["role", "wiki", () => "1"],
    ["dept", "wiki", () => "1"],
    ["clearance", "wiki", () => "3"],
    ["deviceCompliant", "file_share", () => "0"],
    ["employeeActive", "wiki", () => "0"],
    ["expiry", "wiki", (x) => String(BigInt(x) - 1n)],
  ]) {
    it(`tampered attribute ${f} with the ORIGINAL signature is rejected (G-1 closed; the re-signed value is admitted)`, async function () {
      const input = { ...(base === "wiki" ? alice : aliceFs) };
      input[f] = to(input[f]);
      await reject(input);
    });
  }

  it("tampered attribute credentialCommitment (other salt) with the ORIGINAL signature is rejected", async function () {
    await reject({ ...alice, credentialSalt: String(BigInt(alice.credentialSalt) + 1n) });
  });

  it("G-1 attack: Bob claims admin + clearance 3 for the Admin Panel with his original signature -> rejected", async function () {
    const input = await zk.buildInputV4(vecArgs("bob", "admin_panel"), { precheck: false });
    await reject({ ...input, role: "1", clearance: "3" });
  });

  it("self-signed credential presented under the PINNED issuer key is rejected", async function () {
    const input = { ...vecInput.input, ...vec.forged.signature };
    await reject(input);
  });

  it("self-signed credential satisfies the circuit only under the forger's key, which the pin rejects (G-2 closed)", async function () {
    const input = { ...vecInput.input, ...vec.forged.signature, issuerAx: vec.forged.publicKey.Ax, issuerAy: vec.forged.publicKey.Ay };
    const w = await witness(input);
    await t.checkConstraints(w);
    expect(gatewayPinsIssuer(pubOf(w))).to.equal(false);
    expect(gatewayPinsIssuer(vecInput.expectedPublicSignals)).to.equal(true);
  });

  it("self-signed credential with invented attributes (not in the registry) is rejected even under the forger's key", async function () {
    const forger = sha256(vec.forged.seedLabel);
    const c = persona("alice");
    const attributes = { ...c.attributes, role: 1, clearance: 3 };
    const h = await zk.attrHash(attributes, c.commitment);
    const input = {
      ...vecInput.input,
      role: "1",
      clearance: "3",
      ...(await zk.sign(forger, h)),
      issuerAx: vec.forged.publicKey.Ax,
      issuerAy: vec.forged.publicKey.Ay,
    };
    await reject(input);
  });

  it("off-curve issuer key (issuerAx + 1) is rejected", async function () {
    await reject({ ...alice, issuerAx: String(mod(BigInt(alice.issuerAx) + 1n)) });
  });

  it("off-curve R8 (R8y + 1) is rejected", async function () {
    await reject({ ...alice, R8y: String(mod(BigInt(alice.R8y) + 1n)) });
  });

  it("revoked credential: the old path against the current root (leaf zeroed) is rejected; others still admitted", async function () {
    const tree = await zk.createTree(zk.profiles.v4);
    for (const c of vec.credentials) tree.insert(BigInt(c.attrHash));
    const pre = zk.proofFor(tree, 0);
    tree.delete(0); // revoke alice: leaf <- 0
    const current = tree.root.toString();
    expect(current).to.not.equal(pre.root);
    const input = await zk.buildInputV4(vecArgs("alice", "wiki"));
    await reject({ ...input, root: current });
    // her path re-fetched after revocation (siblings unchanged, leaf 0) does not help either
    const after = zk.proofFor(tree, 0);
    expect(after.leaf).to.equal("0");
    await reject({ ...input, root: after.root, pathElements: after.pathElements, pathIndices: after.pathIndices });
    // control: Bob, not revoked, proves against the current root
    const bob = await zk.buildInputV4({ ...vecArgs("bob", "wiki"), merkleProof: zk.proofFor(tree, 1) });
    await t.checkConstraints(await witness(bob));
  });

  it("wrong root (root + 1, empty-tree root) is rejected", async function () {
    await reject({ ...alice, root: String(mod(BigInt(alice.root) + 1n)) });
    await reject({ ...alice, root: vec.tree.emptyRoot });
  });

  it("stale root: a valid member of the new tree presented against the vector root (its own leaf absent) is rejected", async function () {
    const input = await zk.buildInputV4(worldArgs(world, "alice.role", "wiki"));
    await reject({ ...input, root: vec.tree.root });
  });

  it("expired credential (issuer-signed, expiry < now) is rejected", async function () {
    await reject(await zk.buildInputV4(worldArgs(world, "alice.expired", "wiki"), { precheck: false }));
  });

  it("now == expiry and now > expiry are rejected (strict expiry > now)", async function () {
    const exp = BigInt(alice.expiry);
    await reject({ ...alice, now: String(exp) });
    await reject({ ...alice, now: String(exp + 1n) });
  });

  it("policy denial: role bit unset (roleMask 0b1110 vs engineer) is rejected", async function () {
    await reject({ ...alice, roleMask: "14" });
  });

  it("policy denial: dept bit unset (deptMask 0b1110 vs engineering) is rejected", async function () {
    await reject({ ...alice, deptMask: "14" });
  });

  it("policy denial: clearance below minClearance (2 < 3) is rejected", async function () {
    await reject({ ...alice, minClearance: "3" });
  });

  it("policy denial: device required, credential's device not compliant (issuer-signed) is rejected", async function () {
    await reject(await zk.buildInputV4(worldArgs(world, "alice.deviceCompliant", "wiki"), { precheck: false }));
  });

  it("policy denial: inactive employee (issuer-signed employeeActive 0) is rejected under every demo policy", async function () {
    for (const policy of ["wiki", "file_share", "admin_panel"]) {
      await reject(await zk.buildInputV4(worldArgs(world, "alice.employeeActive", policy), { precheck: false }));
    }
  });

  it("policy fields out of range (roleMask 16, minClearance 4, requireDevice 2) are rejected", async function () {
    await reject({ ...alice, roleMask: "16" });
    await reject({ ...alice, minClearance: "4" });
    await reject({ ...alice, requireDevice: "2" });
  });

  it("now >= 2^64 is rejected", async function () {
    await reject({ ...alice, now: (1n << 64n).toString() });
  });
});

// ---------------------------------------------------------------------------------------------
// 4. negatives, public slots
// ---------------------------------------------------------------------------------------------
for (const O of [1, 2]) {
  describe(`v4 negatives, public slots (--O${O}): every public signal changed after witness generation`, function () {
    let t;
    let w;
    before(async function () {
      t = await compileV4(O);
      w = await t.calculateWitness(vecInput.input, true);
      await t.checkConstraints(w);
    });

    PUBLIC.forEach((name, i) => {
      it(`--O${O}: public ${name} (slot ${i}) + 1 is rejected`, async function () {
        const bad = w.slice();
        bad[i + 1] = mod(bad[i + 1] + 1n);
        await expectReject(t.checkConstraints(bad), CONSTRAINT);
      });
    });

    it(`--O${O}: nullifier computed for resourceId 1 presented with resourceId 2, epoch + 1, or another nonce is rejected`, async function () {
      for (const [slot, value] of [
        [11, 2n],
        [12, BigInt(vec.epoch) + 1n],
        [10, BigInt(vec.nonces[1].value)],
      ]) {
        const bad = w.slice();
        bad[slot] = value;
        await expectReject(t.checkConstraints(bad), CONSTRAINT);
      }
    });

    it(`--O${O}: another user's nullifier (Bob's, same resource and epoch) is rejected`, async function () {
      const bad = w.slice();
      bad[1] = BigInt(persona("bob").nullifiers.wiki);
      await expectReject(t.checkConstraints(bad), CONSTRAINT);
    });

    it(`--O${O}: the pinned key in the public slots with a forger-key witness is rejected`, async function () {
      const forged = await t.calculateWitness(
        { ...vecInput.input, ...vec.forged.signature, issuerAx: vec.forged.publicKey.Ax, issuerAy: vec.forged.publicKey.Ay },
        true
      );
      forged[3] = BigInt(PINNED.Ax);
      forged[4] = BigInt(PINNED.Ay);
      await expectReject(t.checkConstraints(forged), CONSTRAINT);
    });
  });
}

// ---------------------------------------------------------------------------------------------
// 5. negatives, witness level: one violated row per gate wiring line
// ---------------------------------------------------------------------------------------------
describe("v4 negatives, witness level (--O0, exactly one violated row per gate wiring line)", function () {
  let t;
  let h; // harness builds
  let W; // alice -> wiki (world tree)
  let Wbob; // bob -> wiki, same challenge

  before(async function () {
    [t, h] = await Promise.all([compileV4(0), harnesses()]);
    W = new NamedWitness(t, await t.calculateWitness(await zk.buildInputV4(worldArgs(world, "alice", "wiki")), true));
    Wbob = new NamedWitness(t, await t.calculateWitness(await zk.buildInputV4(worldArgs(world, "bob", "wiki")), true));
  });

  async function expectOnly(nw, touches) {
    const v = await nw.violated();
    expect(v.length, `violated rows: ${JSON.stringify(v.map((r) => r.row))}`).to.equal(1);
    for (const name of [].concat(touches)) {
      expect(v[0].signals, `violated row should involve ${name}`).to.include(nw.idx(name));
    }
    await expectReject(t.checkConstraints(nw.w), CONSTRAINT);
  }

  /** Overwrite every `prefix` signal with an honest harness sub-witness computed from `input`. */
  async function splice(nw, tester, input, prefix) {
    const hw = new NamedWitness(tester, await tester.calculateWitness(input, true));
    const names = Object.keys(tester.symbols).filter((n) => n.startsWith("main."));
    expect(nw.namesUnder(prefix).length, `layout of ${prefix} vs harness`).to.equal(names.length);
    for (const n of names) nw.set(prefix + n.slice(5), hw.get(n));
    return nw;
  }

  /**
   * Replace the credential side (attr, signature, points, merkle and the private R8/S/path inputs)
   * with the honest sub-witnesses of world credential `name`. Leaves main.<attribute>,
   * main.credentialCommitment, policy and expiryCheck untouched.
   */
  async function spliceCredential(nw, name) {
    const c = world.creds[name];
    const p = zk.proofFor(world.tree, c.leafIndex);
    await splice(nw, h.attr, { ...c.attributes, credentialCommitment: c.commitment }, "main.attr.");
    await splice(nw, h.signature, { ...PINNED, ...c.signature, M: c.attrHash }, "main.signature.");
    await splice(nw, h.points, { ...PINNED, R8x: c.signature.R8x, R8y: c.signature.R8y }, "main.points.");
    await splice(nw, h.merkle, { leaf: c.attrHash, pathElements: p.pathElements, pathIndices: p.pathIndices, root: p.root }, "main.merkle.");
    for (const k of ["R8x", "R8y", "S"]) nw.set(`main.${k}`, c.signature[k]);
    for (let i = 0; i < 16; i++) {
      nw.set(`main.pathElements[${i}]`, p.pathElements[i]);
      nw.set(`main.pathIndices[${i}]`, p.pathIndices[i]);
    }
    nw.set("main.root", p.root);
    return nw;
  }

  /** Recompute main.commitmentHasher for (secret, salt) with an honest Poseidon(2) sub-witness. */
  const rehashCommitment = (nw, secret, salt) => splice(nw, h.poseidon2, { inputs: [secret, salt].map((x) => mod(x)) }, "main.commitmentHasher.");

  const otherSalt = () => mod(W.get("main.credentialSalt") + 1n);

  it("control: the valid witnesses violate no row; spliceCredential(alice) reproduces W exactly", async function () {
    expect(await W.violated()).to.deep.equal([]);
    expect(await Wbob.violated()).to.deep.equal([]);
    expect((await spliceCredential(W.clone(), "alice")).w).to.deep.equal(W.w);
    expect((await rehashCommitment(W.clone(), W.get("main.credentialSecret"), W.get("main.credentialSalt"))).w).to.deep.equal(W.w);
  });

  it("control: every signed variant splices into a witness that violates only rows involving that attribute", async function () {
    for (const f of ATTRS) {
      const nw = await spliceCredential(W.clone(), `alice.${f}`);
      const v = await nw.violated();
      expect(v.length, f).to.equal(1);
      expect(v[0].signals, f).to.include(nw.idx(`main.attr.${f}`));
    }
  });

  // W1-W3: the commitment.
  it("negatives gate: commitmentHasher.inputs[0] <== credentialSecret (Bob's secret in main and binding, hasher honest)", async function () {
    const nw = W.clone().set("main.credentialSecret", Wbob.get("main.credentialSecret")).copyFrom(Wbob, "main.binding.", "main.nullifier");
    await expectOnly(nw, ["main.credentialSecret", "main.commitmentHasher.inputs[0]"]);
  });

  it("negatives gate: commitmentHasher.inputs[1] <== credentialSalt (main.credentialSalt changed)", async function () {
    const nw = W.clone().set("main.credentialSalt", otherSalt());
    await expectOnly(nw, ["main.credentialSalt", "main.commitmentHasher.inputs[1]"]);
  });

  it("negatives gate: credentialCommitment <== commitmentHasher.out (hasher over another salt, commitment kept)", async function () {
    const nw = W.clone().set("main.credentialSalt", otherSalt());
    await rehashCommitment(nw, nw.get("main.credentialSecret"), otherSalt());
    await expectOnly(nw, ["main.credentialCommitment", "main.commitmentHasher.out"]);
  });

  it("negatives gate: attr.credentialCommitment <== credentialCommitment (new commitment, attr hashes the old one)", async function () {
    const nw = W.clone().set("main.credentialSalt", otherSalt());
    await rehashCommitment(nw, nw.get("main.credentialSecret"), otherSalt());
    nw.set("main.credentialCommitment", nw.get("main.commitmentHasher.out"));
    await expectOnly(nw, ["main.credentialCommitment", "main.attr.credentialCommitment"]);
  });

  // W4-W10 and W25-W29, W34: attributes. `attr.X` link: the credential side is the variant's,
  // main.X and its other consumer stay honest. `policy.X` / `expiryCheck.expiry` link: main.X is the
  // variant's value too, only that consumer keeps the honest value.
  for (const f of ATTRS) {
    it(`negatives gate: attr.${f} <== ${f} (credential side = issuer-signed variant, main.${f} honest)`, async function () {
      const nw = await spliceCredential(W.clone(), `alice.${f}`);
      await expectOnly(nw, [`main.${f}`, `main.attr.${f}`]);
    });
  }

  for (const f of ["role", "dept", "clearance", "deviceCompliant", "employeeActive"]) {
    it(`negatives gate: policy.${f} <== ${f} (signed variant ${f} in main, policy sees the honest value)`, async function () {
      const nw = await spliceCredential(W.clone(), `alice.${f}`);
      nw.set(`main.${f}`, nw.get(`main.attr.${f}`));
      await expectOnly(nw, [`main.${f}`, `main.policy.${f}`]);
    });
  }

  it("negatives gate: expiryCheck.expiry <== expiry (EXPIRED signed credential in main, expiry check sees the honest expiry)", async function () {
    const nw = await spliceCredential(W.clone(), "alice.expired");
    nw.set("main.expiry", nw.get("main.attr.expiry"));
    expect(nw.get("main.expiry") < NOW).to.equal(true);
    await expectOnly(nw, ["main.expiry", "main.expiryCheck.expiry"]);
  });

  // W11-W20: issuer key and R8. Negating x (or y) keeps a point on BabyJubJub and leaves BabyCheck's
  // x2 (y2) unchanged, so the on-curve copy can follow main while the verifier keeps the honest point.
  for (const [main, sigIn, pointsIn, check, coord] of [
    ["issuerAx", "Ax", "Ax", "keyOnCurve", "x"],
    ["issuerAy", "Ay", "Ay", "keyOnCurve", "y"],
    ["R8x", "R8x", "R8x", "r8OnCurve", "x"],
    ["R8y", "R8y", "R8y", "r8OnCurve", "y"],
  ]) {
    it(`negatives gate: signature.${sigIn} <== ${main} (main.${main} negated with its on-curve copy; verifier honest)`, async function () {
      const neg = mod(-W.get(`main.${main}`));
      const nw = W.clone().set(`main.${main}`, neg).set(`main.points.${pointsIn}`, neg).set(`main.points.${check}.${coord}`, neg);
      await expectOnly(nw, [`main.${main}`, `main.signature.${sigIn}`]);
    });

    it(`negatives gate: points.${pointsIn} <== ${main} (on-curve copy negated, main and verifier honest)`, async function () {
      const neg = mod(-W.get(`main.${main}`));
      const nw = W.clone().set(`main.points.${pointsIn}`, neg).set(`main.points.${check}.${coord}`, neg);
      await expectOnly(nw, [`main.${main}`, `main.points.${pointsIn}`]);
    });
  }

  it("negatives gate: signature.S <== S (main.S changed)", async function () {
    await expectOnly(W.clone().add("main.S"), ["main.S", "main.signature.S"]);
  });

  it("negatives gate: signature.M <== attr.attrHash (verifier checks Bob's signed attrHash, Alice's attr honest)", async function () {
    const b = world.creds.bob;
    const nw = W.clone();
    await splice(nw, h.signature, { ...PINNED, ...b.signature, M: b.attrHash }, "main.signature.");
    await splice(nw, h.points, { ...PINNED, R8x: b.signature.R8x, R8y: b.signature.R8y }, "main.points.");
    for (const k of ["R8x", "R8y", "S"]) nw.set(`main.${k}`, b.signature[k]);
    await expectOnly(nw, ["main.attr.attrHash", "main.signature.M"]);
  });

  // components/eddsa_verifier.circom (her IssuerSignatureCheck) inside v4, SR-18: one row per
  // `verifier.X <== X` link. The gate side (main / signature.X) moves together, the circomlib
  // verifier keeps the honest values, so only the link row between them is violated.
  it("negatives gate: IssuerSignatureCheck verifier.enabled <== 1 (enabled forced to 0)", async function () {
    const v = "main.signature.verifier.";
    const nw = W.clone().set(`${v}enabled`, 0n).set(`${v}eqCheckX.enabled`, 0n).set(`${v}eqCheckY.enabled`, 0n);
    await expectOnly(nw, `${v}enabled`);
  });

  for (const [main, sig, pointsIn, check, coord] of [
    ["issuerAx", "Ax", "Ax", "keyOnCurve", "x"],
    ["issuerAy", "Ay", "Ay", "keyOnCurve", "y"],
    ["R8x", "R8x", "R8x", "r8OnCurve", "x"],
    ["R8y", "R8y", "R8y", "r8OnCurve", "y"],
  ]) {
    it(`negatives gate: IssuerSignatureCheck verifier.${sig} <== ${sig} (main.${main}, on-curve copy and signature.${sig} negated; verifier honest)`, async function () {
      const neg = mod(-W.get(`main.${main}`));
      const nw = W.clone()
        .set(`main.${main}`, neg)
        .set(`main.points.${pointsIn}`, neg)
        .set(`main.points.${check}.${coord}`, neg)
        .set(`main.signature.${sig}`, neg);
      await expectOnly(nw, [`main.signature.${sig}`, `main.signature.verifier.${sig}`]);
    });
  }

  it("negatives gate: IssuerSignatureCheck verifier.S <== S (main.S and signature.S changed; verifier honest)", async function () {
    const nw = W.clone().add("main.S").add("main.signature.S");
    await expectOnly(nw, ["main.signature.S", "main.signature.verifier.S"]);
  });

  it("negatives gate: IssuerSignatureCheck verifier.M <== M (verifier checks Bob's signed attrHash, signature.M is Alice's)", async function () {
    const b = world.creds.bob;
    const nw = W.clone();
    await splice(nw, h.signature, { ...PINNED, ...b.signature, M: b.attrHash }, "main.signature.");
    await splice(nw, h.points, { ...PINNED, R8x: b.signature.R8x, R8y: b.signature.R8y }, "main.points.");
    for (const k of ["R8x", "R8y", "S"]) nw.set(`main.${k}`, b.signature[k]);
    nw.set("main.signature.M", W.get("main.signature.M"));
    await expectOnly(nw, ["main.signature.M", "main.signature.verifier.M"]);
  });

  // W21-W24: Merkle.
  it("negatives gate: merkle.leaf <== attr.attrHash (tree proves Bob's leaf with his path, Alice's attr honest)", async function () {
    const nw = W.clone().copyFrom(Wbob, "main.merkle.", "main.pathElements[", "main.pathIndices[");
    await expectOnly(nw, ["main.attr.attrHash", "main.merkle.leaf"]);
  });

  it("negatives gate: merkle.root <== root (public root changed)", async function () {
    await expectOnly(W.clone().add("main.root"), ["main.root", "main.merkle.root"]);
  });

  it("negatives gate: merkle.pathElements[i] <== pathElements[i] (main.pathElements[0] changed)", async function () {
    await expectOnly(W.clone().add("main.pathElements[0]"), ["main.pathElements[0]", "main.merkle.pathElements[0]"]);
  });

  it("negatives gate: merkle.pathIndices[i] <== pathIndices[i] (main.pathIndices[0] flipped)", async function () {
    const nw = W.clone().set("main.pathIndices[0]", 1n - W.get("main.pathIndices[0]"));
    await expectOnly(nw, ["main.pathIndices[0]", "main.merkle.pathIndices[0]"]);
  });

  // W30-W33, W35, W37-W39: public inputs with a single consumer.
  for (const [main, link] of [
    ["roleMask", "policy.roleMask"],
    ["deptMask", "policy.deptMask"],
    ["minClearance", "policy.minClearance"],
    ["requireDevice", "policy.requireDevice"],
    ["now", "expiryCheck.now"],
    ["nonce", "binding.nonce"],
    ["resourceId", "binding.resourceId"],
    ["epoch", "binding.epoch"],
  ]) {
    it(`negatives gate: ${link} <== ${main} (public ${main} changed)`, async function () {
      await expectOnly(W.clone().add(`main.${main}`), [`main.${main}`, `main.${link}`]);
    });
  }

  // W36, W40: the nullifier.
  it("negatives gate: binding.credentialSecret <== credentialSecret (binding and nullifier from Bob's witness)", async function () {
    const nw = W.clone().copyFrom(Wbob, "main.binding.", "main.nullifier");
    await expectOnly(nw, ["main.credentialSecret", "main.binding.credentialSecret"]);
  });

  it("negatives gate: nullifier <== binding.nullifier (output changed)", async function () {
    await expectOnly(W.clone().add("main.nullifier"), ["main.nullifier", "main.binding.nullifier"]);
  });
});
