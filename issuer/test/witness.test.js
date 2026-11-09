"use strict";
// Registry <-> circuit floor-8 check: a v3 credential issued through the API, with the path the
// API serves, satisfies the committed v3 circuit (wasm witness calculator). Negative: after
// revocation the old path does not reach the new root and the circuit rejects it.
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const { zk, makeApp, json, post, issue } = require("./helpers");

const WASM = path.join(__dirname, "..", "..", "circuits", "setup", "integrated_access_v3.wasm");

async function witnessOk(input) {
  const out = { type: "mem" };
  await snarkjs.wtns.calculate(input, WASM, out);
  return true;
}

describe("v3 end-to-end: issuer API -> lib input -> circuit witness (floor 8)", function () {
  this.timeout(180000);
  let ctx;
  before(function () {
    if (!fs.existsSync(WASM)) this.skip();
  });
  beforeEach(async () => { ctx = await makeApp({ profile: "v3" }); });
  afterEach(() => ctx.app.close());

  async function buildFor(secrets, cred, root) {
    const merkleProof = json(await ctx.app.inject(`/path/${cred.leafIndex}`));
    const input = await zk.buildInputV3({
      credentialSecret: secrets.credentialSecret,
      credentialSalt: secrets.credentialSalt,
      commitment: secrets.commitment,
      attributes: cred.attributes,
      signature: cred.signature,
      issuer: cred.issuer,
      merkleProof,
    });
    assert.strictEqual(input.root, merkleProof.root);
    return { input, merkleProof };
  }

  it("a credential issued via the API for a client-made commitment satisfies the circuit", async () => {
    await issue(ctx.app, "v3"); // fill leaf 0 so the proven leaf is not index 0
    const { secrets, cred } = await issue(ctx.app, "v3");
    const { input } = await buildFor(secrets, cred);
    assert.strictEqual(await witnessOk(input), true);
  });

  it("every issued leaf of a populated tree has a path the circuit accepts", async () => {
    const all = [];
    for (let i = 0; i < 4; i++) all.push(await issue(ctx.app, "v3"));
    for (const { secrets, cred } of all) {
      const { input } = await buildFor(secrets, cred);
      assert.strictEqual(await witnessOk(input), true);
    }
  });

  it("after revoke: the old path fails against the new root in the lib and in the circuit (floor 3)", async () => {
    await issue(ctx.app, "v3");
    const { secrets, cred } = await issue(ctx.app, "v3");
    const { input: before, merkleProof: oldPath } = await buildFor(secrets, cred);
    await post(ctx.app, `/credentials/${cred.leafIndex}/revoke`, "");
    const newRoot = json(await ctx.app.inject("/root")).root;
    assert.notStrictEqual(newRoot, oldPath.root);
    // the lib refuses to build it
    await assert.rejects(
      zk.buildInputV3({ ...secrets, attributes: cred.attributes, signature: cred.signature, issuer: cred.issuer, merkleProof: { ...oldPath, root: newRoot } }),
      (e) => e.code === "ROOT_MISMATCH"
    );
    // and the circuit rejects the same witness forced against the current root
    await assert.rejects(witnessOk({ ...before, root: newRoot }));
    // the other holder is unaffected
    assert.strictEqual(json(await ctx.app.inject("/path/0")).root, newRoot);
  });

  it("a signature from a different key does not satisfy the circuit's signature check at the issuer pin", async () => {
    // issuer key A signs; swapping in another key's public point must fail in the witness
    const { secrets, cred } = await issue(ctx.app, "v3");
    const { input } = await buildFor(secrets, cred);
    const other = await zk.publicKey(Buffer.alloc(32, 7));
    await assert.rejects(witnessOk({ ...input, Ax: other.Ax, Ay: other.Ay }));
  });
});
