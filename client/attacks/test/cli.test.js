"use strict";
// CLI: `attacks list`, offline `run` (prints the requests and expectations, sends nothing), and
// `run --gateway URL --issuer URL` against the test's model gateway (actual vs expected).
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const os = require("os");
const fs = require("fs");
const { spawn } = require("child_process");
const zk = require("../../../circuits/lib");
const verifier = require("../../../circuits/scripts/verify.js");
const { buildServer } = require("../../../issuer/src/server");
const { ModelGateway, serve } = require("./helpers/modelGateway");

const BIN = path.join(__dirname, "..", "bin", "attacks.js");
const VKEY = verifier.loadVerificationKey(path.join(__dirname, "..", "..", "..", "circuits", "setup", "integrated_access_v4.verification_key.json"));

function cli(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, ...env } });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

test("list prints id, title, obligations", async () => {
  const r = await cli(["list"]);
  assert.equal(r.code, 0);
  const rows = JSON.parse(r.out);
  assert.ok(rows.find((x) => x.id === "replay" && x.obligations.includes(6)));
  assert.equal(rows.length, 9);
});

test("usage errors exit 2", async () => {
  assert.equal((await cli([])).code, 2);
  assert.equal((await cli(["run", "nope"])).code, 2);
  assert.equal((await cli(["run", "replay", "--bogus"])).code, 2);
});

test("offline run prints the requests with expectations and sends nothing", async () => {
  const r = await cli(["run", "forged"]);
  assert.equal(r.code, 0, r.err);
  const out = JSON.parse(r.out);
  assert.equal(out.attacks.length, 1);
  assert.equal(out.attacks[0].requests[0].expect.code, "ISSUER_NOT_PINNED");
  assert.equal(out.attacks[0].requests[0].body.publicSignals.length, 12);
  assert.equal(out.sent, false);
});

const TOKEN = "attack-cli-admin-token-0123456789";

test("--gateway sends the requests and reports actual vs expected (exit 0 when all match, 1 otherwise)", async () => {
  const os_ = fs.mkdtempSync(path.join(os.tmpdir(), "attacks-cli-"));
  const app = await buildServer({
    config: { profile: "v4", keyDir: path.join(os_, "k"), dataDir: path.join(os_, "d"), host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, adminToken: TOKEN },
    logStream: { write() {} },
  });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const issuerUrl = `http://127.0.0.1:${app.server.address().port}`;
  const iss = (await (await fetch(`${issuerUrl}/issuer`)).json()).issuer;
  const gw = new ModelGateway({
    vkey: VKEY, pinned: iss, clock: () => Math.floor(Date.now() / 1000),
    root: async () => (await (await fetch(`${issuerUrl}/root`)).json()).root,
  });
  const srv = await serve(gw);
  try {
    // without the admin token the world cannot enrol anybody: the issuer needs the admin's approval (SR-03)
    const noTok = await cli(["run", "baseline", "--gateway", srv.url, "--issuer", issuerUrl], { ISSUER_ADMIN_TOKEN: "" });
    assert.notEqual(noTok.code, 0);
    assert.doesNotMatch(noTok.out + noTok.err, new RegExp(TOKEN));
    const ok = await cli(["run", "replay", "forged", "--gateway", srv.url, "--issuer", issuerUrl, "--admin-token", TOKEN]);
    assert.equal(ok.code, 0, ok.err);
    const out = JSON.parse(ok.out);
    assert.equal(out.sent, true);
    assert.equal(out.pass, true);
    const steps = out.attacks.flatMap((a) => a.run.steps);
    assert.deepEqual(steps.map((s) => s.actual.code || "admit"), ["admit", "NONCE_USED", "ISSUER_NOT_PINNED"]);
    assert.ok(steps.every((s) => s.pass));

    // a gateway pinned to a different issuer key makes the honest baseline fail: exit 1, mismatch shown
    const gw2 = new ModelGateway({ vkey: VKEY, pinned: { Ax: "1", Ay: "2" }, clock: () => Math.floor(Date.now() / 1000), root: gw.root });
    const srv2 = await serve(gw2);
    try {
      const bad = await cli(["run", "baseline", "--gateway", srv2.url, "--issuer", issuerUrl], { ISSUER_ADMIN_TOKEN: TOKEN });
      assert.equal(bad.code, 1);
      const o = JSON.parse(bad.out);
      assert.equal(o.pass, false);
      assert.equal(o.attacks[0].run.steps[0].actual.code, "ISSUER_NOT_PINNED");
    } finally { await srv2.close(); }
  } finally {
    await srv.close();
    await app.close();
    await verifier.terminate();
    fs.rmSync(os_, { recursive: true, force: true });
  }
});
