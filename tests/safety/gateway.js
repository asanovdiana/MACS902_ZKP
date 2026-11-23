"use strict";
// Gateway harness for the gateway half of floors 3, 4, 5 and 7 (F3.09, F4.06, F5.07, F7.05).
//
// Runs the REAL components end to end, nothing mocked:
//   - the P3 gateway (p3/gateway, compiled to p3/gateway/dist by `npm run build --prefix p3`) with
//     the real snarkjs verifier, the committed v4 verification key and the real Wiki service,
//   - the real issuer (issuer/src, in-process via helpers.makeIssuer, listening on a socket so the
//     gateway reaches it over HTTP exactly as in production),
//   - the real client library (client/src) enrolling through the admin and proving with the
//     committed v4 wasm/zkey.
// One mutable clock drives BOTH the issuer and the gateway, so TTLs, epochs and the root staleness
// window are exercised deterministically (no sleeps). The gateway's own semantics are unchanged.
const fs = require("fs");
const http = require("http");
const path = require("path");
const { pathToFileURL } = require("url");
const h = require("./helpers");

const P3 = h.r("p3");
const DIST = {
  app: path.join(P3, "gateway", "dist", "app", "createApp.js"),
  env: path.join(P3, "gateway", "dist", "config", "env.js"),
  wiki: path.join(P3, "services", "dist", "wiki.js"),
};
const OPERATOR_TOKEN = "safety-gateway-operator-token-4c1d";
const ZK_ASSERTION = "safety-gateway-assertion-secret-0123456789ab";
const SSO_ASSERTION = "safety-sso-assertion-secret-0123456789abcd";

/** Fail loudly (never skip) when the gateway has not been built. */
function requireBuiltGateway() {
  const missing = Object.values(DIST).filter((f) => !fs.existsSync(f));
  if (missing.length) {
    throw new Error(
      `P3 gateway not built (${missing.map((f) => path.relative(h.REPO, f)).join(", ")} missing). ` +
        "Run `npm ci --prefix p3 && npm run build --prefix p3` (or `make test`, which does it).",
    );
  }
}

const listen = (server) =>
  new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`)));

/**
 * Start issuer + gateway + wiki on one shared clock.
 * Returns {iss, clock, gatewayUrl, ctx, sink, enrol(name, attrs, employeeId), prove(name, resource),
 *          access(resource, proofResult), challenge(resource), operatorCookie(), close()}.
 */
async function startGateway({ t0 = 1_800_000_000, gatewayEnv = {} } = {}) {
  requireBuiltGateway();
  const client = require(h.r("client", "src"));
  const pino = require(path.join(P3, "node_modules", "pino"));
  const { createApp } = await import(pathToFileURL(DIST.app).href);
  const { loadConfig } = await import(pathToFileURL(DIST.env).href);
  const { createWiki } = await import(pathToFileURL(DIST.wiki).href);

  const iss = await h.makeIssuer({ t0, overrides: { logLevel: "silent" } });
  const issuerUrl = await iss.app.listen({ host: "127.0.0.1", port: 0 });
  const clock = iss.clock; // unix seconds, shared
  const key = JSON.parse((await iss.app.inject({ method: "GET", url: "/issuer" })).body).issuer;

  const wikiServer = http.createServer(createWiki({ zk: ZK_ASSERTION, sso: SSO_ASSERTION }));
  const wikiUrl = await listen(wikiServer);

  const sink = h.logSink();
  const logger = pino({ level: "trace" }, sink.stream);
  const config = loadConfig({
    NODE_ENV: "test",
    LOG_LEVEL: "trace",
    ZK_PROFILE: "integrated-access-v4",
    REGISTRY_URL: issuerUrl,
    REGISTRY_ADMIN_TOKEN: iss.token,
    TRUSTED_ISSUER_AX: key.Ax,
    TRUSTED_ISSUER_AY: key.Ay,
    ALLOW_DEMO_KEYS: "true",
    OPERATOR_TOKEN,
    ASSERTION_SECRET_ZK: ZK_ASSERTION,
    UPSTREAM_WIKI_URL: wikiUrl,
    ZK_RATE_LIMIT_PER_MIN: "100000",
    ...gatewayEnv,
  });
  const { app, ctx } = createApp({ config, logger, clock: { now: () => clock.t * 1000 } });
  const gwServer = http.createServer(app);
  const gatewayUrl = await listen(gwServer);

  const wallet = new client.Wallet({ home: h.tmpDir("gw-wallet") });
  const issuerClient = new client.IssuerClient({ baseUrl: "http://issuer.test", fetch: h.recordingFetch(iss.app) });

  const json = async (res) => ({ status: res.status, headers: res.headers, body: await res.json().catch(() => null) });
  const challenge = async (resource) => json(await fetch(`${gatewayUrl}/challenge?resource=${resource}`));

  const stack = {
    iss, clock, gatewayUrl, ctx, sink, client, wallet, issuerClient,
    /** Admin enrols `name` with `attrs` (D6 labels allowed); the wallet redeems the code. */
    async enrol(name, attrs, employeeId) {
      await wallet.keygen({ name, profile: "v4", issuerUrl: "http://issuer.test" });
      return h.enrolViaAdmin({ iss, wallet, name, issuer: issuerClient, attributes: attrs, employeeId });
    },
    challenge,
    /** Fetch a gateway challenge for `resource` and prove it with `name`'s credential. */
    async prove(name, resource) {
      const c = await challenge(resource);
      if (c.status !== 200) throw new Error(`challenge refused: ${c.status}`);
      const out = await client.prove({ credential: wallet.load(name), issuer: issuerClient, challenge: c.body });
      return { challenge: c.body, proof: out.proof, publicSignals: out.publicSignals };
    },
    /** POST /access exactly as the client library does. */
    async access(resource, p) {
      return json(
        await fetch(`${gatewayUrl}/access`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ resource, nonce: p.publicSignals[9], proof: p.proof, publicSignals: p.publicSignals }),
        }),
      );
    },
    async revoke(name) {
      const leafIndex = wallet.load(name).leafIndex;
      const res = await iss.admin("POST", `/credentials/${leafIndex}/revoke`, {});
      if (res.statusCode !== 200) throw new Error(`revoke failed: ${res.statusCode} ${res.body}`);
      return JSON.parse(res.body).root;
    },
    async operatorCookie() {
      const r = await fetch(`${gatewayUrl}/api/operator/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: OPERATOR_TOKEN }),
      });
      return r.headers.get("set-cookie").split(";")[0];
    },
    async close() {
      // drop idle keep-alive sockets (fetch) so the test process can exit
      for (const s of [gwServer, wikiServer]) {
        s.closeAllConnections();
        s.close();
      }
      await iss.app.close();
      // release the bn128 worker threads the gateway's verifier started (ffjavascript resets its
      // global cache on terminate, so a later test simply rebuilds the curve)
      if (globalThis.curve_bn128 && typeof globalThis.curve_bn128.terminate === "function") {
        await globalThis.curve_bn128.terminate();
      }
    },
  };
  return stack;
}

/** Proof with one coordinate changed: structurally valid, cryptographically invalid. */
const tamper = (p) => {
  const proof = JSON.parse(JSON.stringify(p.proof));
  proof.pi_a[0] = (BigInt(proof.pi_a[0]) + 1n).toString();
  return { ...p, proof };
};

/** Seconds until the next epoch starts (epoch = floor(t / 600)). */
const toNextEpoch = (t) => 600 - (t % 600);

module.exports = { startGateway, requireBuiltGateway, tamper, toNextEpoch, OPERATOR_TOKEN };
