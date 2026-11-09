"use strict";
// zkgate CLI. Output carries identifiers and hashes only: never the secret, salt, signature,
// Merkle path or circuit input. Policy refusals list reasons that contain the user's own attribute
// values; they go to the local terminal (stderr) only.
const fs = require("fs");
const path = require("path");
const zk = require("../../circuits/lib");
const { ClientError } = require("./errors");
const { Wallet, fingerprint } = require("./wallet");
const { IssuerClient } = require("./issuerClient");
const { requestCredential } = require("./enrol");
const { prove, shutdown } = require("./prover");
const { fetchChallenge, submitProof } = require("./challenge");

const USAGE = `zkgate - ZK Access Gate client

usage:
  zkgate keygen  [--name N] [--profile v3|v4] [--issuer URL]
  zkgate request [--name N] --issuer URL [--issuer-key Ax:Ay] --code CODE
                 (CODE is the one-time enrolment code from your administrator; the administrator
                  assigns your attributes, you cannot choose them. ZKGATE_ENROLMENT_CODE also works.
                  --issuer-key pins the issuer's public key out of band: use it on first contact.)
  zkgate status  [--name N]                           (shows your admin-assigned attributes)
  zkgate prove   [--name N] [--issuer URL] [--out DIR]
                 [--challenge FILE | --gateway URL --resource wiki|file_share|admin_panel] [--submit]

environment: ZKGATE_HOME (wallet directory, default ~/.zkgate), ZKGATE_ISSUER (default --issuer),
             ZKGATE_ENROLMENT_CODE (default --code),
             ZKGATE_ARTEFACTS (proving artefact directory, default circuits/setup)
`;

class UsageError extends Error {}

const BOOLEAN_FLAGS = new Set(["submit", "help"]);

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h") { flags.help = true; continue; }
    if (!a.startsWith("--")) { positional.push(a); continue; }
    const key = a.slice(2);
    if (BOOLEAN_FLAGS.has(key)) { flags[key] = true; continue; }
    const v = argv[++i];
    if (v === undefined || v.startsWith("--")) throw new UsageError(`--${key} needs a value`);
    flags[key] = v;
  }
  return { positional, flags };
}

const need = (flags, key, hint) => {
  if (flags[key] === undefined) throw new UsageError(`missing --${key}${hint ? ` (${hint})` : ""}`);
  return flags[key];
};

/** Human reading of the user's own attributes (local terminal only). */
function formatAttributes(profile, a) {
  const label = (map, v) => Object.keys(map).find((k) => map[k] === v) || String(v);
  return zk.profiles[profile].attributes.map((k) => {
    if (profile === "v4" && k === "role") return `role=${label(zk.ROLES, a[k])}`;
    if (profile === "v4" && k === "dept") return `dept=${label(zk.DEPTS, a[k])}`;
    if (k === "expiry") return `expiry=${a[k]} (${new Date(a[k] * 1000).toISOString()})`;
    return `${k}=${a[k]}`;
  }).join(", ");
}

function parseIssuerKey(s) {
  const m = /^(\d+):(\d+)$/.exec(s || "");
  if (!m) throw new UsageError("--issuer-key must look like Ax:Ay (decimal)");
  return { Ax: m[1], Ay: m[2] };
}

async function run(argv, io) {
  const { positional, flags } = parseArgs(argv);
  const [cmd] = positional;
  const out = (s) => io.stdout.write(s + "\n");
  if (flags.help || cmd === "help") { out(USAGE); return 0; }
  if (!cmd) { io.stderr.write(USAGE); return 2; }
  const wallet = new Wallet({ home: flags.home || io.env.ZKGATE_HOME });
  const name = flags.name || "default";
  const issuerUrl = flags.issuer || io.env.ZKGATE_ISSUER;
  const issuerFor = (url) => {
    if (!url) throw new UsageError("missing --issuer (or ZKGATE_ISSUER)");
    return new IssuerClient({ baseUrl: url, fetch: io.fetch });
  };

  switch (cmd) {
    case "keygen": {
      let profile = flags.profile;
      if (!profile && issuerUrl) profile = (await issuerFor(issuerUrl).getIssuer()).profile;
      const r = await wallet.keygen({ name, profile: profile || "v3", issuerUrl });
      out(`created credential "${r.name}" (profile ${r.profile}, pending)`);
      out(`commitment ${r.commitment}`);
      return 0;
    }
    case "request": {
      const cred = wallet.load(name);
      const url = issuerUrl || cred.issuerUrl;
      const issuer = issuerFor(url);
      for (const f of ["role", "dept", "clearance", "device", "active", "expiry"]) {
        if (flags[f] !== undefined) throw new UsageError(`--${f}: attributes are assigned by your administrator; use --code`);
      }
      const enrolmentCode = flags.code || io.env.ZKGATE_ENROLMENT_CODE;
      if (!enrolmentCode) throw new UsageError("missing --code (the one-time enrolment code from your administrator)");
      const expectedIssuer = flags["issuer-key"] ? parseIssuerKey(flags["issuer-key"]) : undefined;
      const s = await requestCredential({ wallet, name, issuer, enrolmentCode, expectedIssuer });
      out(`issued "${s.name}" (profile ${s.profile}) at leaf ${s.leafIndex}`);
      out(`issuer key ${s.issuerFingerprint}`);
      return 0;
    }
    case "status": {
      const names = flags.name ? [flags.name] : wallet.list().map((c) => c.name);
      if (!names.length) { out("no credentials in the wallet"); return 0; }
      for (const n of names) {
        const s = wallet.summary(n, { withAttributes: true });
        out(`${s.name}: ${s.status}, profile ${s.profile}, commitment ${s.commitment}` +
          (s.status === "issued" ? `, leaf ${s.leafIndex}, issuer key ${s.issuerFingerprint}` : ""));
        if (s.attributes) out(`  attributes (assigned by your administrator): ${formatAttributes(s.profile, s.attributes)}`);
      }
      return 0;
    }
    case "prove": {
      const credential = wallet.load(name);
      const issuer = issuerFor(issuerUrl || credential.issuerUrl);
      let challenge;
      if (flags.challenge) {
        try {
          challenge = JSON.parse(fs.readFileSync(flags.challenge, "utf8"));
        } catch (_) {
          throw new ClientError("INVALID_CHALLENGE", "cannot read the challenge file as JSON");
        }
      } else if (flags.gateway) {
        challenge = await fetchChallenge({ gatewayUrl: flags.gateway, resource: need(flags, "resource"), fetch: io.fetch });
      }
      const r = await prove({ credential, issuer, challenge });
      const result = { proof: r.proof, publicSignals: r.publicSignals };
      if (flags.out) {
        fs.mkdirSync(flags.out, { recursive: true });
        fs.writeFileSync(path.join(flags.out, "proof.json"), JSON.stringify(result.proof, null, 2) + "\n");
        fs.writeFileSync(path.join(flags.out, "public.json"), JSON.stringify(result.publicSignals, null, 2) + "\n");
        out(`wrote ${path.join(flags.out, "proof.json")} and ${path.join(flags.out, "public.json")}`);
      } else if (!flags.submit) {
        out(JSON.stringify(result));
      }
      if (flags.submit) {
        if (!flags.gateway || !challenge) throw new UsageError("--submit needs --gateway and --resource");
        const reply = await submitProof({ gatewayUrl: flags.gateway, resource: flags.resource, nonce: challenge.nonce, ...result, fetch: io.fetch });
        out(`gateway: ${JSON.stringify(reply)}`);
      }
      return 0;
    }
    default:
      throw new UsageError(`unknown command "${cmd}"`);
  }
}

/** Testable entry: returns the exit code. */
async function execute(argv, io) {
  try {
    return await run(argv, io);
  } catch (e) {
    if (e instanceof UsageError) {
      io.stderr.write(`zkgate: ${e.message}\n\n${USAGE}`);
      return 2;
    }
    if (e && e.name === "AccessInputError") e = new ClientError(e.code, e.message, { reasons: e.reasons });
    if (e instanceof ClientError) {
      io.stderr.write(`zkgate: ${e.message}\n`);
      for (const r of e.reasons || []) io.stderr.write(`  - ${r.code}: ${r.message}\n`);
      return 1;
    }
    io.stderr.write("zkgate: unexpected internal error\n");
    return 1;
  } finally {
    await shutdown();
  }
}

async function main(argv) {
  const code = await execute(argv, { stdout: process.stdout, stderr: process.stderr, env: process.env, fetch: globalThis.fetch });
  process.exit(code);
}

module.exports = { main, execute, parseArgs };
