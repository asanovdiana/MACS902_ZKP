#!/usr/bin/env node
"use strict";
// Demo personas (G2-S1-IDEN-022, reworked for issuer.api v2 in G1-S1-IDEN-014): Alice (engineer),
// Bob (contractor), Carol (admin). Each persona is enrolled the way a real employee is:
//   1. the ADMIN creates an enrolment through the admin API (bearer token) with the persona's
//      attributes and receives a one-time code;
//   2. the persona's own wallet (CLIENT library, one wallet home per persona) generates the secret
//      and salt locally and redeems the code with only its commitment (floor 6).
//   <home>/alice, <home>/bob, <home>/carol   (each is a ZKGATE_HOME holding credentials/<name>.json)
// Idempotent: an already issued persona is skipped; a stale unredeemed enrolment (a crashed earlier
// run) is cancelled and re-created. A persona whose credential was revoked is NOT re-enrolled
// automatically: revoke is the admin's decision, and so is a new enrolment.
//
//   node issuer/scripts/seed-personas.js --issuer http://127.0.0.1:8100 --home ./demo-wallets
//        [--expiry <unix s>] [--only alice,bob] [--v3-provable]
//
// Environment: ISSUER_URL (default http://127.0.0.1:8100), ISSUER_ADMIN_TOKEN (required: the admin
// bearer token; never printed), ZKGATE_HOME (wallet root), ZKGATE_SEED_EXPIRY (v4 expiry, default
// 4070908800 = 2099-01-01).
const path = require("path");
const zk = require("../../circuits/lib");
const { Wallet, IssuerClient, requestCredential, ClientError } = require("../../client/src");

const DEFAULT_EXPIRY = 4070908800;
const DEFAULT_ISSUER = "http://127.0.0.1:8100";

// D6 (ADR 0008): role / dept enums from circuits/lib; clearance 0..3.
const PERSONAS = {
  alice: { role: "engineer", dept: "engineering", clearance: 2 },
  bob: { role: "contractor", dept: "operations", clearance: 1 },
  carol: { role: "admin", dept: "it", clearance: 3 },
};

/**
 * v3 has no dept or expiry and its File Share template accepts only role in {2,3} and clearance in
 * {2,3} (opaque numbers, ADR 0008). Seeding by the D6 numbers therefore yields credentials that
 * are valid but cannot prove v3: Alice (role 0) fails the role check, Bob (clearance 1) and Carol
 * (role 1) fail it too, by design. `v3Provable` re-seeds Alice as role 2 / clearance 2 so the G0
 * end-to-end path has one credential that proves.
 */
function attributesFor(profile, name, { expiry = DEFAULT_EXPIRY, v3Provable = false } = {}) {
  const p = PERSONAS[name];
  const role = zk.ROLES[p.role];
  if (profile === "v3") {
    if (v3Provable && name === "alice") return { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 };
    return { role, clearance: p.clearance, deviceCompliant: 1, employeeActive: 1 };
  }
  return { role, dept: zk.DEPTS[p.dept], clearance: p.clearance, deviceCompliant: 1, employeeActive: 1, expiry };
}

/** Admin call against the issuer; throws an Error naming the status and error code only. */
async function adminCall(base, token, method, url, body, fetchFn = globalThis.fetch) {
  const res = await fetchFn(base.replace(/\/+$/, "") + url, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json, code: json && json.error && json.error.code };
}

/**
 * Admin step: create an enrolment for `employeeId` and return its one-time code. A pending enrolment
 * left by an earlier run is cancelled and replaced.
 */
async function createEnrolment({ issuerUrl, adminToken, employeeId, attributes, fetch: fetchFn }) {
  const make = () => adminCall(issuerUrl, adminToken, "POST", "/admin/enrolments", { employeeId, attributes }, fetchFn);
  let r = await make();
  if (r.status === 409 && r.code === "enrolment_pending") {
    const list = await adminCall(issuerUrl, adminToken, "GET", "/admin/enrolments?limit=5000", undefined, fetchFn);
    for (const e of (list.json && list.json.enrolments) || []) {
      if (e.employeeId.toLowerCase() === employeeId.toLowerCase() && e.status === "pending") {
        await adminCall(issuerUrl, adminToken, "DELETE", `/admin/enrolments/${e.enrolmentId}`, undefined, fetchFn);
      }
    }
    r = await make();
  }
  if (r.status !== 201) throw new Error(`the issuer refused the enrolment for "${employeeId}" (HTTP ${r.status} ${r.code || "no code"})`);
  return r.json.code;
}

async function seedPersonas({ issuerUrl = DEFAULT_ISSUER, adminToken, homeRoot, expiry = DEFAULT_EXPIRY, only, v3Provable = false, fetch: fetchFn }) {
  if (!homeRoot) throw new Error("seedPersonas: homeRoot is required");
  if (!adminToken) throw new Error("seedPersonas: the admin token is required (ISSUER_ADMIN_TOKEN or --admin-token)");
  const names = only || Object.keys(PERSONAS);
  for (const n of names) if (!PERSONAS[n]) throw new Error(`unknown persona "${n}" (expected ${Object.keys(PERSONAS).join(", ")})`);
  const issuer = new IssuerClient({ baseUrl: issuerUrl });
  const info = await issuer.getIssuer();
  const results = [];
  for (const name of names) {
    const wallet = new Wallet({ home: path.join(homeRoot, name) });
    let existing = null;
    try {
      existing = wallet.summary(name);
    } catch (e) {
      if (!(e instanceof ClientError) || e.code !== "WALLET_NOT_FOUND") throw e;
    }
    if (existing && existing.status === "issued") {
      results.push({ ...existing, name, skipped: true });
      continue;
    }
    if (!existing) await wallet.keygen({ name, profile: info.profile, issuerUrl });
    const enrolmentCode = await createEnrolment({
      issuerUrl, adminToken, employeeId: name, attributes: attributesFor(info.profile, name, { expiry, v3Provable }), fetch: fetchFn,
    });
    const summary = await requestCredential({ wallet, name, issuer, enrolmentCode });
    results.push({ ...summary, name, skipped: false });
  }
  return results;
}

function parseArgs(argv, env = process.env) {
  const out = {};
  if (env.ISSUER_URL) out.issuerUrl = env.ISSUER_URL;
  if (env.ISSUER_ADMIN_TOKEN) out.adminToken = env.ISSUER_ADMIN_TOKEN;
  if (env.ZKGATE_HOME) out.homeRoot = env.ZKGATE_HOME;
  if (env.ZKGATE_SEED_EXPIRY) out.expiry = Number(env.ZKGATE_SEED_EXPIRY);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === "--issuer") out.issuerUrl = val();
    else if (a === "--admin-token") out.adminToken = val();
    else if (a === "--home") out.homeRoot = val();
    else if (a === "--expiry") out.expiry = Number(val());
    else if (a === "--only") out.only = val().split(",").filter(Boolean);
    else if (a === "--v3-provable") out.v3Provable = true;
    else throw new Error(`unknown option ${a}`);
  }
  return out;
}

module.exports = { seedPersonas, createEnrolment, attributesFor, parseArgs, PERSONAS, DEFAULT_EXPIRY };

/* c8 ignore start */
if (require.main === module) {
  (async () => {
    const opts = parseArgs(process.argv.slice(2));
    if (!opts.homeRoot) throw new Error("--home (or ZKGATE_HOME) is required");
    const res = await seedPersonas(opts);
    // Identifiers and hashes only: never secrets, salts or attributes.
    for (const r of res) console.log(JSON.stringify({ name: r.name, profile: r.profile, leafIndex: r.leafIndex, commitment: r.commitment, skipped: r.skipped, home: path.join(opts.homeRoot, r.name) }));
  })().catch((e) => {
    console.error(`seed-personas: ${e.message}`);
    process.exit(1);
  });
}
/* c8 ignore stop */
