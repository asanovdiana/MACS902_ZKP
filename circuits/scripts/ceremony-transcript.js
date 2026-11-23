#!/usr/bin/env node
// Transcript bookkeeping for circuits/scripts/ceremony.sh (multi-party Groth16 phase 2).
// Not meant to be run by hand. Subcommands (all flags are `--key value`):
//
//   init            write a new transcript (circuit, r1cs, ptau, initial zkey, snarkjs circuit hash)
//   hash-from-log   print the last "Contribution Hash" in a snarkjs contribute/beacon log (128 hex)
//   check           match a `snarkjs zkey verify` log against the transcript chain (exit 1 on mismatch)
//   append          add a contribution entry
//   set-beacon      record the beacon and the final zkey
//   field           print one transcript value (dotted path)
//   same-json       exit 0 iff two JSON files hold the same value
//   summary         print a `check` result for humans
//   ptau-info       print the transcript's ptau object in the .info.json shape setup-manifest.js reads
//   manifest-patch  turn a setup-manifest.js manifest into the multi-party one (stdout)
//
// Transcript format (`zk-access-gate.ceremony-transcript v1`): circuits/ceremony/README.md.
// The transcript never holds entropy: only public hashes, names, dates and file digests.
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { SINGLE_PARTY_LIMITATION } = require("./setup-manifest.js");

const FORMAT = "zk-access-gate.ceremony-transcript v1";
const PARTICIPANT = /^[A-Za-z0-9][A-Za-z0-9 ._@'-]{0,63}$/;
const PUBLIC_PHASE1 = new Set(["pse-ppot-0080", "hermez"]);

const die = (msg) => {
  process.stderr.write(`[ceremony-transcript] ${msg}\n`);
  process.exit(1);
};
const sha256 = (f) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const writeJson = (f, o) => {
  const tmp = `${f}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(o, null, 2) + "\n");
  fs.renameSync(tmp, f);
};
const now = () => new Date().toISOString();

// snarkjs logs colour codes; hashes are printed as 4 lines of 4 space-separated 8-hex words.
const clean = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
function hashAfter(lines, i) {
  const words = [];
  for (let j = i + 1; j < lines.length && words.length < 16; j++) {
    const w = lines[j].trim().split(/\s+/);
    if (!w.every((x) => /^[0-9a-f]{8}$/.test(x))) break;
    words.push(...w);
  }
  return words.length === 16 ? words.join("") : null;
}

/** Parse a `snarkjs zkey verify` log: ok flag, circuit hash, contributions sorted by number. */
function parseVerifyLog(text) {
  const lines = clean(text).split("\n");
  let circuitHash = null;
  const contributions = [];
  lines.forEach((l, i) => {
    if (circuitHash === null && /Circuit hash:\s*$/i.test(l)) circuitHash = hashAfter(lines, i);
    const m = /contribution #(\d+) (.*):\s*$/.exec(l);
    if (m) contributions.push({ n: Number(m[1]), name: m[2], hash: hashAfter(lines, i) });
  });
  contributions.sort((a, b) => a.n - b.n);
  return { ok: lines.some((l) => /ZKey Ok!/.test(l)), circuitHash, contributions };
}

/** The chain the transcript claims: initial zkey, contributions, then the beacon if any. */
function chainOf(t) {
  const problems = [];
  if (t.format !== FORMAT) problems.push(`unknown transcript format ${JSON.stringify(t.format)}`);
  const entries = (t.contributions || []).map((c) => ({ ...c, kind: "contribution", name: c.participant }));
  if (t.beacon) entries.push({ ...t.beacon, kind: "beacon", order: entries.length + 1, name: t.beacon.name });
  let prev = t.initial && t.initial.zkey_sha256;
  const seenZkeys = new Set([prev]);
  const seenHashes = new Set();
  entries.forEach((e, i) => {
    if (e.order !== i + 1) problems.push(`entry ${i + 1} has order ${e.order}`);
    if (e.prev_zkey_sha256 !== prev) problems.push(`entry ${i + 1} (${e.name}) does not extend the previous zkey`);
    if (!/^[0-9a-f]{128}$/.test(e.contribution_hash || "")) problems.push(`entry ${i + 1} has no contribution hash`);
    if (seenZkeys.has(e.zkey_sha256)) problems.push(`entry ${i + 1} (${e.name}) repeats an earlier zkey`);
    if (seenHashes.has(e.contribution_hash)) problems.push(`entry ${i + 1} (${e.name}) repeats an earlier contribution hash`);
    seenZkeys.add(e.zkey_sha256);
    seenHashes.add(e.contribution_hash);
    prev = e.zkey_sha256;
  });
  return { entries, problems };
}

function check(args, need) {
  const t = readJson(need("transcript"));
  const zkeySha = sha256(need("zkey"));
  const log = parseVerifyLog(fs.readFileSync(need("verify-log"), "utf8"));
  const { entries, problems } = chainOf(t);

  if (!log.ok) problems.push("snarkjs zkey verify did not report ZKey Ok!");
  if (log.circuitHash !== t.snarkjs_circuit_hash) {
    problems.push(`circuit hash ${log.circuitHash} != transcript ${t.snarkjs_circuit_hash}`);
  }
  // Position of this zkey in the chain: 0 = initial, k = after entry k.
  let position = -1;
  if (t.initial && zkeySha === t.initial.zkey_sha256) position = 0;
  entries.forEach((e, i) => {
    if (e.zkey_sha256 === zkeySha) position = i + 1;
  });
  if (position < 0) problems.push(`zkey sha256 ${zkeySha} is not listed in the transcript (a fork or a tampered file)`);
  else {
    const want = entries.slice(0, position);
    if (log.contributions.length !== want.length) {
      problems.push(`zkey has ${log.contributions.length} contribution(s), transcript lists ${want.length} up to it`);
    }
    log.contributions.forEach((c, i) => {
      const e = want[i];
      if (!e) return;
      if (c.n !== i + 1) problems.push(`zkey contribution numbering gap at #${c.n}`);
      if (c.hash !== e.contribution_hash) {
        problems.push(`contribution #${c.n} hash in zkey (${c.name}) != transcript entry ${e.order} (${e.name})`);
      }
      if (c.name !== e.name) problems.push(`contribution #${c.n} is named "${c.name}" in the zkey, "${e.name}" in the transcript`);
    });
  }
  if (args["require-latest"] === "1" && position !== entries.length) {
    problems.push(`zkey is not the latest in the transcript (position ${position} of ${entries.length}): refusing to fork the chain`);
  }
  if (args["require-open"] === "1" && t.beacon) problems.push("ceremony already finalized (beacon applied)");
  if (args["require-final"] === "1" && !(t.beacon && position === entries.length)) problems.push("zkey is not the finalized zkey");

  if (problems.length) die(`transcript check FAILED:\n  - ${problems.join("\n  - ")}`);
  process.stdout.write(
    JSON.stringify({
      position,
      of: entries.length,
      finalized: Boolean(t.beacon),
      chain: log.contributions.map((c) => ({ n: c.n, name: c.name, hash: c.hash })),
    }) + "\n",
  );
}

function init(args, need) {
  const out = need("out");
  const setupLog = clean(fs.readFileSync(need("setup-log"), "utf8")).split("\n");
  const i = setupLog.findIndex((l) => /Circuit Hash:\s*$/i.test(l));
  const circuitHash = i >= 0 ? hashAfter(setupLog, i) : null;
  if (!circuitHash) die("could not find the circuit hash in the groth16 setup log");
  let ptau;
  if (args["ptau-info"]) {
    const info = readJson(args["ptau-info"]);
    ptau = { source: info.source, file: info.file, power: info.power, blake2b: info.blake2b };
    if (info.warning) ptau.warning = info.warning;
    if (info.provenance) ptau.provenance = info.provenance;
  } else {
    ptau = { source: "external", file: path.basename(need("ptau")), blake2b: need("ptau-blake2b") };
  }
  const zkey = need("zkey");
  writeJson(out, {
    format: FORMAT,
    name: need("name"),
    circuit: need("circuit"),
    circuit_source_sha256: sha256(need("circuit-file")),
    circom_version: need("circom"),
    circom_flags: "--O2 --r1cs --wasm --sym",
    snarkjs_version: need("snarkjs"),
    constraints: Number(need("constraints")),
    n_pub_in: Number(need("n-pub-in")),
    n_out: Number(need("n-out")),
    r1cs_sha256: sha256(need("r1cs")),
    snarkjs_circuit_hash: circuitHash,
    ptau,
    created: now(),
    initial: { zkey: path.basename(zkey), zkey_sha256: sha256(zkey) },
    contributions: [],
    beacon: null,
  });
}

function hashFromLog(args, need) {
  const lines = clean(fs.readFileSync(need("log"), "utf8")).split("\n");
  let h = null;
  lines.forEach((l, i) => {
    if (/Contribution Hash:\s*$/i.test(l)) h = hashAfter(lines, i) || h;
  });
  if (!h) die("no contribution hash in the snarkjs log");
  process.stdout.write(h + "\n");
}

function append(args, need) {
  const f = need("transcript");
  const t = readJson(f);
  if (t.beacon) die("ceremony already finalized (beacon applied)");
  const participant = need("participant");
  if (!PARTICIPANT.test(participant)) die(`invalid participant name ${JSON.stringify(participant)}`);
  const zkey = need("zkey");
  const hash = need("hash");
  if (!/^[0-9a-f]{128}$/.test(hash)) die("contribution hash must be 128 hex");
  const prev = sha256(need("prev-zkey"));
  const last = t.contributions.length ? t.contributions[t.contributions.length - 1].zkey_sha256 : t.initial.zkey_sha256;
  if (prev !== last) die("the input zkey is not the latest in the transcript: refusing to fork the chain");
  t.contributions.push({
    order: t.contributions.length + 1,
    participant,
    contribution_hash: hash,
    zkey: path.basename(zkey),
    zkey_sha256: sha256(zkey),
    prev_zkey_sha256: prev,
    date: now(),
  });
  writeJson(f, t);
}

function setBeacon(args, need) {
  const f = need("transcript");
  const t = readJson(f);
  if (t.beacon) die("transcript already has a beacon");
  const zkey = need("zkey");
  t.beacon = {
    name: need("label"),
    hash: need("hash").toLowerCase(),
    iterations_exp: Number(need("iterations-exp")),
    source: need("source"),
    public: args.public === "1",
    contribution_hash: need("contribution-hash"),
    zkey: path.basename(zkey),
    zkey_sha256: sha256(zkey),
    prev_zkey_sha256: sha256(need("prev-zkey")),
    date: now(),
  };
  writeJson(f, t);
}

// field --transcript f --key a.b   (also: --file f for any JSON file)
function field(args, need) {
  let v = readJson(args.file || need("transcript"));
  for (const k of need("key").split(".")) v = v == null ? undefined : v[k];
  if (v === undefined || v === null) die(`no field ${args.key}`);
  process.stdout.write((typeof v === "object" ? JSON.stringify(v) : String(v)) + "\n");
}

function sameJson(args, need) {
  const { isDeepStrictEqual } = require("util");
  process.exit(isDeepStrictEqual(readJson(need("a")), readJson(need("b"))) ? 0 : 1);
}

// summary --result <check JSON> : human-readable chain on stderr; exit 0 iff it is the final zkey
function summary(args, need) {
  const r = JSON.parse(need("result"));
  for (const c of r.chain) process.stderr.write(`  #${c.n} ${c.name}  ${c.hash}\n`);
  process.stderr.write(`  position ${r.position} of ${r.of}${r.finalized ? " (finalized)" : ""}\n`);
  process.exit(r.finalized && r.position === r.of ? 0 : 3);
}

function ptauInfo(args, need) {
  process.stdout.write(JSON.stringify(readJson(need("transcript")).ptau) + "\n");
}

/**
 * The multi-party manifest, from the transcript and a setup-manifest.js manifest of the final zkey.
 * Pure (no I/O) so tests can call it on hand-made transcripts.
 *
 * Compatibility with tests/safety floor 9:
 *   - phase2.contributions stays a NUMBER (F9.09 compares `contributions >= 2`); the chain is in
 *     phase2.contributors.
 *   - ptau.* and the "pinned on first download" phase-1 limitation come unchanged from
 *     setup-manifest.js (F9.09).
 *   - status drops "DEV-ONLY" (to "DEMO-ONLY") only with >= 2 contributions, a public phase 1
 *     AND a public beacon; otherwise it stays "DEV-ONLY".
 */
const LOCAL_BEACON_LIMITATION =
  "beacon is local randomness, not a public value fixed in advance, so it is not independently verifiable";

function buildManifest(m, t, transcriptRel, transcriptSha) {
  if (!t.beacon) throw new Error("ceremony not finalized");
  const people = t.contributions.map((c) => c.participant);
  const n = people.length;
  const publicPhase1 = PUBLIC_PHASE1.has(t.ptau.source);
  const publicBeacon = t.beacon.public === true;
  const multi = n >= 2;
  const out = { ...m };

  const phase2Limit =
    `multi-party phase 2 (${n} contributors: ${people.join(", ")}): sound as long as at least one ` +
    "contributor generated their entropy honestly and destroyed it; all of them colluding (or all being " +
    "compromised) could forge proofs";
  // Idempotent: whatever phase-2 and beacon lines the base carries (a setup.sh single-party manifest,
  // or an earlier ceremony's multi-party one) are dropped and replaced by the ones this transcript
  // supports, so no stale line survives a re-run on top of an installed ceremony manifest.
  const limitations = (Array.isArray(m.limitations) ? m.limitations : []).filter(
    (l) => typeof l === "string" && !/single-party phase 2|multi-party phase 2/.test(l) && l !== LOCAL_BEACON_LIMITATION,
  );
  limitations.unshift(multi ? phase2Limit : SINGLE_PARTY_LIMITATION);
  if (!publicBeacon) limitations.push(LOCAL_BEACON_LIMITATION);

  if (multi && publicPhase1 && publicBeacon) {
    out.status = "DEMO-ONLY";
    out.status_detail =
      `DEMO-ONLY (multi-party phase 2: ${n} contributors + public beacon; phase 1 is a public ceremony): ` +
      "no production audit of the ceremony or the circuit; not for production";
  } else {
    out.status = "DEV-ONLY";
    const why = [];
    if (!multi) why.push("single-party phase 2");
    if (!publicPhase1) why.push(`local or unknown phase 1 (ptau source "${t.ptau.source}")`);
    if (!publicBeacon) why.push("beacon not public");
    out.status_detail = `DEV-ONLY (multi-party ceremony tooling, but: ${why.join("; ")}): not for production`;
  }

  out.phase2 = {
    contributions: n,
    contributors: t.contributions.map((c) => ({ order: c.order, participant: c.participant, hash: c.contribution_hash })),
    entropy: "per contributor: /dev/urandom (64 bytes) on stdin, mixed by snarkjs with crypto.randomBytes",
    beacon: true,
    beacon_hash: t.beacon.hash,
    beacon_iterations_exp: t.beacon.iterations_exp,
    beacon_source: t.beacon.source,
    beacon_public: publicBeacon,
    beacon_contribution_hash: t.beacon.contribution_hash,
    transcript: transcriptRel,
    transcript_sha256: transcriptSha,
    limitation: multi ? phase2Limit : SINGLE_PARTY_LIMITATION,
  };
  out.limitations = limitations;
  return out;
}

function manifestPatch(args, need) {
  const m = readJson(need("manifest"));
  const tf = need("transcript");
  const t = readJson(tf);
  if (!t.beacon) die("ceremony not finalized");
  // Repo-relative when the ceremony lives in the tree; never a machine path in a committed file.
  let rel = path.relative(need("repo-root"), path.resolve(tf)).split(path.sep).join("/");
  if (rel.startsWith("..") || path.isAbsolute(rel)) rel = `$CEREMONY_DIR/${t.name}/transcript.json (outside the repository)`;
  process.stdout.write(JSON.stringify(buildManifest(m, t, rel, sha256(tf)), null, 2) + "\n");
}

const commands = {
  init,
  "hash-from-log": hashFromLog,
  check,
  append,
  "set-beacon": setBeacon,
  field,
  "same-json": sameJson,
  summary,
  "ptau-info": ptauInfo,
  "manifest-patch": manifestPatch,
};

function main(argv) {
  const [cmd, ...rest] = argv;
  const args = {};
  for (let i = 0; i < rest.length; i += 2) args[rest[i].replace(/^--/, "")] = rest[i + 1] ?? "";
  const need = (k) => (args[k] === undefined || args[k] === "" ? die(`missing --${k}`) : args[k]);
  if (!commands[cmd]) die(`unknown subcommand ${cmd}; one of ${Object.keys(commands).join(", ")}`);
  commands[cmd](args, need);
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { FORMAT, PARTICIPANT, parseVerifyLog, chainOf, buildManifest };
