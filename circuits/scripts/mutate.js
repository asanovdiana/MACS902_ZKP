#!/usr/bin/env node
"use strict";
// Constraint-removal mutation harness and `<--` audit (floor 1). Ported from the circuits
// prototype (G1-S1-CIRC-002) to the P1/P2 layout by G1-S1-CIRC-036.
// Usage: see circuits/scripts/MUTATION.md. Run from the repository root (paths may also be
// absolute); every target must be a project .circom file under circuits/.
//
//   node circuits/scripts/mutate.js --target <glob...> --test <spec...> [--report <path.md>]
//        [--jobs N] [--only file:line] [--timeout SEC] [--keep] [--grep <mocha grep>]
//        [--forbid-killers <regexp>] [--annotations <json>] [--seed-builds]
//   node circuits/scripts/mutate.js --audit-arrows <glob...> [--allow-arrow-constraint]
//
// Exit: 0 = every mutant killed or documented equivalent (or audit clean); 1 = a mutant survived
// or errored (or audit violations); 2 = usage error, no target files, or the unmutated baseline
// fails.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execSync } = require("child_process");

const { parseSites, auditArrows, statements } = require("./mutate/parse");
const { mutantsFor, applyMutant, mutantText } = require("./mutate/mutants");
const { expand } = require("./mutate/glob");
const { REPO, makeWorkspace, removeWorkspace, runSpecs, classifyRun, pool } = require("./mutate/run");
const { writeReport } = require("./mutate/report");

class UsageError extends Error {}

function parseArgs(argv) {
  const o = {
    target: [], test: [], only: [], audit: [], jobs: 1, timeout: 1800, keep: false, allowArrowConstraint: false, seedBuilds: false,
  };
  const multi = { "--target": "target", "--test": "test", "--only": "only", "--audit-arrows": "audit" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (multi[a]) {
      const key = multi[a];
      if (key === "audit") o.auditMode = true;
      // Collect values up to the next flag, so unquoted shell-expanded globs also work.
      while (argv[i + 1] !== undefined && !argv[i + 1].startsWith("--")) o[key].push(argv[++i]);
    } else if (a === "--report") o.report = argv[++i];
    else if (a === "--grep") o.grep = argv[++i];
    else if (a === "--forbid-killers") o.forbidKillers = argv[++i];
    else if (a === "--annotations") o.annotations = argv[++i];
    else if (a === "--jobs") o.jobs = Number(argv[++i]);
    else if (a === "--timeout") o.timeout = Number(argv[++i]);
    else if (a === "--keep") o.keep = true;
    else if (a === "--seed-builds") o.seedBuilds = true;
    else if (a === "--allow-arrow-constraint") o.allowArrowConstraint = true;
    else if (a === "--help" || a === "-h") o.help = true;
    else throw new UsageError(`unknown argument: ${a}`);
  }
  if (!(o.jobs >= 1)) throw new UsageError("--jobs must be >= 1");
  if ("grep" in o && !o.grep) throw new UsageError("--grep needs a pattern");
  if ("annotations" in o && !o.annotations) throw new UsageError("--annotations needs a file");
  if ("forbidKillers" in o) {
    if (!o.forbidKillers) throw new UsageError("--forbid-killers needs a pattern");
    try {
      new RegExp(o.forbidKillers);
    } catch (e) {
      throw new UsageError(`--forbid-killers: invalid regexp: ${e.message}`);
    }
  }
  return o;
}

/** Normalise a user path/glob (relative to cwd, or absolute) to repo-root-relative with "/". */
function toRootRel(p, cwd = process.cwd()) {
  return path.relative(REPO, path.resolve(cwd, p)).split(path.sep).join("/");
}

/** Project .circom files only: under circuits/, never node_modules (circomlib is trusted upstream). */
function projectCircomFiles(patterns) {
  const pats = patterns.map((p) => toRootRel(p)).filter((p) => p.startsWith("circuits/"));
  return expand(pats, REPO).filter((f) => f.endsWith(".circom") && !f.split("/").includes("node_modules"));
}

/** Quote one argv entry for the report's reproducible command line. */
const shq = (a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : "'" + a.replace(/'/g, "'\\''") + "'");

function circomVersion() {
  const env = { ...process.env, PATH: path.join(os.homedir(), ".cargo", "bin") + path.delimiter + process.env.PATH };
  try {
    return execSync("circom --version", { encoding: "utf8", env }).trim();
  } catch (_) {
    return "circom (not found)";
  }
}

function audit(o) {
  const files = projectCircomFiles(o.audit);
  if (files.length === 0) throw new UsageError("no project .circom files match " + o.audit.join(" "));
  let arrows = 0;
  const violations = [];
  for (const f of files) {
    const src = fs.readFileSync(path.join(REPO, f), "utf8");
    arrows += statements(src).filter((s) => s.op === "<--" || s.op === "-->").length;
    violations.push(...auditArrows(src, f, { allowArrowConstraint: o.allowArrowConstraint }));
  }
  for (const v of violations) {
    console.log(`${v.file}:${v.line}  template ${v.template}: '${v.signal}' is assigned with <--/--> but no later === in the template references it\n    ${v.text}`);
  }
  console.log(`arrow audit: ${files.length} file(s), ${arrows} <--/--> statement(s), ${violations.length} violation(s)`);
  return violations.length ? 1 : 0;
}

function matchesOnly(site, only) {
  if (only.length === 0) return true;
  return only.some((spec) => {
    const m = /^(.*):(\d+)$/.exec(spec);
    if (!m) throw new UsageError(`--only expects file:line, got ${spec}`);
    const file = toRootRel(m[1]);
    const line = Number(m[2]);
    return (site.file === file || site.file.endsWith("/" + m[1])) && line >= site.line && line <= site.endLine;
  });
}

/**
 * Annotations: [{file, statement, equivalent, note}]. `statement` is the site text as the report
 * prints it. An `equivalent: true` entry turns a SURVIVED outcome into `equivalent` (documented,
 * not claimed as a kill, does not fail the run); the note must say why no new witness is admitted.
 * Every entry must match a site, so a stale annotation is a usage error.
 */
function loadAnnotations(file, sites) {
  if (!file) return () => null;
  const raw = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), file), "utf8"));
  const list = raw.annotations || [];
  for (const a of list) {
    if (!a.file || !a.statement || !a.note) throw new UsageError(`annotation needs file, statement and note: ${JSON.stringify(a)}`);
    if (!sites.some((s) => s.file === a.file && s.text === a.statement)) {
      throw new UsageError(`annotation matches no site: ${a.file}: ${a.statement}`);
    }
  }
  return (site) => list.find((a) => a.file === site.file && a.statement === site.text) || null;
}

async function mutate(o) {
  if (o.target.length === 0) throw new UsageError("--target <glob...> is required");
  if (o.test.length === 0) throw new UsageError("--test <mocha spec(s)> is required");
  const files = projectCircomFiles(o.target);
  if (files.length === 0) throw new UsageError("no project .circom files match " + o.target.join(" "));
  const specs = o.test.map((p) => toRootRel(p));
  for (const s of specs) {
    if (!s.startsWith("circuits/") || !fs.existsSync(path.join(REPO, s))) throw new UsageError(`spec not found under circuits/: ${s}`);
  }

  // Enumerate sites and mutants.
  const sources = {};
  const all = [];
  for (const f of files) {
    sources[f] = fs.readFileSync(path.join(REPO, f), "utf8");
    for (const site of parseSites(sources[f], f)) all.push(site);
  }
  all.forEach((s, i) => (s.id = `S${i + 1}`));
  const annotationFor = loadAnnotations(o.annotations, all);
  const sites = all.filter((s) => matchesOnly(s, o.only));
  if (o.only.length && sites.length === 0) throw new UsageError(`--only ${o.only.join(" ")} matches no site`);
  const mutants = sites.flatMap((s) => mutantsFor(s));
  console.log(`mutate: ${files.length} file(s), ${all.length} site(s), running ${mutants.length} mutant(s) with ${specs.join(" ")} (jobs=${o.jobs})`);
  if (o.grep) console.log(`mutate: --grep ${JSON.stringify(o.grep)}`);
  if (o.forbidKillers) console.log(`mutate: --forbid-killers ${JSON.stringify(o.forbidKillers)} (a kill only by such tests counts as survived)`);
  const runOpts = { timeoutMs: o.timeout * 1000, grep: o.grep, forbid: o.forbidKillers };
  const classOpts = { forbid: o.forbidKillers };

  // Baseline: the unmutated tree must pass, or a "kill" means nothing.
  const t0 = Date.now();
  const bws = makeWorkspace();
  const bRun = await runSpecs(bws, specs, runOpts);
  const bOut = classifyRun(bRun);
  // --seed-builds: each mutant workspace starts with a copy of the baseline's build/ directory. The
  // tests' build caches are stamped with the hash of their sources, so every build that includes
  // the mutated file recompiles; untouched builds (circomlib harnesses, other components) are
  // reused. A cache whose source list missed the mutated file could only make a test PASS (a stale
  // honest build), i.e. turn a kill into a visible survivor, never invent a kill.
  const seed = o.seedBuilds && fs.existsSync(path.join(bws, "build")) ? path.join(bws, "build") : null;
  const dropBaseline = () => {
    if (!o.keep) removeWorkspace(bws);
  };
  if (!seed) dropBaseline();
  const baseline = { passed: bOut.outcome === "survived", passes: bRun.results ? bRun.results.passes : 0, ms: Date.now() - t0 };
  if (!baseline.passed) {
    console.error(`baseline FAILED on the unmutated tree (${bOut.outcome}: ${bOut.firstFailure || bOut.detail || ""})`);
    console.error(bRun.log.slice(-3000));
    dropBaseline();
    return { code: 2 };
  }
  console.log(`baseline: pass (${baseline.passes} tests, ${(baseline.ms / 1000).toFixed(1)}s)`);

  let done = 0;
  const results = await pool(mutants, o.jobs, async (m) => {
    const t = Date.now();
    const ws = makeWorkspace();
    if (seed) fs.cpSync(seed, path.join(ws, "build"), { recursive: true });
    fs.writeFileSync(path.join(ws, m.site.file), applyMutant(sources[m.site.file], m));
    const run = await runSpecs(ws, specs, runOpts);
    const res = classifyRun(run, classOpts);
    const ann = annotationFor(m.site);
    if (ann && ann.equivalent && res.outcome === "survived") res.outcome = "equivalent";
    if (o.keep) res.workspace = ws;
    else removeWorkspace(ws);
    const rec = {
      id: m.site.id,
      kind: m.kind,
      file: m.site.file,
      line: m.site.line,
      endLine: m.site.endLine,
      template: m.site.template,
      context: m.site.context,
      original: m.site.text,
      mutant: mutantText(m),
      description: m.description,
      outcome: res.outcome,
      killer: res.killer || "",
      firstFailure: res.firstFailure,
      ...(ann ? { note: (ann.equivalent ? "EQUIVALENT: " : "") + ann.note } : {}),
      ...(res.failures ? { failures: res.failures } : {}),
      ...(res.forbiddenKillers && res.forbiddenKillers.length ? { forbiddenKillers: res.forbiddenKillers } : {}),
      ...(res.detail ? { detail: res.detail } : {}),
      ...(res.workspace ? { workspace: res.workspace } : {}),
      ms: Date.now() - t,
    };
    if (res.outcome === "error") rec.log = run.log.slice(-2000);
    done++;
    const tag = res.outcome === "survived" ? "SURVIVED" : res.outcome.toUpperCase();
    const why = res.killer || res.firstFailure || (rec.forbiddenKillers ? "forbidden killer only: " + rec.forbiddenKillers[0] : "");
    console.log(`[${done}/${mutants.length}] ${rec.id} ${rec.file}:${rec.line} ${tag}  ${rec.original}  =>  ${rec.mutant}${why ? "  (" + why + ")" : ""}`);
    return rec;
  });

  if (seed) dropBaseline();
  const count = (k) => results.filter((r) => r.outcome === k).length;
  const summary = {
    total: results.length,
    killed: count("killed"),
    survived: count("survived"),
    equivalent: count("equivalent"),
    compile_error: count("compile_error"),
    timeout: count("timeout"),
    error: count("error"),
  };
  const scored = summary.total - summary.compile_error - summary.equivalent;
  summary.score = scored ? `${summary.killed + summary.timeout}/${scored}` : "n/a";
  const report = {
    title: files.length === 1 ? files[0] : `${files.length} files`,
    command: "node circuits/scripts/mutate.js " + process.argv.slice(2).map(shq).join(" "),
    generatedAt: new Date().toISOString(),
    circom: circomVersion(),
    targets: files,
    specs,
    ...(o.grep ? { grep: o.grep } : {}),
    ...(o.forbidKillers ? { forbidKillers: o.forbidKillers } : {}),
    ...(o.annotations ? { annotations: toRootRel(o.annotations) } : {}),
    seedBuilds: Boolean(seed),
    baseline,
    summary,
    mutants: results,
  };
  if (o.report) {
    const w = writeReport(report, path.resolve(process.cwd(), o.report));
    console.log(`report: ${w.md} (+ .json)`);
  }
  console.log(
    `summary: ${summary.total} mutants, ${summary.killed} killed, ${summary.survived} survived, ` +
      `${summary.equivalent} equivalent, ${summary.compile_error} compile errors, ${summary.timeout} timeouts, ${summary.error} errors`
  );
  const code = summary.survived > 0 || summary.error > 0 ? 1 : 0;
  return { code, report };
}

const HELP = `usage:
  node circuits/scripts/mutate.js --target <glob...> --test <spec...> [--report <path.md>] [--jobs N]
                         [--only <file:line>...] [--timeout <sec>] [--keep]
                         [--grep <mocha grep>] [--forbid-killers <regexp>] [--annotations <json>]
                         [--seed-builds]
  node circuits/scripts/mutate.js --audit-arrows <glob...> [--allow-arrow-constraint]
Paths are relative to the current directory (or absolute) and must lie under circuits/.
See circuits/scripts/MUTATION.md.`;

async function main(argv) {
  try {
    const o = parseArgs(argv);
    if (o.help) {
      console.log(HELP);
      return 0;
    }
    if (o.auditMode) return audit(o);
    return (await mutate(o)).code;
  } catch (e) {
    if (e instanceof UsageError) {
      console.error(`mutate: ${e.message}\n${HELP}`);
      return 2;
    }
    throw e;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      console.error(e);
      process.exit(2);
    }
  );
}

module.exports = { main, parseArgs, projectCircomFiles, toRootRel };
