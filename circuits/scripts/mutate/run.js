"use strict";
// Mutant execution (ported from the removed circuits prototype by G1-S1-CIRC-036).
//
// Each mutant runs in its own throw-away copy of the repository's circuit tree: `circuits/`
// (without build output, reports and the committed setup artefacts), the root `.mocharc.json` and
// `package.json`, and a symlink to the root `node_modules`. Tests need no changes: helpers.js
// resolves REPO, sources and `build/test/` against its own __dirname, which is now the copy, and
// circuits include circomlib as `../node_modules/...` relative to the copy. Parallel jobs never
// share a build directory.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const REPO = path.resolve(__dirname, "..", "..", "..");
// What a workspace gets from REPO. Inside circuits/, these entries are skipped.
const COPY_ROOT_FILES = [".mocharc.json", "package.json"];
const CIRCUITS_SKIP = new Set(["node_modules", "build", "reports", "setup", ".git"]);

function tmpBase() {
  return process.env.MUTATE_TMPDIR || os.tmpdir();
}

function makeWorkspace(root = REPO, base = tmpBase()) {
  const ws = fs.mkdtempSync(path.join(base, "zk-mutant-"));
  for (const f of COPY_ROOT_FILES) {
    if (fs.existsSync(path.join(root, f))) fs.copyFileSync(path.join(root, f), path.join(ws, f));
  }
  fs.mkdirSync(path.join(ws, "circuits"));
  for (const ent of fs.readdirSync(path.join(root, "circuits"), { withFileTypes: true })) {
    if (CIRCUITS_SKIP.has(ent.name)) continue;
    fs.cpSync(path.join(root, "circuits", ent.name), path.join(ws, "circuits", ent.name), { recursive: true });
  }
  fs.symlinkSync(path.join(root, "node_modules"), path.join(ws, "node_modules"), "dir");
  return ws;
}

function removeWorkspace(ws) {
  fs.rmSync(ws, { recursive: true, force: true });
}

/**
 * Mocha config for the copy: the project's .mocharc minus its spec, plus ours.
 * `grep` restricts which tests run. With `forbid` (a RegExp source) mocha does not bail: the
 * reporter aborts the run at the first failure whose title does NOT match `forbid`, so a forbidden
 * (e.g. static source / constraint-count) failure never hides a later soundness test.
 */
function writeMochaConfig(ws, specs, root = REPO, { grep, forbid } = {}) {
  let base = {};
  const rc = path.join(root, ".mocharc.json");
  if (fs.existsSync(rc)) base = JSON.parse(fs.readFileSync(rc, "utf8"));
  delete base.spec;
  const cfg = {
    ...base,
    spec: specs,
    reporter: path.join(__dirname, "reporter.js"),
    bail: !forbid, // first failure is enough to kill a mutant (the reporter bails when forbid is set)
    parallel: false,
  };
  if (grep) cfg.grep = grep;
  const file = path.join(ws, ".mutate-mocharc.json");
  fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
  return file;
}

/** Run mocha on `specs` inside workspace `ws`. Resolves to {exitCode, results, timedOut, log}. */
function runSpecs(ws, specs, { timeoutMs = 30 * 60 * 1000, root = REPO, grep, forbid } = {}) {
  const forbidSrc = forbid instanceof RegExp ? forbid.source : forbid;
  const cfg = writeMochaConfig(ws, specs, root, { grep, forbid: forbidSrc });
  const resultFile = path.join(ws, ".mutate-result.json");
  const mochaBin = path.join(root, "node_modules", "mocha", "bin", "mocha.js");
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [mochaBin, "--config", cfg], {
      cwd: ws,
      env: { ...process.env, MUTATE_RESULT_FILE: resultFile, MUTATE_FORBID: forbidSrc || "" },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true, // own process group so a timeout can kill circom children too
    });
    let log = "";
    const keep = (d) => {
      log = (log + d).slice(-8000);
    };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch (_) {
        child.kill("SIGKILL");
      }
    }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      let results = null;
      try {
        results = JSON.parse(fs.readFileSync(resultFile, "utf8"));
      } catch (_) {
        /* mocha crashed before run end */
      }
      resolve({ exitCode: code, results, timedOut, log });
    });
  });
}

const COMPILER_RE = /circom compiler error/i;

/**
 * Turn a mocha run into an outcome:
 *   killed         a test failed (the mutant was detected by a test); `killer` names it
 *   compile_error  the first failure is the circom compiler rejecting the mutant (it is gone,
 *                  but no test proved anything — reported separately)
 *   survived       every test passed: the constraint is not covered by any test — or, with
 *                  `forbid`, every failing test matched it (e.g. a static source-text or
 *                  constraint-count test), so nothing proved the circuit unsound
 *   timeout        the run exceeded --timeout
 *   error          mocha crashed or ran no tests (inconclusive; counts as a harness failure)
 * `failures` lists every failing test title, `forbiddenKillers` those that matched `forbid`.
 */
function classifyRun({ exitCode, results, timedOut }, { forbid } = {}) {
  if (timedOut) return { outcome: "timeout", firstFailure: "", killer: "" };
  if (!results) return { outcome: "error", firstFailure: "", killer: "", detail: `mocha exited ${exitCode} without results` };
  const fails = results.failures || [];
  if (fails.length > 0) {
    const f = fails[0];
    if (COMPILER_RE.test(f.err)) {
      const m = /error\[[A-Z0-9]+\][^\n]*/.exec(f.err.replace(/\x1b\[[0-9;]*m/g, ""));
      return { outcome: "compile_error", firstFailure: f.fullTitle, killer: "", detail: m ? m[0] : "circom compiler error" };
    }
    const re = typeof forbid === "string" ? (forbid ? new RegExp(forbid) : null) : forbid || null;
    const failures = fails.map((x) => x.fullTitle);
    const forbiddenKillers = re ? failures.filter((t) => re.test(t)) : [];
    const killer = failures.find((t) => !(re && re.test(t)));
    if (killer === undefined) {
      return {
        outcome: "survived",
        firstFailure: "",
        killer: "",
        failures,
        forbiddenKillers,
        detail: `only forbidden killer(s) failed: ${forbiddenKillers.join("; ")}`,
      };
    }
    return { outcome: "killed", firstFailure: killer, killer, failures, forbiddenKillers };
  }
  if (exitCode !== 0) return { outcome: "error", firstFailure: "", killer: "", detail: `mocha exited ${exitCode} with no failures` };
  if (!results.passes) return { outcome: "error", firstFailure: "", killer: "", detail: "no tests ran" };
  return { outcome: "survived", firstFailure: "", killer: "" };
}

/** Simple promise pool. */
async function pool(items, jobs, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(jobs, items.length)) }, worker));
  return out;
}

module.exports = { REPO, makeWorkspace, removeWorkspace, runSpecs, classifyRun, pool };
