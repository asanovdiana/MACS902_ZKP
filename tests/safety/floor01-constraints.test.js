"use strict";
// Floor 1: every circuit constraint has a negative test that fails when the constraint is removed;
// every <-- is followed by an === that checks it.
//
// Evidence reused: the committed mutation report circuits/reports/mutation-v4.{json,md} (produced
// by circuits/scripts/mutate.js, which deletes each === and weakens each <== to <-- and requires a
// failing negative test), and the arrow audit of the same script. This file checks that the
// report says what floor 1 needs AND still describes the current sources (a stale report is no
// evidence), and re-runs the arrow audit plus an independent one.
const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { REPO, r, readJson } = require("./helpers");

const REPORT = readJson(r("circuits", "reports", "mutation-v4.json"));
const V4_MAIN = "circuits/integrated_access_v4.circom";

// Source with line and block comments blanked (line structure kept).
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .split("\n")
    .map((l) => l.replace(/\/\/.*$/, ""))
    .join("\n");
}

/** Project .circom files reachable from `file` through `include` (circomlib excluded). */
function includeClosure(file, seen = new Set()) {
  const abs = path.resolve(REPO, file);
  const rel = path.relative(REPO, abs);
  if (seen.has(rel)) return seen;
  seen.add(rel);
  const src = stripComments(fs.readFileSync(abs, "utf8"));
  for (const m of src.matchAll(/include\s+"([^"]+)"/g)) {
    const inc = path.resolve(path.dirname(abs), m[1]);
    if (inc.includes(`${path.sep}node_modules${path.sep}`)) continue;
    includeClosure(path.relative(REPO, inc), seen);
  }
  return seen;
}

describe("floor 1: constraints and arrows", () => {
  test("F1.01 mutation report: baseline passes, 0 survivors, 0 compile errors/timeouts/errors", () => {
    const s = REPORT.summary;
    assert.equal(REPORT.baseline.passed, true, "unmutated baseline must pass");
    assert.equal(s.survived, 0, "a surviving mutant is a constraint without a killing negative test");
    assert.equal(s.compile_error, 0);
    assert.equal(s.timeout, 0);
    assert.equal(s.error, 0);
    assert.equal(s.total, s.killed + s.equivalent);
    // tightened 95 -> 102 in G1-S1-SAFETY-021: CIRC-039 added eddsa_verifier.circom (SR-18)
    assert.ok(s.total >= 102, `the v4 run covered ${s.total} sites; it must never shrink below 102`);
    for (const m of REPORT.mutants) {
      assert.ok(["killed", "equivalent"].includes(m.outcome), `${m.id} ${m.file}:${m.line} is ${m.outcome}`);
      if (m.outcome === "equivalent") assert.ok(m.note && m.note.length > 20, `${m.id}: an equivalent mutant needs a written proof`);
      if (m.outcome === "killed") assert.ok(m.killer, `${m.id}: killed without a named killer`);
    }
  });

  test("F1.02 mutation report is not stale: every mutated site still reads as recorded", () => {
    for (const m of REPORT.mutants) {
      const lines = fs.readFileSync(r(m.file), "utf8").split("\n");
      const text = lines.slice(m.line - 1, (m.endLine || m.line)).map((l) => l.trim()).join(" ").replace(/\s+/g, " ");
      const want = m.original.replace(/\s+/g, " ").trim();
      assert.ok(text.includes(want), `${m.id}: ${m.file}:${m.line} no longer reads "${want}" (re-run npm run mutate:v4)`);
    }
  });

  test("F1.03 mutation report is complete: every constraint statement in every target is a site", () => {
    const sites = new Map();
    for (const m of REPORT.mutants) {
      if (!sites.has(m.file)) sites.set(m.file, []);
      sites.get(m.file).push([m.line, m.endLine || m.line]);
    }
    let checked = 0;
    for (const file of REPORT.targets) {
      const lines = stripComments(fs.readFileSync(r(file), "utf8")).split("\n");
      lines.forEach((l, i) => {
        if (!/<==|==>|===/.test(l)) return;
        const n = i + 1;
        const hit = (sites.get(file) || []).some(([a, b]) => a <= n && n <= b);
        assert.ok(hit, `${file}:${n} "${l.trim()}" is a constraint with no mutant in the report`);
        checked += 1;
      });
    }
    assert.ok(checked >= 60, `only ${checked} constraint lines found; parser broken?`);
  });

  test("F1.04 every project circuit file in the v4 main's include closure is covered", () => {
    const closure = [...includeClosure(V4_MAIN)].sort();
    const targets = new Set(REPORT.targets);
    // Documented exception: P1's eddsa_verifier.circom (IssuerSignatureCheck, used unchanged by v4)
    // is not mutated by mutate:v4; circuits/test/v3.test.js carries one tamper test per wiring line.
    const v3Spec = fs.readFileSync(r("circuits", "test", "v3.test.js"), "utf8");
    const EXCEPTIONS = {
      "circuits/components/eddsa_verifier.circom": () => {
        assert.match(v3Spec, /IssuerSignatureCheck: verifier\.enabled <== 1/);
        assert.match(v3Spec, /IssuerSignatureCheck: verifier\.\$\{sig\} <== \$\{sig\}/);
        assert.match(v3Spec, /IssuerSignatureCheck: verifier\.M <== M/);
      },
    };
    for (const f of closure) {
      if (targets.has(f)) continue;
      assert.ok(EXCEPTIONS[f], `${f} is compiled into the v4 main but is neither a mutation target nor a documented exception`);
      EXCEPTIONS[f]();
    }
    assert.ok(closure.length >= 9, `v4 include closure has ${closure.length} files`);
  });

  test("F1.05 arrow audit (circuits/scripts/mutate.js --audit-arrows) reports 0 violations", () => {
    const out = execFileSync(process.execPath, [
      r("circuits", "scripts", "mutate.js"), "--audit-arrows",
      "circuits/*.circom", "circuits/components/*.circom", "circuits/test/circuits/*.circom",
    ], { cwd: REPO, encoding: "utf8" });
    const m = /(\d+) file\(s\), (\d+) <--\/--> statement\(s\), (\d+) violation\(s\)/.exec(out);
    assert.ok(m, `unexpected audit output: ${out}`);
    assert.ok(Number(m[1]) >= 20, "audit saw too few files");
    assert.equal(Number(m[3]), 0, out);
  });

  test("F1.06 independent arrow audit: each <-- / --> is followed by an === on the same signal", () => {
    const dirs = [r("circuits"), r("circuits", "components"), r("circuits", "test", "circuits")];
    let files = 0;
    for (const d of dirs) {
      for (const f of fs.readdirSync(d).filter((x) => x.endsWith(".circom"))) {
        files += 1;
        const lines = stripComments(fs.readFileSync(path.join(d, f), "utf8")).split("\n");
        lines.forEach((l, i) => {
          let sig;
          const a = /([A-Za-z_][\w.\[\]]*)\s*<--/.exec(l);
          const b = /-->\s*([A-Za-z_][\w.\[\]]*)/.exec(l);
          if (a) sig = a[1];
          else if (b) sig = b[1];
          else return;
          const base = sig.replace(/\[.*$/, "");
          const checked = lines.slice(i + 1).some((x) => x.includes("===") && x.includes(base));
          assert.ok(checked, `${path.relative(REPO, path.join(d, f))}:${i + 1}: ${sig} assigned with an arrow and never checked by ===`);
        });
      }
    }
    assert.ok(files >= 20);
  });

  test("F1.07 the 7 redundant-but-killed v4 sites are killed by their component's own spec", () => {
    // Safety ruling (docs/security/review-G1-P2.md, SR-01): duplicated range checks between
    // AttributeHash and AccessPolicyV4 are acceptable defence in depth because each copy is killed
    // standalone. This test keeps that true.
    const expected = { S1: /policy v4/, S7: /policy v4/, S13: /policy v4/, S21: /AttributeHash/, S22: /AttributeHash/, S23: /AttributeHash/, S25: /AttributeHash/ };
    for (const [id, killer] of Object.entries(expected)) {
      const m = REPORT.mutants.find((x) => x.id === id);
      assert.ok(m, `${id} missing from the report`);
      assert.equal(m.outcome, "killed", `${id}`);
      assert.match(m.killer, killer, `${id} must be killed by the component's own negative test`);
      assert.match(m.note || "", /[Rr]edundant/, `${id} keeps its redundancy note`);
    }
  });

  test("F1.08 v3: the 2 equivalent mutants (redundant booleans in P1's main) keep their equivalence tests", () => {
    const v3Spec = fs.readFileSync(r("circuits", "test", "v3.test.js"), "utf8");
    assert.match(v3Spec, /is implied by FileShareAccess \$\{sig\} === 1 \(equivalent mutant\)/);
    // the two constraints they cover are still present in the v3 main, and FileShareAccess still pins both to 1
    const main = fs.readFileSync(r("circuits", "integrated_access_v3.circom"), "utf8");
    const pol = fs.readFileSync(r("circuits", "components", "access_policy.circom"), "utf8");
    for (const s of ["deviceCompliant", "employeeActive"]) {
      assert.ok(main.includes(`${s} * (${s} - 1) === 0;`));
      assert.ok(pol.includes(`${s} === 1;`), `FileShareAccess must still force ${s} === 1 for the mutant to stay equivalent`);
    }
  });

  test("F1.09 one report covers the whole v4 closure: every included project file is a mutation target, no exceptions (eddsa_verifier.circom included)", () => {
    // SR-18 closed by G1-S1-CIRC-039. Supersedes F1.04's documented exception without removing it.
    const closure = [...includeClosure(V4_MAIN)].sort();
    const targets = new Set(REPORT.targets);
    assert.ok(targets.has("circuits/components/eddsa_verifier.circom"), "eddsa_verifier.circom is not a mutate:v4 target");
    for (const f of closure) assert.ok(targets.has(f), `${f} is compiled into the v4 main but not mutated`);
    const eddsa = REPORT.mutants.filter((m) => m.file === "circuits/components/eddsa_verifier.circom");
    assert.ok(eddsa.length >= 7, `only ${eddsa.length} eddsa_verifier sites in the report`);
    for (const m of eddsa) assert.equal(m.outcome, "killed", `${m.id} ${m.file}:${m.line}`);
    // the npm script that regenerates the report still names it
    const pkg = readJson(r("package.json"));
    assert.match(pkg.scripts["mutate:v4"], /circuits\/components\/eddsa_verifier\.circom/);
  });
});
