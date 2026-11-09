"use strict";
// G1-S1-CIRC-036: tests for the constraint-removal mutation harness and the `<--` audit
// (circuits/scripts/mutate.js, ported from the removed circuits prototype), floor 1:
// "every circuit constraint has a negative test that fails when the constraint is removed;
//  every <-- is followed by an === that checks it".
// Also pins the committed v4 report (circuits/reports/mutation-v4.json) to the current sources.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { expect } = require("chai");

const { REPO } = require("./helpers");
const { parseSites, auditArrows } = require("../scripts/mutate/parse");
const { mutantsFor, applyMutant } = require("../scripts/mutate/mutants");
const { classifyRun } = require("../scripts/mutate/run");
const { parseArgs } = require("../scripts/mutate");

const FIX = path.join(__dirname, "fixtures", "mutate");
const FIX_REL = "circuits/test/fixtures/mutate";
const CLI = path.join(REPO, "circuits", "scripts", "mutate.js");
const read = (f) => fs.readFileSync(path.join(FIX, f), "utf8");

function cli(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: REPO, encoding: "utf8" });
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

function tmpReport(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mutate-test-"));
  return path.join(dir, name + ".md");
}
const jsonOf = (mdPath) => JSON.parse(fs.readFileSync(mdPath.replace(/\.md$/, ".json"), "utf8"));

describe("mutate: parser", function () {
  const src = read("sites.circom");
  const sites = parseSites(src, "sites.circom");

  it("enumerates exactly the constraint-bearing statements (===, <==, ==>), one site per statement", function () {
    expect(sites.map((s) => s.line)).to.deep.equal([17, 19, 23, 25, 27, 30]);
    expect(sites.map((s) => s.op)).to.deep.equal(["<==", "<==", "===", "==>", "<==", "==="]);
  });

  it("ignores comments, strings and <-- statements", function () {
    for (const s of sites) expect(s.text).to.not.match(/decoy|<--|\/\/|\/\*/);
  });

  it("joins a multi-line statement into one site with its full text and line span", function () {
    const s = sites.find((x) => x.line === 19);
    expect(s.text).to.equal("acc[i + 1] <== acc[i] + in[i] * in[i];");
    expect(s.endLine).to.equal(21);
  });

  it("records loop / conditional context and the template", function () {
    const ctx = Object.fromEntries(sites.map((s) => [s.line, s.context]));
    expect(ctx).to.deep.equal({ 17: "", 19: "for", 23: "for", 25: "if", 27: "else", 30: "" });
    expect(sites.find((x) => x.line === 25).template).to.equal("Sites");
  });

  it("M1 turns <== / ==> into <-- / --> and keeps the rest of the file byte-identical", function () {
    for (const line of [19, 25]) {
      const site = sites.find((x) => x.line === line);
      const [m] = mutantsFor(site);
      const out = applyMutant(src, m);
      expect(out.split("\n").length).to.equal(src.split("\n").length);
      expect(out.split("\n")[line - 1]).to.contain(site.op === "<==" ? "acc[i + 1] <--" : "s * s --> out;");
      expect(out.slice(0, site.opStart) + site.op + out.slice(site.opEnd)).to.equal(src);
    }
  });

  it("M1 deletes an === as an empty block, valid even as an unbraced loop body", function () {
    const site = sites.find((x) => x.line === 23);
    const out = applyMutant(src, mutantsFor(site)[0]);
    const l23 = out.split("\n")[22];
    expect(l23).to.match(/^ {4}for \(var j = 0; j < n; j\+\+\) \{.*\}/);
    expect(l23).to.not.contain("===");
  });
});

describe("mutate: arrow audit (<-- must be followed by an === in the same template)", function () {
  it("flags a bare <-- and a <-- whose only check is in another template", function () {
    const v = auditArrows(read("bare_arrow.circom"), "bare_arrow.circom");
    expect(v.map((x) => [x.template, x.signal, x.line])).to.deep.equal([
      ["BareArrow", "inv", 7],
      ["Other", "t", 15],
    ]);
  });

  it("passes <-- and --> that are checked by a later === (loops, multi-line)", function () {
    expect(auditArrows(read("checked_arrow.circom"), "checked_arrow.circom")).to.deep.equal([]);
  });

  it("CLI --audit-arrows exits 1 on the bare fixture and 0 on the checked one", function () {
    const bad = cli(["--audit-arrows", `${FIX_REL}/bare_arrow.circom`]);
    expect(bad.code, bad.out).to.equal(1);
    expect(bad.out).to.contain("bare_arrow.circom:7").and.contain("inv");
    const good = cli(["--audit-arrows", `${FIX_REL}/checked_arrow.circom`]);
    expect(good.code, good.out).to.equal(0);
  });

  it("every project circuit (mains, components, test mains) passes the arrow audit", function () {
    const r = cli(["--audit-arrows", "circuits/*.circom", "circuits/components/*.circom", "circuits/test/circuits/*.circom"]);
    expect(r.code, r.out).to.equal(0);
    expect(r.out).to.match(/0 violation\(s\)/);
  });

  it("refuses circomlib / node_modules and paths outside circuits/ (exit 2)", function () {
    const r = cli(["--audit-arrows", "node_modules/circomlib/circuits/poseidon.circom"]);
    expect(r.code).to.equal(2);
    expect(r.out).to.match(/no project \.circom files/i);
  });
});

describe("mutate: outcome classification and options", function () {
  it("classifies mocha runs: compile error, killed, survived, no tests", function () {
    const ce = classifyRun({
      exitCode: 1,
      results: { passes: 0, failures: [{ fullTitle: "x before all", err: "Error: circom compiler error: error[TAC01]" }] },
    });
    expect(ce.outcome).to.equal("compile_error");
    const killed = classifyRun({ exitCode: 1, results: { passes: 1, failures: [{ fullTitle: "t rejects", err: "x" }] } });
    expect(killed).to.include({ outcome: "killed", killer: "t rejects" });
    expect(classifyRun({ exitCode: 0, results: { passes: 3, failures: [] } }).outcome).to.equal("survived");
    expect(classifyRun({ exitCode: 0, results: { passes: 0, failures: [] } }).outcome).to.equal("error");
    expect(classifyRun({ exitCode: 1, results: null }).outcome).to.equal("error");
  });

  it("forbidden killers: the first allowed failure kills; only forbidden failures = survived", function () {
    const forbid = /layout|constraint count|hook/;
    const mixed = classifyRun(
      {
        exitCode: 1,
        results: {
          passes: 5,
          failures: [
            { fullTitle: "v4 layout constraint count depth 16 --O2", err: "x" },
            { fullTitle: "v4 negatives gate: attr.role <== role", err: "x" },
          ],
        },
      },
      { forbid }
    );
    expect(mixed).to.include({ outcome: "killed", killer: "v4 negatives gate: attr.role <== role" });
    expect(mixed.forbiddenKillers).to.deep.equal(["v4 layout constraint count depth 16 --O2"]);
    const onlyStatic = classifyRun(
      { exitCode: 1, results: { passes: 9, failures: [{ fullTitle: "v4 layout constraint count depth 16 --O2", err: "x" }] } },
      { forbid }
    );
    expect(onlyStatic.outcome).to.equal("survived");
    expect(onlyStatic.detail).to.match(/forbidden/);
  });

  it("parses --grep, --forbid-killers and --annotations; rejects a bad regexp", function () {
    const o = parseArgs(["--test", "t.js", "--grep", "negatives", "--forbid-killers", "a|b", "--annotations", "x.json"]);
    expect(o).to.include({ grep: "negatives", forbidKillers: "a|b", annotations: "x.json" });
    expect(() => parseArgs(["--forbid-killers", "("])).to.throw(/forbid-killers/);
  });
});

describe("mutate: harness end-to-end on the toy fixture", function () {
  const TOY = `${FIX_REL}/toy.circom`;

  it("kills both toy mutants with C-TOY-1 negatives only, naming the killing test (exit 0)", function () {
    const report = tmpReport("toy");
    const r = cli([
      "--target", TOY, "--test", `${FIX_REL}/toy.spec.js`,
      "--grep", "C-TOY-1", "--forbid-killers", "hook|positives",
      "--jobs", "2", "--report", report,
    ]);
    expect(r.code, r.out).to.equal(0);
    const j = jsonOf(report);
    expect(j.baseline.passed).to.equal(true);
    expect(j.summary).to.include({ total: 2, killed: 2, survived: 0 });
    const s1 = j.mutants.find((m) => m.original === "hasher.inputs[0] <== secret;");
    expect(s1.killer).to.match(/overwritten/);
    const s2 = j.mutants.find((m) => m.original === "h === hasher.out;");
    expect(s2.killer).to.match(/C-TOY-1/);
    expect(fs.readFileSync(report, "utf8")).to.contain("| S1 |").and.contain("Killed by");
  });

  it("a deliberately weak (positive-only) spec leaves survivors and the harness exits 1", function () {
    const report = tmpReport("weak");
    const r = cli(["--target", TOY, "--test", `${FIX_REL}/weak_toy.spec.js`, "--jobs", "2", "--report", report]);
    expect(r.code, r.out).to.equal(1);
    const j = jsonOf(report);
    expect(j.summary.survived).to.equal(2);
    expect(r.out).to.match(/SURVIVED/);
  });

  it("--forbid-killers: a kill credited only to a forbidden test counts as survived (exit 1)", function () {
    const report = tmpReport("forbid");
    const r = cli([
      "--target", TOY, "--test", `${FIX_REL}/toy.spec.js`,
      "--grep", "C-TOY-1", "--forbid-killers", "C-TOY-1",
      "--only", `${TOY}:12`, "--report", report,
    ]);
    expect(r.code, r.out).to.equal(1);
    const [m] = jsonOf(report).mutants;
    expect(m.outcome).to.equal("survived");
    expect(m.forbiddenKillers).to.be.an("array").that.is.not.empty;
  });

  it("--annotations: an equivalent survivor is documented as `equivalent` with its reason (exit 0)", function () {
    const report = tmpReport("equiv");
    const ann = path.join(path.dirname(report), "ann.json");
    fs.writeFileSync(
      ann,
      JSON.stringify({ annotations: [{ file: TOY, statement: "h === hasher.out;", equivalent: true, note: "fixture reason" }] })
    );
    const r = cli([
      "--target", TOY, "--test", `${FIX_REL}/weak_toy.spec.js`,
      "--only", `${TOY}:12`, "--annotations", ann, "--report", report,
    ]);
    expect(r.code, r.out).to.equal(0);
    const j = jsonOf(report);
    expect(j.mutants[0]).to.include({ outcome: "equivalent", note: "EQUIVALENT: fixture reason" });
    expect(j.summary.equivalent).to.equal(1);
    expect(fs.readFileSync(report, "utf8")).to.contain("Annotated mutants").and.contain("fixture reason");
  });

  it("an annotation that matches no site is a usage error (exit 2)", function () {
    const ann = path.join(path.dirname(tmpReport("stale")), "ann.json");
    fs.writeFileSync(ann, JSON.stringify({ annotations: [{ file: TOY, statement: "no such;", note: "x" }] }));
    const r = cli(["--target", TOY, "--test", `${FIX_REL}/weak_toy.spec.js`, "--annotations", ann]);
    expect(r.code, r.out).to.equal(2);
    expect(r.out).to.match(/matches no site/);
  });

  it("--grep that matches no test fails the baseline (exit 2)", function () {
    const r = cli(["--target", TOY, "--test", `${FIX_REL}/toy.spec.js`, "--grep", "no test has this title"]);
    expect(r.code, r.out).to.equal(2);
    expect(r.out).to.match(/baseline FAILED/);
  });

  it("reports a circom compile error as compile_error, not a kill, and does not fail on it", function () {
    const report = tmpReport("anon");
    const r = cli(["--target", `${FIX_REL}/anon.circom`, "--test", `${FIX_REL}/anon.spec.js`, "--report", report]);
    expect(r.code, r.out).to.equal(0);
    const j = jsonOf(report);
    expect(j.mutants.map((m) => m.outcome)).to.deep.equal(["compile_error"]);
    expect(j.mutants[0].detail).to.match(/TAC01|Anonymous|nonymous/);
  });
});

describe("mutate: committed v4 report (circuits/reports/mutation-v4.json)", function () {
  const report = JSON.parse(fs.readFileSync(path.join(REPO, "circuits", "reports", "mutation-v4.json"), "utf8"));

  it("covers exactly the current constraint sites of every v4 target (report is not stale)", function () {
    const current = [];
    for (const f of report.targets) {
      for (const s of parseSites(fs.readFileSync(path.join(REPO, f), "utf8"), f)) current.push(`${f}:${s.line} ${s.text}`);
    }
    expect(report.mutants.map((m) => `${m.file}:${m.line} ${m.original}`)).to.deep.equal(current);
  });

  it("targets the v4 main, the gate and every component the gate includes, her IssuerSignatureCheck too (SR-18; not her v3 files)", function () {
    expect(report.targets).to.include.members([
      "circuits/integrated_access_v4.circom",
      "circuits/components/integrated_access_v4_gate.circom",
      "circuits/components/attribute_hash.circom",
      "circuits/components/issuer_key.circom",
      "circuits/components/merkle_membership_n.circom",
      "circuits/components/access_policy_v4.circom",
      "circuits/components/expiry.circom",
      "circuits/components/challenge_binding.circom",
      "circuits/components/eddsa_verifier.circom",
    ]);
    expect(report.targets.join(" ")).to.not.match(/integrated_access_v3|access_policy\.circom|merkle_membership\.circom/);
  });

  it("0 survivors, 0 errors; every kill is by a non-forbidden test", function () {
    expect(report.baseline.passed).to.equal(true);
    expect(report.summary.survived).to.equal(0);
    expect(report.summary.error).to.equal(0);
    expect(report.forbidKillers).to.be.a("string");
    const forbid = new RegExp(report.forbidKillers);
    for (const m of report.mutants.filter((x) => x.outcome === "killed")) {
      expect(m.killer, m.original).to.be.a("string").and.not.equal("");
      expect(forbid.test(m.killer), m.killer).to.equal(false);
    }
    for (const m of report.mutants) expect(["killed", "equivalent", "compile_error"]).to.include(m.outcome);
  });
});
