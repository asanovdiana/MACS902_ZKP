"use strict";
// Floor 10: tests/safety/** is append-only.
//
// MANIFEST.json lists every safety test ID ever committed, with its file. Rules enforced here:
//   - every manifest ID still exists as a test title in its file (no test removed or renamed away);
//   - every test in the suite is in the manifest (new tests are registered when added);
//   - the manifest committed at HEAD is a subset of the working manifest (IDs are never dropped);
//   - git history shows no deletion or rename of any tests/safety file.
// Weakening a test body is not machine-detectable; it is a review rule (tests/safety/README.md).
const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const h = require("./helpers");

const DIR = __dirname;
const MANIFEST = path.join(DIR, "MANIFEST.json");
const ID = /\btest\(\s*"(F\d{1,2}\.\d{2})\b/g;

function idsInSuite() {
  const out = new Map();
  for (const f of fs.readdirSync(DIR).filter((x) => x.endsWith(".test.js")).sort()) {
    const src = fs.readFileSync(path.join(DIR, f), "utf8");
    for (const m of src.matchAll(ID)) {
      assert.ok(!out.has(m[1]), `duplicate test ID ${m[1]} (${out.get(m[1])} and ${f})`);
      out.set(m[1], f);
    }
  }
  return out;
}

const manifest = () => JSON.parse(fs.readFileSync(MANIFEST, "utf8"));

describe("floor 10: tests/safety is append-only", () => {
  test("F10.01 every manifest ID is still a test in its recorded file", () => {
    const suite = idsInSuite();
    const m = manifest();
    assert.ok(Array.isArray(m.tests) && m.tests.length > 0);
    for (const t of m.tests) {
      assert.ok(suite.has(t.id), `${t.id} was removed or renamed (floor 10)`);
      assert.equal(suite.get(t.id), t.file, `${t.id} moved from ${t.file} to ${suite.get(t.id)}`);
    }
  });

  test("F10.02 every test in the suite is registered in the manifest, with one entry per ID", () => {
    const suite = idsInSuite();
    const m = manifest();
    const ids = m.tests.map((t) => t.id);
    assert.equal(new Set(ids).size, ids.length, "duplicate manifest entry");
    for (const id of suite.keys()) assert.ok(ids.includes(id), `${id} is not in MANIFEST.json`);
    // every floor 1-10 has at least one test
    for (let f = 1; f <= 10; f++) {
      const floors = new Set(m.tests.flatMap((t) => t.floors));
      assert.ok(floors.has(f), `floor ${f} has no test in the manifest`);
    }
  });

  test("F10.03 the manifest at HEAD is a subset of the working manifest", () => {
    let head;
    try {
      head = JSON.parse(h.git("show", "HEAD:tests/safety/MANIFEST.json"));
    } catch (_) {
      return; // first commit of the suite: nothing to compare yet
    }
    const now = new Set(manifest().tests.map((t) => t.id));
    for (const t of head.tests) assert.ok(now.has(t.id), `${t.id} was dropped from MANIFEST.json`);
  });

  test("F10.04 git history: no tests/safety file was ever deleted or renamed away", () => {
    const out = h.git("log", "--diff-filter=DR", "--name-status", "--format=%h", "--", "tests/safety").trim();
    assert.equal(out, "", `deleted/renamed safety files:\n${out}`);
  });
});
