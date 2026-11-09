"use strict";
// Ported unchanged in behaviour from the circuits prototype (G1-S1-CIRC-002) by
// G1-S1-CIRC-036. See circuits/scripts/MUTATION.md.
// Tiny dependency-free glob: `*`, `?`, `**`, `{a,b}`. Patterns are relative to `base`.
// node_modules, build and dot-directories are never walked.
const fs = require("fs");
const path = require("path");

const SKIP_DIRS = new Set(["node_modules", "build", ".git"]);

function globToRegex(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") {
      if (pattern[i + 1] === "*") {
        const slash = pattern[i + 2] === "/";
        re += slash ? "(?:.*/)?" : ".*";
        i += slash ? 2 : 1;
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else if (c === "{") {
      const j = pattern.indexOf("}", i);
      re += "(?:" + pattern.slice(i + 1, j).split(",").map((s) => s.replace(/[.+^$()|[\]\\]/g, "\\$&")).join("|") + ")";
      i = j;
    } else re += c.replace(/[.+^$()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}

function walk(dir, base, out) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name) || ent.name.startsWith(".")) continue;
      walk(abs, base, out);
    } else out.push(path.relative(base, abs).split(path.sep).join("/"));
  }
  return out;
}

/** Expand patterns (literal paths pass through if they exist) to sorted, de-duplicated relative paths. */
function expand(patterns, base) {
  const all = new Set();
  let files = null;
  for (const p of patterns) {
    const norm = p.split(path.sep).join("/").replace(/^\.\//, "");
    if (!/[*?{]/.test(norm)) {
      if (fs.existsSync(path.join(base, norm))) all.add(norm);
      continue;
    }
    files = files || walk(base, base, []);
    const re = globToRegex(norm);
    for (const f of files) if (re.test(f)) all.add(f);
  }
  return [...all].sort();
}

module.exports = { expand, globToRegex };
