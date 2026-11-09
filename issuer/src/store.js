"use strict";
// Registry persistence: one JSON file, written atomically (temp file + rename), mode 0600.
// Holds commitments, leaves, revocation flags and the root history; no secrets, no signatures,
// no attributes (v4 attributes live only inside the leaf hash).
const fs = require("fs");
const path = require("path");

const STATE_FILE = "registry.json";

function createStore(dir) {
  const file = path.join(dir, STATE_FILE);
  return {
    file,
    /** The stored state object, or null on first start. */
    load() {
      if (!fs.existsSync(file)) return null;
      return JSON.parse(fs.readFileSync(file, "utf8"));
    },
    save(state) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
      fs.chmodSync(tmp, 0o600);
      fs.renameSync(tmp, file);
    },
  };
}

module.exports = { createStore, STATE_FILE };
