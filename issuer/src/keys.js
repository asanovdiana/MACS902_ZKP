"use strict";
// Issuer EdDSA private key (floor 9): 32 random bytes generated once into the key directory,
// mode 0600, created atomically (write a temp file, then link() it into place so a concurrent
// creator cannot overwrite an existing key). Loaded on start; never logged or returned.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const KEY_FILE = "issuer.key";
const HEX64 = /^[0-9a-f]{64}$/;

function readKey(file) {
  const st = fs.statSync(file);
  if (st.mode & 0o077) throw new Error("issuer key file has group/other permissions; expected 0600");
  const text = fs.readFileSync(file, "utf8").trim();
  if (!HEX64.test(text)) throw new Error("issuer key file is malformed (expected 64 hex characters)");
  return Buffer.from(text, "hex");
}

/**
 * The key directory must not be reachable by group or other (SR-10). A directory created here is
 * chmod 0700 (mkdir's mode is subject to the umask); one that already exists is refused if too open.
 */
function ensureKeyDir(dir) {
  const created = fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (created !== undefined) fs.chmodSync(dir, 0o700);
  if (fs.statSync(dir).mode & 0o077) {
    throw new Error("issuer key directory has group/other permissions; expected 0700 (chmod 700 it)");
  }
}

/** Return the 32-byte private key in `dir`, creating it (once) if absent. */
function loadOrCreateKey(dir) {
  ensureKeyDir(dir);
  const file = path.join(dir, KEY_FILE);
  if (!fs.existsSync(file)) {
    const tmp = path.join(dir, `.${KEY_FILE}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`);
    try {
      fs.writeFileSync(tmp, crypto.randomBytes(32).toString("hex") + "\n", { flag: "wx", mode: 0o600 });
      fs.chmodSync(tmp, 0o600);
      try {
        fs.linkSync(tmp, file); // atomic; fails with EEXIST if someone else won the race
      } catch (e) {
        if (e.code !== "EEXIST") throw e;
      }
    } finally {
      fs.rmSync(tmp, { force: true });
    }
  }
  return readKey(file);
}

module.exports = { loadOrCreateKey, KEY_FILE };
