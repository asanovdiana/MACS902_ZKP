"use strict";
// Wallet: credential.file v1 (docs/CONTRACTS.md). Holds credentialSecret and credentialSalt, which
// never leave this process except into the local prover (floor 6).
//
// Layout:  ${ZKGATE_HOME:-~/.zkgate}/credentials/<name>.json   (files 0600, directories 0700)
//          ${ZKGATE_HOME:-~/.zkgate}/pins.json                 (issuer key pins, public values)
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const zk = require("../../circuits/lib");
const { ClientError } = require("./errors");
const { stripSlash } = require("./http");

const FORMAT = "zk-access-gate/credential";
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const STATUSES = ["pending", "issued"];

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** 31 CSPRNG bytes -> canonical decimal (< 2^248 < p, so no modular reduction; never 0). */
function randomField() {
  for (;;) {
    const v = BigInt("0x" + crypto.randomBytes(31).toString("hex"));
    if (v !== 0n) return v.toString();
  }
}

/** Atomic write: temp file (0600) in the same directory, fsync, then rename (or link when exclusive). */
function writeAtomic(file, data, { exclusive = false } = {}) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  let fd;
  try {
    fd = fs.openSync(tmp, "wx", 0o600);
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    if (exclusive) {
      try {
        fs.linkSync(tmp, file);
      } catch (e) {
        if (e.code === "EEXIST") throw new ClientError("WALLET_EXISTS", "a credential with this name already exists; refusing to overwrite its secret");
        throw e;
      }
      fs.unlinkSync(tmp);
    } else {
      fs.renameSync(tmp, file);
    }
  } catch (e) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) { /* ignore */ }
    try { fs.unlinkSync(tmp); } catch (_) { /* already gone */ }
    throw e;
  }
}

const corrupt = (why) => new ClientError("WALLET_CORRUPT", `credential file is not a valid credential.file v1 (${why})`);

function validate(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) throw corrupt("not an object");
  if (c.format !== FORMAT || c.version !== 1) throw corrupt("format/version");
  if (c.profile !== "v3" && c.profile !== "v4") throw corrupt("profile");
  if (!STATUSES.includes(c.status)) throw corrupt("status");
  if (!c.secrets || !zk.isCanonical(c.secrets.credentialSecret) || !zk.isCanonical(c.secrets.credentialSalt)) throw corrupt("secrets");
  if (!zk.isCanonical(c.commitment)) throw corrupt("commitment");
  if (c.status === "issued") {
    for (const k of ["attributes", "issuer", "signature"]) if (!c[k] || typeof c[k] !== "object") throw corrupt(k);
    if (!Number.isSafeInteger(c.leafIndex) || c.leafIndex < 0) throw corrupt("leafIndex");
  }
  return c;
}

class Wallet {
  constructor({ home } = {}) {
    this.home = path.resolve(home || Wallet.defaultHome());
    this.dir = path.join(this.home, "credentials");
  }

  static defaultHome(env = process.env) {
    return env.ZKGATE_HOME || path.join(os.homedir(), ".zkgate");
  }

  pathOf(name) {
    if (typeof name !== "string" || !NAME_RE.test(name)) {
      throw new ClientError("INVALID_NAME", "credential name must be 1-64 characters of letters, digits, '.', '_' or '-', starting with a letter or digit");
    }
    return path.join(this.dir, `${name}.json`);
  }

  #ensureDirs() {
    for (const d of [this.home, this.dir]) {
      if (!fs.existsSync(d)) {
        fs.mkdirSync(d, { recursive: true, mode: 0o700 });
        fs.chmodSync(d, 0o700); // mkdir's mode is subject to the umask
      }
    }
  }

  /** Create a fresh secret + salt, write a pending credential. Returns public facts only. */
  async keygen({ name = "default", profile = "v3", issuerUrl } = {}) {
    const file = this.pathOf(name);
    if (profile !== "v3" && profile !== "v4") throw new ClientError("INVALID_PROFILE", 'profile must be "v3" or "v4"');
    const secrets = { credentialSecret: randomField(), credentialSalt: randomField() };
    const commitment = await zk.commitment(secrets.credentialSecret, secrets.credentialSalt);
    const cred = {
      format: FORMAT, version: 1, profile,
      issuerUrl: issuerUrl === undefined ? undefined : stripSlash(issuerUrl),
      status: "pending", secrets, commitment, createdAt: nowSeconds(),
    };
    this.#ensureDirs();
    writeAtomic(file, JSON.stringify(cred, null, 2) + "\n", { exclusive: true });
    return { name, profile, status: "pending", commitment };
  }

  /** Read and validate a credential. Refuses group/other-accessible files. Includes secrets. */
  load(name) {
    const file = this.pathOf(name);
    let st;
    try {
      st = fs.statSync(file);
    } catch (e) {
      if (e.code === "ENOENT") throw new ClientError("WALLET_NOT_FOUND", `no credential named "${name}" in the wallet`);
      throw e;
    }
    if (st.mode & 0o077) {
      throw new ClientError("WALLET_PERMISSIONS", `credential "${name}" is accessible by other users (mode ${(st.mode & 0o777).toString(8)}); run chmod 600 on it`);
    }
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (_) {
      throw corrupt("unparseable JSON");
    }
    return validate(parsed);
  }

  /** Atomically replace an existing credential. */
  save(name, cred) {
    const file = this.pathOf(name);
    validate(cred);
    this.#ensureDirs();
    writeAtomic(file, JSON.stringify(cred, null, 2) + "\n");
  }

  list() {
    if (!fs.existsSync(this.dir)) return [];
    return fs.readdirSync(this.dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -5))
      .filter((n) => NAME_RE.test(n))
      .sort()
      .map((name) => {
        const c = this.load(name);
        return { name, profile: c.profile, status: c.status };
      });
  }

  /**
   * Public view of a credential: identifiers and hashes, never secrets or signature. The user's own
   * admin-assigned attributes are included only on request (`withAttributes`, for the local
   * terminal and the user's own portal), never by default.
   */
  summary(name, { withAttributes = false } = {}) {
    const c = this.load(name);
    const s = { name, profile: c.profile, status: c.status, commitment: c.commitment, createdAt: c.createdAt };
    if (c.issuerUrl) s.issuerUrl = c.issuerUrl;
    if (c.status === "issued") {
      s.leafIndex = c.leafIndex;
      s.issuedAt = c.issuedAt;
      s.issuerFingerprint = fingerprint(c.issuer);
      if (withAttributes) s.attributes = { ...c.attributes };
    }
    return s;
  }

  // Issuer key pins (public values). Keyed by issuer URL.
  #pinFile() { return path.join(this.home, "pins.json"); }

  /**
   * Pins on disk. No file means no pins (first use). A file that exists but cannot be read or parsed
   * fails closed (SR-09): treating it as "no pins" would let a corrupted or tampered file silently
   * re-pin whatever key the issuer advertises. Fix or delete the file, or pass --issuer-key.
   */
  #readPins() {
    let text;
    try {
      text = fs.readFileSync(this.#pinFile(), "utf8");
    } catch (e) {
      if (e.code === "ENOENT") return {};
      throw new ClientError("PINS_CORRUPT", "the issuer pin file exists but cannot be read; fix or delete it, or pass --issuer-key");
    }
    let p;
    try {
      p = JSON.parse(text);
    } catch (_) {
      p = null;
    }
    const entryOk = (e) => e && typeof e === "object" && zk.isCanonical(String(e.Ax)) && zk.isCanonical(String(e.Ay));
    if (!p || typeof p !== "object" || Array.isArray(p) || !Object.values(p).every(entryOk)) {
      throw new ClientError("PINS_CORRUPT", "the issuer pin file is not valid; fix or delete it, or pass --issuer-key");
    }
    return p;
  }

  getPin(issuerUrl) {
    return this.#readPins()[stripSlash(issuerUrl)];
  }

  setPin(issuerUrl, key) {
    const pins = this.#readPins();
    pins[stripSlash(issuerUrl)] = { Ax: String(key.Ax), Ay: String(key.Ay) };
    this.#ensureDirs();
    writeAtomic(this.#pinFile(), JSON.stringify(pins, null, 2) + "\n");
  }
}

/** Short stable id for an issuer key (public data; shown instead of the coordinates). */
function fingerprint(key) {
  return crypto.createHash("sha256").update(`${key.Ax}:${key.Ay}`).digest("hex").slice(0, 16);
}

module.exports = { Wallet, fingerprint, nowSeconds };
