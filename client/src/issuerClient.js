"use strict";
// issuer.api v2 client. The request body for POST /credentials is built from an allow-list
// ({commitment, enrolmentCode}); credentialSecret and credentialSalt have no way into any request
// (floor 6), and there is no way to send attributes: the admin assigns them (SR-03). The path cache
// follows the contract's privacy note: one path fetch per root.
const zk = require("../../circuits/lib");
const { ClientError } = require("./errors");
const { requestJson, stripSlash } = require("./http");

const CODE_RE = /^[A-Za-z0-9_-]{16,128}$/;

class IssuerClient {
  constructor({ baseUrl, fetch = globalThis.fetch, timeoutMs = 10000 }) {
    if (typeof baseUrl !== "string" || !/^https?:\/\//.test(baseUrl)) {
      throw new ClientError("INVALID_REQUEST", "issuer URL must start with http:// or https://");
    }
    this.baseUrl = stripSlash(baseUrl);
    this._fetch = fetch;
    this._timeoutMs = timeoutMs;
    this._paths = new Map(); // leafIndex -> path response (valid while its root is current)
  }

  async _call(method, p, body) {
    const { json } = await requestJson({
      fetch: this._fetch, method, url: this.baseUrl + p, body, timeoutMs: this._timeoutMs, who: "ISSUER",
    });
    return json;
  }

  /** GET /issuer -> {profile, depth, issuer:{Ax,Ay}} */
  getIssuer() { return this._call("GET", "/issuer"); }

  /** GET /root -> {root, updatedAt, profile, depth} */
  getRoot() { return this._call("GET", "/root"); }

  /**
   * POST /credentials. Only `commitment` and `enrolmentCode` are read from the argument; any other
   * property (a secret, a salt, attributes) is ignored, so a caller cannot send one by accident.
   * The issuer answers with the credential for the attributes the admin assigned.
   */
  async requestCredential(arg) {
    const commitment = arg && arg.commitment;
    const enrolmentCode = arg && arg.enrolmentCode;
    if (typeof commitment !== "string" || !zk.isCanonical(commitment) || commitment === "0") {
      throw new ClientError("INVALID_REQUEST", "commitment must be a canonical decimal string");
    }
    if (typeof enrolmentCode !== "string" || !CODE_RE.test(enrolmentCode)) {
      throw new ClientError("INVALID_REQUEST", "an enrolment code from your administrator is required");
    }
    const res = await this._call("POST", "/credentials", { commitment, enrolmentCode });
    if (!res || typeof res.credential !== "object" || res.credential === null) {
      throw new ClientError("ISSUER_BAD_RESPONSE", "issuer reply has no credential");
    }
    return res;
  }

  /**
   * GET /path/:leafIndex, cached per root: the (cheap, index-free) root is fetched each time and the
   * path only when the root moved, so the registry sees the leaf index once per root change.
   * Throws ClientError code "revoked" (HTTP 410) for a revoked leaf.
   */
  async getPath(leafIndex) {
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) {
      throw new ClientError("INVALID_REQUEST", "leaf index must be a non-negative integer");
    }
    const { root } = await this.getRoot();
    const hit = this._paths.get(leafIndex);
    if (hit && hit.root === root) return hit;
    const p = await this._call("GET", `/path/${leafIndex}`);
    this._paths.set(leafIndex, p);
    return p;
  }
}

module.exports = { IssuerClient };
