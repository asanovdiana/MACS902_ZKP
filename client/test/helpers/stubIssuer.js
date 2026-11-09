"use strict";
// In-process stub of issuer.api v2 for client tests: an admin-assigned enrolment per code (see `enrol`). Uses circuits/lib for signing and the tree,
// so the client is exercised against the real encodings. TEST-ONLY keys derived from public labels.
const http = require("http");
const crypto = require("crypto");
const zk = require("../../../circuits/lib");

const keyFrom = (label) => crypto.createHash("sha256").update(label).digest();
const FORBIDDEN = new Set(["credentialSecret", "credentialSalt", "secret", "salt"]);
const hasForbidden = (o) =>
  o !== null && typeof o === "object" && Object.entries(o).some(([k, v]) => FORBIDDEN.has(k) || hasForbidden(v));

/**
 * opts.profile "v3"|"v4"; opts.mode: undefined | "foreign-issuer" (credential signed and claimed by
 * a different key than /issuer) | "bad-signature" (claims the right key, signed by another) |
 * "altered-attributes" (returns different attributes than it signed).
 * Use `stub.enrol(attributes)` to create an enrolment and get its one-time code.
 */
async function startStubIssuer(opts = {}) {
  const profile = zk.profiles[opts.profile || "v3"];
  const prv = keyFrom("zkgate client test issuer");
  const other = keyFrom("zkgate client test FORGER");
  const pub = await zk.publicKey(prv);
  const otherPub = await zk.publicKey(other);
  const tree = await zk.createTree(profile);
  const revoked = new Set();
  const requests = [];
  const codes = new Map(); // code -> {attributes, used}
  let updatedAt = 1;

  const send = (res, status, obj) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  const err = (res, status, code) => send(res, status, { error: { code, message: code } });

  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      requests.push({ method: req.method, url: req.url, body: raw });
      try {
        const url = new URL(req.url, "http://x");
        if (req.method === "GET" && url.pathname === "/issuer") {
          return send(res, 200, { profile: profile.name, depth: profile.depth, issuer: { Ax: pub.Ax, Ay: pub.Ay } });
        }
        if (req.method === "GET" && url.pathname === "/root") {
          return send(res, 200, { root: tree.root.toString(), updatedAt, profile: profile.name, depth: profile.depth });
        }
        if (req.method === "POST" && url.pathname === "/credentials") {
          const body = JSON.parse(raw);
          if (hasForbidden(body)) return err(res, 400, "forbidden_field");
          if (Object.prototype.hasOwnProperty.call(body, "attributes")) return err(res, 400, "attributes_not_accepted");
          const { commitment, enrolmentCode } = body;
          const rec = codes.get(enrolmentCode);
          if (!rec) return err(res, 403, "invalid_enrolment_code");
          if (rec.used) return err(res, 409, "enrolment_used");
          rec.used = true;
          const attributes = rec.attributes;
          const M = await profile.message({ commitment, attributes });
          const forged = opts.mode === "foreign-issuer" || opts.mode === "bad-signature";
          const signature = await zk.sign(forged ? other : prv, M);
          tree.insert(BigInt(await profile.leaf({ commitment, attributes })));
          updatedAt += 1;
          const returned = opts.mode === "altered-attributes" ? { ...attributes, clearance: 3 } : attributes;
          const claim = opts.mode === "foreign-issuer" ? otherPub : pub;
          return send(res, 201, {
            credential: {
              profile: profile.name, attributes: returned, signature,
              issuer: { Ax: claim.Ax, Ay: claim.Ay }, leafIndex: tree.leaves.length - 1,
            },
          });
        }
        let m = /^\/credentials\/(\d+)\/revoke$/.exec(url.pathname);
        if (req.method === "POST" && m) {
          tree.delete(Number(m[1]));
          revoked.add(Number(m[1]));
          updatedAt += 1;
          return send(res, 200, { root: tree.root.toString() });
        }
        m = /^\/path\/(\d+)$/.exec(url.pathname);
        if (req.method === "GET" && m) {
          const i = Number(m[1]);
          if (i >= tree.leaves.length) return err(res, 404, "unknown_leaf");
          if (revoked.has(i)) return err(res, 410, "revoked");
          const p = zk.proofFor(tree, i);
          return send(res, 200, { profile: profile.name, ...p, pathIndices: p.pathIndices.map(Number) });
        }
        return err(res, 404, "not_found");
      } catch (e) {
        return err(res, 500, "internal");
      }
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url, profile, pub, requests, tree,
    /** Admin-side: create an enrolment for `attributes`; returns the one-time code. */
    enrol: (attributes) => {
      const code = crypto.randomBytes(24).toString("base64url");
      codes.set(code, { attributes, used: false });
      return code;
    },
    revoke: (i) => fetch(`${url}/credentials/${i}/revoke`, { method: "POST" }),
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  };
}

module.exports = { startStubIssuer };
