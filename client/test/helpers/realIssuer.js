"use strict";
// `clock` (unix s) pins the issuer clock so fixed-NOW tests agree with it (no wall-clock time bomb).
// The REAL issuer (issuer/src/server.js) listening on 127.0.0.1:0 with temp key and data
// directories. TEST-ONLY: the key is generated fresh in a temp dir and removed on close.
const { buildServer } = require("../../../issuer/src/server");
const { mk, rm } = require("./tmp");
const { toInts } = require("./attrs");

async function startRealIssuer({ profile = "v4", clock } = {}) {
  const keyDir = mk();
  const dataDir = mk();
  const adminToken = "client-test-admin-token-0123456789";
  const config = { profile, keyDir, dataDir, host: "127.0.0.1", port: 0, stalenessSeconds: 30, historyRetentionSeconds: 900, adminToken };
  const auth = { authorization: `Bearer ${adminToken}`, "content-type": "application/json" };
  let seq = 0;
  const app = await buildServer({ config, ...(clock ? { clock } : {}), logStream: { write() {} } });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const url = `http://127.0.0.1:${app.server.address().port}`;
  return {
    url,
    adminToken,
    /** Admin-side: create an enrolment for `attributes` (integers; v4 includes expiry); returns the one-time code. */
    enrol: async (attributes, employeeId = `emp-${++seq}`) => {
      const r = await fetch(`${url}/admin/enrolments`, { method: "POST", headers: auth, body: JSON.stringify({ employeeId, attributes: toInts(profile, attributes) }) });
      if (r.status !== 201) throw new Error(`enrolment failed: ${r.status} ${await r.text()}`);
      return (await r.json()).code;
    },
    revoke: async (leafIndex) => {
      const r = await fetch(`${url}/credentials/${leafIndex}/revoke`, { method: "POST", headers: auth });
      if (r.status !== 200) throw new Error(`revoke failed: ${r.status}`);
    },
    close: async () => { await app.close(); rm(keyDir); rm(dataDir); },
  };
}

module.exports = { startRealIssuer };
