#!/usr/bin/env node
"use strict";
// Attack Lab CLI.
//   attacks list
//   attacks run [<id>... | all] [--gateway URL --issuer URL [--admin-token T]] [--skip-waits] [--lenient-codes]
// Without --gateway nothing is sent: the requests and expectations are printed as JSON.
// With --gateway the requests are sent and actual vs expected is reported; --issuer is then
// required (it must be the issuer the gateway pins). Exit: 0 ok, 1 an attack did not behave as
// expected, 2 usage. The admin token may also come from ISSUER_ADMIN_TOKEN (never printed).
const lab = require("../src");

const usage = () => {
  console.error("usage: attacks list | attacks run [<id>...|all] [--gateway URL --issuer URL [--admin-token T]] [--skip-waits] [--lenient-codes]");
  return 2;
};

function parse(argv) {
  const o = { ids: [], flags: {} };
  const withValue = ["--gateway", "--issuer", "--admin-token"];
  const bool = ["--skip-waits", "--lenient-codes"];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (withValue.includes(a)) {
      if (!argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`${a} needs a value`);
      o.flags[a.slice(2)] = argv[++i];
    } else if (bool.includes(a)) o.flags[a.slice(2)] = true;
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else o.ids.push(a);
  }
  return o;
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "list") {
    console.log(JSON.stringify(lab.ATTACK_IDS.map((id) => {
      const a = lab.ATTACKS[id];
      return { id, title: a.title, scope: a.scope, floor: a.floor, obligations: a.obligations };
    }), null, 2));
    return 0;
  }
  if (cmd !== "run") return usage();
  let o;
  try { o = parse(rest); } catch (e) { console.error(e.message); return usage(); }
  const ids = o.ids.length === 0 || o.ids.includes("all") ? lab.ATTACK_IDS : o.ids;
  const unknown = ids.filter((i) => !lab.ATTACK_IDS.includes(i));
  if (unknown.length) { console.error(`unknown attack: ${unknown.join(", ")}`); return usage(); }
  const gateway = o.flags.gateway;
  if (gateway && !o.flags.issuer) { console.error("--gateway needs --issuer (the issuer the gateway pins)"); return usage(); }

  const world = await lab.createWorld({ issuerUrl: o.flags.issuer, adminToken: o.flags["admin-token"] || process.env.ISSUER_ADMIN_TOKEN });
  if (gateway) world.setChallengeSource(lab.httpChallengeSource(gateway));
  const send = gateway ? lab.httpSender(gateway) : null;
  const attacks = [];
  let pass = true;
  try {
    // one at a time: a revocation moves the root under proofs built earlier
    for (const id of ids) {
      const built = await lab.buildAttack(id, world);
      const entry = { ...built };
      if (send) {
        entry.run = await lab.runAttack(built, { send, wait: (s) => world.advance(s), skipWaits: !!o.flags["skip-waits"], lenientCodes: !!o.flags["lenient-codes"] });
        pass = pass && entry.run.pass;
      }
      attacks.push(entry);
    }
  } finally {
    await world.close();
    await lab.shutdown();
  }
  console.log(JSON.stringify({ sent: !!send, gateway: gateway || null, pass: send ? pass : null, attacks }, null, 2));
  return send && !pass ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => { console.error(`error: ${e && e.message}`); process.exit(1); },
);
