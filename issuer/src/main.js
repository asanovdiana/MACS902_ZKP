"use strict";
// Entry point: `node src/main.js` (or `npm start --prefix issuer`). Configuration: src/config.js.
const { loadConfig } = require("./config");
const { buildServer } = require("./server");

async function start(env = process.env) {
  const config = loadConfig(env);
  const app = await buildServer({ config });
  const address = await app.listen({ host: config.host, port: config.port });
  app.log.info({ address, profile: config.profile }, "issuer listening");
  return { app, address, config };
}

module.exports = { start };

/* c8 ignore start */
if (require.main === module) {
  start().catch((e) => {
    console.error(JSON.stringify({ level: "fatal", msg: "issuer failed to start", error: e.message }));
    process.exit(1);
  });
}
/* c8 ignore stop */
