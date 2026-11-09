import { createServer } from 'node:http';
import { createApp } from './app/createApp.js';
import { loadConfig } from './config/env.js';
import { attachEventStream } from './events/ws.js';
import { SnarkjsGroth16Verifier } from './verification/groth16.js';

const config = loadConfig();
const { app, ctx } = createApp({ config });
const server = createServer(app);
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
attachEventStream(server, ctx.bus, ctx.operator, config.allowedOrigins);

const art = ctx.artifacts();
if (art.status === 'ready' && ctx.verifier instanceof SnarkjsGroth16Verifier) {
  await ctx.verifier.warmUp(art.vkey, art.vkey.nPublic);
}

server.listen(config.GATEWAY_PORT, config.GATEWAY_HOST, () => {
  const elig = ctx.pipeline.authorizationEligible();
  ctx.logger.info(
    { port: config.GATEWAY_PORT, profile: ctx.profile.id, artifacts: ctx.artifacts().status },
    'ZK gateway listening',
  );
  if (!elig.eligible)
    ctx.logger.warn(
      { missing: elig.missing },
      'REAL ZK AUTHORIZATION BLOCKED: sessions will not be issued',
    );
  if (config.usingDevSecrets.length)
    ctx.logger.warn({ secrets: config.usingDevSecrets }, 'development secrets in use');
});

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
