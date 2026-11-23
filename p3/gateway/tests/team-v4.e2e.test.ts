/**
 * END-TO-END against the team's real components, in-process:
 *   - the team issuer (issuer/src, profile v4, its own fresh key) over HTTP,
 *   - this gateway (integrated-access-v4 profile, REAL snarkjs verifier, committed v4 key),
 *   - the team Attack Lab library (client/attacks), which enrols real personas, generates REAL
 *     Groth16 proofs with the client prover and sends them to GET /challenge and POST /access.
 * Every attack must produce exactly the team's expected outcome and reason code, including the
 * 125 s wait of `replay_expired`: the gateway runs on an offset clock that the wait advances, so the
 * nonce really expires at the gateway (no real sleep, nothing skipped).
 * Skipped (BLOCKED) when the team issuer/client/circuit files are not present.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import { createServer, type Server } from 'node:http';
import { existsSync, mkdtempSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createApp } from '../src/app/createApp.js';
import { TEAM_ROOT } from '../src/config/env.js';
import { listen, testConfig } from './helpers.js';

const present = [
  'issuer/src/server.js',
  'client/attacks/src/index.js',
  'circuits/setup/integrated_access_v4.zkey',
].every((f) => existsSync(resolve(TEAM_ROOT, f)));
const require = createRequire(import.meta.url);
const ADMIN = 'e2e-admin-token-0123456789abcdef0123';

/* eslint-disable @typescript-eslint/no-explicit-any */
describe.skipIf(!present)('team v4 issuer + attack suite → this gateway (real proofs)', () => {
  let issuerApp: any;
  let lab: any;
  let world: any;
  let gwServer: Server;
  let gw: string;
  let issuerUrl: string;
  let offsetMs = 0;
  const clock = { now: () => Date.now() + offsetMs };

  beforeAll(async () => {
    const { loadConfig } = require(resolve(TEAM_ROOT, 'issuer/src/config.js'));
    const { buildServer } = require(resolve(TEAM_ROOT, 'issuer/src/server.js'));
    const keyDir = mkdtempSync(join(tmpdir(), 'zkag-ik-'));
    chmodSync(keyDir, 0o700);
    const config = loadConfig({
      ISSUER_PROFILE: 'v4',
      ISSUER_ADMIN_TOKEN: ADMIN,
      ISSUER_KEY_DIR: keyDir,
      ISSUER_DATA_DIR: mkdtempSync(join(tmpdir(), 'zkag-id-')),
      ISSUER_PORT: '0',
      ISSUER_LOG_LEVEL: 'silent',
    });
    issuerApp = await buildServer({ config });
    issuerUrl = await issuerApp.listen({ host: '127.0.0.1', port: 0 });
    const key = (await (await fetch(`${issuerUrl}/issuer`)).json()).issuer;

    const { app } = createApp({
      config: testConfig({
        ZK_PROFILE: 'integrated-access-v4',
        REGISTRY_URL: issuerUrl,
        REGISTRY_ADMIN_TOKEN: ADMIN,
        TRUSTED_ISSUER_AX: key.Ax,
        TRUSTED_ISSUER_AY: key.Ay,
        ALLOW_DEMO_KEYS: 'true',
        ZK_RATE_LIMIT_PER_MIN: '100000',
      }),
      clock,
    });
    gwServer = createServer(app);
    gw = await listen(gwServer);

    lab = require(resolve(TEAM_ROOT, 'client/attacks/src/index.js'));
    world = await lab.createWorld({ issuerUrl, adminToken: ADMIN });
    world.setChallengeSource(lab.httpChallengeSource(gw));
  });

  afterAll(async () => {
    await world?.close?.();
    await lab?.shutdown?.();
    gwServer?.close();
    await issuerApp?.close?.();
  });

  const ids = present
    ? (require(resolve(TEAM_ROOT, 'client/attacks/src/index.js')).ATTACK_IDS as string[])
    : [];
  it.each(ids)('attack %s behaves exactly as the team suite expects', async (id) => {
    const built = await lab.buildAttack(id, world);
    const run = await lab.runAttack(built, {
      send: lab.httpSender(gw),
      wait: (s: number) => {
        offsetMs += s * 1000;
      },
    });
    const summary = run.steps.map(
      (s: any) =>
        `${s.label}: expect ${s.expect.outcome}/${s.expect.code} got ${s.actual ? `${s.actual.status}/${s.actual.code}` : 'skipped'}`,
    );
    expect(run.pass, summary.join('\n')).toBe(true);
    expect(run.steps.filter((s: any) => s.skipped)).toEqual([]);
  });
});
