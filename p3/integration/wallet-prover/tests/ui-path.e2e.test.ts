/**
 * The exact path the demo UI takes, with real components:
 *   gateway POST /api/zk/challenges → wallet-prover (team client, seeded wallet) → gateway /api/zk/verify
 * Expect: Alice → File Share GRANTED with a session; Bob → File Share refused by his own client
 * (no proof exists); Carol → Admin Panel GRANTED; Alice after revocation → refused.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createRequire } from 'node:module';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { chmodSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { TEAM_ROOT, teamAvailable } from '../src/team.js';
import { createProver } from '../src/server.js';
import { createApp } from '../../../gateway/src/app/createApp.js';
import { loadConfig } from '../../../gateway/src/config/env.js';

const require = createRequire(import.meta.url);
const ADMIN = 'ui-path-admin-token-0123456789abcdef';
const listen = (s: Server) =>
  new Promise<string>((r) =>
    s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)),
  );

/* eslint-disable @typescript-eslint/no-explicit-any */
describe.skipIf(!teamAvailable())('UI path: gateway ↔ team wallet prover ↔ team issuer', () => {
  let issuerApp: any;
  let prover: ReturnType<typeof createProver>;
  let guarded: ReturnType<typeof createProver>;
  let gwUrl: string;
  let gwApp: any;
  let issuerUrl: string;
  const servers: Server[] = [];

  beforeAll(async () => {
    const { loadConfig: issuerConfig } = require(resolve(TEAM_ROOT, 'issuer/src/config.js'));
    const { buildServer } = require(resolve(TEAM_ROOT, 'issuer/src/server.js'));
    const keyDir = mkdtempSync(join(tmpdir(), 'zkag-k-'));
    chmodSync(keyDir, 0o700);
    issuerApp = await buildServer({
      config: issuerConfig({
        ISSUER_PROFILE: 'v4',
        ISSUER_ADMIN_TOKEN: ADMIN,
        ISSUER_KEY_DIR: keyDir,
        ISSUER_DATA_DIR: mkdtempSync(join(tmpdir(), 'zkag-d-')),
        ISSUER_LOG_LEVEL: 'silent',
      }),
    });
    issuerUrl = await issuerApp.listen({ host: '127.0.0.1', port: 0 });
    const walletRoot = mkdtempSync(join(tmpdir(), 'zkag-w-'));
    const { seedPersonas } = require(resolve(TEAM_ROOT, 'issuer/scripts/seed-personas.js'));
    await seedPersonas({ issuerUrl, adminToken: ADMIN, homeRoot: walletRoot });
    const key = (await (await fetch(`${issuerUrl}/issuer`)).json()).issuer;

    const { app } = createApp({
      config: loadConfig({
        NODE_ENV: 'test',
        LOG_LEVEL: 'silent',
        ZK_PROFILE: 'integrated-access-v4',
        REGISTRY_URL: issuerUrl,
        REGISTRY_ADMIN_TOKEN: ADMIN,
        TRUSTED_ISSUER_AX: key.Ax,
        TRUSTED_ISSUER_AY: key.Ay,
        ALLOW_DEMO_KEYS: 'true',
        ROOT_CACHE_MS: '0',
      }),
    });
    gwApp = app;
    const gwServer = createServer(app);
    servers.push(gwServer);
    const gatewayUrl = await listen(gwServer);
    prover = createProver({
      walletRoot,
      issuerUrl,
      gatewayUrl,
      adminToken: ADMIN,
      uiOrigins: [],
      requireOperator: false,
    });
    guarded = createProver({
      walletRoot,
      issuerUrl,
      gatewayUrl,
      adminToken: ADMIN,
      uiOrigins: [],
      requireOperator: true,
    });
    gwUrl = gatewayUrl;
  });

  afterAll(async () => {
    await prover?.close();
    servers.forEach((s) => s.close());
    await issuerApp?.close();
  });

  const attempt = async (persona: string, resource: string) => {
    const challenge = (
      await request(gwApp).post('/api/zk/challenges').send({ resource }).expect(201)
    ).body;
    const p = await request(prover.app)
      .post('/v1/prover/proofs')
      .send({
        credentialRef: `cred-${persona}`,
        challenge: {
          challengeId: challenge.challengeId,
          profile: challenge.scheme.profile,
          nonce: challenge.nonce,
          resourceField: challenge.resourceField,
          epoch: challenge.epoch,
          now: challenge.now,
          policy: challenge.policy,
        },
      });
    if (p.status !== 200) return { prover: p.status, code: p.body.error.code };
    const v = await request(gwApp).post('/api/zk/verify').send({
      challengeId: challenge.challengeId,
      proof: p.body.proof,
      publicSignals: p.body.publicSignals,
    });
    return {
      prover: 200,
      status: v.status,
      decision: v.body.decision,
      reason: v.body.reason,
      cookie: v.headers['set-cookie'],
      provingMs: p.body.provingMs,
    };
  };

  it('REGRESSION: proving and attack runs require a gateway operator session', async () => {
    const body = {
      credentialRef: 'cred-alice',
      challenge: {
        profile: 'integrated-access-v4',
        nonce: '1',
        resourceField: '1',
        epoch: '1',
        now: '1',
        policy: { roleMask: '15', deptMask: '15', minClearance: '0', requireDevice: '1' },
      },
    };
    expect((await request(guarded.app).post('/v1/prover/proofs').send(body)).status).toBe(401);
    expect(
      (
        await request(guarded.app)
          .post('/v1/prover/proofs')
          .set('Cookie', 'zkag_operator=forged')
          .send(body)
      ).status,
    ).toBe(401);
    expect((await request(guarded.app).post('/v1/attacks/baseline/run')).status).toBe(401);
    const login = await fetch(`${gwUrl}/api/operator/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'dev-operator-token-change-me-000000' }),
    });
    const op = login.headers.get('set-cookie')!.split(';')[0]!;
    expect((await request(guarded.app).get('/v1/attacks').set('Cookie', op)).status).toBe(200);
  });
  it('reports ready with the seeded personas', async () => {
    const h = await request(prover.app).get('/v1/health');
    expect(h.body).toMatchObject({ proverReady: true, personas: ['alice', 'bob', 'carol'] });
  });
  it('Alice → File Share: GRANTED with a resource-scoped session', async () => {
    const r = await attempt('alice', 'file-share');
    expect(r).toMatchObject({ prover: 200, status: 200, decision: 'granted' });
    expect(String(r.cookie)).toMatch(/zkag_file_share=.*Path=\/svc\/file-share/);
    expect(r.provingMs).toBeGreaterThan(0);
  });
  it('Bob → File Share: his own client refuses, no proof exists', async () => {
    expect(await attempt('bob', 'file-share')).toMatchObject({
      prover: 422,
      code: 'POLICY_NOT_SATISFIED',
    });
  });
  it('Carol → Admin Panel: GRANTED; Bob → Wiki: GRANTED', async () => {
    expect(await attempt('carol', 'admin-panel')).toMatchObject({ decision: 'granted' });
    expect(await attempt('bob', 'wiki')).toMatchObject({ decision: 'granted' });
  });
  it('after revoking Alice her client cannot prove membership any more', async () => {
    const login = await request(gwApp)
      .post('/api/operator/login')
      .send({ token: 'dev-operator-token-change-me-000000' });
    const op = String(login.headers['set-cookie']).split(';')[0]!;
    expect(
      (await request(gwApp).post('/api/admin/credentials/leaf-0/revoke').set('Cookie', op).send({}))
        .status,
    ).toBe(200);
    const r = await attempt('alice', 'wiki');
    expect(r.prover).toBe(422);
  });
  it('lists and runs a team attack through the adapter', async () => {
    const list = await request(prover.app).get('/v1/attacks');
    expect(list.body.ids).toContain('forged');
    const run = await request(prover.app).post('/v1/attacks/forged/run');
    expect(run.status).toBe(200);
    expect(run.body.pass).toBe(true);
  });
});
