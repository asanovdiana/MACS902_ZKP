/**
 * Exercises the session / proxy / nullifier path for the PROPOSED zkag-access-v1 profile.
 * P1 has not delivered such a circuit, so the Groth16 verifier here is an explicit TEST
 * DOUBLE injected through `testOverrides` (not selectable via configuration). These tests
 * validate the gateway's own logic, not cryptographic soundness.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createServer, type Server } from 'node:http';
import WebSocket from 'ws';
import {
  POLICIES,
  RESOURCES,
  policyPublicParams,
  signAssertion,
  type ResourceId,
} from '@zkag/shared';
import { createApp } from '../src/app/createApp.js';
import { attachEventStream } from '../src/events/ws.js';
import { PROFILES } from '../src/verification/profiles.js';
import type { ArtifactState } from '../src/verification/artifacts.js';
import type { Groth16Verifier } from '../src/verification/groth16.js';
import {
  FakeClock,
  FakeRegistry,
  TEST_OPERATOR_TOKEN,
  cookieFrom,
  listen,
  testConfig,
} from './helpers.js';
import { createWiki } from '../../services/src/wiki.js';
import { createFileShare } from '../../services/src/fileShare.js';
import { createAdminPanel } from '../../services/src/adminPanel.js';

const ISSUER = { ax: '111', ay: '222' };
const ROOT = '9876543210';
const ZK_SECRET = 'test-zk-assertion-secret-0123456789abcdef';
const SSO_SECRET = 'test-sso-assertion-secret-0123456789abcdef';

/** TEST DOUBLE: "valid" iff pi_a[0] === '1'. */
const doubleVerifier: Groth16Verifier = {
  kind: 'test-double',
  verify: async (_vk, _signals, proof) => ({ valid: proof.pi_a[0] === '1', durationMs: 0.1 }),
};
const reviewedArtifacts =
  (reviewed = true): (() => ArtifactState) =>
  () => ({
    status: 'ready',
    reviewed,
    vkeySha256: 'test-double',
    vkey: { protocol: 'groth16', curve: 'bn128', nPublic: 12 },
    manifest: {
      circuitId: 'zkag_access_v1',
      profile: 'zkag-access-v1',
      version: 'test',
      proofSystem: 'groth16',
      curve: 'bn128',
      nPublic: 12,
      publicSignals: [...PROFILES['zkag-access-v1'].signals],
      securityStatus: 'test',
      files: { verificationKey: { path: 'x', sha256: 'x' } },
    },
  });
const proof = (valid = true) => ({
  pi_a: [valid ? '1' : '2', '2', '1'],
  pi_b: [
    ['1', '2'],
    ['3', '4'],
    ['1', '0'],
  ],
  pi_c: ['5', '6', '1'],
  protocol: 'groth16',
  curve: 'bn128',
});

const services: Server[] = [];
const upstream: Record<string, string> = {};
beforeAll(async () => {
  const secrets = { zk: ZK_SECRET, sso: SSO_SECRET };
  const apps = {
    wiki: createWiki(secrets),
    'file-share': createFileShare(secrets),
    'admin-panel': createAdminPanel(secrets),
  };
  for (const [k, a] of Object.entries(apps)) {
    const s = createServer(a);
    services.push(s);
    upstream[k] = await listen(s);
  }
});
afterAll(() => services.forEach((s) => s.close()));

function setup(opts: { reviewed?: boolean; issuer?: boolean; maxPerEpoch?: string } = {}) {
  const clock = new FakeClock();
  const registry = new FakeRegistry(ROOT);
  const config = testConfig({
    ZK_PROFILE: 'zkag-access-v1',
    ASSERTION_SECRET_ZK: ZK_SECRET,
    UPSTREAM_WIKI_URL: upstream.wiki!,
    UPSTREAM_FILE_SHARE_URL: upstream['file-share']!,
    UPSTREAM_ADMIN_PANEL_URL: upstream['admin-panel']!,
    NULLIFIER_MAX_PER_EPOCH: opts.maxPerEpoch ?? '1',
    ...(opts.issuer === false
      ? {}
      : { TRUSTED_ISSUER_AX: ISSUER.ax, TRUSTED_ISSUER_AY: ISSUER.ay }),
  });
  const { app, ctx } = createApp({
    config,
    clock,
    registry,
    testOverrides: {
      verifier: doubleVerifier,
      artifacts: reviewedArtifacts(opts.reviewed ?? true),
    },
  });
  const challenge = async (resource: ResourceId) =>
    (await request(app).post('/api/zk/challenges').send({ resource }).expect(201)).body;
  const signals = (
    c: { nonce: string; epoch: string; resource: ResourceId },
    o: Record<string, string> = {},
  ) => {
    const p = policyPublicParams(POLICIES[c.resource]);
    const v: Record<string, string> = {
      nullifier: o.nullifier ?? '424242',
      root: ROOT,
      nonce: c.nonce,
      resourceId: RESOURCES[c.resource].fieldId.toString(),
      epoch: c.epoch,
      roleMask: p.roleMask.toString(),
      deptMask: p.deptMask.toString(),
      minClearance: p.minClearance.toString(),
      requireDevice: p.requireDevice.toString(),
      currentTime: String(Math.floor(clock.now() / 1000)),
      issuerAx: ISSUER.ax,
      issuerAy: ISSUER.ay,
      ...o,
    };
    return PROFILES['zkag-access-v1'].signals.map((n) => v[n]!);
  };
  const grant = async (resource: ResourceId, o: Record<string, string> = {}) => {
    const c = await challenge(resource);
    return request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: proof(), publicSignals: signals(c, o) });
  };
  return { app, ctx, clock, registry, challenge, signals, grant };
}

describe('full-capability profile: authorization, sessions and proxy', () => {
  it('valid user + satisfied policy → granted, resource-scoped HttpOnly cookie, proxied content', async () => {
    const { app, grant } = setup();
    const res = await grant('wiki');
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('granted');
    const raw = (res.headers['set-cookie'] as unknown as string[])[0]!;
    expect(raw).toMatch(/HttpOnly/);
    expect(raw).toMatch(/SameSite=Strict/);
    expect(raw).toMatch(/Path=\/svc\/wiki/);
    expect(raw).toMatch(/Max-Age=600/);
    const cookie = cookieFrom(res.headers['set-cookie'], 'zkag_wiki')!;
    const page = await request(app).get('/svc/wiki/').set('Cookie', cookie);
    expect(page.status).toBe(200);
    expect(page.body.viewer.frontDoor).toBe('zk-gateway');
    expect(page.body.viewer.subject).toMatch(/^zk-/);
    expect(page.headers['set-cookie']).toBeUndefined();
  });

  it('cross-resource: a Wiki session does not authorize Admin Panel', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom((await grant('wiki')).headers['set-cookie'], 'zkag_wiki')!;
    const sid = cookie.split('=')[1];
    const res = await request(app)
      .get('/svc/admin-panel/')
      .set('Cookie', `zkag_admin_panel=${sid}`);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('SESSION_WRONG_RESOURCE');
  });

  it('invalid / missing session is rejected', async () => {
    const { app } = setup();
    expect((await request(app).get('/svc/wiki/')).body.error.code).toBe('SESSION_MISSING');
    expect(
      (await request(app).get('/svc/wiki/').set('Cookie', 'zkag_wiki=forgedsessionid')).body.error
        .code,
    ).toBe('SESSION_INVALID');
  });

  it('session expires after 10 minutes (re-prove required)', async () => {
    const { app, grant, clock } = setup();
    const cookie = cookieFrom((await grant('wiki')).headers['set-cookie'], 'zkag_wiki')!;
    clock.advance(600_000);
    expect((await request(app).get('/svc/wiki/').set('Cookie', cookie)).body.error.code).toBe(
      'SESSION_EXPIRED',
    );
  });

  it('revocation: a root change invalidates already-issued sessions', async () => {
    const { app, grant, registry } = setup();
    const cookie = cookieFrom(
      (await grant('file-share')).headers['set-cookie'],
      'zkag_file_share',
    )!;
    expect((await request(app).get('/svc/file-share/').set('Cookie', cookie)).status).toBe(200);
    registry.setRoot('1111');
    const res = await request(app).get('/svc/file-share/').set('Cookie', cookie);
    expect(res.status).toBe(401);
    expect(['SESSION_INVALID', 'SESSION_REVOKED_ROOT_CHANGED']).toContain(res.body.error.code);
  });

  it('logout invalidates the session', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom((await grant('wiki')).headers['set-cookie'], 'zkag_wiki')!;
    await request(app).post('/svc/wiki/_zkag/logout').set('Cookie', cookie).expect(200);
    expect((await request(app).get('/svc/wiki/').set('Cookie', cookie)).status).toBe(401);
  });

  it('replay → 409; nonce/resource/epoch/policy/issuer/time mismatches are denied', async () => {
    const { app, challenge, signals } = setup();
    const c = await challenge('wiki');
    await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: proof(), publicSignals: signals(c) })
      .expect(200);
    expect(
      (
        await request(app)
          .post('/api/zk/verify')
          .send({ challengeId: c.challengeId, proof: proof(), publicSignals: signals(c) })
      ).status,
    ).toBe(409);
    const cases: Array<[Record<string, string>, string, ResourceId?]> = [
      [{ nonce: '5' }, 'NONCE_MISMATCH'],
      [{ resourceId: '3' }, 'RESOURCE_MISMATCH'],
      [{ epoch: '1' }, 'EPOCH_MISMATCH'],
      [{ minClearance: '0' }, 'POLICY_PARAMS_MISMATCH', 'admin-panel'],
      [{ roleMask: '15' }, 'POLICY_PARAMS_MISMATCH', 'file-share'],
      [{ issuerAx: '999' }, 'ISSUER_UNTRUSTED'],
      [{ currentTime: '1' }, 'TIME_OUT_OF_RANGE'],
      [{ root: '1' }, 'ROOT_MISMATCH'],
    ];
    for (const [o, reason, resource] of cases) {
      const ch = await challenge(resource ?? 'wiki');
      const r = await request(app)
        .post('/api/zk/verify')
        .send({ challengeId: ch.challengeId, proof: proof(), publicSignals: signals(ch, o) });
      expect(r.body.reason, JSON.stringify(o)).toBe(reason);
      expect(r.headers['set-cookie']).toBeUndefined();
    }
  });

  it('invalid proof → denied', async () => {
    const { app, challenge, signals } = setup();
    const c = await challenge('wiki');
    const r = await request(app)
      .post('/api/zk/verify')
      .send({ challengeId: c.challengeId, proof: proof(false), publicSignals: signals(c) });
    expect(r.body.reason).toBe('PROOF_INVALID');
  });

  it('duplicate nullifier in the same epoch → rate limited (429), and an invalid proof never consumes a nullifier', async () => {
    const { app, challenge, signals, grant } = setup();
    const c = await challenge('wiki');
    await request(app)
      .post('/api/zk/verify')
      .send({
        challengeId: c.challengeId,
        proof: proof(false),
        publicSignals: signals(c, { nullifier: '77' }),
      });
    expect((await grant('wiki', { nullifier: '77' })).status).toBe(200);
    const spam = await grant('wiki', { nullifier: '77' });
    expect(spam.status).toBe(429);
    expect(spam.body.reason).toBe('NULLIFIER_RATE_LIMITED');
    expect((await grant('file-share', { nullifier: '77' })).status).toBe(200);
  });

  it('concurrent duplicate nullifiers: only one is accepted', async () => {
    const { app, challenge, signals } = setup();
    const cs = await Promise.all([1, 2, 3, 4].map(() => challenge('wiki')));
    const rs = await Promise.all(
      cs.map((c) =>
        request(app)
          .post('/api/zk/verify')
          .send({
            challengeId: c.challengeId,
            proof: proof(),
            publicSignals: signals(c, { nullifier: '88' }),
          }),
      ),
    );
    expect(rs.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it('fails closed without a trusted issuer or without an accepted security review', async () => {
    expect((await setup({ issuer: false }).grant('wiki')).body.reason).toBe(
      'ISSUER_NOT_CONFIGURED',
    );
    const r = await setup({ reviewed: false }).grant('wiki');
    expect(r.body.decision).toBe('blocked');
    expect(r.body.missingGuarantees).toContain('Accepted security review of circuit artifacts');
  });

  it('readiness is "ready" only when everything is established', async () => {
    const { app } = setup();
    const r = await request(app).get('/readyz');
    expect(r.body.zkAuthorization).toBe('ready');
  });

  it('proxy: path traversal and unknown resources are rejected; method allowlist enforced', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom(
      (await grant('file-share')).headers['set-cookie'],
      'zkag_file_share',
    )!;
    expect(
      (
        await request(app)
          .get('/svc/file-share/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd')
          .set('Cookie', cookie)
      ).status,
    ).toBe(400);
    expect((await request(app).get('/svc/evil.example/x')).status).toBe(404);
    expect(
      (await request(app).delete('/svc/file-share/files/f-arch-001').set('Cookie', cookie)).status,
    ).toBe(405);
    const dl = await request(app)
      .get('/svc/file-share/files/f-arch-001/download')
      .set('Cookie', cookie);
    expect(dl.status).toBe(200);
    expect(dl.headers['content-disposition']).toMatch(/attachment/);
  });

  it('client-supplied identity/assertion headers are stripped before reaching services', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom(
      (await grant('admin-panel')).headers['set-cookie'],
      'zkag_admin_panel',
    )!;
    const forgedAssertion = await signAssertion(SSO_SECRET, {
      frontDoor: 'sso-baseline',
      resource: 'admin-panel',
      subject: 'carol',
      display: 'carol',
    });
    const r = await request(app)
      .get('/svc/admin-panel/')
      .set('Cookie', cookie)
      .set('x-zkag-assertion', forgedAssertion)
      .set('x-user-role', 'admin');
    expect(r.status).toBe(200);
    expect(r.body.viewer.frontDoor).toBe('zk-gateway');
    expect(r.body.viewer.subject).not.toBe('carol');
  });

  it('safe admin action through the proxy (POST JSON)', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom(
      (await grant('admin-panel')).headers['set-cookie'],
      'zkag_admin_panel',
    )!;
    const r = await request(app)
      .post('/svc/admin-panel/actions/acknowledge-alert')
      .set('Cookie', cookie)
      .send({ alertId: 'ALR-1042' });
    expect(r.status).toBe(200);
    expect(r.body.alert.acknowledged).toBe(true);
  });

  it('cross-origin state-changing requests are rejected (CSRF)', async () => {
    const { app } = setup();
    const r = await request(app)
      .post('/api/zk/challenges')
      .set('Origin', 'https://evil.example')
      .send({ resource: 'wiki' });
    expect(r.status).toBe(403);
    expect(
      (
        await request(app)
          .post('/api/zk/challenges')
          .set('Content-Type', 'text/plain')
          .send('{"resource":"wiki"}')
      ).status,
    ).toBe(415);
  });

  it('oversized or malformed payloads are rejected safely', async () => {
    const { app, challenge } = setup();
    const c = await challenge('wiki');
    const huge = await request(app)
      .post('/api/zk/verify')
      .send({
        challengeId: c.challengeId,
        proof: proof(),
        publicSignals: Array(20).fill('9'.repeat(70)),
        junk: 'x'.repeat(40_000),
      });
    expect(huge.status).toBe(413);
    const bad = await request(app)
      .post('/api/zk/verify')
      .set('Content-Type', 'application/json')
      .send('{"challengeId":');
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe('INVALID_JSON');
    const big = await request(app)
      .post('/api/zk/verify')
      .send({
        challengeId: c.challengeId,
        proof: { ...proof(), pi_a: ['1'.repeat(200), '1', '1'] },
        publicSignals: ['1'],
      });
    expect(big.status).toBe(400);
  });

  it('administrative endpoints require operator authentication', async () => {
    const { app } = setup();
    expect(
      (await request(app).post('/api/admin/credentials/cred-bob/revoke').send({})).status,
    ).toBe(401);
    expect((await request(app).get('/api/operator/events')).status).toBe(401);
    expect((await request(app).post('/api/operator/login').send({ token: 'wrong' })).status).toBe(
      401,
    );
    const login = await request(app)
      .post('/api/operator/login')
      .send({ token: TEST_OPERATOR_TOKEN })
      .expect(200);
    const op = cookieFrom(login.headers['set-cookie'], 'zkag_operator')!;
    expect((await request(app).get('/api/operator/events').set('Cookie', op)).status).toBe(200);
  });

  it('events never contain session identifiers or private data', async () => {
    const { ctx, grant } = setup();
    const res = await grant('wiki');
    const sid = cookieFrom(res.headers['set-cookie'], 'zkag_wiki')!.split('=')[1]!;
    const dump = JSON.stringify(ctx.bus.recent());
    expect(dump).not.toContain(sid);
    expect(dump).toContain('verification.completed');
  });
});

describe('direct upstream bypass', () => {
  it('services reject requests without a front-door assertion, with wrong audience, or untrusted signer', async () => {
    expect((await request(upstream.wiki!).get('/')).status).toBe(401);
    const wrongAud = await signAssertion(ZK_SECRET, {
      frontDoor: 'zk-gateway',
      resource: 'file-share',
      subject: 's',
      display: 'd',
    });
    expect(
      (await request(upstream.wiki!).get('/').set('x-zkag-assertion', wrongAud)).body.error.code,
    ).toBe('ASSERTION_WRONG_AUDIENCE');
    const rogue = await signAssertion('rogue-secret-rogue-secret-rogue-secret-00', {
      frontDoor: 'zk-gateway',
      resource: 'wiki',
      subject: 's',
      display: 'd',
    });
    expect(
      (await request(upstream.wiki!).get('/').set('x-zkag-assertion', rogue)).body.error.code,
    ).toBe('ASSERTION_INVALID');
  });
});

describe('authenticated WebSocket event stream', () => {
  it('rejects unauthenticated / cross-origin subscriptions and streams to operators', async () => {
    const { app, ctx } = setup();
    const server = createServer(app);
    attachEventStream(server, ctx.bus, ctx.operator, ctx.config.allowedOrigins);
    const base = await listen(server);
    const wsUrl = base.replace('http', 'ws') + '/api/events/ws';
    const tryOpen = (headers: Record<string, string>) =>
      new Promise<{ ok: boolean; first?: unknown }>((resolve) => {
        const ws = new WebSocket(wsUrl, { headers });
        ws.on('message', (m) => {
          resolve({ ok: true, first: JSON.parse(String(m)) });
          ws.close();
        });
        ws.on('error', () => resolve({ ok: false }));
        ws.on('unexpected-response', () => resolve({ ok: false }));
      });
    expect((await tryOpen({ Origin: 'http://localhost:5173' })).ok).toBe(false);
    const login = await request(app)
      .post('/api/operator/login')
      .send({ token: TEST_OPERATOR_TOKEN });
    const op = cookieFrom(login.headers['set-cookie'], 'zkag_operator')!;
    expect((await tryOpen({ Origin: 'https://evil.example', Cookie: op })).ok).toBe(false);
    const ok = await tryOpen({ Origin: 'http://localhost:5173', Cookie: op });
    expect(ok.ok).toBe(true);
    expect((ok.first as { kind: string }).kind).toBe('snapshot');
    server.close();
  });
});

describe('security review regressions', () => {
  it('a blocked (ineligible) authorization does not consume the nullifier budget', async () => {
    const { ctx, grant } = setup({ reviewed: false });
    const r = await grant('wiki', { nullifier: '991' });
    expect(r.body.decision).toBe('blocked');
    expect(ctx.nullifiers.size).toBe(0);
  });
  it('rejects non-canonical (percent-encoded) resource segments in proxy paths', async () => {
    const { app, grant } = setup();
    const cookie = cookieFrom((await grant('wiki')).headers['set-cookie'], 'zkag_wiki')!;
    const r = await request(app).get('/svc/wik%69/articles').set('Cookie', cookie);
    expect(r.status).toBe(400);
  });
});
