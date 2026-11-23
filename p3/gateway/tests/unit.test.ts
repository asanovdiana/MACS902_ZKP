import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BN254_FIELD_MODULUS,
  POLICIES,
  evaluatePolicy,
  isCanonicalFieldElement,
  policyPublicParams,
  sanitizeUpstreamPath,
} from '@zkag/shared';
import { loadConfig } from '../src/config/env.js';
import { ChallengeStore } from '../src/security/challenges.js';
import { NullifierStore } from '../src/security/nullifiers.js';
import { SessionStore } from '../src/sessions/sessions.js';
import { EventBus } from '../src/events/bus.js';
import { OperatorAuth } from '../src/security/operator.js';
import { PROFILES, missingCapabilities } from '../src/verification/profiles.js';
import { FakeClock } from './helpers.js';

describe('configuration', () => {
  it('applies safe defaults', () => {
    const c = loadConfig({ NODE_ENV: 'test' });
    expect(c.SESSION_TTL_SECONDS).toBe(600);
    expect(c.ZK_PROFILE).toBe('integrated-access-v4');
    expect(c.REGISTRY_API).toBe('issuer-v1');
    expect(c.ALLOW_DEMO_KEYS).toBe(false);
    expect(c.trustedIssuer).toBeNull();
    expect(c.ROOT_CACHE_MS).toBeLessThanOrEqual(30000);
  });
  it('refuses development secrets in production', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', COOKIE_SECURE: 'true' })).toThrow(
      /dev secrets/,
    );
  });
  it('requires Secure cookies in production', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        OPERATOR_TOKEN: 'x'.repeat(30),
        ASSERTION_SECRET_ZK: 'y'.repeat(40),
        REGISTRY_ADMIN_TOKEN: 'z'.repeat(30),
      }),
    ).toThrow(/COOKIE_SECURE/);
  });
  it('rejects upstream URLs with paths or credentials (no open proxy via config)', () => {
    expect(() => loadConfig({ UPSTREAM_WIKI_URL: 'http://evil.example/redirect' })).toThrow(
      /upstream/,
    );
    expect(() => loadConfig({ UPSTREAM_WIKI_URL: 'http://user:pw@127.0.0.1:1' })).toThrow(
      /upstream/,
    );
  });
  it('refuses demo keys in production and a non-600 s epoch for v4', () => {
    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        COOKIE_SECURE: 'true',
        ALLOW_DEMO_KEYS: 'true',
        OPERATOR_TOKEN: 'x'.repeat(30),
        ASSERTION_SECRET_ZK: 'y'.repeat(40),
        REGISTRY_ADMIN_TOKEN: 'z'.repeat(30),
      }),
    ).toThrow(/ALLOW_DEMO_KEYS/);
    expect(() => loadConfig({ EPOCH_SECONDS: '300' })).toThrow(/EPOCH_SECONDS/);
    expect(loadConfig({ ZK_PROFILE: 'p1-integrated-v3', EPOCH_SECONDS: '300' }).REGISTRY_API).toBe(
      'p3-standin',
    );
  });
  it('loads the pinned issuer key from a file', () => {
    const dir = mkdtempSync(join(tmpdir(), 'zkag-pin-'));
    writeFileSync(join(dir, 'issuer.json'), JSON.stringify({ Ax: '11', Ay: '22' }));
    expect(loadConfig({ TRUSTED_ISSUER_FILE: join(dir, 'issuer.json') }).trustedIssuer).toEqual({
      Ax: '11',
      Ay: '22',
    });
    expect(loadConfig({ TRUSTED_ISSUER_AX: '1', TRUSTED_ISSUER_AY: '2' }).trustedIssuer).toEqual({
      Ax: '1',
      Ay: '2',
    });
  });
  it('caps the root staleness window at 30 s (Project Scope M2)', () => {
    expect(() => loadConfig({ ROOT_CACHE_MS: '60000' })).toThrow();
  });
});

describe('field encoding', () => {
  it('accepts only canonical decimal field elements', () => {
    expect(isCanonicalFieldElement('0')).toBe(true);
    expect(isCanonicalFieldElement('123')).toBe(true);
    expect(isCanonicalFieldElement('0123')).toBe(false);
    expect(isCanonicalFieldElement('-1')).toBe(false);
    expect(isCanonicalFieldElement('0x10')).toBe(false);
    expect(isCanonicalFieldElement(BN254_FIELD_MODULUS.toString())).toBe(false);
    expect(isCanonicalFieldElement((BN254_FIELD_MODULUS - 1n).toString())).toBe(true);
    expect(isCanonicalFieldElement(5)).toBe(false);
  });
});

describe('policies (server authoritative)', () => {
  it('matches the Project Scope table', () => {
    expect(POLICIES.wiki).toMatchObject({ minClearance: 0, requireDeviceCompliant: true });
    expect(POLICIES['file-share'].allowedRoles).toEqual(['engineer', 'admin']);
    expect(POLICIES['admin-panel']).toMatchObject({
      allowedRoles: ['admin'],
      minClearance: 3,
      requireDeviceCompliant: true,
    });
  });
  it('encodes proposed public parameters', () => {
    expect(policyPublicParams(POLICIES['admin-panel'])).toEqual({
      roleMask: 2n,
      deptMask: 15n,
      minClearance: 3n,
      requireDevice: 1n,
    });
    expect(policyPublicParams(POLICIES['file-share']).roleMask).toBe(3n);
  });
  it('evaluates SSO attributes (role mapping)', () => {
    const bob = { roles: ['contractor'], clearance: 1, deviceCompliant: true };
    expect(evaluatePolicy(POLICIES.wiki, bob)).toEqual({ allowed: true });
    expect(evaluatePolicy(POLICIES['file-share'], bob)).toEqual({
      allowed: false,
      reason: 'ROLE_NOT_ALLOWED',
    });
    expect(
      evaluatePolicy(POLICIES['admin-panel'], {
        roles: ['admin'],
        clearance: 2,
        deviceCompliant: true,
      }),
    ).toEqual({ allowed: false, reason: 'CLEARANCE_TOO_LOW' });
    expect(
      evaluatePolicy(POLICIES['admin-panel'], {
        roles: ['admin'],
        clearance: 3,
        deviceCompliant: false,
      }),
    ).toEqual({ allowed: false, reason: 'DEVICE_NOT_COMPLIANT' });
    expect(
      evaluatePolicy(POLICIES.wiki, {
        roles: ['engineer'],
        clearance: null,
        deviceCompliant: true,
      }),
    ).toEqual({ allowed: false, reason: 'MISSING_CLAIM' });
    expect(
      evaluatePolicy(POLICIES.wiki, { roles: ['ceo'], clearance: 3, deviceCompliant: true }),
    ).toEqual({ allowed: false, reason: 'ROLE_NOT_ALLOWED' });
  });
});

describe('challenge store', () => {
  const make = (clock = new FakeClock(), max = 100) => ({
    clock,
    store: new ChallengeStore(clock, 60_000, 600_000, max),
  });
  it('creates unique challenges with field-element nonces', () => {
    const { store } = make();
    const a = store.create('wiki', 'p')!;
    const b = store.create('wiki', 'p')!;
    expect(a.id).not.toBe(b.id);
    expect(a.nonce).not.toBe(b.nonce);
    expect(isCanonicalFieldElement(a.nonce)).toBe(true);
    expect(a.id).toMatch(/^[A-Za-z0-9_-]{24}$/);
  });
  it('consumes exactly once', () => {
    const { store } = make();
    const c = store.create('wiki', 'p')!;
    expect(store.consume(c.id).ok).toBe(true);
    expect(store.consume(c.id)).toMatchObject({ ok: false, reason: 'CHALLENGE_REPLAYED' });
  });
  it('rejects expired and unknown challenges, and burns expired ones', () => {
    const { store, clock } = make();
    const c = store.create('wiki', 'p')!;
    clock.advance(60_001);
    expect(store.consume(c.id)).toMatchObject({ ok: false, reason: 'CHALLENGE_EXPIRED' });
    expect(store.consume(c.id)).toMatchObject({ ok: false, reason: 'CHALLENGE_REPLAYED' });
    expect(store.consume('nope')).toMatchObject({ ok: false, reason: 'CHALLENGE_UNKNOWN' });
  });
  it('bounds outstanding challenges and sweeps old ones', () => {
    const { store, clock } = make(new FakeClock(), 3);
    for (let i = 0; i < 3; i++) expect(store.create('wiki', 'p')).not.toBeNull();
    expect(store.create('wiki', 'p')).toBeNull();
    clock.advance(130_000);
    expect(store.create('wiki', 'p')).not.toBeNull();
    expect(store.size).toBe(1);
  });
  it('issues 128-bit nonces, a challenge now, and epoch = floor(now / 600)', () => {
    const { store, clock } = make();
    const c = store.create('wiki', 'p')!;
    expect(BigInt(c.nonce) < 2n ** 128n).toBe(true);
    expect(c.now).toBe(String(Math.floor(clock.now() / 1000)));
    expect(c.epoch).toBe(String(Math.floor(Number(c.now) / 600)));
    expect(store.idForNonce(c.nonce)).toBe(c.id);
    expect(store.idForNonce('123')).toBeUndefined();
  });
  it('derives epochs from time', () => {
    const { store } = make();
    expect(store.epochAt(600_000 * 5 + 1)).toBe('5');
  });
});

describe('nullifier store', () => {
  it('rate-limits a nullifier per resource and epoch', () => {
    const s = new NullifierStore(1);
    expect(s.record('wiki', '10', '42').ok).toBe(true);
    expect(s.record('wiki', '10', '42')).toEqual({ ok: false, uses: 1 });
    expect(s.record('wiki', '11', '42').ok).toBe(true);
    expect(s.record('file-share', '10', '42').ok).toBe(true);
  });
  it('allows a configurable budget and sweeps old epochs', () => {
    const s = new NullifierStore(2);
    expect(s.record('wiki', '1', 'n').ok).toBe(true);
    expect(s.record('wiki', '1', 'n').ok).toBe(true);
    expect(s.record('wiki', '1', 'n').ok).toBe(false);
    s.sweep(5n);
    expect(s.size).toBe(0);
  });
});

describe('session store', () => {
  it('scopes sessions to one resource and expires them', () => {
    const clock = new FakeClock();
    const s = new SessionStore(clock, 600_000);
    const sess = s.issue('wiki', '7');
    expect(s.lookup(sess.id, 'wiki').ok).toBe(true);
    expect(s.lookup(sess.id, 'admin-panel')).toEqual({
      ok: false,
      reason: 'SESSION_WRONG_RESOURCE',
    });
    expect(s.lookup('forged', 'wiki')).toEqual({ ok: false, reason: 'SESSION_INVALID' });
    expect(s.lookup(undefined, 'wiki')).toEqual({ ok: false, reason: 'SESSION_MISSING' });
    clock.advance(600_000);
    expect(s.lookup(sess.id, 'wiki')).toEqual({ ok: false, reason: 'SESSION_EXPIRED' });
  });
  it('issues a fresh identifier each time and revokes sessions by root', () => {
    const s = new SessionStore(new FakeClock(), 600_000);
    const a = s.issue('wiki', '1');
    const b = s.issue('wiki', '1');
    const c = s.issue('wiki', '2');
    expect(a.id).not.toBe(b.id);
    expect(a.pseudonym).not.toBe(b.pseudonym);
    expect(s.distinctRoots().sort()).toEqual(['1', '2']);
    expect(
      s
        .revokeByRoot('1')
        .map((x) => x.id)
        .sort(),
    ).toEqual([a.id, b.id].sort());
    expect(s.lookup(c.id, 'wiki').ok).toBe(true);
  });
});

describe('proxy path sanitisation', () => {
  it.each([
    ['/articles', true],
    ['/files/f-1/download', true],
    ['/../etc/passwd', false],
    ['/a/%2e%2e/b', false],
    ['/a/%252e%252e/b', false],
    ['/a\\b', false],
    ['//evil.example/x', false],
    ['/http://evil', false],
    ['/a/%00', false],
    ['relative', false],
    ['/%E0%A4%A', false],
  ])('%s → %s', (path, ok) => {
    expect(sanitizeUpstreamPath(path, '').ok).toBe(ok);
  });
});

describe('event bus', () => {
  it('refuses events carrying secret-looking keys', () => {
    const bus = new EventBus();
    expect(() =>
      bus.publish({
        type: 'sso.logout',
        source: 'zk-gateway',
        correlationId: 'x',
        username: 'a',
        secret: 's',
      } as never),
    ).toThrow(/sensitive/);
  });
  it('keeps bounded history', () => {
    const bus = new EventBus(3);
    for (let i = 0; i < 5; i++)
      bus.publish({
        type: 'sso.logout',
        source: 'zk-gateway',
        correlationId: String(i),
        username: 'u',
      });
    expect(bus.recent().map((e) => e.correlationId)).toEqual(['2', '3', '4']);
  });
});

describe('operator auth', () => {
  it('compares tokens in constant time and expires sessions', () => {
    const clock = new FakeClock();
    const a = new OperatorAuth('operator-token-abcdefghijklmnopq', clock);
    expect(a.checkToken('wrong')).toBe(false);
    expect(a.checkToken(undefined)).toBe(false);
    expect(a.checkToken('operator-token-abcdefghijklmnopq')).toBe(true);
    const s = a.login();
    expect(a.isValid(s.id)).toBe(true);
    clock.advance(8 * 3600 * 1000);
    expect(a.isValid(s.id)).toBe(false);
  });
});

describe('profiles', () => {
  it('marks the delivered P1 circuit as missing required guarantees', () => {
    expect(missingCapabilities(PROFILES['p1-integrated-v3'])).toEqual([
      'attributeBinding',
      'issuerBinding',
      'policyBinding',
      'nonceBinding',
      'resourceBinding',
      'epochBinding',
      'nullifier',
      'expiryCheck',
    ]);
    expect(missingCapabilities(PROFILES['integrated-access-v4'])).toEqual([]);
  });
});

describe('rate limiting', () => {
  it('returns the JSON error envelope when the per-IP budget is exhausted', async () => {
    const { default: request } = await import('supertest');
    const { createApp } = await import('../src/app/createApp.js');
    const { FakeRegistry, testConfig } = await import('./helpers.js');
    const { app } = createApp({
      config: testConfig({ ZK_RATE_LIMIT_PER_MIN: '10' }),
      registry: new FakeRegistry('1'),
    });
    for (let i = 0; i < 10; i++)
      await request(app).post('/api/zk/challenges').send({ resource: 'wiki' }).expect(201);
    const r = await request(app).post('/api/zk/challenges').send({ resource: 'wiki' });
    expect(r.status).toBe(429);
    expect(r.body.error.code).toBe('RATE_LIMITED');
  });
});
