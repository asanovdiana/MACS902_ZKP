import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from 'jose';
import { loadSsoConfig } from '../src/config.js';
import { createSsoApp } from '../src/app.js';
import { mapIdentity, validateToken } from '../src/oidc.js';
import { createWiki } from '../../../services/src/wiki.js';
import { createFileShare } from '../../../services/src/fileShare.js';
import { createAdminPanel } from '../../../services/src/adminPanel.js';

const SSO_SECRET = 'test-sso-assertion-secret-0123456789abcdef';
const ISS = 'http://localhost:8080/realms/zkag';
const CLIENT = 'zkag-sso-baseline';
let key: CryptoKey;
let otherKey: CryptoKey;
let jwks: ReturnType<typeof createLocalJWKSet>;
const servers: Server[] = [];
const up: Record<string, string> = {};

const listen = (s: Server) =>
  new Promise<string>((r) =>
    s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)),
  );

beforeAll(async () => {
  const kp = await generateKeyPair('RS256');
  key = kp.privateKey as CryptoKey;
  otherKey = (await generateKeyPair('RS256')).privateKey as CryptoKey;
  const jwk: JWK = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  jwks = createLocalJWKSet({ keys: [jwk] });
  const secrets = { zk: 'test-zk-assertion-secret-0123456789abcdef', sso: SSO_SECRET };
  for (const [k, a] of Object.entries({
    wiki: createWiki(secrets),
    'file-share': createFileShare(secrets),
    'admin-panel': createAdminPanel(secrets),
  })) {
    const s = createServer(a);
    servers.push(s);
    up[k] = await listen(s);
  }
});
afterAll(() => servers.forEach((s) => s.close()));

interface TokOpts {
  iss?: string;
  aud?: string;
  azp?: string;
  exp?: string | number;
  nonce?: string;
  signer?: CryptoKey;
  claims?: Record<string, unknown>;
  alg?: string;
}
async function token(o: TokOpts = {}) {
  return new SignJWT({
    azp: o.azp ?? CLIENT,
    typ: 'Bearer',
    nonce: o.nonce,
    preferred_username: 'alice',
    email: 'alice@northwind.example',
    name: 'Alice Anders',
    realm_access: { roles: ['engineer', 'offline_access'] },
    clearance: 2,
    department: 'engineering',
    device_compliant: true,
    ...o.claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(o.iss ?? ISS)
    .setAudience(o.aud ?? CLIENT)
    .setSubject('user-alice')
    .setIssuedAt()
    .setExpirationTime(o.exp ?? '5m')
    .sign(o.signer ?? key);
}
const expect_ = (kind: 'id' | 'access', nonce?: string) => ({
  issuer: ISS,
  audience: CLIENT,
  clientId: CLIENT,
  keys: jwks,
  kind,
  ...(nonce ? { nonce } : {}),
});

describe('JWT validation (no decode-and-trust)', () => {
  it('accepts a correctly signed access token', async () => {
    const v = await validateToken(await token(), expect_('access'));
    expect(v.ok).toBe(true);
    expect(v.checks.map((c) => c.id)).toEqual(['signature', 'issuer', 'audience', 'expiry', 'azp']);
  });
  it.each([
    ['bad signature', { signer: undefined as unknown as CryptoKey }, 'TOKEN_BAD_SIGNATURE'],
    ['wrong issuer', { iss: 'http://evil/realms/zkag' }, 'TOKEN_WRONG_ISSUER'],
    ['wrong audience', { aud: 'other-client' }, 'TOKEN_WRONG_AUDIENCE'],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 120 }, 'TOKEN_EXPIRED'],
    ['wrong authorized party', { azp: 'other-client' }, 'TOKEN_WRONG_AZP'],
  ])('rejects %s', async (_n, o, reason) => {
    const opts = { ...o } as TokOpts;
    if ('signer' in o) opts.signer = otherKey;
    const v = await validateToken(await token(opts), expect_('access'));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe(reason);
  });
  it('rejects HS256 and alg=none tokens', async () => {
    const hs = await new SignJWT({ azp: CLIENT })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer(ISS)
      .setAudience(CLIENT)
      .setSubject('x')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode('k'.repeat(32)));
    expect((await validateToken(hs, expect_('access'))).ok).toBe(false);
    const none = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${Buffer.from(JSON.stringify({ iss: ISS, aud: CLIENT, sub: 'x', exp: 9e9, iat: 1, azp: CLIENT })).toString('base64url')}.`;
    expect((await validateToken(none, expect_('access'))).ok).toBe(false);
  });
  it('rejects tokens missing required claims and enforces the ID-token nonce', async () => {
    const noSub = await new SignJWT({ azp: CLIENT })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
      .setIssuer(ISS)
      .setAudience(CLIENT)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(key);
    expect((await validateToken(noSub, expect_('access'))).reason).toBe('TOKEN_MISSING_CLAIM');
    expect((await validateToken(await token({ nonce: 'a' }), expect_('id', 'b'))).reason).toBe(
      'TOKEN_NONCE_MISMATCH',
    );
    expect((await validateToken(await token({ nonce: 'a' }), expect_('id', 'a'))).ok).toBe(true);
  });
  it('maps roles and attributes, dropping unknown roles and invalid clearance', () => {
    expect(
      mapIdentity({
        sub: 's',
        realm_access: { roles: ['admin', 'superuser'] },
        clearance: '3',
        device_compliant: 'true',
      }),
    ).toMatchObject({ roles: ['admin'], clearance: 3, deviceCompliant: true });
    expect(mapIdentity({ sub: 's', clearance: 9 }).clearance).toBeNull();
  });
});

describe('SSO baseline front door (Authorization Code + PKCE, mocked token endpoint)', () => {
  const build = (identity: Record<string, unknown>) => {
    const config = loadSsoConfig({
      NODE_ENV: 'test',
      ASSERTION_SECRET_SSO: SSO_SECRET,
      UPSTREAM_WIKI_URL: up.wiki!,
      UPSTREAM_FILE_SHARE_URL: up['file-share']!,
      UPSTREAM_ADMIN_PANEL_URL: up['admin-panel']!,
    });
    let lastVerifier = '';
    let nonce = '';
    const sso = createSsoApp({
      config,
      keys: jwks,
      exchangeCode: async (_code, verifier) => {
        lastVerifier = verifier;
        return {
          id_token: await token({ nonce, claims: identity }),
          access_token: await token({ claims: identity }),
        };
      },
    });
    return { ...sso, config, setNonce: (n: string) => (nonce = n), verifier: () => lastVerifier };
  };
  const login = async (b: ReturnType<typeof build>) => {
    const start = await request(b.app)
      .get('/sso/login?resource=wiki&returnTo=/compare')
      .expect(302);
    const loc = new URL(start.headers.location!);
    expect(loc.searchParams.get('code_challenge_method')).toBe('S256');
    expect(loc.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const state = loc.searchParams.get('state')!;
    b.setNonce(loc.searchParams.get('nonce')!);
    const stateCookie = (start.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
    const cb = await request(b.app)
      .get(`/sso/callback?code=abc&state=${state}`)
      .set('Cookie', stateCookie);
    expect(cb.status).toBe(302);
    expect(b.verifier()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    return (cb.headers['set-cookie'] as unknown as string[])
      .find((c) => c.startsWith('zkag_sso='))!
      .split(';')[0]!;
  };

  it('rejects callbacks with a forged or unbound state (login CSRF)', async () => {
    const b = build({});
    await request(b.app).get('/sso/login').expect(302);
    expect((await request(b.app).get('/sso/callback?code=x&state=forged')).status).toBe(400);
  });

  it('Alice (engineer, clearance 2): Wiki + File Share granted, Admin Panel denied; service learns her identity', async () => {
    const b = build({});
    const cookie = await login(b);
    const wiki = await request(b.app).get('/sso/svc/wiki/').set('Cookie', cookie);
    expect(wiki.status).toBe(200);
    expect(wiki.body.viewer).toMatchObject({ frontDoor: 'sso-baseline', display: 'alice' });
    expect((await request(b.app).get('/sso/svc/file-share/').set('Cookie', cookie)).status).toBe(
      200,
    );
    const admin = await request(b.app).get('/sso/svc/admin-panel/').set('Cookie', cookie);
    expect(admin.status).toBe(403);
    expect(admin.body.error.code).toBe('ROLE_NOT_ALLOWED');
    const decision = b.history.find((e) => e.type === 'sso.decision');
    expect(decision).toMatchObject({
      username: 'alice',
      email: 'alice@northwind.example',
      roles: ['engineer'],
      clearance: 2,
    });
  });

  it('Bob (contractor) is denied File Share; Carol (admin, clearance 3) gets Admin Panel', async () => {
    const bob = build({
      preferred_username: 'bob',
      realm_access: { roles: ['contractor'] },
      clearance: 1,
    });
    expect(
      (
        await request(bob.app)
          .get('/sso/svc/file-share/')
          .set('Cookie', await login(bob))
      ).status,
    ).toBe(403);
    const carol = build({
      preferred_username: 'carol',
      realm_access: { roles: ['admin'] },
      clearance: 3,
    });
    expect(
      (
        await request(carol.app)
          .get('/sso/svc/admin-panel/')
          .set('Cookie', await login(carol))
      ).status,
    ).toBe(200);
  });

  it('requires login, rejects traversal and supports logout', async () => {
    const b = build({});
    expect((await request(b.app).get('/sso/svc/wiki/')).status).toBe(401);
    const cookie = await login(b);
    expect((await request(b.app).get('/sso/svc/wiki/%2e%2e/x').set('Cookie', cookie)).status).toBe(
      400,
    );
    const out = await request(b.app).post('/sso/logout').set('Cookie', cookie).expect(200);
    expect(out.body.endSessionUrl).toContain('/protocol/openid-connect/logout');
    expect((await request(b.app).get('/sso/svc/wiki/').set('Cookie', cookie)).status).toBe(401);
  });

  it('operator events require authentication', async () => {
    const b = build({});
    expect((await request(b.app).get('/sso/operator/events')).status).toBe(401);
  });
});

describe('security review regressions (SSO)', () => {
  it('bounds unauthenticated pending-login state', async () => {
    process.env.SSO_MAX_PENDING_LOGINS = '3';
    vi.resetModules();
    const { createSsoApp: fresh } = await import('../src/app.js');
    const { app } = fresh({ config: loadSsoConfig({ NODE_ENV: 'test' }), keys: jwks });
    for (let i = 0; i < 3; i++) expect((await request(app).get('/sso/login')).status).toBe(302);
    expect((await request(app).get('/sso/login')).status).toBe(503);
    delete process.env.SSO_MAX_PENDING_LOGINS;
  });
});
