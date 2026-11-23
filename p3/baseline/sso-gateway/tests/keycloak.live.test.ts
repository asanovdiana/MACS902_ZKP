/**
 * LIVE Keycloak end to end (no mocks): real realm import, real Authorization Code + PKCE login by
 * submitting Keycloak's own login form, real back-channel code exchange with the client secret,
 * real RS256 validation against the realm JWKS, then the same three services and policies.
 *
 * Requires a running Keycloak with baseline/keycloak/realm-zkag.json imported:
 *   cd p3 && docker compose up -d keycloak
 *   KEYCLOAK_LIVE_URL=http://localhost:8080 npm test -w baseline/sso-gateway
 * Without KEYCLOAK_LIVE_URL the suite is reported as skipped (never silently passed); CI sets it.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { loadSsoConfig } from '../src/config.js';
import { createSsoApp } from '../src/app.js';
import { createWiki } from '../../../services/src/wiki.js';
import { createFileShare } from '../../../services/src/fileShare.js';
import { createAdminPanel } from '../../../services/src/adminPanel.js';

const KC = process.env.KEYCLOAK_LIVE_URL;
const SSO_SECRET = 'live-sso-assertion-secret-0123456789abcdef';
const listen = (s: Server) =>
  new Promise<string>((r) =>
    s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)),
  );

/** Minimal cookie jar for the Keycloak side of the browser. */
class Jar {
  private c = new Map<string, string>();
  store(res: Response) {
    for (const sc of res.headers.getSetCookie()) {
      const [kv] = sc.split(';');
      const i = kv!.indexOf('=');
      this.c.set(kv!.slice(0, i), kv!.slice(i + 1));
    }
  }
  header() {
    return [...this.c].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}
const decode = (s: string) =>
  s
    .replace(/&amp;/g, '&')
    .replace(/&#x2F;/gi, '/')
    .replace(/&#x3D;/gi, '=');

describe.skipIf(!KC)('live Keycloak: Authorization Code + PKCE, JWKS validation, policies', () => {
  const servers: Server[] = [];
  let sso: ReturnType<typeof createSsoApp>;

  beforeAll(async () => {
    const secrets = { zk: 'live-zk-assertion-secret-0123456789abcdef0', sso: SSO_SECRET };
    const up: Record<string, string> = {};
    for (const [k, a] of Object.entries({
      wiki: createWiki(secrets),
      'file-share': createFileShare(secrets),
      'admin-panel': createAdminPanel(secrets),
    })) {
      const s = createServer(a);
      servers.push(s);
      up[k] = await listen(s);
    }
    const config = loadSsoConfig({
      NODE_ENV: 'test',
      KEYCLOAK_PUBLIC_URL: KC,
      KEYCLOAK_INTERNAL_URL: KC,
      ASSERTION_SECRET_SSO: SSO_SECRET,
      UPSTREAM_WIKI_URL: up.wiki,
      UPSTREAM_FILE_SHARE_URL: up['file-share'],
      UPSTREAM_ADMIN_PANEL_URL: up['admin-panel'],
    });
    sso = createSsoApp({ config }); // real JWKS + real token endpoint
  });
  afterAll(() => servers.forEach((s) => s.close()));

  /** Drive a real browser-style login; resolves the SSO session cookie, or null if Keycloak refused. */
  async function login(username: string, password: string): Promise<string | null> {
    const start = await request(sso.app)
      .get('/sso/login?resource=wiki&returnTo=/compare')
      .expect(302);
    const authUrl = start.headers.location!;
    expect(new URL(authUrl).searchParams.get('code_challenge_method')).toBe('S256');
    const stateCookie = (start.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
    const jar = new Jar();
    const page = await fetch(authUrl, { redirect: 'manual' });
    jar.store(page);
    const html = await page.text();
    const action = /<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/.exec(html)?.[1];
    expect(action, 'Keycloak login form not found').toBeTruthy();
    const post = await fetch(decode(action!), {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
      body: new URLSearchParams({ username, password, credentialId: '' }),
    });
    const loc = post.headers.get('location');
    if (post.status !== 302 || !loc || !loc.includes('/sso/callback')) return null;
    const cb = new URL(loc);
    expect(cb.searchParams.get('state')).toBeTruthy();
    const done = await request(sso.app)
      .get(`/sso/callback?${cb.searchParams.toString()}`)
      .set('Cookie', stateCookie);
    expect(done.status, JSON.stringify(done.body)).toBe(302);
    return (done.headers['set-cookie'] as unknown as string[])
      .find((c) => c.startsWith('zkag_sso='))!
      .split(';')[0]!;
  }

  it('Alice (engineer, clearance 2): real login; Wiki and File Share granted, Admin Panel denied', async () => {
    const cookie = await login('alice', 'alice-dev-password');
    expect(cookie).toBeTruthy();
    const me = await request(sso.app).get('/sso/me').set('Cookie', cookie!);
    expect(me.body.identity).toMatchObject({
      username: 'alice',
      roles: ['engineer'],
      clearance: 2,
      department: 'engineering',
      deviceCompliant: true,
    });
    const wiki = await request(sso.app).get('/sso/svc/wiki/').set('Cookie', cookie!);
    expect(wiki.status).toBe(200);
    expect(wiki.body.viewer).toMatchObject({ frontDoor: 'sso-baseline', display: 'alice' });
    expect((await request(sso.app).get('/sso/svc/file-share/').set('Cookie', cookie!)).status).toBe(
      200,
    );
    const admin = await request(sso.app).get('/sso/svc/admin-panel/').set('Cookie', cookie!);
    expect(admin.status).toBe(403);
    expect(admin.body.error.code).toBe('ROLE_NOT_ALLOWED');
    const decision = sso.history.find((e) => e.type === 'sso.decision' && e.resource === 'wiki');
    expect(decision).toMatchObject({ username: 'alice', email: 'alice@northwind.example' });
    expect(
      (decision as { jwtChecks: Array<{ id: string; status: string }> }).jwtChecks.map((c) => c.id),
    ).toEqual(['signature', 'issuer', 'audience', 'expiry', 'azp']);
  });

  it('Bob (contractor, clearance 1): Wiki granted, File Share and Admin Panel denied', async () => {
    const cookie = await login('bob', 'bob-dev-password');
    expect((await request(sso.app).get('/sso/svc/wiki/').set('Cookie', cookie!)).status).toBe(200);
    expect(
      (await request(sso.app).get('/sso/svc/file-share/').set('Cookie', cookie!)).body.error.code,
    ).toBe('ROLE_NOT_ALLOWED');
    expect(
      (await request(sso.app).get('/sso/svc/admin-panel/').set('Cookie', cookie!)).status,
    ).toBe(403);
  });

  it('Carol (admin, clearance 3, device compliant): Admin Panel granted', async () => {
    const cookie = await login('carol', 'carol-dev-password');
    expect(
      (await request(sso.app).get('/sso/svc/admin-panel/').set('Cookie', cookie!)).status,
    ).toBe(200);
  });

  it('a wrong password yields no authorization code and no session', async () => {
    expect(await login('alice', 'not-the-password')).toBeNull();
  });

  it('logout ends the session and returns the Keycloak end-session URL', async () => {
    const cookie = await login('alice', 'alice-dev-password');
    const out = await request(sso.app).post('/sso/logout').set('Cookie', cookie!).expect(200);
    expect(out.body.endSessionUrl).toContain(`${KC}/realms/zkag/protocol/openid-connect/logout`);
    expect((await request(sso.app).get('/sso/svc/wiki/').set('Cookie', cookie!)).status).toBe(401);
  });
});
