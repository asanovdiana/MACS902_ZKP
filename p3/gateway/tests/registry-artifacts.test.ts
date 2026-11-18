import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { cpSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  IssuerV1Registry,
  RegistryUnavailableError,
  StandinRegistry,
} from '../src/registry/index.js';
import { loadArtifacts } from '../src/verification/artifacts.js';
import { PROFILES } from '../src/verification/profiles.js';
import { REPO_ROOT, TEAM_ROOT } from '../src/config/env.js';
import { FakeClock, listen } from './helpers.js';

let server: Server | null = null;
afterEach(() => server?.close());

type Reply = { status: number; body: string; delayMs?: number };
async function serve(handler: (path: string, req: IncomingMessage) => Reply) {
  server = createServer((req, res) => {
    const r = handler(req.url ?? '', req);
    setTimeout(
      () => res.writeHead(r.status, { 'content-type': 'application/json' }).end(r.body),
      r.delayMs ?? 0,
    );
  });
  return listen(server);
}
const TOKEN = 'admin-token-xxxxxxxxxxxxxxxx';

describe('P3 stand-in registry adapter', () => {
  it('reads and validates the root, caches within the staleness window and notifies on change', async () => {
    let root = '123';
    const base = await serve(() => ({ status: 200, body: JSON.stringify({ root, version: 3 }) }));
    const clock = new FakeClock();
    const c = new StandinRegistry(base, TOKEN, 1000, 2000, clock);
    const changes: string[] = [];
    c.onRootChange((_p, n) => changes.push(n.root));
    expect((await c.getCurrentRoot()).root).toBe('123');
    root = '456';
    expect((await c.getCurrentRoot()).fromCache).toBe(true);
    clock.advance(2001);
    expect((await c.getCurrentRoot()).root).toBe('456');
    expect((await c.getCurrentRoot({ maxAgeMs: 0 })).fromCache).toBe(false);
    expect(changes).toEqual(['123', '456']);
    expect((await c.assessProofRoot('123')).acceptable).toBe(false);
  });
  it.each([
    [
      'non-canonical root',
      { status: 200, body: JSON.stringify({ root: '00123' }) },
      'REGISTRY_BAD_RESPONSE',
    ],
    ['hex root', { status: 200, body: JSON.stringify({ root: '0xabc' }) }, 'REGISTRY_BAD_RESPONSE'],
    [
      'numeric JSON root',
      { status: 200, body: JSON.stringify({ root: 123 }) },
      'REGISTRY_BAD_RESPONSE',
    ],
    ['non-JSON', { status: 200, body: '<html>' }, 'REGISTRY_BAD_RESPONSE'],
    ['server error', { status: 500, body: '{}' }, 'REGISTRY_BAD_RESPONSE'],
    [
      'timeout',
      { status: 200, body: JSON.stringify({ root: '1' }), delayMs: 400 },
      'REGISTRY_TIMEOUT',
    ],
  ])('fails closed on %s', async (_n, reply, code) => {
    const base = await serve(() => reply);
    await expect(
      new StandinRegistry(base, TOKEN, 150, 0, new FakeClock()).getCurrentRoot(),
    ).rejects.toMatchObject({ code });
  });
  it('fails closed when unreachable', async () => {
    const c = new StandinRegistry('http://127.0.0.1:1', TOKEN, 500, 0, new FakeClock());
    await expect(c.getCurrentRoot()).rejects.toBeInstanceOf(RegistryUnavailableError);
    expect((await c.health()).ok).toBe(false);
  });
});

describe('team issuer adapter (issuer.api v1 / issuer.admin v1.1)', () => {
  const NOW = 1_800_000_000;
  const clock = new FakeClock(NOW * 1000);
  // History: R0 --insert@NOW-100--> R1 --revoke@NOW-50--> R2 --insert@NOW-20--> R3 (current)
  const history = {
    now: NOW,
    current: '33',
    roots: [
      { root: '10', validFrom: NOW - 300, supersededAt: NOW - 100, supersededBy: 'insert' },
      { root: '11', validFrom: NOW - 100, supersededAt: NOW - 50, supersededBy: 'revoke' },
      { root: '22', validFrom: NOW - 50, supersededAt: NOW - 20, supersededBy: 'insert' },
      { root: '33', validFrom: NOW - 20, supersededAt: null, supersededBy: null },
    ],
  };
  const auth: Array<string | undefined> = [];
  const issuer = (profile = 'v4', depth = 16) =>
    serve((path, req) => {
      if (path.startsWith('/admin') || path.includes('/revoke'))
        auth.push(req.headers.authorization);
      if (path === '/root')
        return {
          status: 200,
          body: JSON.stringify({ root: '33', updatedAt: NOW - 20, profile, depth }),
        };
      if (path.startsWith('/root/history')) return { status: 200, body: JSON.stringify(history) };
      if (path === '/issuer')
        return {
          status: 200,
          body: JSON.stringify({ profile, depth, issuer: { Ax: '1', Ay: '2' } }),
        };
      if (path.startsWith('/admin/leaves'))
        return {
          status: 200,
          body: JSON.stringify({
            profile,
            depth,
            total: 2,
            from: 0,
            leaves: [
              { leafIndex: 0, status: 'issued', leaf: '7' },
              { leafIndex: 1, status: 'revoked', leaf: '0' },
            ],
          }),
        };
      if (path === '/admin/enrolments')
        return {
          status: 200,
          body: JSON.stringify({ enrolments: [{ employeeId: 'alice', leafIndex: 0 }] }),
        };
      if (path === '/credentials/0/revoke')
        return { status: 200, body: JSON.stringify({ root: '44' }) };
      return { status: 404, body: '{}' };
    });
  const make = (base: string) =>
    new IssuerV1Registry(base, TOKEN, 1000, 0, clock, { profile: 'v4', depth: 16 }, 30);

  it('applies the staleness rule: current, recent insert-only, too old, revoked since, unknown', async () => {
    const r = make(await issuer());
    expect(await r.assessProofRoot('33', NOW)).toMatchObject({
      acceptable: true,
      status: 'current',
    });
    expect(await r.assessProofRoot('22', NOW)).toMatchObject({
      acceptable: true,
      status: 'recent-insert',
    });
    expect(await r.assessProofRoot('22', NOW + 11)).toMatchObject({
      acceptable: false,
      status: 'stale',
    });
    expect(await r.assessProofRoot('11', NOW)).toMatchObject({
      acceptable: false,
      status: 'revoked',
    });
    expect(await r.assessProofRoot('10', NOW)).toMatchObject({
      acceptable: false,
      status: 'revoked',
    });
    expect(await r.assessProofRoot('99', NOW)).toMatchObject({
      acceptable: false,
      status: 'unknown',
    });
  });
  it('REGRESSION: a revocation takes effect for new proofs even inside the root cache window', async () => {
    let current = '33';
    const hist = {
      now: NOW,
      current: '33',
      roots: [
        {
          root: '33',
          validFrom: NOW - 20,
          supersededAt: null as number | null,
          supersededBy: null as string | null,
        },
      ],
    };
    const base = await serve((path) => {
      if (path === '/root')
        return {
          status: 200,
          body: JSON.stringify({ root: current, updatedAt: NOW, profile: 'v4', depth: 16 }),
        };
      if (path.startsWith('/root/history')) return { status: 200, body: JSON.stringify(hist) };
      return { status: 404, body: '{}' };
    });
    const r = new IssuerV1Registry(
      base,
      TOKEN,
      1000,
      30_000,
      clock,
      { profile: 'v4', depth: 16 },
      30,
    ); // 30 s cache
    expect((await r.getCurrentRoot()).root).toBe('33'); // cached
    current = '44';
    hist.current = '44';
    hist.roots[0]!.supersededAt = NOW;
    hist.roots[0]!.supersededBy = 'revoke';
    hist.roots.push({ root: '44', validFrom: NOW, supersededAt: null, supersededBy: null });
    expect(await r.assessProofRoot('33', NOW)).toMatchObject({
      acceptable: false,
      status: 'revoked',
    });
  });
  it('keeps sessions across enrolments but not across a revocation', async () => {
    const r = make(await issuer());
    expect(await r.sessionRootValid('33')).toBe(true);
    expect(await r.sessionRootValid('22')).toBe(true);
    expect(await r.sessionRootValid('11')).toBe(false);
    expect(await r.sessionRootValid('99')).toBe(false);
  });
  it('fails closed when the issuer serves another profile or depth', async () => {
    await expect(make(await issuer('v3', 2)).getCurrentRoot()).rejects.toMatchObject({
      code: 'REGISTRY_BAD_RESPONSE',
    });
  });
  it('maps admin leaves (with enrolment labels) and revokes by leaf index with the bearer token', async () => {
    auth.length = 0;
    const r = make(await issuer());
    const leaves = await r.listLeaves();
    expect(leaves?.leaves).toEqual([
      { index: 0, credentialId: 'leaf-0', label: 'alice', status: 'active', leaf: '7' },
      { index: 1, credentialId: 'leaf-1', label: null, status: 'revoked', leaf: '0' },
    ]);
    expect((await r.revoke('leaf-0')).status).toBe(200);
    expect((await r.revoke('../x')).status).toBe(400);
    expect((await r.credentialStatus('leaf-1')).body).toMatchObject({ status: 'revoked' });
    expect(auth.every((a) => a === `Bearer ${TOKEN}`)).toBe(true);
    expect(await r.issuerKey()).toEqual({ Ax: '1', Ay: '2' });
  });
});

const TEAM_MANIFEST = resolve(TEAM_ROOT, 'circuits/setup/integrated_access_v4.manifest.json');
describe.skipIf(!existsSync(TEAM_MANIFEST))('team v4 artifacts (circuits/setup)', () => {
  it('loads the committed v4 key; DEV-ONLY keys are unreviewed unless demo keys are allowed', () => {
    const s = loadArtifacts(TEAM_MANIFEST, PROFILES['integrated-access-v4']);
    expect(s).toMatchObject({ status: 'ready', trust: 'unreviewed', reviewed: false });
    expect(
      loadArtifacts(TEAM_MANIFEST, PROFILES['integrated-access-v4'], { allowDemoKeys: true }),
    ).toMatchObject({ trust: 'demo-accepted', reviewed: true });
  });
  it('rejects the v4 key for the v3 profile, and a tampered verification key', () => {
    expect(loadArtifacts(TEAM_MANIFEST, PROFILES['p1-integrated-v3']).status).toBe('invalid');
    const dir = mkdtempSync(join(tmpdir(), 'zkag-v4-'));
    cpSync(TEAM_MANIFEST, join(dir, 'integrated_access_v4.manifest.json'));
    const vk = JSON.parse(
      readFileSync(
        resolve(TEAM_ROOT, 'circuits/setup/integrated_access_v4.verification_key.json'),
        'utf8',
      ),
    );
    vk.vk_alpha_1[0] = '1';
    writeFileSync(join(dir, 'integrated_access_v4.verification_key.json'), JSON.stringify(vk));
    expect(
      loadArtifacts(
        join(dir, 'integrated_access_v4.manifest.json'),
        PROFILES['integrated-access-v4'],
      ).status,
    ).toBe('invalid');
  });
});

const V3 = resolve(REPO_ROOT, 'artifacts/p1-integrated-v3/manifest.json');
describe.skipIf(!existsSync(V3))('P3 diagnostic v3 artifacts', () => {
  it('accepts them for the matching profile, unreviewed', () => {
    expect(loadArtifacts(V3, PROFILES['p1-integrated-v3'])).toMatchObject({
      status: 'ready',
      reviewed: false,
    });
  });
  it('rejects a manifest whose public signal layout differs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'zkag-art-'));
    for (const f of ['manifest.json', 'verification_key.json'])
      cpSync(resolve(REPO_ROOT, 'artifacts/p1-integrated-v3', f), join(dir, f));
    const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
    m.publicSignals = ['nullifier'];
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(m));
    expect(loadArtifacts(join(dir, 'manifest.json'), PROFILES['p1-integrated-v3'])).toMatchObject({
      status: 'invalid',
    });
  });
});

describe('missing artifacts', () => {
  it('reports missing', () => {
    expect(
      loadArtifacts(join(tmpdir(), 'nope-zkag', 'm.json'), PROFILES['integrated-access-v4']).status,
    ).toBe('missing');
  });
});
