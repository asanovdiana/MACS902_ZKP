import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { HttpRegistryClient, RegistryUnavailableError } from '../src/registry/registryClient.js';
import { loadArtifacts } from '../src/verification/artifacts.js';
import { PROFILES } from '../src/verification/profiles.js';
import { REPO_ROOT } from '../src/config/env.js';
import { FakeClock, listen } from './helpers.js';

let server: Server | null = null;
afterEach(() => server?.close());

async function registryReturning(
  handler: (path: string) => { status: number; body: string; delayMs?: number },
) {
  server = createServer((req, res) => {
    const r = handler(req.url ?? '');
    setTimeout(
      () => res.writeHead(r.status, { 'content-type': 'application/json' }).end(r.body),
      r.delayMs ?? 0,
    );
  });
  return listen(server);
}

describe('P2 registry adapter (HTTP contract)', () => {
  it('reads and validates the current root, caches within the staleness window and notifies on change', async () => {
    let root = '123';
    const base = await registryReturning(() => ({
      status: 200,
      body: JSON.stringify({ root, version: 3 }),
    }));
    const clock = new FakeClock();
    const c = new HttpRegistryClient(base, 'admin-token-xxxxxxxxxxxxxxxx', 1000, 2000, clock);
    const changes: string[] = [];
    c.onRootChange((_p, n) => changes.push(n.root));
    expect((await c.getCurrentRoot()).root).toBe('123');
    root = '456';
    expect((await c.getCurrentRoot()).fromCache).toBe(true);
    clock.advance(2001);
    expect((await c.getCurrentRoot()).root).toBe('456');
    expect((await c.getCurrentRoot({ maxAgeMs: 0 })).fromCache).toBe(false);
    expect(changes).toEqual(['123', '456']);
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
    ['server error', { status: 500, body: '{}' }, 'REGISTRY_ERROR'],
    [
      'timeout',
      { status: 200, body: JSON.stringify({ root: '1' }), delayMs: 400 },
      'REGISTRY_TIMEOUT',
    ],
  ])('fails closed on %s', async (_n, reply, code) => {
    const base = await registryReturning(() => reply);
    const c = new HttpRegistryClient(base, 'admin-token-xxxxxxxxxxxxxxxx', 150, 0, new FakeClock());
    await expect(c.getCurrentRoot()).rejects.toMatchObject({ code });
  });
  it('fails closed when unreachable', async () => {
    const c = new HttpRegistryClient(
      'http://127.0.0.1:1',
      'admin-token-xxxxxxxxxxxxxxxx',
      500,
      0,
      new FakeClock(),
    );
    await expect(c.getCurrentRoot()).rejects.toBeInstanceOf(RegistryUnavailableError);
    expect((await c.health()).ok).toBe(false);
  });
  it('sends the admin bearer token only on admin requests', async () => {
    const seen: Array<string | undefined> = [];
    server = createServer((req, res) => {
      seen.push(req.headers.authorization);
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ root: '1' }));
    });
    const base = await listen(server);
    const c = new HttpRegistryClient(
      base,
      'admin-token-xxxxxxxxxxxxxxxx',
      1000,
      0,
      new FakeClock(),
    );
    await c.getCurrentRoot();
    await c.adminRequest('POST', '/v1/credentials/x/revoke', {});
    expect(seen).toEqual([undefined, 'Bearer admin-token-xxxxxxxxxxxxxxxx']);
  });
});

const ART = resolve(REPO_ROOT, 'artifacts/p1-integrated-v3');
describe.skipIf(!existsSync(join(ART, 'manifest.json')))('artifact integrity', () => {
  const copy = () => {
    const dir = mkdtempSync(join(tmpdir(), 'zkag-art-'));
    for (const f of ['manifest.json', 'verification_key.json']) cpSync(join(ART, f), join(dir, f));
    return dir;
  };
  it('accepts the real P1 artifacts for the matching profile and reports them unreviewed', () => {
    const s = loadArtifacts(ART, PROFILES['p1-integrated-v3']);
    expect(s.status).toBe('ready');
    if (s.status === 'ready') expect(s.reviewed).toBe(false);
  });
  it('rejects artifacts for a different profile (version mismatch)', () => {
    expect(loadArtifacts(ART, PROFILES['zkag-access-v1']).status).toBe('invalid');
  });
  it('rejects a verification key whose hash differs from the manifest', () => {
    const dir = copy();
    const vk = JSON.parse(readFileSync(join(dir, 'verification_key.json'), 'utf8'));
    vk.vk_alpha_1[0] = '1';
    writeFileSync(join(dir, 'verification_key.json'), JSON.stringify(vk));
    const s = loadArtifacts(dir, PROFILES['p1-integrated-v3']);
    expect(s).toMatchObject({ status: 'invalid' });
  });
  it('rejects a manifest whose public signal layout differs', () => {
    const dir = copy();
    const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
    m.publicSignals = ['nullifier'];
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify(m));
    expect(loadArtifacts(dir, PROFILES['p1-integrated-v3'])).toMatchObject({ status: 'invalid' });
  });
  it('reports missing artifacts', () => {
    expect(loadArtifacts(join(tmpdir(), 'nope-zkag'), PROFILES['p1-integrated-v3']).status).toBe(
      'missing',
    );
  });
});
