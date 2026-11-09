import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { loadConfig, type Config } from '../src/config/env.js';
import type { RegistryClient, RootSnapshot } from '../src/registry/registryClient.js';
import { RegistryUnavailableError } from '../src/registry/registryClient.js';
import type { Clock } from '../src/utils/clock.js';

export const TEST_OPERATOR_TOKEN = 'test-operator-token-0123456789abcdef';

export function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    OPERATOR_TOKEN: TEST_OPERATOR_TOKEN,
    ...overrides,
  });
}

export class FakeClock implements Clock {
  constructor(public t = Date.UTC(2026, 10, 8, 12, 0, 0)) {}
  now() {
    return this.t;
  }
  advance(ms: number) {
    this.t += ms;
  }
}

/** In-memory registry double implementing the same interface as the P2 HTTP adapter. */
export class FakeRegistry implements RegistryClient {
  private listeners: Array<(p: RootSnapshot | null, n: RootSnapshot) => void> = [];
  private current: RootSnapshot | null = null;
  up = true;
  adminCalls: Array<{ method: string; path: string }> = [];
  constructor(root: string) {
    this.setRoot(root);
  }
  setRoot(root: string) {
    const prev = this.current;
    this.current = {
      root,
      version: String(Number(prev?.version ?? 0) + 1),
      updatedAt: null,
      treeDepth: 2,
      source: 'fake',
      fetchedAt: Date.now(),
      fromCache: false,
    };
    if (prev && prev.root !== root) for (const l of this.listeners) l(prev, this.current);
  }
  async getCurrentRoot() {
    if (!this.up) throw new RegistryUnavailableError('down', 'REGISTRY_UNREACHABLE');
    return this.current!;
  }
  async health() {
    return { ok: this.up, detail: 'fake' };
  }
  async adminRequest(method: 'GET' | 'POST', path: string) {
    this.adminCalls.push({ method, path });
    return { status: 200, body: { ok: true } };
  }
  onRootChange(l: (p: RootSnapshot | null, n: RootSnapshot) => void) {
    this.listeners.push(l);
  }
}

export function listen(server: Server): Promise<string> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`),
    ),
  );
}

export function cookieFrom(
  setCookie: string[] | string | undefined,
  name: string,
): string | undefined {
  const list = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const c = list.find((s) => s.startsWith(`${name}=`));
  return c?.split(';')[0];
}
