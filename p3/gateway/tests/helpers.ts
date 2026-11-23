import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { loadConfig, type Config } from '../src/config/env.js';
import {
  RegistryUnavailableError,
  type AdminResult,
  type RegistryClient,
  type RootAssessment,
  type RootSnapshot,
} from '../src/registry/index.js';
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

/**
 * In-memory registry double implementing the RegistryClient interface, including the issuer.api
 * staleness semantics: `setRoot(root, 'insert')` keeps older roots acceptable (no time window in the
 * fake), `setRoot(root, 'revoke')` makes every older root unacceptable.
 */
export class FakeRegistry implements RegistryClient {
  readonly api = 'p3-standin' as const;
  private listeners: Array<(p: RootSnapshot | null, n: RootSnapshot) => void> = [];
  private current: RootSnapshot | null = null;
  private chain: Array<{ root: string; supersededBy: 'insert' | 'revoke' | null }> = [];
  up = true;
  adminCalls: Array<{ method: string; id?: string }> = [];
  constructor(root: string) {
    this.setRoot(root);
  }
  setRoot(root: string, kind: 'insert' | 'revoke' = 'revoke') {
    const prev = this.current;
    if (this.chain.length) this.chain[this.chain.length - 1]!.supersededBy = kind;
    this.chain.push({ root, supersededBy: null });
    this.current = {
      root,
      version: String(this.chain.length),
      updatedAt: null,
      treeDepth: 16,
      source: 'fake',
      fetchedAt: Date.now(),
      fromCache: false,
    };
    if (prev && prev.root !== root) for (const l of this.listeners) l(prev, this.current);
  }
  private ensureUp() {
    if (!this.up) throw new RegistryUnavailableError('down', 'REGISTRY_UNREACHABLE');
  }
  async getCurrentRoot() {
    this.ensureUp();
    return this.current!;
  }
  private insertOnlySince(root: string): boolean | null {
    const idx = this.chain.findIndex((c) => c.root === root);
    if (idx === -1) return null;
    return this.chain.slice(idx, -1).every((c) => c.supersededBy === 'insert');
  }
  async assessProofRoot(root: string): Promise<RootAssessment> {
    this.ensureUp();
    const current = this.current!;
    if (root === current.root)
      return { acceptable: true, status: 'current', detail: 'current', current };
    const ok = this.insertOnlySince(root);
    if (ok === null)
      return { acceptable: false, status: 'unknown', detail: 'unknown root', current };
    return ok
      ? { acceptable: true, status: 'recent-insert', detail: 'inserts only', current }
      : { acceptable: false, status: 'revoked', detail: 'revoked since', current };
  }
  async sessionRootValid(root: string) {
    this.ensureUp();
    return root === this.current!.root || this.insertOnlySince(root) === true;
  }
  async health() {
    return { ok: this.up, detail: 'fake' };
  }
  onRootChange(l: (p: RootSnapshot | null, n: RootSnapshot) => void) {
    this.listeners.push(l);
  }
  async listLeaves() {
    return { treeDepth: 16, leaves: [] };
  }
  async rootHistory() {
    return [];
  }
  private ok(method: string, id?: string): AdminResult {
    this.adminCalls.push({ method, id });
    return { status: 200, body: { ok: true } };
  }
  async revoke(id: string) {
    return this.ok('revoke', id);
  }
  async credentialStatus(id: string) {
    return this.ok('status', id);
  }
  async issue() {
    return this.ok('issue');
  }
  async reset() {
    return this.ok('reset');
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
