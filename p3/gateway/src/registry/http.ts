import { isCanonicalFieldElement } from '@zkag/shared';
import type { Clock } from '../utils/clock.js';
import { RegistryUnavailableError, type RootSnapshot } from './types.js';

export interface FetchResult {
  status: number;
  body: unknown;
}

/** Shared HTTP plumbing: bounded responses, timeouts, no redirects, root caching + change events. */
export abstract class HttpRegistryBase {
  private cached: RootSnapshot | null = null;
  private inflight: Promise<RootSnapshot> | null = null;
  private listeners: Array<(prev: RootSnapshot | null, next: RootSnapshot) => void> = [];

  constructor(
    protected readonly baseUrl: string,
    private readonly adminToken: string,
    private readonly timeoutMs: number,
    private readonly cacheMs: number,
    protected readonly clock: Clock,
  ) {}

  onRootChange(listener: (prev: RootSnapshot | null, next: RootSnapshot) => void) {
    this.listeners.push(listener);
  }

  protected async fetchJson(
    method: string,
    path: string,
    body?: unknown,
    admin = false,
  ): Promise<FetchResult> {
    const url = new URL(path, this.baseUrl);
    if (url.origin !== new URL(this.baseUrl).origin)
      throw new RegistryUnavailableError('invalid registry path', 'REGISTRY_ERROR');
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(url, {
        method,
        signal: ctrl.signal,
        headers: {
          accept: 'application/json',
          ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
          ...(admin ? { authorization: `Bearer ${this.adminToken}` } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        redirect: 'error',
      });
      const text = await res.text();
      if (text.length > 2_000_000)
        throw new RegistryUnavailableError('registry response too large', 'REGISTRY_BAD_RESPONSE');
      let json: unknown = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        throw new RegistryUnavailableError(
          'registry returned non-JSON',
          'REGISTRY_BAD_RESPONSE',
          res.status,
        );
      }
      return { status: res.status, body: json };
    } catch (err) {
      if (err instanceof RegistryUnavailableError) throw err;
      if ((err as Error).name === 'AbortError')
        throw new RegistryUnavailableError('registry timed out', 'REGISTRY_TIMEOUT');
      throw new RegistryUnavailableError('registry unreachable', 'REGISTRY_UNREACHABLE');
    } finally {
      clearTimeout(timer);
    }
  }

  /** Subclasses fetch and validate the current root (throw on anything unexpected). */
  protected abstract fetchRootSnapshot(): Promise<Omit<RootSnapshot, 'fetchedAt' | 'fromCache'>>;

  async getCurrentRoot(opts: { maxAgeMs?: number } = {}): Promise<RootSnapshot> {
    const maxAge = Math.min(opts.maxAgeMs ?? this.cacheMs, this.cacheMs);
    if (this.cached && this.clock.now() - this.cached.fetchedAt < maxAge)
      return { ...this.cached, fromCache: true };
    this.inflight ??= this.refresh().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async refresh(): Promise<RootSnapshot> {
    const s = await this.fetchRootSnapshot();
    if (!isCanonicalFieldElement(s.root))
      throw new RegistryUnavailableError('registry root malformed', 'REGISTRY_BAD_RESPONSE');
    const next: RootSnapshot = { ...s, fetchedAt: this.clock.now(), fromCache: false };
    const prev = this.cached;
    this.cached = next;
    if (!prev || prev.root !== next.root) for (const l of this.listeners) l(prev, next);
    return next;
  }

  protected invalidate() {
    this.cached = null;
  }
}

export const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);
