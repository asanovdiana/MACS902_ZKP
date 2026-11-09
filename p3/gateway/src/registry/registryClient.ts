import { isCanonicalFieldElement } from '@zkag/shared';
import { z } from 'zod';
import type { Clock } from '../utils/clock.js';

export class RegistryUnavailableError extends Error {
  constructor(
    message: string,
    readonly code:
      'REGISTRY_UNREACHABLE' | 'REGISTRY_TIMEOUT' | 'REGISTRY_BAD_RESPONSE' | 'REGISTRY_ERROR',
    readonly status?: number,
  ) {
    super(message);
  }
}

const rootSchema = z.object({
  root: z
    .string()
    .refine(isCanonicalFieldElement, 'root must be a canonical decimal field element'),
  version: z.union([z.string(), z.number()]).transform(String).optional(),
  updatedAt: z.string().optional(),
  treeDepth: z.number().int().optional(),
  source: z.string().optional(),
});

export interface RootSnapshot {
  root: string;
  version: string | null;
  updatedAt: string | null;
  treeDepth: number | null;
  source: string | null;
  fetchedAt: number;
  fromCache: boolean;
}

export interface RegistryClient {
  getCurrentRoot(opts?: { maxAgeMs?: number }): Promise<RootSnapshot>;
  health(): Promise<{ ok: boolean; detail: unknown }>;
  adminRequest(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
  ): Promise<{ status: number; body: unknown }>;
  onRootChange(listener: (prev: RootSnapshot | null, next: RootSnapshot) => void): void;
}

/**
 * HTTP adapter for the P2 registry (language independent, see contracts/p2-registry.openapi.yaml).
 * Fails closed: on any error or malformed response the caller receives an exception, never a root.
 */
export class HttpRegistryClient implements RegistryClient {
  private cached: RootSnapshot | null = null;
  private inflight: Promise<RootSnapshot> | null = null;
  private listeners: Array<(prev: RootSnapshot | null, next: RootSnapshot) => void> = [];

  constructor(
    private readonly baseUrl: string,
    private readonly adminToken: string,
    private readonly timeoutMs: number,
    private readonly cacheMs: number,
    private readonly clock: Clock,
  ) {}

  onRootChange(listener: (prev: RootSnapshot | null, next: RootSnapshot) => void) {
    this.listeners.push(listener);
  }

  private async fetchJson(method: string, path: string, body?: unknown, admin = false) {
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
      if (text.length > 1_000_000)
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

  async getCurrentRoot(opts: { maxAgeMs?: number } = {}): Promise<RootSnapshot> {
    const maxAge = Math.min(opts.maxAgeMs ?? this.cacheMs, this.cacheMs);
    if (this.cached && this.clock.now() - this.cached.fetchedAt < maxAge)
      return { ...this.cached, fromCache: true };
    // Coalesce concurrent fetches.
    this.inflight ??= this.fetchRoot().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  private async fetchRoot(): Promise<RootSnapshot> {
    const { status, body } = await this.fetchJson('GET', '/v1/registry/root');
    if (status !== 200)
      throw new RegistryUnavailableError(`registry responded ${status}`, 'REGISTRY_ERROR', status);
    const parsed = rootSchema.safeParse(body);
    if (!parsed.success)
      throw new RegistryUnavailableError(
        'registry root response malformed',
        'REGISTRY_BAD_RESPONSE',
      );
    const next: RootSnapshot = {
      root: parsed.data.root,
      version: parsed.data.version ?? null,
      updatedAt: parsed.data.updatedAt ?? null,
      treeDepth: parsed.data.treeDepth ?? null,
      source: parsed.data.source ?? null,
      fetchedAt: this.clock.now(),
      fromCache: false,
    };
    const prev = this.cached;
    this.cached = next;
    if (!prev || prev.root !== next.root) for (const l of this.listeners) l(prev, next);
    return next;
  }

  async health() {
    try {
      const { status, body } = await this.fetchJson('GET', '/v1/health');
      return { ok: status === 200, detail: body };
    } catch (err) {
      return { ok: false, detail: (err as RegistryUnavailableError).code ?? 'REGISTRY_ERROR' };
    }
  }

  async adminRequest(method: 'GET' | 'POST', path: string, body?: unknown) {
    const res = await this.fetchJson(method, path, body, true);
    if (method === 'POST') this.cached = null; // force a fresh root after admin mutations
    return res;
  }
}
