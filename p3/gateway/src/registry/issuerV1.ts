import { isCanonicalFieldElement } from '@zkag/shared';
import type { Clock } from '../utils/clock.js';
import { HttpRegistryBase, isObj } from './http.js';
import {
  RegistryUnavailableError,
  type AdminResult,
  type RegistryClient,
  type RegistryLeaf,
  type RootAssessment,
  type RootHistoryItem,
} from './types.js';

interface HistoryEntry {
  root: string;
  validFrom: number;
  supersededAt: number | null;
  supersededBy: 'insert' | 'revoke' | null;
}

/**
 * Adapter for the team issuer (`issuer.api v1/v1.1/v2`, `issuer.admin v1/v1.1`; docs/CONTRACTS.md).
 * Root acceptance implements the contract's staleness rule: a proof root is accepted iff it is
 * current, or it is in the history, was superseded at most `stalenessSeconds` ago, and every
 * transition from it to the current root was an insert (never a revocation).
 */
export class IssuerV1Registry extends HttpRegistryBase implements RegistryClient {
  readonly api = 'issuer-v1' as const;

  constructor(
    baseUrl: string,
    adminToken: string,
    timeoutMs: number,
    cacheMs: number,
    clock: Clock,
    private readonly expected: { profile: string; depth: number },
    private readonly stalenessSeconds: number,
  ) {
    super(baseUrl, adminToken, timeoutMs, cacheMs, clock);
  }

  protected async fetchRootSnapshot() {
    const { status, body } = await this.fetchJson('GET', '/root');
    if (status !== 200 || !isObj(body))
      throw new RegistryUnavailableError(
        `issuer /root responded ${status}`,
        'REGISTRY_ERROR',
        status,
      );
    if (body.profile !== this.expected.profile || body.depth !== this.expected.depth) {
      throw new RegistryUnavailableError(
        `issuer serves profile ${String(body.profile)}/depth ${String(body.depth)}, expected ${this.expected.profile}/${this.expected.depth}`,
        'REGISTRY_BAD_RESPONSE',
      );
    }
    if (!isCanonicalFieldElement(body.root))
      throw new RegistryUnavailableError('issuer root malformed', 'REGISTRY_BAD_RESPONSE');
    const updated =
      typeof body.updatedAt === 'number' ? new Date(body.updatedAt * 1000).toISOString() : null;
    return {
      root: body.root,
      version: typeof body.updatedAt === 'number' ? String(body.updatedAt) : null,
      updatedAt: updated,
      treeDepth: body.depth as number,
      source: 'issuer.api v1',
    };
  }

  private async history(sinceSeconds: number): Promise<{ current: string; roots: HistoryEntry[] }> {
    const { status, body } = await this.fetchJson(
      'GET',
      `/root/history?since=${Math.max(0, Math.floor(sinceSeconds))}`,
    );
    if (
      status !== 200 ||
      !isObj(body) ||
      !Array.isArray(body.roots) ||
      !isCanonicalFieldElement(body.current)
    ) {
      throw new RegistryUnavailableError(
        'issuer /root/history malformed',
        'REGISTRY_BAD_RESPONSE',
        status,
      );
    }
    const roots: HistoryEntry[] = [];
    for (const e of body.roots) {
      if (!isObj(e) || !isCanonicalFieldElement(e.root))
        throw new RegistryUnavailableError('history entry malformed', 'REGISTRY_BAD_RESPONSE');
      roots.push({
        root: e.root,
        validFrom: Number(e.validFrom),
        supersededAt: typeof e.supersededAt === 'number' ? e.supersededAt : null,
        supersededBy:
          e.supersededBy === 'insert' || e.supersededBy === 'revoke' ? e.supersededBy : null,
      });
    }
    return { current: body.current, roots };
  }

  /** Transitions from `root` to current: null if unknown, else whether any was a revocation. */
  private chainFrom(h: { current: string; roots: HistoryEntry[] }, root: string) {
    const idx = h.roots.findIndex((r) => r.root === root);
    if (idx === -1) return null;
    const chain = h.roots.slice(idx).filter((r) => r.root !== h.current);
    return { entry: h.roots[idx]!, revoked: chain.some((r) => r.supersededBy !== 'insert') };
  }

  async assessProofRoot(root: string, gatewayNow: number): Promise<RootAssessment> {
    // New authorizations never use the cache: a revocation must take effect immediately for new
    // proofs (contract obligation 3: a revoked leaf is never re-admitted). The cache only bounds
    // how often existing sessions are re-checked.
    const current = await this.getCurrentRoot({ maxAgeMs: 0 });
    if (root === current.root)
      return { acceptable: true, status: 'current', detail: 'current registry root', current };
    const h = await this.history(gatewayNow - 900);
    if (root === h.current) {
      const fresh = await this.getCurrentRoot({ maxAgeMs: 0 });
      return {
        acceptable: root === fresh.root,
        status: 'current',
        detail: 'current registry root (cache refreshed)',
        current: fresh,
      };
    }
    const c = this.chainFrom(h, root);
    if (!c)
      return {
        acceptable: false,
        status: 'unknown',
        detail: 'root not in registry history (unknown or older than retention)',
        current,
      };
    if (c.revoked)
      return {
        acceptable: false,
        status: 'revoked',
        detail: 'a revocation happened after this root',
        current,
      };
    const age = c.entry.supersededAt === null ? 0 : gatewayNow - c.entry.supersededAt;
    if (age > this.stalenessSeconds)
      return {
        acceptable: false,
        status: 'stale',
        detail: `root superseded ${age}s ago (> ${this.stalenessSeconds}s window)`,
        current,
      };
    return {
      acceptable: true,
      status: 'recent-insert',
      detail: `superseded ${age}s ago by enrolments only`,
      current,
    };
  }

  async sessionRootValid(root: string): Promise<boolean> {
    const current = await this.getCurrentRoot();
    if (root === current.root) return true;
    const h = await this.history(Math.floor(this.clock.now() / 1000) - 900);
    const c = this.chainFrom(h, root);
    return !!c && !c.revoked;
  }

  async health() {
    try {
      const { status, body } = await this.fetchJson('GET', '/issuer');
      return {
        ok: status === 200 && isObj(body) && body.profile === this.expected.profile,
        detail: isObj(body) ? { profile: body.profile, depth: body.depth } : body,
      };
    } catch (err) {
      return { ok: false, detail: (err as RegistryUnavailableError).code ?? 'REGISTRY_ERROR' };
    }
  }

  /** Public issuer key as published by the issuer (used by the setup script to write the pin file). */
  async issuerKey(): Promise<{ Ax: string; Ay: string } | null> {
    const { status, body } = await this.fetchJson('GET', '/issuer');
    if (status !== 200 || !isObj(body) || !isObj(body.issuer)) return null;
    const { Ax, Ay } = body.issuer as Record<string, unknown>;
    return isCanonicalFieldElement(Ax) && isCanonicalFieldElement(Ay) ? { Ax, Ay } : null;
  }

  async listLeaves() {
    const { status, body } = await this.fetchJson(
      'GET',
      '/admin/leaves?from=0&limit=5000',
      undefined,
      true,
    );
    if (status !== 200 || !isObj(body) || !Array.isArray(body.leaves)) return null;
    const labels = new Map<number, string>();
    try {
      const en = await this.fetchJson('GET', '/admin/enrolments', undefined, true);
      if (en.status === 200 && isObj(en.body) && Array.isArray(en.body.enrolments)) {
        for (const e of en.body.enrolments) {
          if (isObj(e) && typeof e.leafIndex === 'number' && typeof e.employeeId === 'string')
            labels.set(e.leafIndex, e.employeeId);
        }
      }
    } catch {
      /* labels are optional */
    }
    const leaves: RegistryLeaf[] = body.leaves.filter(isObj).map((l) => ({
      index: Number(l.leafIndex),
      credentialId: `leaf-${Number(l.leafIndex)}`,
      label: labels.get(Number(l.leafIndex)) ?? null,
      status: l.status === 'revoked' ? 'revoked' : 'active',
      leaf: String(l.leaf),
    }));
    return { treeDepth: typeof body.depth === 'number' ? body.depth : null, leaves };
  }

  async rootHistory(): Promise<RootHistoryItem[] | null> {
    try {
      const h = await this.history(Math.floor(this.clock.now() / 1000) - 900);
      return h.roots
        .map((r, i) => ({
          root: r.root,
          version: i + 1,
          changedAt: new Date(r.validFrom * 1000).toISOString(),
          reason:
            i === 0 ? 'oldest retained root' : `after ${h.roots[i - 1]!.supersededBy ?? 'change'}`,
        }))
        .reverse();
    } catch {
      return null;
    }
  }

  private leafIndexOf(credentialId: string): number | null {
    const m = /^(?:leaf-)?(\d{1,6})$/.exec(credentialId);
    return m ? Number(m[1]) : null;
  }

  async revoke(credentialId: string): Promise<AdminResult> {
    const i = this.leafIndexOf(credentialId);
    if (i === null)
      return {
        status: 400,
        body: { error: { code: 'INVALID_REQUEST', message: 'credential id must be leaf-<index>' } },
      };
    const r = await this.fetchJson('POST', `/credentials/${i}/revoke`, {}, true);
    this.invalidate();
    return r;
  }

  async credentialStatus(credentialId: string): Promise<AdminResult> {
    const i = this.leafIndexOf(credentialId);
    const all = await this.listLeaves();
    const leaf = all?.leaves.find((l) => l.index === i);
    if (!leaf)
      return { status: 404, body: { error: { code: 'NOT_FOUND', message: 'unknown credential' } } };
    return {
      status: 200,
      body: { credentialId: leaf.credentialId, status: leaf.status, label: leaf.label },
    };
  }

  /** Admin-assigned enrolment (issuer.api v2): returns a one-time code for the employee. */
  async issue(body: unknown): Promise<AdminResult> {
    const r = await this.fetchJson('POST', '/admin/enrolments', body, true);
    return r;
  }

  async reset() {
    return null; // the team issuer has no reset: revocation is permanent by design
  }
}
