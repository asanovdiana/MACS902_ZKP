import { isCanonicalFieldElement } from '@zkag/shared';
import { HttpRegistryBase, isObj } from './http.js';
import {
  RegistryUnavailableError,
  type RegistryClient,
  type RegistryLeaf,
  type RootAssessment,
  type RootHistoryItem,
} from './types.js';

/** Adapter for the P3 diagnostic stand-in (contracts/p2-registry.openapi.yaml). Strict current-root rule. */
export class StandinRegistry extends HttpRegistryBase implements RegistryClient {
  readonly api = 'p3-standin' as const;

  protected async fetchRootSnapshot() {
    const { status, body } = await this.fetchJson('GET', '/v1/registry/root');
    if (status !== 200 || !isObj(body) || !isCanonicalFieldElement(body.root)) {
      throw new RegistryUnavailableError(
        `registry root response invalid (${status})`,
        'REGISTRY_BAD_RESPONSE',
        status,
      );
    }
    return {
      root: body.root,
      version: body.version === undefined ? null : String(body.version),
      updatedAt: typeof body.updatedAt === 'string' ? body.updatedAt : null,
      treeDepth: typeof body.treeDepth === 'number' ? body.treeDepth : null,
      source: typeof body.source === 'string' ? body.source : null,
    };
  }

  async assessProofRoot(root: string): Promise<RootAssessment> {
    const current = await this.getCurrentRoot({ maxAgeMs: 0 }); // fresh for every new authorization
    return root === current.root
      ? { acceptable: true, status: 'current', detail: 'current registry root', current }
      : {
          acceptable: false,
          status: 'stale',
          detail: 'proof root is not the current registry root (revoked or stale)',
          current,
        };
  }

  async sessionRootValid(root: string) {
    return (await this.getCurrentRoot()).root === root;
  }

  async health() {
    try {
      const { status, body } = await this.fetchJson('GET', '/v1/health');
      return { ok: status === 200, detail: body };
    } catch (err) {
      return { ok: false, detail: (err as RegistryUnavailableError).code ?? 'REGISTRY_ERROR' };
    }
  }

  async listLeaves() {
    try {
      const { status, body } = await this.fetchJson('GET', '/v1/registry/leaves', undefined, true);
      if (status !== 200 || !isObj(body) || !Array.isArray(body.leaves)) return null;
      const leaves: RegistryLeaf[] = body.leaves.filter(isObj).map((l) => ({
        index: Number(l.index),
        credentialId: String(l.credentialId ?? `slot-${String(l.index)}`),
        label: typeof l.credentialId === 'string' ? l.credentialId.replace(/^cred-/, '') : null,
        status: l.status === 'revoked' ? 'revoked' : l.status === 'empty' ? 'empty' : 'active',
        leaf: String(l.leaf),
      }));
      return { treeDepth: typeof body.treeDepth === 'number' ? body.treeDepth : null, leaves };
    } catch {
      return null;
    }
  }

  async rootHistory(): Promise<RootHistoryItem[] | null> {
    try {
      const { status, body } = await this.fetchJson('GET', '/v1/registry/history', undefined, true);
      if (status !== 200 || !isObj(body) || !Array.isArray(body.items)) return null;
      return body.items.filter(isObj).map((i) => ({
        root: String(i.root),
        version: Number(i.version),
        changedAt: String(i.changedAt),
        reason: String(i.reason),
      }));
    } catch {
      return null;
    }
  }

  async revoke(id: string) {
    const r = await this.fetchJson(
      'POST',
      `/v1/credentials/${encodeURIComponent(id)}/revoke`,
      {},
      true,
    );
    this.invalidate();
    return r;
  }

  credentialStatus(id: string) {
    return this.fetchJson(
      'GET',
      `/v1/credentials/${encodeURIComponent(id)}/status`,
      undefined,
      true,
    );
  }

  issue(body: unknown) {
    return this.fetchJson('POST', '/v1/credentials', body, true);
  }

  async reset() {
    const r = await this.fetchJson('POST', '/v1/admin/reset', {}, true);
    this.invalidate();
    return r;
  }
}
