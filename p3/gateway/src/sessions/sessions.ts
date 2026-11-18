import type { ResourceId } from '@zkag/shared';
import type { Clock } from '../utils/clock.js';
import { randomId } from '../utils/ids.js';

export interface ZkSession {
  id: string;
  resource: ResourceId;
  /** Per-session random pseudonym forwarded to services instead of any identity. */
  pseudonym: string;
  /** Registry root the authorizing proof was verified against. */
  root: string;
  issuedAt: number;
  expiresAt: number;
}

export type SessionLookup =
  | { ok: true; session: ZkSession }
  | {
      ok: false;
      reason: 'SESSION_MISSING' | 'SESSION_INVALID' | 'SESSION_EXPIRED' | 'SESSION_WRONG_RESOURCE';
    };

/**
 * Server-side, resource-scoped sessions. The cookie only carries a 144-bit random ID; a
 * fresh ID is minted on every issuance (no fixation). Sessions are bound to the registry
 * root at issuance and are invalidated as soon as the gateway observes a different root.
 */
export class SessionStore {
  private readonly sessions = new Map<string, ZkSession>();

  constructor(
    private readonly clock: Clock,
    private readonly ttlMs: number,
  ) {}

  issue(resource: ResourceId, root: string): ZkSession {
    const now = this.clock.now();
    const session: ZkSession = {
      id: randomId(18),
      resource,
      pseudonym: `zk-${randomId(9)}`,
      root,
      issuedAt: now,
      expiresAt: now + this.ttlMs,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  lookup(id: string | undefined, resource: ResourceId): SessionLookup {
    if (!id) return { ok: false, reason: 'SESSION_MISSING' };
    const session = this.sessions.get(id);
    if (!session) return { ok: false, reason: 'SESSION_INVALID' };
    if (this.clock.now() >= session.expiresAt) {
      this.sessions.delete(id);
      return { ok: false, reason: 'SESSION_EXPIRED' };
    }
    if (session.resource !== resource) return { ok: false, reason: 'SESSION_WRONG_RESOURCE' };
    return { ok: true, session };
  }

  revoke(id: string): ZkSession | undefined {
    const s = this.sessions.get(id);
    this.sessions.delete(id);
    return s;
  }

  distinctRoots(): string[] {
    return [...new Set([...this.sessions.values()].map((s) => s.root))];
  }

  /** Invalidate every session authorized under `root`. */
  revokeByRoot(root: string): ZkSession[] {
    const revoked: ZkSession[] = [];
    for (const s of this.sessions.values()) {
      if (s.root === root) {
        this.sessions.delete(s.id);
        revoked.push(s);
      }
    }
    return revoked;
  }

  sweep() {
    const now = this.clock.now();
    for (const [id, s] of this.sessions) if (now >= s.expiresAt) this.sessions.delete(id);
  }

  clear() {
    this.sessions.clear();
  }

  get size() {
    return this.sessions.size;
  }
}

export const sessionCookieName = (resource: ResourceId) => `zkag_${resource.replace('-', '_')}`;
