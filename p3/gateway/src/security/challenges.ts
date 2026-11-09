import type { ResourceId } from '@zkag/shared';
import type { Clock } from '../utils/clock.js';
import { randomFieldNonce, randomId } from '../utils/ids.js';

export interface Challenge {
  id: string;
  nonce: string;
  resource: ResourceId;
  profile: string;
  epoch: string;
  createdAt: number;
  expiresAt: number;
  state: 'issued' | 'consumed';
}

export type ConsumeResult =
  | { ok: true; challenge: Challenge }
  | {
      ok: false;
      reason: 'CHALLENGE_UNKNOWN' | 'CHALLENGE_EXPIRED' | 'CHALLENGE_REPLAYED';
      challenge?: Challenge;
    };

/**
 * One-time challenges. State lives in process memory: this gateway is a SINGLE-INSTANCE
 * deployment. `consume` is synchronous, so the
 * check-and-mark transition is atomic with respect to the Node.js event loop: two
 * concurrent submissions for the same challenge can never both observe state "issued".
 * Consumed challenges are retained until expiry + grace so replays are reported as such.
 */
export class ChallengeStore {
  private readonly items = new Map<string, Challenge>();

  constructor(
    private readonly clock: Clock,
    private readonly ttlMs: number,
    private readonly epochMs: number,
    private readonly maxOutstanding: number,
  ) {}

  epochAt(ts: number): string {
    return Math.floor(ts / this.epochMs).toString();
  }

  create(resource: ResourceId, profile: string): Challenge | null {
    this.sweep();
    if (this.items.size >= this.maxOutstanding) return null;
    const now = this.clock.now();
    const challenge: Challenge = {
      id: randomId(18),
      nonce: randomFieldNonce(),
      resource,
      profile,
      epoch: this.epochAt(now),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      state: 'issued',
    };
    this.items.set(challenge.id, challenge);
    return challenge;
  }

  /** Atomically consume. Any submission attempt burns the challenge, valid or not. */
  consume(id: string): ConsumeResult {
    const challenge = this.items.get(id);
    if (!challenge) return { ok: false, reason: 'CHALLENGE_UNKNOWN' };
    if (challenge.state === 'consumed')
      return { ok: false, reason: 'CHALLENGE_REPLAYED', challenge };
    challenge.state = 'consumed';
    if (this.clock.now() > challenge.expiresAt)
      return { ok: false, reason: 'CHALLENGE_EXPIRED', challenge };
    return { ok: true, challenge };
  }

  peek(id: string): Challenge | undefined {
    return this.items.get(id);
  }

  sweep() {
    const cutoff = this.clock.now() - this.ttlMs; // keep consumed/expired ones for one extra TTL
    for (const [id, c] of this.items) if (c.expiresAt < cutoff) this.items.delete(id);
  }

  clear() {
    this.items.clear();
  }

  get size() {
    return this.items.size;
  }
}
