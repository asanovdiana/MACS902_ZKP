import type { ResourceId } from '@zkag/shared';
import type { Clock } from '../utils/clock.js';
import { randomId, randomNonce128 } from '../utils/ids.js';

export interface Challenge {
  id: string;
  /** 128 random bits, canonical decimal (access.public_signals v4: "gateway issues 128 random bits"). */
  nonce: string;
  resource: ResourceId;
  profile: string;
  /** Unix seconds issued with the challenge; the proof's `now` must equal it (obligation 5). */
  now: string;
  /** floor(now / EPOCH_SECONDS). */
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
 * One-time challenges, addressable by ID (P3 API) or by nonce (team client `/access`). State lives in
 * process memory: this gateway is a SINGLE-INSTANCE deployment. `consume` is synchronous, so the
 * check-and-mark transition is atomic with respect to the Node.js event loop: two concurrent
 * submissions for the same challenge can never both observe state "issued". Consumed challenges are
 * retained until expiry + one TTL so replays are reported as replays.
 */
export class ChallengeStore {
  private readonly items = new Map<string, Challenge>();
  private readonly byNonce = new Map<string, string>();

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
    const nowSeconds = Math.floor(now / 1000);
    const challenge: Challenge = {
      id: randomId(18),
      nonce: randomNonce128(),
      resource,
      profile,
      now: String(nowSeconds),
      // Derived from the same second as `now` so that epoch === floor(now / EPOCH) always holds.
      epoch: this.epochAt(nowSeconds * 1000),
      createdAt: now,
      expiresAt: now + this.ttlMs,
      state: 'issued',
    };
    this.items.set(challenge.id, challenge);
    this.byNonce.set(challenge.nonce, challenge.id);
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

  /** Resolve the challenge ID for a nonce (team client `/access`), without consuming. */
  idForNonce(nonce: string): string | undefined {
    return this.byNonce.get(nonce);
  }

  peek(id: string): Challenge | undefined {
    return this.items.get(id);
  }

  sweep() {
    const cutoff = this.clock.now() - this.ttlMs; // keep consumed/expired ones for one extra TTL
    for (const [id, c] of this.items) {
      if (c.expiresAt < cutoff) {
        this.items.delete(id);
        this.byNonce.delete(c.nonce);
      }
    }
  }

  clear() {
    this.items.clear();
    this.byNonce.clear();
  }

  get size() {
    return this.items.size;
  }
}
