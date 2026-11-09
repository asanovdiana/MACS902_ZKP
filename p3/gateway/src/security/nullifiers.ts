import type { ResourceId } from '@zkag/shared';

export type NullifierResult = { ok: true; uses: number } | { ok: false; uses: number };

/**
 * Nullifier rate limiting: a verified nullifier (circuit output Poseidon(secret, resource, epoch))
 * may be used at most `maxPerEpoch` times per (resource, epoch). Only nullifiers taken from a
 * proof that already passed Groth16 verification are ever recorded. `record` is synchronous and
 * therefore atomic within this single-instance gateway.
 */
export class NullifierStore {
  private readonly uses = new Map<string, number>();

  constructor(private readonly maxPerEpoch: number) {}

  private key(resource: ResourceId, epoch: string, nullifier: string) {
    return `${resource}|${epoch}|${nullifier}`;
  }

  record(resource: ResourceId, epoch: string, nullifier: string): NullifierResult {
    const k = this.key(resource, epoch, nullifier);
    const used = this.uses.get(k) ?? 0;
    if (used >= this.maxPerEpoch) return { ok: false, uses: used };
    this.uses.set(k, used + 1);
    return { ok: true, uses: used + 1 };
  }

  /** Drop entries for epochs older than `currentEpoch - 1`. */
  sweep(currentEpoch: bigint) {
    for (const k of this.uses.keys()) {
      const epoch = BigInt(k.split('|')[1] ?? '0');
      if (epoch < currentEpoch - 1n) this.uses.delete(k);
    }
  }

  clear() {
    this.uses.clear();
  }

  get size() {
    return this.uses.size;
  }
}
