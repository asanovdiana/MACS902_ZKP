import type { FixtureFile } from './fixtures.js';
import { computeTree } from './p1.js';

export type CredentialStatus = 'active' | 'revoked';

export interface RootRecord {
  root: string;
  version: number;
  changedAt: string;
  reason: string;
}

/**
 * Depth-2 Poseidon registry matching P1's MerkleMembership. Revoking zeroes the leaf,
 * which changes the root (Project Scope M2). Diagnostic stand-in for the P2 registry.
 */
export class DiagnosticRegistry {
  private leaves: bigint[] = [];
  private status = new Map<string, CredentialStatus>();
  private currentRoot = 0n;
  private version = 0;
  readonly history: RootRecord[] = [];

  constructor(private readonly fixtures: FixtureFile) {}

  async init() {
    this.leaves = this.fixtures.leaves.map((l) => BigInt(l));
    this.status = new Map(this.fixtures.personas.map((p) => [p.credentialId, 'active' as const]));
    await this.recompute('initialised from diagnostic fixtures');
  }

  private async recompute(reason: string) {
    const { root } = await computeTree(this.leaves);
    this.currentRoot = root;
    this.version += 1;
    this.history.unshift({
      root: root.toString(),
      version: this.version,
      changedAt: new Date().toISOString(),
      reason,
    });
    this.history.splice(50);
  }

  get root() {
    return {
      root: this.currentRoot.toString(),
      version: String(this.version),
      updatedAt: this.history[0]!.changedAt,
    };
  }

  get initialLeaves(): bigint[] {
    return this.fixtures.leaves.map((l) => BigInt(l));
  }

  get currentLeaves(): bigint[] {
    return [...this.leaves];
  }

  credentialStatus(id: string): CredentialStatus | null {
    return this.status.get(id) ?? null;
  }

  leafView() {
    return this.leaves.map((leaf, index) => {
      const persona = this.fixtures.personas.find((p) => p.slot === index);
      return {
        index,
        credentialId: persona?.credentialId ?? null,
        status: persona ? this.status.get(persona.credentialId)! : ('empty' as const),
        leaf: leaf.toString(),
      };
    });
  }

  async revoke(id: string): Promise<boolean> {
    const persona = this.fixtures.personas.find((p) => p.credentialId === id);
    if (!persona || this.status.get(id) !== 'active') return false;
    this.leaves[persona.slot] = 0n;
    this.status.set(id, 'revoked');
    await this.recompute(`credential ${id} revoked`);
    return true;
  }

  async reset() {
    this.leaves = this.initialLeaves;
    for (const p of this.fixtures.personas) this.status.set(p.credentialId, 'active');
    await this.recompute('demo reset');
  }
}
