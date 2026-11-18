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

export interface RootSnapshot {
  root: string;
  version: string | null;
  updatedAt: string | null;
  treeDepth: number | null;
  source: string | null;
  fetchedAt: number;
  fromCache: boolean;
}

export type RootStatus = 'current' | 'recent-insert' | 'stale' | 'revoked' | 'unknown';

export interface RootAssessment {
  acceptable: boolean;
  status: RootStatus;
  detail: string;
  current: RootSnapshot;
}

export interface RegistryLeaf {
  index: number;
  credentialId: string;
  /** Admin-side label (e.g. the employeeId the admin typed); never sent to the gateway's events. */
  label: string | null;
  status: 'active' | 'revoked' | 'empty';
  leaf: string;
}

export interface RootHistoryItem {
  root: string;
  version: number;
  changedAt: string;
  reason: string;
}

export interface AdminResult {
  status: number;
  body: unknown;
}

/** The gateway's view of the credential registry (P2). Fails closed: errors throw, never return a root. */
export interface RegistryClient {
  readonly api: 'issuer-v1' | 'p3-standin';
  getCurrentRoot(opts?: { maxAgeMs?: number }): Promise<RootSnapshot>;
  /** Is `root` acceptable for a NEW proof right now (contract obligation 3)? */
  assessProofRoot(root: string, gatewayNowSeconds: number): Promise<RootAssessment>;
  /** May a session authorized under `root` continue (no revocation since)? */
  sessionRootValid(root: string): Promise<boolean>;
  health(): Promise<{ ok: boolean; detail: unknown }>;
  onRootChange(listener: (prev: RootSnapshot | null, next: RootSnapshot) => void): void;
  // ---- operator-only administration (Admin Console) ----
  listLeaves(): Promise<{ treeDepth: number | null; leaves: RegistryLeaf[] } | null>;
  rootHistory(): Promise<RootHistoryItem[] | null>;
  revoke(credentialId: string): Promise<AdminResult>;
  credentialStatus(credentialId: string): Promise<AdminResult>;
  issue(body: unknown): Promise<AdminResult>;
  reset(): Promise<AdminResult | null>;
}
