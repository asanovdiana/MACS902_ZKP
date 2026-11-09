import type {
  ApiError,
  Challenge,
  GatewayStatus,
  PolicyInfo,
  ProverResult,
  ResourceId,
  VerifyResponse,
} from '../types/api';

export class HttpError extends Error implements ApiError {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public body?: unknown,
  ) {
    super(message);
  }
}

async function call<T>(
  method: string,
  url: string,
  body?: unknown,
): Promise<{ status: number; data: T }> {
  const res = await fetch(url, {
    method,
    credentials: 'same-origin',
    headers: body !== undefined ? { 'content-type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new HttpError(res.status, 'NON_JSON', `unexpected response (${res.status})`);
  }
  return { status: res.status, data: data as T };
}

async function json<T>(method: string, url: string, body?: unknown): Promise<T> {
  const { status, data } = await call<T & { error?: { code: string; message: string } }>(
    method,
    url,
    body,
  );
  if (status >= 400) {
    const err = (data as { error?: { code: string; message: string } } | null)?.error;
    throw new HttpError(
      status,
      err?.code ?? `HTTP_${status}`,
      err?.message ?? `request failed (${status})`,
      data,
    );
  }
  return data;
}

export const api = {
  status: () => json<GatewayStatus>('GET', '/api/status'),
  policies: () => json<{ items: PolicyInfo[] }>('GET', '/api/policies'),
  audit: () =>
    json<{
      generatedAt: string;
      summary: Record<string, number>;
      findings: Array<{ id: string; question: string; verdict: string; evidence: string }>;
      trustedSetup: string;
    }>('GET', '/api/evidence/p1-audit'),
  bench: () => json<BenchResults>('GET', '/api/bench/results'),
  challenge: (resource: ResourceId) => json<Challenge>('POST', '/api/zk/challenges', { resource }),
  /** Returns the verification decision for any HTTP status (denials are data, not exceptions). */
  verify: async (body: {
    challengeId: string;
    proof: unknown;
    publicSignals: string[];
    client?: { provingMs?: number; prover?: string };
  }) => {
    const { status, data } = await call<
      Partial<VerifyResponse> & { error?: { code: string; message: string } }
    >('POST', '/api/zk/verify', body);
    if (!data || typeof data.decision !== 'string')
      throw new HttpError(
        status,
        data?.error?.code ?? `HTTP_${status}`,
        data?.error?.message ?? 'verification request failed',
        data,
      );
    return { status, body: data as VerifyResponse };
  },
  service: (resource: ResourceId, path = '/', via: 'zk' | 'sso' = 'zk') =>
    call<Record<string, unknown>>('GET', `${via === 'zk' ? '' : '/sso'}/svc/${resource}${path}`),
  servicePost: (resource: ResourceId, path: string, body: unknown, via: 'zk' | 'sso' = 'zk') =>
    call<Record<string, unknown>>(
      'POST',
      `${via === 'zk' ? '' : '/sso'}/svc/${resource}${path}`,
      body,
    ),
  zkLogout: (resource: ResourceId) => json('POST', `/svc/${resource}/_zkag/logout`, {}),

  operatorMe: () => json<{ authenticated: boolean }>('GET', '/api/operator/me'),
  operatorLogin: async (token: string) => {
    await json('POST', '/api/operator/login', { token });
    // Best effort: the SSO baseline has its own operator session for its (identity-bearing) event stream.
    await json('POST', '/sso/operator/login', { token }).catch(() => undefined);
  },
  operatorLogout: () => json('POST', '/api/operator/logout', {}),

  registry: () => json<RegistryView>('GET', '/api/admin/registry'),
  revoke: (id: string) =>
    json<Record<string, unknown>>(
      'POST',
      `/api/admin/credentials/${encodeURIComponent(id)}/revoke`,
      {},
    ),
  credentialStatus: (id: string) =>
    json<{ credentialId: string; status: string }>(
      'GET',
      `/api/admin/credentials/${encodeURIComponent(id)}/status`,
    ),
  issue: (body: Record<string, unknown>) =>
    call<Record<string, unknown>>('POST', '/api/admin/credentials', body),
  reset: () => json<{ ok: boolean; registryReset: string }>('POST', '/api/admin/demo/reset', {}),

  ssoMe: () =>
    call<{ authenticated: boolean; identity?: Record<string, unknown> }>('GET', '/sso/me'),
  ssoLogout: () => json<{ endSessionUrl: string }>('POST', '/sso/logout', {}),
  ssoHealth: () =>
    json<{ keycloak: boolean; issuerMatches?: boolean }>('GET', '/sso/health/keycloak'),
};

/** User-side prover (P2 client, or the P3 diagnostic stand-in). Never routed through the gateway. */
export const prover = {
  health: () =>
    json<{ status: string; kind: string; proverReady: boolean }>('GET', '/p2/v1/health'),
  prove: (credentialRef: string, challenge: Challenge, variant = 'honest') =>
    json<ProverResult>('POST', '/p2/v1/prover/proofs', {
      credentialRef,
      variant,
      challenge: {
        challengeId: challenge.challengeId,
        profile: challenge.scheme.profile,
        nonce: challenge.nonce,
        resourceField: challenge.resourceField,
        epoch: challenge.epoch,
      },
    }),
};

export interface RegistryView {
  current: {
    root: string;
    version: string | null;
    treeDepth: number | null;
    source: string | null;
    fetchedAt: number;
  };
  leaves?: {
    treeDepth?: number;
    root?: string;
    leaves?: Array<{ index: number; credentialId: string | null; status: string; leaf: string }>;
    unavailable?: boolean;
  };
  history?: {
    items?: Array<{ root: string; version: number; changedAt: string; reason: string }>;
    unavailable?: boolean;
  };
  gatewayRootHistory: Array<{ root: string; version: string | null; observedAt: string }>;
}

export interface BenchMetric {
  id: string;
  label: string;
  unit: string;
  status: 'measured' | 'blocked';
  reason?: string;
  samples?: number;
  median?: number;
  p95?: number;
  min?: number;
  max?: number;
  mean?: number;
  note?: string;
}
export interface BenchResults {
  generatedAt: string;
  environment: Record<string, string | number>;
  artifact: Record<string, unknown>;
  config: Record<string, unknown>;
  metrics: BenchMetric[];
}
