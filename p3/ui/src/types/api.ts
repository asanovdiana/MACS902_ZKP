import type { Decision, GatewayEvent, ResourceId, VerificationCheck } from '@zkag/shared';
export type { Decision, GatewayEvent, ResourceId, VerificationCheck };

export interface Challenge {
  challengeId: string;
  nonce: string;
  resource: ResourceId;
  resourceField: string;
  epoch: string;
  now: string;
  issuedAt: string;
  expiresAt: string;
  policy: {
    summary: string;
    roleMask: string;
    deptMask: string;
    minClearance: string;
    requireDevice: string;
  };
  scheme: { proofSystem: string; curve: string; profile: string; publicSignals: string[] };
  correlationId: string;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export interface ProverResult {
  proof: Groth16Proof;
  publicSignals: string[];
  provingMs: number;
  prover: { kind: string; circuit: string; variant: string };
  bindings: Record<string, boolean>;
}

export interface VerifyResponse {
  decision: Decision;
  reason: string;
  /** Team wire code (client/attacks codes); null when granted. */
  code: string | null;
  message: string;
  correlationId: string;
  challengeId: string | null;
  resource: ResourceId | null;
  policy: string | null;
  profile: { id: string; title: string; authorizationEligible: boolean };
  groth16: { valid: boolean | null; verifyMs: number | null; verifier: string };
  checks: VerificationCheck[];
  publicSignals: { name: string; value: string }[];
  proof: { bytes: number; jsonBytes: number; digest: string } | null;
  timings: { totalMs: number; verifyMs: number | null; registryMs: number | null };
  root: { trusted: string | null; version: string | null } | null;
  session?: { resource: ResourceId; expiresAt: string };
  missingGuarantees?: string[];
}

export interface Capability {
  id: string;
  label: string;
  supported: boolean;
}

export interface GatewayStatus {
  mode: 'diagnostic-p1' | 'real-integration';
  zkAuthorization: 'ready' | 'blocked';
  components: Record<
    string,
    { ok: boolean; detail?: unknown; missing?: string[]; profile?: string }
  >;
  profile: {
    id: string;
    title: string;
    signals: string[];
    notes: string[];
    capabilities: Capability[];
  };
  artifacts: {
    status: string;
    circuitId?: string;
    version?: string;
    securityStatus?: string;
    trustedSetup?: string | null;
    vkeySha256?: string;
    reviewed?: boolean;
    trust?: 'reviewed' | 'demo-accepted' | 'unreviewed';
    detail?: string;
  };
  settings: {
    sessionTtlSeconds: number;
    challengeTtlSeconds: number;
    epochSeconds: number;
    nullifierMaxPerEpoch: number;
    rootCacheMs: number;
    registryApi?: string;
    issuerPinned?: boolean;
    demoKeysAllowed?: boolean;
  };
  devSecretsInUse: boolean;
}

export interface PolicyInfo {
  resource: ResourceId;
  name: string;
  description: string;
  resourceField: string;
  summary: string;
  allowedRoles: string[];
  minClearance: number;
  requireDeviceCompliant: boolean;
  supportedByActiveCircuit: boolean;
}

export interface ApiError {
  status: number;
  code: string;
  message: string;
  body?: unknown;
}
