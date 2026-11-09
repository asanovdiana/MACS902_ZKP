import type { ResourceId } from './resources.js';

/**
 * Typed, privacy-safe security events streamed to the demo UI.
 * Events MUST NOT carry private witness values, credential secrets, private attributes,
 * session identifiers or bearer tokens.
 */
export type CheckStatus = 'pass' | 'fail' | 'not-supported' | 'skipped';

export interface VerificationCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail?: string;
}

export type Decision = 'granted' | 'denied' | 'blocked';

interface BaseEvent {
  id: string;
  ts: string;
  correlationId: string;
  source: 'zk-gateway' | 'sso-baseline' | 'registry';
}

export type ZkEvent =
  | (BaseEvent & {
      type: 'challenge.created';
      resource: ResourceId;
      challengeId: string;
      nonce: string;
      epoch: string;
      expiresAt: string;
      profile: string;
    })
  | (BaseEvent & {
      type: 'proof.submitted';
      resource: ResourceId | null;
      challengeId: string;
      proofBytes: number;
      proofDigest: string;
      publicSignals: { name: string; value: string }[];
    })
  | (BaseEvent & {
      type: 'verification.completed';
      resource: ResourceId | null;
      challengeId: string;
      decision: Decision;
      reason: string;
      groth16Valid: boolean | null;
      verifyMs: number | null;
      totalMs: number;
      checks: VerificationCheck[];
      profile: string;
      proofBytes: number;
      publicSignals: { name: string; value: string }[];
      nullifier: string | null;
      /** Everything the gateway received about the requester. Kept explicit for the privacy demo. */
      requesterFields: string[];
    })
  | (BaseEvent & {
      type: 'replay.rejected';
      resource: ResourceId | null;
      challengeId: string;
      reason: string;
    })
  | (BaseEvent & {
      type: 'nullifier.rate_limited';
      resource: ResourceId;
      nullifier: string;
      epoch: string;
    })
  | (BaseEvent & {
      type: 'root.changed';
      previousRoot: string | null;
      root: string;
      version: string | null;
    })
  | (BaseEvent & { type: 'credential.revoked'; credentialId: string; root: string | null })
  | (BaseEvent & { type: 'session.issued'; resource: ResourceId; expiresAt: string })
  | (BaseEvent & { type: 'session.revoked'; resource: ResourceId; reason: string })
  | (BaseEvent & {
      type: 'proxy.forwarded';
      resource: ResourceId;
      method: string;
      path: string;
      status: number;
    })
  | (BaseEvent & {
      type: 'sso.login';
      username: string;
      email: string | null;
      name: string | null;
      roles: string[];
      claims: Record<string, unknown>;
      latencyMs: number;
    })
  | (BaseEvent & {
      type: 'sso.decision';
      resource: ResourceId;
      decision: 'granted' | 'denied';
      reason: string;
      username: string;
      email: string | null;
      name: string | null;
      roles: string[];
      clearance: number | null;
      department: string | null;
      deviceCompliant: boolean | null;
      jwtChecks: VerificationCheck[];
      latencyMs: number;
      path: string;
    })
  | (BaseEvent & { type: 'sso.logout'; username: string });

export type GatewayEvent = ZkEvent;
export type GatewayEventType = GatewayEvent['type'];
