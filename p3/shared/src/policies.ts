import type { ResourceId } from './resources.js';

/** Roles from the Project Scope (M1). Codes per team ADR 0008 (engineer 0, admin 1, contractor 2, finance 3). */
export const ROLES = ['engineer', 'admin', 'contractor', 'finance'] as const;
export type Role = (typeof ROLES)[number];

/** Bit positions for roleMask (bit i set => role with code i allowed), ADR 0008. */
export const PROPOSED_ROLE_CODES: Record<Role, number> = {
  engineer: 0,
  admin: 1,
  contractor: 2,
  finance: 3,
};

export interface AccessPolicy {
  resource: ResourceId;
  allowedRoles: readonly Role[];
  minClearance: number;
  requireDeviceCompliant: boolean;
  /** Human readable summary, matching the Project Scope table. */
  summary: string;
}

/** Server-authoritative policies (Project Scope, M5 table). */
export const POLICIES: Record<ResourceId, AccessPolicy> = {
  wiki: {
    resource: 'wiki',
    allowedRoles: ROLES,
    minClearance: 0,
    requireDeviceCompliant: true,
    summary: 'Any role, clearance ≥ 0, device compliant',
  },
  'file-share': {
    resource: 'file-share',
    allowedRoles: ['engineer', 'admin'],
    minClearance: 2,
    requireDeviceCompliant: false,
    summary: 'Engineer or admin, clearance ≥ 2',
  },
  'admin-panel': {
    resource: 'admin-panel',
    allowedRoles: ['admin'],
    minClearance: 3,
    requireDeviceCompliant: true,
    summary: 'Admin only, clearance 3, device compliant',
  },
};

export function roleMask(roles: readonly Role[]): bigint {
  return roles.reduce((mask, r) => mask | (1n << BigInt(PROPOSED_ROLE_CODES[r])), 0n);
}

/** Policy parameters exactly as the v4 circuit's public inputs (team CONTRACTS.md demo policies). */
export function policyPublicParams(policy: AccessPolicy) {
  return {
    roleMask: roleMask(policy.allowedRoles),
    /** Scope policies do not restrict department: all 4 departments allowed (deptMask 15). */
    deptMask: 0b1111n,
    minClearance: BigInt(policy.minClearance),
    requireDevice: policy.requireDeviceCompliant ? 1n : 0n,
  };
}

export interface ClaimedAttributes {
  roles: readonly string[];
  clearance: number | null;
  deviceCompliant: boolean | null;
}

export type PolicyEvaluation =
  | { allowed: true }
  | {
      allowed: false;
      reason: 'ROLE_NOT_ALLOWED' | 'CLEARANCE_TOO_LOW' | 'DEVICE_NOT_COMPLIANT' | 'MISSING_CLAIM';
    };

/**
 * Plain attribute-based evaluation. Used ONLY by the SSO baseline, where the identity
 * provider asserts attributes in a signed token. The ZK gateway never evaluates
 * plaintext attributes: it relies on circuit constraints.
 */
export function evaluatePolicy(policy: AccessPolicy, attrs: ClaimedAttributes): PolicyEvaluation {
  if (attrs.clearance === null || attrs.deviceCompliant === null) {
    return { allowed: false, reason: 'MISSING_CLAIM' };
  }
  const allowed = new Set<string>(policy.allowedRoles);
  if (!attrs.roles.some((r) => allowed.has(r)))
    return { allowed: false, reason: 'ROLE_NOT_ALLOWED' };
  if (!Number.isInteger(attrs.clearance) || attrs.clearance < policy.minClearance) {
    return { allowed: false, reason: 'CLEARANCE_TOO_LOW' };
  }
  if (policy.requireDeviceCompliant && attrs.deviceCompliant !== true) {
    return { allowed: false, reason: 'DEVICE_NOT_COMPLIANT' };
  }
  return { allowed: true };
}
