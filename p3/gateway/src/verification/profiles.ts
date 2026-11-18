import type { ResourceId } from '@zkag/shared';

/**
 * A circuit profile describes WHAT a given compiled circuit actually proves, i.e. which
 * security properties are cryptographically enforced, and the exact order of its public
 * signals. The gateway only issues sessions for a profile whose every required capability
 * is established AND whose artifacts carry an accepted security review.
 */
export type SignalName =
  | 'nullifier'
  | 'root'
  | 'nonce'
  | 'resourceId'
  | 'epoch'
  | 'roleMask'
  | 'deptMask'
  | 'minClearance'
  | 'requireDevice'
  | 'now'
  | 'issuerAx'
  | 'issuerAy';

export const REQUIRED_CAPABILITIES = [
  'rootBinding',
  'attributeBinding',
  'issuerBinding',
  'policyBinding',
  'nonceBinding',
  'resourceBinding',
  'epochBinding',
  'nullifier',
  'expiryCheck',
] as const;
export type Capability = (typeof REQUIRED_CAPABILITIES)[number];

export const CAPABILITY_LABELS: Record<Capability, string> = {
  rootBinding: 'Proof bound to registry Merkle root',
  attributeBinding: 'Attributes bound to issuer-signed credential',
  issuerBinding: 'Signature key bound to trusted issuer',
  policyBinding: 'Resource policy enforced as public input',
  nonceBinding: 'Proof bound to gateway challenge nonce',
  resourceBinding: 'Proof bound to resource ID',
  epochBinding: 'Proof bound to epoch',
  nullifier: 'Nullifier output for rate limiting',
  expiryCheck: 'Credential expiry enforced',
};

export interface CircuitProfile {
  id: 'p1-integrated-v3' | 'integrated-access-v4';
  circuitId: string;
  title: string;
  /** Ordered exactly as snarkjs emits publicSignals (outputs first, then public inputs). */
  signals: readonly SignalName[];
  capabilities: Record<Capability, boolean>;
  /** Resources whose policy the circuit can express. */
  policyCoverage: readonly ResourceId[];
  notes: string[];
}

export const PROFILES: Record<CircuitProfile['id'], CircuitProfile> = {
  'p1-integrated-v3': {
    id: 'p1-integrated-v3',
    circuitId: 'integrated_access_v3',
    title: 'P1 integrated_access_v3 (as delivered)',
    signals: ['root'],
    capabilities: {
      rootBinding: true,
      attributeBinding: false,
      issuerBinding: false,
      policyBinding: false,
      nonceBinding: false,
      resourceBinding: false,
      epochBinding: false,
      nullifier: false,
      expiryCheck: false,
    },
    policyCoverage: [],
    notes: [
      'Verified by the executed P1 audit (npm run p1:audit): attributes are not signed and the issuer key is a private witness.',
      'Hard-coded FileShareAccess() policy over unbound attributes, so it does not establish the File Share policy either.',
      'Diagnostic only: Groth16 validity is reported, sessions are never issued.',
    ],
  },
  'integrated-access-v4': {
    id: 'integrated-access-v4',
    circuitId: 'integrated_access_v4',
    title: 'Team v4 access circuit (integrated_access_v4, depth 16)',
    // access.public_signals v4 (docs/CONTRACTS.md, ADR 0007): output first, then declaration order.
    signals: [
      'nullifier',
      'root',
      'issuerAx',
      'issuerAy',
      'roleMask',
      'deptMask',
      'minClearance',
      'requireDevice',
      'now',
      'nonce',
      'resourceId',
      'epoch',
    ],
    capabilities: {
      rootBinding: true,
      attributeBinding: true,
      issuerBinding: true,
      policyBinding: true,
      nonceBinding: true,
      resourceBinding: true,
      epochBinding: true,
      nullifier: true,
      expiryCheck: true,
    },
    policyCoverage: ['wiki', 'file-share', 'admin-panel'],
    notes: [
      'attrHash = Poseidon(7)(role, dept, clearance, deviceCompliant, employeeActive, expiry, commitment) is the signed message and the Merkle leaf.',
      'Issuer key, policy, now, nonce, resourceId and epoch are public inputs; nullifier = Poseidon(3)(secret, resourceId, epoch).',
      'Gateway enforces contract obligations 1–8 (issuer pin, root staleness rule, policy, challenge now/epoch, nonce, nullifier).',
    ],
  },
};

export function missingCapabilities(profile: CircuitProfile): Capability[] {
  return REQUIRED_CAPABILITIES.filter((c) => !profile.capabilities[c]);
}
