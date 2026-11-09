import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { GatewayStatus } from '../../src/types/api';

const verify = vi.fn();
const prove = vi.fn();
vi.mock('../../src/services/api', async () => {
  class HttpError extends Error {
    constructor(
      public status: number,
      public code: string,
      message: string,
      public body?: unknown,
    ) {
      super(message);
    }
  }
  return {
    HttpError,
    api: {
      challenge: vi.fn(async (r: string) => ({
        challengeId: 'c'.repeat(24),
        resource: r,
        scheme: { profile: 'p', publicSignals: ['root'] },
      })),
      verify,
    },
    prover: { prove },
  };
});
const { SCENARIOS, runScenario } = await import('../../src/features/attack-lab/scenarios');
const { HttpError } = await import('../../src/services/api');

const status = (supported: boolean): GatewayStatus => ({
  mode: 'diagnostic-p1',
  zkAuthorization: 'blocked',
  components: {},
  artifacts: { status: 'ready' },
  settings: {
    sessionTtlSeconds: 600,
    challengeTtlSeconds: 60,
    epochSeconds: 600,
    nullifierMaxPerEpoch: 1,
    rootCacheMs: 0,
  },
  devSecretsInUse: true,
  profile: {
    id: 'x',
    title: 'x',
    signals: ['root'],
    notes: [],
    capabilities: [
      'attributeBinding',
      'issuerBinding',
      'nonceBinding',
      'nullifier',
      'expiryCheck',
      'policyBinding',
      'resourceBinding',
    ].map((id) => ({ id, label: id, supported })),
  },
});
const verifyBody = (decision: string, reason: string, valid: boolean | null) => ({
  status: decision === 'granted' ? 200 : 424,
  body: { decision, reason, groth16: { valid, verifyMs: 1 }, checks: [] },
});
const tamper = SCENARIOS.find((s) => s.id === 'tamper')!;

beforeEach(() => {
  verify.mockReset();
  prove.mockReset();
});

describe('attack verdicts are derived from real responses, never hard-coded', () => {
  it('FAIL when a forged proof is mathematically valid and the circuit lacks the binding (even though access was refused)', async () => {
    prove.mockResolvedValue({ proof: {}, publicSignals: ['1'], provingMs: 5 });
    verify.mockResolvedValue(verifyBody('blocked', 'PROFILE_NOT_AUTHORIZATION_ELIGIBLE', true));
    expect((await runScenario(tamper, status(false))).verdict).toBe('FAIL');
  });
  it('PASS when the prover cannot produce a witness for forged attributes', async () => {
    prove.mockRejectedValue(new HttpError(422, 'WITNESS_UNSATISFIABLE', 'assert failed'));
    expect((await runScenario(tamper, status(true))).verdict).toBe('PASS');
  });
  it('FAIL (critical) when a forged proof is granted', async () => {
    prove.mockResolvedValue({ proof: {}, publicSignals: ['1'], provingMs: 5 });
    verify.mockResolvedValue(verifyBody('granted', 'ACCESS_GRANTED', true));
    const r = await runScenario(tamper, status(true));
    expect(r.verdict).toBe('FAIL');
    expect(r.summary).toMatch(/GRANTED/);
  });
  it('BLOCKED when the prover is unreachable', async () => {
    prove.mockRejectedValue(new HttpError(0, 'PROVER_UNREACHABLE', 'down'));
    expect((await runScenario(tamper, status(true))).verdict).toBe('BLOCKED');
  });
  it('nullifier and expiry scenarios are BLOCKED when the circuit lacks them', async () => {
    for (const id of ['nullifier', 'expired']) {
      const r = await runScenario(
        SCENARIOS.find((s) => s.id === id)!,
        status(false),
      );
      expect(r.verdict).toBe('BLOCKED');
    }
    expect(prove).not.toHaveBeenCalled();
  });
});
