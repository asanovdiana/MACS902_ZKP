import { api, prover, type HttpError } from '../../services/api';
import type { Challenge, ProverResult, ResourceId, VerifyResponse } from '../../types/api';

export const STEPS = [
  { id: 'challenge-requested', label: 'Challenge requested' },
  { id: 'challenge-received', label: 'Challenge received' },
  { id: 'witness', label: 'Witness / prover preparation' },
  { id: 'proving', label: 'Proof generation' },
  { id: 'submitted', label: 'Proof submitted' },
  { id: 'verifying', label: 'Gateway verification' },
  { id: 'decision', label: 'Authorization decision' },
  { id: 'access', label: 'Protected resource access' },
] as const;
export type StepId = (typeof STEPS)[number]['id'];
export type StepStatus = 'pending' | 'active' | 'done' | 'failed' | 'skipped' | 'blocked';
export interface StepState {
  status: StepStatus;
  startedAt?: number;
  ms?: number;
  detail?: string;
}
export type StepMap = Record<StepId, StepState>;
export const initialSteps = (): StepMap =>
  Object.fromEntries(STEPS.map((s) => [s.id, { status: 'pending' }])) as StepMap;

export interface FlowResult {
  simulated: boolean;
  challenge?: Challenge;
  prover?: ProverResult;
  verify?: { status: number; body: VerifyResponse };
  service?: { status: number; data: Record<string, unknown> };
  error?: { stage: StepId; code: string; message: string };
  timings: {
    challengeMs?: number;
    proverRoundTripMs?: number;
    provingMs?: number;
    verifyMs?: number | null;
    gatewayMs?: number;
    totalMs?: number;
  };
}

type OnStep = (id: StepId, patch: StepState) => void;

/** Real end-to-end flow: gateway challenge → user-side prover → gateway verification → resource. */
export async function runZkFlow(opts: {
  credentialRef: string;
  resource: ResourceId;
  variant?: string;
  onStep?: OnStep;
}): Promise<FlowResult> {
  const on: OnStep = opts.onStep ?? (() => undefined);
  const t0 = performance.now();
  const result: FlowResult = { simulated: false, timings: {} };
  const stage = (id: StepId) => {
    const s = performance.now();
    on(id, { status: 'active', startedAt: Date.now() });
    return (status: StepStatus = 'done', detail?: string) => {
      const ms = performance.now() - s;
      on(id, { status, ms, ...(detail ? { detail } : {}) });
      return ms;
    };
  };
  let end = stage('challenge-requested');
  try {
    result.challenge = await api.challenge(opts.resource);
    result.timings.challengeMs = end('done');
  } catch (e) {
    end('failed', (e as Error).message);
    result.error = {
      stage: 'challenge-requested',
      code: (e as HttpError).code ?? 'ERROR',
      message: (e as Error).message,
    };
    return result;
  }
  on('challenge-received', {
    status: 'done',
    ms: 0,
    detail: `nonce ${result.challenge.nonce.slice(0, 10)}… · expires ${new Date(result.challenge.expiresAt).toLocaleTimeString()}`,
  });
  on('witness', {
    status: 'done',
    ms: 0,
    detail: 'credential + challenge handed to the local prover (not the gateway)',
  });
  end = stage('proving');
  try {
    result.prover = await prover.prove(opts.credentialRef, result.challenge, opts.variant);
    result.timings.proverRoundTripMs = end(
      'done',
      `prover reported ${result.prover.provingMs.toFixed(0)} ms (witness + Groth16)`,
    );
    result.timings.provingMs = result.prover.provingMs;
  } catch (e) {
    const err = e as HttpError;
    end('failed', err.message);
    result.error = { stage: 'proving', code: err.code ?? 'PROVER_ERROR', message: err.message };
    for (const id of ['submitted', 'verifying', 'decision', 'access'] as StepId[])
      on(id, { status: 'skipped' });
    return result;
  }
  on('submitted', {
    status: 'done',
    ms: 0,
    detail: `${result.prover.publicSignals.length} public signal(s), Groth16 proof`,
  });
  end = stage('verifying');
  try {
    result.verify = await api.verify({
      challengeId: result.challenge.challengeId,
      proof: result.prover.proof,
      publicSignals: result.prover.publicSignals,
      client: { provingMs: result.prover.provingMs, prover: result.prover.prover.kind },
    });
    result.timings.gatewayMs = end(
      'done',
      `Groth16 ${result.verify.body.groth16.valid === null ? 'not run' : result.verify.body.groth16.valid ? 'valid' : 'INVALID'}`,
    );
    result.timings.verifyMs = result.verify.body.groth16.verifyMs;
  } catch (e) {
    end('failed', (e as Error).message);
    result.error = {
      stage: 'verifying',
      code: (e as HttpError).code ?? 'ERROR',
      message: (e as Error).message,
    };
    return result;
  }
  const d = result.verify.body.decision;
  on('decision', {
    status: d === 'granted' ? 'done' : d === 'blocked' ? 'blocked' : 'failed',
    ms: 0,
    detail: `${d.toUpperCase()} · ${result.verify.body.reason}`,
  });
  if (d === 'granted') {
    end = stage('access');
    result.service = await api.service(opts.resource, '/');
    end(result.service.status === 200 ? 'done' : 'failed', `HTTP ${result.service.status}`);
  } else on('access', { status: 'skipped', detail: 'no session issued' });
  result.timings.totalMs = performance.now() - t0;
  return result;
}

/** UI DEVELOPMENT MODE ONLY: deterministic, clearly-labelled simulation. Never calls the gateway. */
export async function runSimulatedFlow(resource: ResourceId, onStep?: OnStep): Promise<FlowResult> {
  const on: OnStep = onStep ?? (() => undefined);
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const delays: Record<StepId, number> = {
    'challenge-requested': 250,
    'challenge-received': 100,
    witness: 300,
    proving: 1200,
    submitted: 120,
    verifying: 350,
    decision: 100,
    access: 200,
  };
  for (const s of Object.keys(delays) as StepId[]) {
    on(s, { status: 'active', startedAt: Date.now() });
    await wait(delays[s]);
    on(s, { status: 'done', ms: delays[s], detail: 'SIMULATED' });
  }
  return {
    simulated: true,
    timings: {},
    verify: {
      status: 0,
      body: {
        decision: 'granted',
        reason: 'SIMULATED',
        message: 'Simulated outcome for UI development — not a real verification.',
        correlationId: 'simulated',
        challengeId: 'simulated',
        resource,
        policy: null,
        profile: { id: 'simulated', title: 'UI development mode', authorizationEligible: false },
        groth16: { valid: null, verifyMs: null, verifier: 'none' },
        checks: [{ id: 'sim', label: 'Simulated — no cryptography executed', status: 'skipped' }],
        publicSignals: [{ name: 'simulated', value: '0' }],
        proof: null,
        timings: { totalMs: 0, verifyMs: null, registryMs: null },
        root: null,
      },
    },
  };
}
