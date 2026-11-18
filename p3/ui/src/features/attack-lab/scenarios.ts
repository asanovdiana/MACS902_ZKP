import { api, HttpError, prover } from '../../services/api';
import type {
  Challenge,
  GatewayStatus,
  ProverResult,
  ResourceId,
  VerifyResponse,
} from '../../types/api';

export type Verdict = 'PASS' | 'FAIL' | 'BLOCKED';
export interface Evidence {
  label: string;
  value: string;
  tone?: 'ok' | 'bad' | 'warn';
}
export interface AttackOutcome {
  verdict: Verdict;
  summary: string;
  explanation: string;
  evidence: Evidence[];
  responses: unknown[];
  ms: number;
}
export interface Scenario {
  id: string;
  n: number | string;
  title: string;
  property: string;
  setup: string;
  expected: string;
  group: 'scope' | 'gateway';
  run: (ctx: { status: GatewayStatus }) => Promise<Omit<AttackOutcome, 'ms'>>;
}

const cap = (s: GatewayStatus, id: string) =>
  s.profile.capabilities.find((c) => c.id === id)?.supported === true;
const checkStatus = (v: VerifyResponse, id: string) =>
  v.checks.find((c) => c.id === id)?.status ?? 'absent';
const summarize = (v: { status: number; body: VerifyResponse }) => ({
  http: v.status,
  decision: v.body.decision,
  reason: v.body.reason,
  groth16Valid: v.body.groth16.valid,
  verifyMs: v.body.groth16.verifyMs,
  checks: v.body.checks.map((c) => `${c.id}:${c.status}`),
});
const decisionEv = (label: string, v: { status: number; body: VerifyResponse }): Evidence => ({
  label,
  value: `HTTP ${v.status} · ${v.body.decision.toUpperCase()} · ${v.body.reason} · Groth16 ${v.body.groth16.valid === null ? 'not run' : v.body.groth16.valid ? 'valid' : 'invalid'}`,
  tone: v.body.decision === 'granted' ? 'bad' : 'ok',
});

async function tryProve(
  cred: string,
  c: Challenge,
  variant = 'honest',
): Promise<{ ok: true; p: ProverResult } | { ok: false; err: HttpError }> {
  try {
    return { ok: true, p: await prover.prove(cred, c, variant) };
  } catch (e) {
    return {
      ok: false,
      err:
        e instanceof HttpError ? e : new HttpError(0, 'PROVER_UNREACHABLE', (e as Error).message),
    };
  }
}
const verify = (c: Challenge, p: ProverResult) =>
  api.verify({ challengeId: c.challengeId, proof: p.proof, publicSignals: p.publicSignals });
const proverBlocked = (err: HttpError): Omit<AttackOutcome, 'ms'> => ({
  verdict: 'BLOCKED',
  summary: `Prover unavailable or unsupported: ${err.code}`,
  explanation: `The user-side prover returned ${err.status} ${err.code}: ${err.message}. Without a proof the attack cannot be executed.`,
  evidence: [{ label: 'prover', value: `${err.status} ${err.code}`, tone: 'warn' }],
  responses: [err.body ?? err.message],
});

/** Attack against a circuit-level property: tampered attributes or rogue issuer. */
async function circuitForgery(
  status: GatewayStatus,
  cred: string,
  variant: string,
  capability: string,
  what: string,
): Promise<Omit<AttackOutcome, 'ms'>> {
  const c = await api.challenge('file-share');
  const pr = await tryProve(cred, c, variant);
  if (!pr.ok) {
    if (pr.err.code === 'WITNESS_UNSATISFIABLE') {
      return {
        verdict: 'PASS',
        summary: 'Circuit constraints reject the forged witness — no proof can be produced.',
        explanation: `The prover could not satisfy the circuit with ${what}, so nothing can be presented to the gateway.`,
        evidence: [{ label: 'prover', value: pr.err.message, tone: 'ok' }],
        responses: [pr.err.body],
      };
    }
    return proverBlocked(pr.err);
  }
  const v = await verify(c, pr.p);
  const ev = [
    {
      label: 'forged proof generated',
      value: `yes, in ${pr.p.provingMs.toFixed(0)} ms`,
      tone: 'bad' as const,
    },
    decisionEv('gateway', v),
  ];
  if (v.body.decision === 'granted') {
    return {
      verdict: 'FAIL',
      summary: 'Forged credential was GRANTED access.',
      explanation: `A credential with ${what} produced an accepted proof and the gateway issued a session. Critical authorization failure.`,
      evidence: ev,
      responses: [summarize(v)],
    };
  }
  if (v.body.groth16.valid === true && !cap(status, capability)) {
    return {
      verdict: 'FAIL',
      summary:
        'P1 circuit vulnerability confirmed: forged proof is mathematically VALID. Gateway still refused (fail-closed).',
      explanation: `The delivered circuit does not enforce "${capability}", so a credential with ${what} still yields a valid Groth16 proof against the trusted root. The gateway refuses to issue sessions for this circuit profile, so no access was granted — but the security property the scenario tests does not hold cryptographically.`,
      evidence: ev,
      responses: [summarize(v)],
    };
  }
  return {
    verdict: 'PASS',
    summary: `Rejected: ${v.body.reason}`,
    explanation: `The gateway denied the forged proof (${v.body.reason}).`,
    evidence: ev,
    responses: [summarize(v)],
  };
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'replay',
    n: 1,
    group: 'scope',
    title: 'Replay a captured proof',
    property: 'Freshness: every proof is bound to a one-time challenge nonce',
    setup:
      'Alice proves for File Share; the attacker re-submits the identical proof (a) on the same challenge and (b) on a fresh challenge.',
    expected: 'Denied: nonce already used / expired',
    run: async ({ status }) => {
      const c1 = await api.challenge('file-share');
      const pr = await tryProve('cred-alice', c1);
      if (!pr.ok) return proverBlocked(pr.err);
      const first = await verify(c1, pr.p);
      const sameChallenge = await verify(c1, pr.p);
      const c2 = await api.challenge('file-share');
      const fresh = await verify(c2, pr.p);
      const ev = [
        decisionEv('original submission', first),
        decisionEv('(a) same challenge', sameChallenge),
        decisionEv('(b) fresh challenge', fresh),
      ];
      const responses = [summarize(first), summarize(sameChallenge), summarize(fresh)];
      if (sameChallenge.body.reason !== 'CHALLENGE_REPLAYED' || fresh.body.decision === 'granted') {
        return {
          verdict: 'FAIL',
          summary: 'Replay was not rejected.',
          explanation: 'A replayed proof was accepted.',
          evidence: ev,
          responses,
        };
      }
      if (checkStatus(fresh.body, 'nonce') === 'not-supported' || !cap(status, 'nonceBinding')) {
        return {
          verdict: 'BLOCKED',
          summary:
            'Gateway-state replay rejected (CHALLENGE_REPLAYED). Cryptographic nonce binding unavailable in P1.',
          explanation:
            'One-time challenge consumption works. However the delivered circuit has no public nonce, so the captured proof is still mathematically valid under a fresh challenge (b). The gateway issues no session for this circuit, but full replay resistance requires P1 to bind the nonce.',
          evidence: ev,
          responses,
        };
      }
      return {
        verdict: 'PASS',
        summary: `Rejected: ${sameChallenge.body.reason} / ${fresh.body.reason}`,
        explanation: 'The proof is bound to its challenge nonce and the challenge is single use.',
        evidence: ev,
        responses,
      };
    },
  },
  {
    id: 'revoked',
    n: 2,
    group: 'scope',
    title: 'Revoked credential tries again',
    property: 'Revocation: proofs must be against the current registry root',
    setup:
      "Carol's credential is revoked through the Admin API (P2). Carol then (a) tries to prove against the new tree and (b) presents a proof built from her cached pre-revocation Merkle path.",
    expected: 'Denied: root mismatch, not in tree',
    run: async () => {
      const responses: unknown[] = [];
      const st = await api.credentialStatus('cred-carol').catch(() => null);
      if (!st)
        return {
          verdict: 'BLOCKED',
          summary: 'Registry credential status unavailable',
          explanation: 'P2 registry did not answer the credential status request.',
          evidence: [],
          responses,
        };
      if (st.status === 'active') responses.push(await api.revoke('cred-carol'));
      const c1 = await api.challenge('file-share');
      const honest = await tryProve('cred-carol', c1);
      const c2 = await api.challenge('file-share');
      const stale = await tryProve('cred-carol', c2, 'stale-root');
      if (!stale.ok) return proverBlocked(stale.err);
      const v = await verify(c2, stale.p);
      responses.push(summarize(v));
      const ev: Evidence[] = [
        {
          label: '(a) prove against new tree',
          value: honest.ok
            ? 'proof produced (unexpected)'
            : `${honest.err.code}: no membership witness`,
          tone: honest.ok ? 'bad' : 'ok',
        },
        decisionEv('(b) stale-root proof', v),
      ];
      if (v.body.reason === 'ROOT_MISMATCH' && !honest.ok) {
        return {
          verdict: 'PASS',
          summary: 'Rejected: ROOT_MISMATCH — credential no longer in the current tree.',
          explanation:
            'Revocation removed the leaf and changed the root. The old proof verifies only against the old root, which the gateway no longer trusts. Use Admin Console → Reset demo to restore Carol.',
          evidence: ev,
          responses,
        };
      }
      return {
        verdict: 'FAIL',
        summary: `Unexpected: ${v.body.reason}`,
        explanation: 'The revoked credential was not rejected as expected.',
        evidence: ev,
        responses,
      };
    },
  },
  {
    id: 'tamper',
    n: 3,
    group: 'scope',
    title: 'Tamper attributes (contractor → admin)',
    property: 'Attribute integrity: attributes must be the ones the issuer signed',
    setup:
      'Bob (contractor, clearance 1) edits his local credential to role=admin, clearance=3 and keeps the original issuer signature.',
    expected: 'Denied: issuer signature invalid',
    run: ({ status }) =>
      circuitForgery(
        status,
        'cred-bob',
        'tamper-attributes',
        'attributeBinding',
        'self-edited attributes',
      ),
  },
  {
    id: 'forged',
    n: 4,
    group: 'scope',
    title: 'Forged credential (self-signed)',
    property: 'Issuer trust: only the trusted issuer key is accepted',
    setup:
      'Alice re-signs her credential commitment with a freshly generated key that the gateway has never seen.',
    expected: 'Denied: signature not from issuer',
    run: ({ status }) =>
      circuitForgery(
        status,
        'cred-alice',
        'forged-issuer',
        'issuerBinding',
        'a self-generated issuer key',
      ),
  },
  {
    id: 'wrong-resource',
    n: 5,
    group: 'scope',
    title: 'Valid user, wrong service (Bob → Admin Panel)',
    property: 'Policy enforcement per resource',
    setup:
      "Bob requests a challenge for Admin Panel and asks his prover for an honest proof. Additionally, Alice's File Share proof is presented for an Admin Panel challenge.",
    expected: "Denied: policy not satisfied (proof can't be generated)",
    run: async ({ status }) => {
      const c = await api.challenge('admin-panel');
      const bob = await tryProve('cred-bob', c);
      const ev: Evidence[] = [
        {
          label: 'Bob honest proof for Admin Panel',
          value: bob.ok ? 'proof produced' : `${bob.err.code}`,
          tone: bob.ok ? 'bad' : 'ok',
        },
      ];
      const responses: unknown[] = [bob.ok ? 'proof produced' : bob.err.body];
      if (bob.ok) {
        const v = await verify(c, bob.p);
        ev.push(decisionEv('gateway', v));
        responses.push(summarize(v));
        if (v.body.decision === 'granted')
          return {
            verdict: 'FAIL',
            summary: 'Bob was granted Admin Panel',
            explanation: 'Policy enforcement failed.',
            evidence: ev,
            responses,
          };
      } else if (bob.err.code !== 'WITNESS_UNSATISFIABLE') return proverBlocked(bob.err);
      const fsC = await api.challenge('file-share');
      const alice = await tryProve('cred-alice', fsC);
      if (alice.ok) {
        const adminC = await api.challenge('admin-panel');
        const cross = await verify(adminC, alice.p);
        ev.push(decisionEv('Alice File Share proof → Admin Panel', cross));
        responses.push(summarize(cross));
        if (cross.body.decision === 'granted')
          return {
            verdict: 'FAIL',
            summary: 'Cross-resource proof accepted',
            explanation: 'A proof for one resource authorized another.',
            evidence: ev,
            responses,
          };
      }
      if (!cap(status, 'policyBinding') || !cap(status, 'resourceBinding')) {
        return {
          verdict: 'BLOCKED',
          summary: 'No access granted, but per-resource policy is not enforced by the P1 circuit.',
          explanation:
            "Bob's honest witness fails only because P1 hard-codes the FileShare predicate; the circuit has no Admin Panel policy, no policy public inputs and no resource ID. A cross-resource proof is still mathematically valid. Requires P1 policy and resource binding.",
          evidence: ev,
          responses,
        };
      }
      return {
        verdict: 'PASS',
        summary: 'Denied: policy not satisfied / resource mismatch',
        explanation:
          'No valid proof exists for an unsatisfied policy, and proofs are bound to their resource.',
        evidence: ev,
        responses,
      };
    },
  },
  {
    id: 'nullifier',
    n: 6,
    group: 'scope',
    title: 'Spam requests (nullifier rate limit)',
    property: 'Rate limiting: same nullifier twice in one epoch is refused',
    setup: 'Alice submits two fresh proofs for the same resource within one epoch.',
    expected: 'Rate-limited: same nullifier in this epoch',
    run: async ({ status }) => {
      if (!cap(status, 'nullifier')) {
        return {
          verdict: 'BLOCKED',
          summary: 'Circuit has no nullifier output.',
          explanation:
            'The gateway implements nullifier rate limiting (unit/integration tested), but the delivered P1 circuit outputs no nullifier = Poseidon(secret, resource_id, epoch), so there is nothing verified to rate-limit on. Requires P1.',
          evidence: [{ label: 'active profile', value: status.profile.id, tone: 'warn' }],
          responses: [],
        };
      }
      const out: Array<{ status: number; body: VerifyResponse }> = [];
      for (let i = 0; i < 2; i++) {
        const c = await api.challenge('wiki');
        const pr = await tryProve('cred-alice', c);
        if (!pr.ok) return proverBlocked(pr.err);
        out.push(await verify(c, pr.p));
      }
      const ev = out.map((v, i) => decisionEv(`request ${i + 1}`, v));
      return out[1]!.body.reason === 'NULLIFIER_RATE_LIMITED'
        ? {
            verdict: 'PASS',
            summary: 'Second request rate-limited (429).',
            explanation: 'The verified nullifier was already used in this epoch.',
            evidence: ev,
            responses: out.map(summarize),
          }
        : {
            verdict: 'FAIL',
            summary: `Second request: ${out[1]!.body.reason}`,
            explanation: 'Duplicate nullifier was not rate-limited.',
            evidence: ev,
            responses: out.map(summarize),
          };
    },
  },
  {
    id: 'expired',
    n: 7,
    group: 'scope',
    title: 'Expired credential',
    property: 'Expiry: expiry > now is enforced in-circuit',
    setup: 'A credential whose expiry timestamp is in the past attempts to prove.',
    expected: 'Denied: expiry check fails',
    run: async ({ status }) => {
      if (!cap(status, 'expiryCheck')) {
        return {
          verdict: 'BLOCKED',
          summary: 'Circuit has no expiry attribute or time input.',
          explanation:
            'The delivered P1 circuit does not include expiry or a public current-time input, so an expired credential cannot be distinguished. Requires P1 (expiry > now constraint) and P2 (expired credential fixture).',
          evidence: [{ label: 'active profile', value: status.profile.id, tone: 'warn' }],
          responses: [],
        };
      }
      const c = await api.challenge('wiki');
      const pr = await tryProve('cred-expired', c);
      if (!pr.ok)
        return pr.err.code === 'WITNESS_UNSATISFIABLE'
          ? {
              verdict: 'PASS',
              summary: 'No proof possible for an expired credential.',
              explanation: 'The expiry constraint is unsatisfiable.',
              evidence: [{ label: 'prover', value: pr.err.code, tone: 'ok' }],
              responses: [pr.err.body],
            }
          : proverBlocked(pr.err);
      const v = await verify(c, pr.p);
      return v.body.decision === 'granted'
        ? {
            verdict: 'FAIL',
            summary: 'Expired credential granted',
            explanation: 'Expiry not enforced.',
            evidence: [decisionEv('gateway', v)],
            responses: [summarize(v)],
          }
        : {
            verdict: 'PASS',
            summary: `Denied: ${v.body.reason}`,
            explanation: 'Expired credential rejected.',
            evidence: [decisionEv('gateway', v)],
            responses: [summarize(v)],
          };
    },
  },
  {
    id: 'tampered-signal',
    n: 'G1',
    group: 'gateway',
    title: 'Tampered public input',
    property: 'Proof is bound to its public signals',
    setup: 'A valid proof is submitted with its root signal changed to the attacker-chosen value.',
    expected: 'Denied: root mismatch or invalid proof',
    run: async () => {
      const c = await api.challenge('file-share');
      const pr = await tryProve('cred-alice', c);
      if (!pr.ok) return proverBlocked(pr.err);
      const signals = [...pr.p.publicSignals];
      const idx = c.scheme.publicSignals.indexOf('root');
      signals[idx] = (BigInt(signals[idx]!) + 1n).toString();
      const v = await api.verify({
        challengeId: c.challengeId,
        proof: pr.p.proof,
        publicSignals: signals,
      });
      return v.body.decision !== 'granted' &&
        ['ROOT_MISMATCH', 'PROOF_INVALID'].includes(v.body.reason)
        ? {
            verdict: 'PASS',
            summary: `Denied: ${v.body.reason}`,
            explanation: 'Changing any public signal invalidates the proof or the root check.',
            evidence: [decisionEv('gateway', v)],
            responses: [summarize(v)],
          }
        : {
            verdict: 'FAIL',
            summary: v.body.reason,
            explanation: 'Tampered public input not rejected.',
            evidence: [decisionEv('gateway', v)],
            responses: [summarize(v)],
          };
    },
  },
  {
    id: 'malformed',
    n: 'G2',
    group: 'gateway',
    title: 'Malformed / oversized proof',
    property: 'Input validation before any cryptographic work',
    setup: 'A request with a non-canonical field element and a request with a 40 kB payload.',
    expected: 'Rejected with 400 / 413, no verification performed',
    run: async () => {
      const c = await api.challenge('wiki');
      const bad = await api
        .verify({
          challengeId: c.challengeId,
          proof: {
            pi_a: ['01', '2', '1'],
            pi_b: [
              ['1', '2'],
              ['3', '4'],
              ['1', '0'],
            ],
            pi_c: ['1', '2', '1'],
            protocol: 'groth16',
            curve: 'bn128',
          },
          publicSignals: ['-1'],
        })
        .catch((e: HttpError) => ({ status: e.status, body: e.body as VerifyResponse }));
      const big = await fetch('/api/zk/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: c.challengeId, junk: 'x'.repeat(40000) }),
      });
      const ok = bad.status === 400 && big.status === 413;
      return {
        verdict: ok ? 'PASS' : 'FAIL',
        summary: `HTTP ${bad.status} / HTTP ${big.status}`,
        explanation: 'Strict schemas and body limits reject malformed input before snarkjs runs.',
        evidence: [
          {
            label: 'non-canonical values',
            value: `HTTP ${bad.status}`,
            tone: bad.status === 400 ? 'ok' : 'bad',
          },
          {
            label: '40 kB body',
            value: `HTTP ${big.status}`,
            tone: big.status === 413 ? 'ok' : 'bad',
          },
        ],
        responses: [bad.body],
      };
    },
  },
  {
    id: 'session-forgery',
    n: 'G3',
    group: 'gateway',
    title: 'Forged session / direct service access',
    property: 'Only gateway-issued, resource-scoped sessions reach services',
    setup:
      'The attacker plants a made-up session cookie for Admin Panel and requests the service through the gateway.',
    expected: 'Rejected: invalid session (401)',
    run: async () => {
      document.cookie =
        'zkag_admin_panel=forged-session-identifier-000; path=/svc/admin-panel; SameSite=Strict';
      const r = await api.service('admin-panel' as ResourceId, '/');
      document.cookie = 'zkag_admin_panel=; path=/svc/admin-panel; max-age=0';
      const code = (r.data?.error as { code?: string } | undefined)?.code ?? '';
      return r.status === 401
        ? {
            verdict: 'PASS',
            summary: `Rejected: ${code}`,
            explanation:
              'Session IDs are random server-side handles; unknown IDs are refused before any upstream request. Services additionally require a signed front-door assertion.',
            evidence: [{ label: 'gateway', value: `HTTP ${r.status} ${code}`, tone: 'ok' }],
            responses: [r.data],
          }
        : {
            verdict: 'FAIL',
            summary: `HTTP ${r.status}`,
            explanation: 'Forged session reached the service.',
            evidence: [{ label: 'gateway', value: `HTTP ${r.status}`, tone: 'bad' }],
            responses: [r.data],
          };
    },
  },
];

export async function runScenario(s: Scenario, status: GatewayStatus): Promise<AttackOutcome> {
  const t0 = performance.now();
  try {
    const r = await s.run({ status });
    return { ...r, ms: performance.now() - t0 };
  } catch (e) {
    const err = e as HttpError;
    return {
      verdict: 'BLOCKED',
      summary: `Could not execute: ${err.code ?? 'ERROR'}`,
      explanation: err.message,
      evidence: [
        {
          label: 'error',
          value: `${err.status ?? ''} ${err.code ?? ''} ${err.message}`,
          tone: 'warn',
        },
      ],
      responses: [err.body ?? null],
      ms: performance.now() - t0,
    };
  }
}
