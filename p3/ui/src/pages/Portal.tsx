import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  ArrowRight,
  Check,
  Clock,
  Fingerprint,
  Loader2,
  Lock,
  Play,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  SkipForward,
  X,
} from 'lucide-react';
import { api } from '../services/api';
import {
  Badge,
  Button,
  Card,
  CheckList,
  DecisionBadge,
  KV,
  PageHeader,
  Stat,
  ms,
  short,
} from '../components/ui';
import { SimulatedBanner } from '../components/SimulatedBanner';
import { ServiceView } from '../components/ServiceView';
import { PERSONAS, type Persona } from '../features/portal/personas';
import {
  STEPS,
  initialSteps,
  runSimulatedFlow,
  runZkFlow,
  type FlowResult,
  type StepId,
  type StepMap,
} from '../features/portal/flow';
import type { ResourceId } from '../types/api';
import { useProverHealth } from '../app/Layout';

export function PortalPage() {
  const policies = useQuery({ queryKey: ['policies'], queryFn: api.policies });
  const proverH = useProverHealth();
  const [persona, setPersona] = useState<Persona>(PERSONAS[0]!);
  const [resource, setResource] = useState<ResourceId>('wiki');
  const [devMode, setDevMode] = useState(false);
  const [steps, setSteps] = useState<StepMap>(initialSteps());
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<FlowResult | null>(null);

  const run = async () => {
    setRunning(true);
    setResult(null);
    setSteps(initialSteps());
    const onStep = (id: StepId, patch: StepMap[StepId]) =>
      setSteps((s) => ({ ...s, [id]: { ...s[id], ...patch } }));
    try {
      setResult(
        devMode
          ? await runSimulatedFlow(resource, onStep)
          : await runZkFlow({ credentialRef: persona.credentialRef, resource, onStep }),
      );
    } finally {
      setRunning(false);
    }
  };

  const proverDown = proverH.isError || (proverH.isSuccess && !proverH.data.proverReady);

  return (
    <>
      <PageHeader
        eyebrow="Screen 1 · User Portal"
        title="Prove you satisfy the policy — without saying who you are"
        description="Pick a persona and a service. The credential stays with the user-side prover; the gateway receives only a Groth16 proof and its public signals."
        actions={
          <label className="flex cursor-pointer items-center gap-2 rounded-lg px-3 py-2 text-xs text-ink-300 ring-1 ring-inset ring-ink-600">
            <input
              type="checkbox"
              className="accent-fuchsia-400"
              checked={devMode}
              onChange={(e) => setDevMode(e.target.checked)}
            />
            UI development mode (simulated)
          </label>
        }
      />
      {devMode && (
        <div className="mb-4">
          <SimulatedBanner />
        </div>
      )}
      {!devMode && proverDown && (
        <div
          role="alert"
          className="mb-4 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-warn"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          User-side prover unavailable (
          {proverH.isError ? 'not reachable at /p2' : 'P1 proving artifacts missing'}). Real proofs
          cannot be generated; start P2's prover or the P3 diagnostic stand-in, or use UI
          development mode.
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
        <div className="space-y-6">
          <Card
            title="1 · Persona"
            subtitle="Local demo identities. Their names never reach the gateway."
          >
            <div className="grid gap-2.5" role="radiogroup" aria-label="Persona">
              {PERSONAS.map((p) => (
                <button
                  key={p.id}
                  role="radio"
                  aria-checked={persona.id === p.id}
                  onClick={() => setPersona(p)}
                  className={clsx(
                    'flex items-center gap-3 rounded-xl p-3 text-left ring-1 ring-inset transition',
                    persona.id === p.id
                      ? 'bg-cyan-500/5 ring-cyan-400/50'
                      : 'ring-ink-700 hover:ring-ink-500',
                  )}
                >
                  <div
                    className={clsx(
                      'grid h-10 w-10 place-items-center rounded-full bg-gradient-to-br text-sm font-bold text-ink-950',
                      p.accent,
                    )}
                  >
                    {p.name[0]}
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium">
                      {p.name} <span className="text-ink-400">· {p.role}</span>
                    </div>
                    <div className="mono mt-0.5 text-[11px] text-ink-400">
                      clearance {p.attributes.clearance} · {p.attributes.department} · device{' '}
                      {p.attributes.device ? 'compliant' : 'non-compliant'}
                    </div>
                  </div>
                  {persona.id === p.id && <Check className="h-4 w-4 text-accent" />}
                </button>
              ))}
            </div>
            <p className="mt-3 flex items-start gap-1.5 text-[11.5px] leading-relaxed text-ink-400">
              <Lock className="mt-0.5 h-3 w-3 shrink-0" /> Attributes shown here live in the
              holder's credential. Only{' '}
              <span className="mono text-ink-300">{persona.credentialRef}</span> is passed to the
              local prover.
            </p>
          </Card>

          <Card title="2 · Service" subtitle="Policies are server-authoritative.">
            <div className="grid gap-2.5" role="radiogroup" aria-label="Service">
              {(policies.data?.items ?? []).map((p) => (
                <button
                  key={p.resource}
                  role="radio"
                  aria-checked={resource === p.resource}
                  onClick={() => setResource(p.resource)}
                  className={clsx(
                    'rounded-xl p-3 text-left ring-1 ring-inset transition',
                    resource === p.resource
                      ? 'bg-cyan-500/5 ring-cyan-400/50'
                      : 'ring-ink-700 hover:ring-ink-500',
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{p.name}</span>
                    {p.supportedByActiveCircuit ? (
                      <Badge tone="ok">circuit supports</Badge>
                    ) : (
                      <Badge tone="warn">not in active circuit</Badge>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-ink-400">{p.summary}</div>
                </button>
              ))}
            </div>
            <Button
              className="mt-4 w-full"
              onClick={() => void run()}
              loading={running}
              disabled={running || (!devMode && proverDown)}
            >
              <Play className="h-4 w-4" />{' '}
              {devMode ? 'Run simulated flow' : `Request access as ${persona.name}`}
            </Button>
          </Card>
        </div>

        <div className="space-y-6">
          <Card
            title="Proof lifecycle"
            subtitle={
              devMode
                ? 'Simulated timings'
                : 'Live timings measured in this browser and reported by the prover and gateway'
            }
          >
            <ol className="relative grid gap-0 sm:grid-cols-2 xl:grid-cols-4">
              {STEPS.map((s, i) => (
                <StepTile key={s.id} index={i + 1} label={s.label} state={steps[s.id]} />
              ))}
            </ol>
          </Card>
          {result && <ResultPanel result={result} />}
        </div>
      </div>
    </>
  );
}

function StepTile({
  index,
  label,
  state,
}: {
  index: number;
  label: string;
  state: StepMap[StepId];
}) {
  const [, tick] = useState(0);
  const raf = useRef<number>();
  useEffect(() => {
    if (state.status !== 'active') return;
    const loop = () => {
      tick((x) => x + 1);
      raf.current = requestAnimationFrame(loop);
    };
    raf.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf.current!);
  }, [state.status]);
  const elapsed =
    state.status === 'active' && state.startedAt ? Date.now() - state.startedAt : state.ms;
  const icon = {
    pending: <span className="text-xs text-ink-500">{index}</span>,
    active: <Loader2 className="h-4 w-4 animate-spin text-accent" />,
    done: <Check className="h-4 w-4 text-ok" />,
    failed: <X className="h-4 w-4 text-bad" />,
    blocked: <ShieldAlert className="h-4 w-4 text-warn" />,
    skipped: <SkipForward className="h-4 w-4 text-ink-500" />,
  }[state.status];
  return (
    <li
      className={clsx(
        'm-1 rounded-xl p-3 ring-1 ring-inset transition',
        state.status === 'active'
          ? 'bg-cyan-500/5 ring-cyan-400/40'
          : state.status === 'failed'
            ? 'bg-red-500/5 ring-red-500/30'
            : state.status === 'blocked'
              ? 'bg-amber-500/5 ring-amber-500/30'
              : state.status === 'done'
                ? 'ring-emerald-500/20'
                : 'ring-ink-700',
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={clsx(
            'grid h-7 w-7 place-items-center rounded-full bg-ink-800 ring-1 ring-ink-600',
            state.status === 'active' && 'pulse-ring',
          )}
        >
          {icon}
        </span>
        <span className="text-[13px] font-medium">{label}</span>
      </div>
      <div className="mono mt-2 flex items-center gap-1 text-[11px] text-ink-400">
        <Clock className="h-3 w-3" /> {elapsed !== undefined ? ms(elapsed, 0) : '—'}
      </div>
      {state.detail && (
        <div className="mt-1 line-clamp-2 text-[11px] text-ink-400">{state.detail}</div>
      )}
    </li>
  );
}

function ResultPanel({ result }: { result: FlowResult }) {
  const v = result.verify?.body;
  if (result.error && !v) {
    return (
      <Card title="Outcome">
        <div className="flex items-start gap-3 rounded-xl bg-red-500/5 p-4 ring-1 ring-red-500/30">
          <ShieldX className="h-6 w-6 shrink-0 text-bad" />
          <div>
            <div className="font-medium text-bad">
              {result.error.stage === 'proving' ? 'No proof could be generated' : 'Request failed'}
            </div>
            <div className="mono mt-1 text-xs text-ink-300">{result.error.code}</div>
            <p className="mt-1 text-sm text-ink-300">{result.error.message}</p>
            {result.error.code === 'WITNESS_UNSATISFIABLE' && (
              <p className="mt-2 text-xs text-ink-400">
                The prover cannot satisfy the circuit constraints with this credential, so there is
                nothing for the gateway to verify. With the delivered P1 circuit this reflects its
                hard-coded FileShare predicate over the holder's claimed attributes.
              </p>
            )}
          </div>
        </div>
      </Card>
    );
  }
  if (!v) return null;
  const tone = v.decision === 'granted' ? 'ok' : v.decision === 'blocked' ? 'warn' : 'bad';
  return (
    <div className="space-y-6">
      {result.simulated && <SimulatedBanner />}
      <div
        className={clsx(
          'panel flex flex-wrap items-center gap-4 p-5',
          tone === 'ok' && 'ring-1 ring-emerald-500/30',
          tone === 'warn' && 'ring-1 ring-amber-500/30',
          tone === 'bad' && 'ring-1 ring-red-500/30',
        )}
      >
        {tone === 'ok' ? (
          <ShieldCheck className="h-9 w-9 text-ok" />
        ) : tone === 'warn' ? (
          <ShieldAlert className="h-9 w-9 text-warn" />
        ) : (
          <ShieldX className="h-9 w-9 text-bad" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <DecisionBadge decision={v.decision} />
            <span className="mono text-xs text-ink-400">{v.reason}</span>
          </div>
          <p className="mt-1 text-sm text-ink-200">{v.message}</p>
        </div>
        <div className="text-right text-xs text-ink-400">
          Groth16{' '}
          {v.groth16.valid === null ? (
            <span className="text-ink-300">not run</span>
          ) : v.groth16.valid ? (
            <span className="text-ok">mathematically valid</span>
          ) : (
            <span className="text-bad">invalid</span>
          )}
          <div className="mono mt-0.5">corr {short(v.correlationId, 4)}</div>
        </div>
      </div>
      {!result.simulated && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat
            label="Proof size"
            value={v.proof ? v.proof.bytes : '—'}
            unit="bytes"
            hint={v.proof ? `${v.proof.jsonBytes} B as JSON` : undefined}
          />
          <Stat
            label="Proving (prover)"
            value={result.timings.provingMs !== undefined ? ms(result.timings.provingMs, 0) : '—'}
            hint="reported by the prover"
          />
          <Stat
            label="Verify (gateway)"
            value={ms(v.groth16.verifyMs)}
            hint="snarkjs groth16.verify"
            tone="accent"
          />
          <Stat
            label="End-to-end"
            value={ms(result.timings.totalMs, 0)}
            hint="challenge → decision (browser)"
          />
        </div>
      )}
      {v.missingGuarantees && v.missingGuarantees.length > 0 && (
        <Card
          title="Why no session was issued"
          subtitle="The proof verifies, but the circuit does not prove the full authorization statement."
        >
          <ul className="grid gap-1.5 sm:grid-cols-2">
            {v.missingGuarantees.map((m) => (
              <li key={m} className="flex items-start gap-2 text-sm text-ink-200">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" /> {m}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Gateway checks" subtitle={v.policy ?? undefined}>
          <CheckList checks={v.checks} />
        </Card>
        <Card
          title="What the gateway received"
          subtitle="Public signals + proof. No name, email, role or clearance."
        >
          <dl>
            {v.publicSignals.map((s) => (
              <KV
                key={s.name}
                k={<span className="mono">{s.name}</span>}
                v={short(s.value, 10)}
                mono
              />
            ))}
            {v.proof && <KV k="proof digest" v={v.proof.digest} mono />}
            {v.root && <KV k="trusted root (registry)" v={short(v.root.trusted, 10)} mono />}
          </dl>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {['name', 'email', 'role', 'department', 'clearance', 'device posture'].map((f) => (
              <Badge key={f} tone="ok">
                no {f}
              </Badge>
            ))}
          </div>
        </Card>
      </div>
      {result.service && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-accent" /> Protected resource (via ZK gateway)
            </span>
          }
          actions={<ArrowRight className="h-4 w-4 text-ink-500" />}
        >
          <ServiceView status={result.service.status} data={result.service.data} via="zk" />
        </Card>
      )}
    </div>
  );
}
