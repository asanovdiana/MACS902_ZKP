import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { prover } from '../services/api';
import { TeamAttackCard, type TeamResult } from '../features/attack-lab/TeamAttackCard';
import clsx from 'clsx';
import {
  ChevronDown,
  Loader2,
  Play,
  PlayCircle,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
} from 'lucide-react';
import { useStatus } from '../app/Layout';
import { Badge, Button, PageHeader, Stat, ms } from '../components/ui';
import {
  SCENARIOS,
  runScenario,
  type AttackOutcome,
  type Scenario,
  type Verdict,
} from '../features/attack-lab/scenarios';

const verdictStyle: Record<
  Verdict,
  { tone: 'ok' | 'bad' | 'warn'; icon: typeof ShieldCheck; ring: string; label: string }
> = {
  PASS: {
    tone: 'ok',
    icon: ShieldCheck,
    ring: 'ring-emerald-500/40',
    label: 'PASS · attack defeated',
  },
  FAIL: {
    tone: 'bad',
    icon: ShieldX,
    ring: 'ring-red-500/50',
    label: 'FAIL · property does not hold',
  },
  BLOCKED: {
    tone: 'warn',
    icon: ShieldAlert,
    ring: 'ring-amber-500/40',
    label: 'BLOCKED · dependency missing',
  },
};

export function AttackLabPage() {
  const { data: status } = useStatus();
  const v4 = status?.profile.id === 'integrated-access-v4';
  const team = useQuery({
    queryKey: ['team-attacks'],
    queryFn: prover.attacks,
    enabled: v4,
    retry: 0,
  });
  const [results, setResults] = useState<Record<string, AttackOutcome>>({});
  const [teamResults, setTeamResults] = useState<Record<string, TeamResult>>({});
  const [running, setRunning] = useState<string | null>(null);
  const scenarios = SCENARIOS.filter((s) => !v4 || s.group === 'gateway');

  const run = async (s: Scenario) => {
    if (!status) return;
    setRunning(s.id);
    const r = await runScenario(s, status);
    setResults((prev) => ({ ...prev, [s.id]: r }));
    setRunning(null);
  };
  const runTeam = async (id: string) => {
    setRunning(`team:${id}`);
    try {
      const r = await prover.runAttack(id);
      setTeamResults((p) => ({ ...p, [id]: { ok: true, run: r } }));
    } catch (e) {
      setTeamResults((p) => ({ ...p, [id]: { ok: false, error: (e as Error).message } }));
    }
    setRunning(null);
  };
  const runAll = async () => {
    if (v4) for (const id of team.data?.ids ?? []) await runTeam(id);
    for (const s of scenarios) await run(s);
  };
  const counts = Object.values(results).reduce(
    (a, r) => ({ ...a, [r.verdict]: (a[r.verdict] ?? 0) + 1 }),
    {} as Record<Verdict, number>,
  );
  for (const r of Object.values(teamResults)) {
    const v: Verdict = r.ok ? (r.run.pass ? 'PASS' : 'FAIL') : 'BLOCKED';
    counts[v] = (counts[v] ?? 0) + 1;
  }
  const titleOf = (id: string) => {
    const a = team.data?.attacks.find((x) => x.id === id);
    return a?.title ?? id;
  };

  return (
    <>
      <PageHeader
        eyebrow="Screen 5 · Attack Lab"
        title="Attacks that must fail"
        description={
          v4
            ? "The team's attack suite builds each attack with REAL Groth16 proofs from freshly enrolled personas and sends it to this gateway. PASS means the gateway gave the team's expected outcome and reason code for every step — nothing is hard-coded."
            : 'Each scenario sends real requests to the gateway and the user-side prover. Verdicts are computed from the actual responses and from the guarantees the active circuit really provides — nothing is hard-coded.'
        }
        actions={
          <Button onClick={() => void runAll()} disabled={!!running || !status}>
            <PlayCircle className="h-4 w-4" /> Run all
          </Button>
        }
      />
      <div className="mb-6 grid grid-cols-3 gap-3">
        <Stat
          label="Pass"
          value={counts.PASS ?? 0}
          tone="ok"
          hint="attack defeated with the expected reason"
        />
        <Stat
          label="Fail"
          value={counts.FAIL ?? 0}
          tone="bad"
          hint="gateway answer differs from the expected one"
        />
        <Stat
          label="Blocked"
          value={counts.BLOCKED ?? 0}
          tone="warn"
          hint="could not be executed"
        />
      </div>
      {v4 && (
        <section className="mb-8">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.16em] text-ink-400">
            Project Scope attack scenarios · team suite (client/attacks)
          </h2>
          {team.isError && (
            <p className="text-sm text-warn">
              Team attack suite unavailable: start the wallet prover (npm run dev).
            </p>
          )}
          <div className="grid gap-4 lg:grid-cols-2">
            {(team.data?.ids ?? []).map((id) => (
              <TeamAttackCard
                key={id}
                id={id}
                title={titleOf(id)}
                result={teamResults[id]}
                running={running === `team:${id}`}
                disabled={!!running}
                onRun={() => void runTeam(id)}
              />
            ))}
          </div>
        </section>
      )}
      {(['scope', 'gateway'] as const)
        .filter((g) => !v4 || g === 'gateway')
        .map((g) => (
          <section key={g} className="mb-8">
            <h2 className="mb-3 text-xs font-semibold uppercase tracking-[0.16em] text-ink-400">
              {g === 'scope'
                ? 'Project Scope attack scenarios (P1 v3 diagnostic)'
                : 'Gateway hardening checks'}
            </h2>
            <div className="grid gap-4 lg:grid-cols-2">
              {scenarios
                .filter((s) => s.group === g)
                .map((s) => (
                  <AttackCard
                    key={s.id}
                    s={s}
                    result={results[s.id]}
                    running={running === s.id}
                    disabled={!!running || !status}
                    onRun={() => void run(s)}
                  />
                ))}
            </div>
          </section>
        ))}
    </>
  );
}

function AttackCard({
  s,
  result,
  running,
  disabled,
  onRun,
}: {
  s: Scenario;
  result?: AttackOutcome;
  running: boolean;
  disabled: boolean;
  onRun: () => void;
}) {
  const [open, setOpen] = useState(false);
  const st = result ? verdictStyle[result.verdict] : null;
  const Icon = st?.icon;
  return (
    <article
      className={clsx(
        'panel flex flex-col p-5 ring-1 transition',
        st ? st.ring : 'ring-transparent',
      )}
    >
      <header className="flex items-start gap-3">
        <span className="mono grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-ink-800 text-xs text-ink-300 ring-1 ring-ink-600">
          {s.n}
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold">{s.title}</h3>
          <p className="mt-0.5 text-xs text-accent">{s.property}</p>
        </div>
        <Button
          variant={result ? 'ghost' : 'primary'}
          className="px-3 py-1.5 text-xs"
          onClick={onRun}
          disabled={disabled}
        >
          {running ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}{' '}
          {result ? 'Re-run' : 'Run'}
        </Button>
      </header>
      <dl className="mt-3 grid gap-2 text-xs">
        <div>
          <dt className="inline font-semibold text-ink-400">Setup · </dt>
          <dd className="inline text-ink-200">{s.setup}</dd>
        </div>
        <div>
          <dt className="inline font-semibold text-ink-400">Expected · </dt>
          <dd className="inline text-ink-200">{s.expected}</dd>
        </div>
      </dl>
      {result && st && Icon && (
        <div className="mt-4 rounded-xl bg-ink-900/70 p-4 ring-1 ring-ink-700">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className={clsx('h-5 w-5', `text-${st.tone}`)} />
            <Badge tone={st.tone}>{st.label}</Badge>
            <span className="mono ml-auto text-[11px] text-ink-400">{ms(result.ms, 0)}</span>
          </div>
          <p className="mt-2 text-sm font-medium text-ink-100">{result.summary}</p>
          <p className="mt-1 text-xs leading-relaxed text-ink-300">{result.explanation}</p>
          {result.evidence.length > 0 && (
            <ul className="mt-3 space-y-1">
              {result.evidence.map((e) => (
                <li key={e.label} className="flex gap-2 text-xs">
                  <span className="shrink-0 text-ink-400">{e.label}:</span>
                  <span
                    className={clsx(
                      'mono break-all',
                      e.tone === 'ok' && 'text-ok',
                      e.tone === 'bad' && 'text-bad',
                      e.tone === 'warn' && 'text-warn',
                    )}
                  >
                    {e.value}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <button
            className="mt-3 flex items-center gap-1 text-[11px] text-ink-400 hover:text-ink-200"
            onClick={() => setOpen(!open)}
            aria-expanded={open}
          >
            <ChevronDown className={clsx('h-3.5 w-3.5 transition', open && 'rotate-180')} /> Actual
            backend responses
          </button>
          {open && (
            <pre className="mono mt-2 max-h-64 overflow-auto rounded-lg bg-ink-950 p-3 text-[11px] text-ink-300">
              {JSON.stringify(result.responses, null, 2)}
            </pre>
          )}
        </div>
      )}
    </article>
  );
}
