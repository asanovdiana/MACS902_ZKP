import { useState } from 'react';
import clsx from 'clsx';
import { ChevronDown, Loader2, Play, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { Badge, Button, ms } from '../../components/ui';
import type { TeamAttackRun } from '../../services/api';

export type TeamResult = { ok: true; run: TeamAttackRun } | { ok: false; error: string };

const TITLES: Record<string, { n: string; property: string }> = {
  baseline: { n: '0', property: 'Control: an honest user is admitted' },
  replay: { n: '1', property: 'Freshness: a nonce is single-use (obligation 6)' },
  replay_expired: { n: '1b', property: 'Freshness: nonce TTL 120 s (obligation 6)' },
  revoked: { n: '2', property: 'Revocation: root must be current (obligation 3)' },
  tamper: { n: '3', property: 'Attribute integrity: attributes are issuer-signed (obligation 1)' },
  forged: { n: '4', property: 'Issuer trust: the issuer key is pinned (obligation 2)' },
  wrong_service: { n: '5', property: 'Policy per service (obligation 4)' },
  spam: { n: '6', property: 'Rate limit: one nullifier per epoch (obligation 7)' },
  expired: { n: '7', property: 'Expiry: now < expiry, now fixed by the challenge (obligation 5)' },
};

/**
 * One attack from the TEAM suite (client/attacks). The adapter enrols fresh personas, builds the
 * exact requests with real Groth16 proofs and sends them to this gateway; PASS means the gateway
 * answered every step with the team's expected outcome AND reason code.
 */
export function TeamAttackCard({
  id,
  title,
  result,
  running,
  disabled,
  onRun,
  onRunRealWait,
}: {
  id: string;
  title: string;
  result?: TeamResult;
  running: boolean;
  disabled: boolean;
  onRun: () => void;
  /** Only for attacks with a timed step (replay_expired): run against the real clock. */
  onRunRealWait?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const meta = TITLES[id] ?? { n: '·', property: '' };
  const verdict = !result ? null : result.ok ? (result.run.pass ? 'PASS' : 'FAIL') : 'BLOCKED';
  const tone = verdict === 'PASS' ? 'ok' : verdict === 'FAIL' ? 'bad' : 'warn';
  const Icon = verdict === 'PASS' ? ShieldCheck : verdict === 'FAIL' ? ShieldX : ShieldAlert;
  return (
    <article
      className={clsx(
        'panel flex flex-col p-5 ring-1 transition',
        verdict === 'PASS'
          ? 'ring-emerald-500/40'
          : verdict === 'FAIL'
            ? 'ring-red-500/50'
            : verdict
              ? 'ring-amber-500/40'
              : 'ring-transparent',
      )}
    >
      <header className="flex items-start gap-3">
        <span className="mono grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-ink-800 text-xs text-ink-300 ring-1 ring-ink-600">
          {meta.n}
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold">{title}</h3>
          <p className="mt-0.5 text-xs text-accent">{meta.property}</p>
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
        {onRunRealWait && (
          <Button
            variant="ghost"
            className="px-3 py-1.5 text-xs"
            onClick={onRunRealWait}
            disabled={disabled}
            title="Holds the proof 125 s on the real clock before presenting it"
          >
            Run with real wait (≈2 min)
          </Button>
        )}
      </header>
      {result && verdict && (
        <div className="mt-4 rounded-xl bg-ink-900/70 p-4 ring-1 ring-ink-700">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className={clsx('h-5 w-5', `text-${tone}`)} />
            <Badge tone={tone}>
              {verdict === 'PASS'
                ? 'PASS · attack defeated'
                : verdict === 'FAIL'
                  ? 'FAIL · unexpected gateway answer'
                  : 'BLOCKED · could not run'}
            </Badge>
            {result.ok && (
              <span className="mono ml-auto text-[11px] text-ink-400">{ms(result.run.ms, 0)}</span>
            )}
          </div>
          {!result.ok && <p className="mt-2 text-xs text-warn">{result.error}</p>}
          {result.ok && (
            <>
              <ul className="mt-3 space-y-1.5">
                {result.run.steps.map((s) => (
                  <li key={s.label} className="text-xs">
                    <div className="text-ink-200">{s.label}</div>
                    <div className="mono flex flex-wrap gap-x-3 text-[11px]">
                      <span className="text-ink-400">
                        expected {s.expect.outcome === 'admit' ? 'ADMIT' : `DENY ${s.expect.code}`}
                      </span>
                      {s.skipped ? (
                        <span className="text-ink-400">
                          skipped (needs a real 125 s wait: use “Run with real wait”; the automated
                          suite covers it with an injected clock)
                        </span>
                      ) : (
                        <span className={s.pass ? 'text-ok' : 'text-bad'}>
                          got HTTP {s.actual?.status}{' '}
                          {s.actual?.outcome === 'admit' ? 'ADMIT' : s.actual?.code}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
              {(result.run.local ?? []).length > 0 && (
                <div className="mt-3 border-t border-ink-700/60 pt-2">
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-400">
                    Refused before reaching the gateway
                  </div>
                  <ul className="mt-1 space-y-0.5">
                    {result.run.local!.map((l, i) => (
                      <li key={i} className="mono text-[11px] text-ok">
                        {l.stage}: {l.code}
                        {l.reasons?.length ? ` (${l.reasons.join(', ')})` : ''}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <button
                className="mt-3 flex items-center gap-1 text-[11px] text-ink-400 hover:text-ink-200"
                onClick={() => setOpen(!open)}
                aria-expanded={open}
              >
                <ChevronDown className={clsx('h-3.5 w-3.5 transition', open && 'rotate-180')} />{' '}
                Actual backend responses
              </button>
              {open && (
                <pre className="mono mt-2 max-h-64 overflow-auto rounded-lg bg-ink-950 p-3 text-[11px] text-ink-300">
                  {JSON.stringify(result.run.steps, null, 2)}
                </pre>
              )}
            </>
          )}
        </div>
      )}
    </article>
  );
}
