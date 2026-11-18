import clsx from 'clsx';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { CheckCircle2, CircleSlash, Loader2, MinusCircle, XCircle } from 'lucide-react';
import type { VerificationCheck } from '../types/api';

export function Card({
  title,
  subtitle,
  actions,
  children,
  className,
  padded = true,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section className={clsx('panel', className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-ink-700/70 px-5 py-3.5">
          <div className="min-w-0">
            {title && (
              <h2 className="text-[13px] font-semibold tracking-wide text-ink-100">{title}</h2>
            )}
            {subtitle && <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx(padded && 'p-5')}>{children}</div>
    </section>
  );
}

type Tone = 'neutral' | 'ok' | 'bad' | 'warn' | 'info' | 'accent';
const toneCls: Record<Tone, string> = {
  neutral: 'bg-ink-700/60 text-ink-200 ring-ink-600',
  ok: 'bg-emerald-500/10 text-ok ring-emerald-500/30',
  bad: 'bg-red-500/10 text-bad ring-red-500/30',
  warn: 'bg-amber-500/10 text-warn ring-amber-500/30',
  info: 'bg-blue-500/10 text-blue-300 ring-blue-500/30',
  accent: 'bg-cyan-500/10 text-accent ring-cyan-500/30',
};
export function Badge({
  tone = 'neutral',
  children,
  className,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ring-1 ring-inset',
        toneCls[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Button({
  variant = 'primary',
  loading,
  children,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger' | 'subtle';
  loading?: boolean;
}) {
  const v = {
    primary:
      'bg-accent-strong text-ink-950 hover:bg-accent shadow-[0_0_0_1px_rgba(34,211,238,.4),0_8px_24px_-12px_rgba(34,211,238,.6)]',
    ghost: 'bg-transparent text-ink-200 ring-1 ring-inset ring-ink-600 hover:bg-ink-700/50',
    danger: 'bg-red-500/15 text-bad ring-1 ring-inset ring-red-500/40 hover:bg-red-500/25',
    subtle: 'bg-ink-700/60 text-ink-100 hover:bg-ink-600/70',
  }[variant];
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={clsx(
        'inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50',
        v,
        className,
      )}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Dot({ ok, pending }: { ok: boolean | null; pending?: boolean }) {
  return (
    <span
      aria-hidden
      className={clsx(
        'inline-block h-2 w-2 rounded-full',
        pending
          ? 'bg-warn'
          : ok
            ? 'bg-ok shadow-[0_0_8px_#34d399]'
            : ok === null
              ? 'bg-ink-500'
              : 'bg-bad',
      )}
    />
  );
}

export function KV({
  k,
  v,
  mono,
  tone,
}: {
  k: ReactNode;
  v: ReactNode;
  mono?: boolean;
  tone?: 'ok' | 'bad' | 'warn';
}) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5 text-sm">
      <dt className="shrink-0 text-ink-400">{k}</dt>
      <dd
        className={clsx(
          'min-w-0 truncate text-right',
          mono && 'mono text-[12.5px]',
          tone === 'ok' && 'text-ok',
          tone === 'bad' && 'text-bad',
          tone === 'warn' && 'text-warn',
          !tone && 'text-ink-100',
        )}
      >
        {v}
      </dd>
    </div>
  );
}

export function Stat({
  label,
  value,
  unit,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  hint?: ReactNode;
  tone?: 'ok' | 'bad' | 'warn' | 'accent';
}) {
  return (
    <div className="panel px-4 py-3.5">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-ink-400">{label}</div>
      <div
        className={clsx(
          'mt-1 flex items-baseline gap-1 text-2xl font-semibold tabular-nums',
          tone === 'ok' && 'text-ok',
          tone === 'bad' && 'text-bad',
          tone === 'warn' && 'text-warn',
          tone === 'accent' && 'text-accent',
        )}
      >
        {value}
        {unit && <span className="text-sm font-medium text-ink-400">{unit}</span>}
      </div>
      {hint && <div className="mt-1 text-xs text-ink-400">{hint}</div>}
    </div>
  );
}

export function CheckList({ checks }: { checks: VerificationCheck[] }) {
  return (
    <ul className="divide-y divide-ink-700/60">
      {checks.map((c) => (
        <li key={c.id + c.label} className="flex items-start gap-2.5 py-2 text-sm">
          <CheckIcon status={c.status} />
          <div className="min-w-0 flex-1">
            <div className={clsx(c.status === 'not-supported' ? 'text-ink-300' : 'text-ink-100')}>
              {c.label}
            </div>
            {c.detail && (
              <div className="mono mt-0.5 break-words text-[11.5px] text-ink-400">{c.detail}</div>
            )}
          </div>
          <span
            className={clsx(
              'shrink-0 text-[10.5px] font-semibold uppercase tracking-wider',
              {
                pass: 'text-ok',
                fail: 'text-bad',
                'not-supported': 'text-warn',
                skipped: 'text-ink-400',
              }[c.status],
            )}
          >
            {c.status === 'not-supported' ? 'not in circuit' : c.status}
          </span>
        </li>
      ))}
    </ul>
  );
}

export function CheckIcon({ status }: { status: VerificationCheck['status'] }) {
  const cls = 'mt-0.5 h-4 w-4 shrink-0';
  if (status === 'pass') return <CheckCircle2 className={clsx(cls, 'text-ok')} aria-label="pass" />;
  if (status === 'fail') return <XCircle className={clsx(cls, 'text-bad')} aria-label="fail" />;
  if (status === 'not-supported')
    return <CircleSlash className={clsx(cls, 'text-warn')} aria-label="not supported" />;
  return <MinusCircle className={clsx(cls, 'text-ink-400')} aria-label="skipped" />;
}

export function DecisionBadge({
  decision,
}: {
  decision: 'granted' | 'denied' | 'blocked' | string;
}) {
  if (decision === 'granted') return <Badge tone="ok">Granted</Badge>;
  if (decision === 'blocked') return <Badge tone="warn">Blocked</Badge>;
  return <Badge tone="bad">Denied</Badge>;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-3xl">
        <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-accent">
          {eyebrow}
        </div>
        <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-ink-100">{title}</h1>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-300">{description}</p>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Empty({
  icon,
  title,
  children,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon && <div className="text-ink-500">{icon}</div>}
      <div className="text-sm font-medium text-ink-200">{title}</div>
      {children && <div className="max-w-md text-xs leading-relaxed text-ink-400">{children}</div>}
    </div>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-medium text-ink-300">{label}</span>
      {children}
    </label>
  );
}

export const inputCls =
  'w-full rounded-lg border border-ink-600 bg-ink-900 px-3 py-2 text-sm text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none';

export function short(v: string | null | undefined, n = 6) {
  if (!v) return '—';
  if (v.length <= n * 2 + 1) return v;
  return `${v.slice(0, n)}…${v.slice(-n)}`;
}

export function ms(v: number | null | undefined, digits = 1) {
  return v === null || v === undefined
    ? '—'
    : v >= 1000
      ? `${(v / 1000).toFixed(2)} s`
      : `${v.toFixed(digits)} ms`;
}
