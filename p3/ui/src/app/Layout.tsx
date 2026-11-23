import { useState, type ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  Activity,
  BarChart3,
  Boxes,
  FlaskConical,
  GitCompareArrows,
  KeyRound,
  LogOut,
  Menu,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react';
import { api, prover } from '../services/api';
import { useOperator } from '../state/operator';
import { useEvents } from '../hooks/useEventStream';
import { Dot } from '../components/ui';
import { ErrorBoundary } from '../components/ErrorBoundary';

const NAV = [
  { to: '/portal', label: 'User Portal', icon: UserRound, hint: 'Prove & access' },
  { to: '/live', label: 'Gateway Live View', icon: Activity, hint: 'What the gateway sees' },
  { to: '/compare', label: 'SSO vs ZK', icon: GitCompareArrows, hint: 'Privacy comparison' },
  { to: '/admin', label: 'Admin Console', icon: KeyRound, hint: 'Registry & revocation' },
  { to: '/attacks', label: 'Attack Lab', icon: FlaskConical, hint: 'Negative tests' },
  { to: '/performance', label: 'Performance', icon: BarChart3, hint: 'Measured results' },
  { to: '/integration', label: 'Integration Status', icon: Boxes, hint: 'P1 / P2 readiness' },
];

export function useStatus() {
  return useQuery({ queryKey: ['status'], queryFn: api.status, refetchInterval: 5000 });
}
export function useProverHealth() {
  return useQuery({
    queryKey: ['prover-health'],
    queryFn: prover.health,
    refetchInterval: 10000,
    retry: 0,
  });
}

export function Layout({ children }: { children: ReactNode }) {
  const { data: status, isError } = useStatus();
  const proverH = useProverHealth();
  const { zkState, ssoState } = useEvents();
  const { logout } = useOperator();
  const [open, setOpen] = useState(false);
  const c = status?.components;
  const pills: Array<[string, boolean | null]> = [
    ['Gateway', isError ? false : status ? true : null],
    ['Artifacts', c ? (c.artifacts?.ok ?? false) : null],
    ['Registry', c ? (c.registry?.ok ?? false) : null],
    ['Prover', proverH.isSuccess ? proverH.data.proverReady : proverH.isError ? false : null],
    ['SSO', c ? (c.ssoBaseline?.ok ?? false) : null],
    ['Keycloak', c ? (c.keycloak?.ok ?? false) : null],
    ['Live feed', zkState === 'open'],
  ];

  return (
    <div className="flex h-full">
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-40 w-64 shrink-0 border-r border-ink-700/70 bg-ink-900/95 backdrop-blur transition-transform lg:static lg:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex h-16 items-center gap-3 border-b border-ink-700/70 px-5">
          <div className="grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-cyan-400/20 to-blue-500/20 ring-1 ring-cyan-400/40">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
          </div>
          <div>
            <div className="text-sm font-semibold tracking-tight">ZK Access Gate</div>
            <div className="text-[11px] text-ink-400">Zero-knowledge zero-trust gateway</div>
          </div>
          <button
            className="ml-auto lg:hidden"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <nav className="space-y-1 p-3" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon, hint }) => (
            <NavLink
              key={to}
              to={to}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                clsx(
                  'group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors',
                  isActive
                    ? 'bg-cyan-500/10 text-ink-100 ring-1 ring-inset ring-cyan-400/30'
                    : 'text-ink-300 hover:bg-ink-800 hover:text-ink-100',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={clsx(
                      'h-4 w-4',
                      isActive ? 'text-accent' : 'text-ink-400 group-hover:text-ink-200',
                    )}
                    aria-hidden
                  />
                  <span className="flex-1">
                    <span className="block font-medium">{label}</span>
                    <span className="block text-[11px] text-ink-400">{hint}</span>
                  </span>
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="absolute inset-x-0 bottom-0 border-t border-ink-700/70 p-4 text-[11px] text-ink-400">
          <div className="flex items-center justify-between">
            <span>Event streams</span>
            <span className="flex items-center gap-2">
              ZK <Dot ok={zkState === 'open'} pending={zkState === 'connecting'} /> SSO{' '}
              <Dot ok={ssoState === 'open'} pending={ssoState === 'connecting'} />
            </span>
          </div>
          <button
            onClick={() => void logout()}
            className="mt-3 flex items-center gap-2 text-ink-300 hover:text-ink-100"
          >
            <LogOut className="h-3.5 w-3.5" /> Sign out operator
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 border-b border-ink-700/70 bg-ink-950/85 backdrop-blur">
          <div className="flex h-16 items-center gap-3 px-4 lg:px-8">
            <button
              className="lg:hidden"
              onClick={() => setOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            {status && (
              <div
                className={clsx(
                  'flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium ring-1 ring-inset',
                  status.zkAuthorization === 'ready'
                    ? 'bg-emerald-500/10 text-ok ring-emerald-500/30'
                    : 'bg-amber-500/10 text-warn ring-amber-500/30',
                )}
              >
                {status.zkAuthorization === 'ready' ? (
                  <ShieldCheck className="h-4 w-4" />
                ) : (
                  <ShieldAlert className="h-4 w-4" />
                )}
                {status.zkAuthorization === 'ready'
                  ? status.artifacts.trust === 'demo-accepted'
                    ? 'Real ZK authorization active · DEMO keys (single-party setup)'
                    : 'Real ZK authorization active'
                  : status.mode === 'diagnostic-p1'
                    ? 'Diagnostic P1 mode · ZK authorization blocked'
                    : 'ZK authorization blocked'}
              </div>
            )}
            <div
              className="ml-auto hidden flex-wrap items-center gap-x-4 gap-y-1 md:flex"
              aria-label="Integration status"
            >
              {pills.map(([label, ok]) => (
                <span key={label} className="flex items-center gap-1.5 text-xs text-ink-300">
                  <Dot ok={ok} /> {label}
                </span>
              ))}
            </div>
          </div>
        </header>
        <main className="grid-bg min-h-0 flex-1 overflow-y-auto px-4 py-6 lg:px-8 lg:py-8">
          <div className="mx-auto max-w-[1400px]">
            <ErrorBoundary>{children}</ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
}
