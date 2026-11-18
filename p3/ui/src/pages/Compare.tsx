import { useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import {
  EyeOff,
  KeyRound,
  LogIn,
  LogOut,
  Play,
  ShieldAlert,
  Fingerprint,
  UserRound,
} from 'lucide-react';
import { api } from '../services/api';
import { useEvents } from '../hooks/useEventStream';
import {
  Badge,
  Button,
  Card,
  CheckList,
  DecisionBadge,
  PageHeader,
  ms,
  short,
} from '../components/ui';
import { PERSONAS, RESOURCE_META } from '../features/portal/personas';
import { runZkFlow } from '../features/portal/flow';
import type { GatewayEvent, ResourceId } from '../types/api';

type SsoDecision = Extract<GatewayEvent, { type: 'sso.decision' }>;
type SsoLogin = Extract<GatewayEvent, { type: 'sso.login' }>;
type ZkVerify = Extract<GatewayEvent, { type: 'verification.completed' }>;

export function ComparePage() {
  const { zk, sso, ssoState } = useEvents();
  const [resource, setResource] = useState<ResourceId>('wiki');
  const [personaIdx, setPersonaIdx] = useState(0);
  const [busy, setBusy] = useState<'sso' | 'zk' | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const me = useQuery({
    queryKey: ['sso-me'],
    queryFn: api.ssoMe,
    refetchInterval: 10000,
    retry: 0,
  });
  const kc = useQuery({
    queryKey: ['kc-health'],
    queryFn: api.ssoHealth,
    refetchInterval: 10000,
    retry: 0,
  });

  const ssoD = [...sso]
    .reverse()
    .find((e): e is SsoDecision => e.type === 'sso.decision' && e.resource === resource);
  const ssoL = [...sso].reverse().find((e): e is SsoLogin => e.type === 'sso.login');
  const zkV = [...zk]
    .reverse()
    .find((e): e is ZkVerify => e.type === 'verification.completed' && e.resource === resource);
  const ssoLoggedIn = me.data?.data?.authenticated === true;
  const ssoAvailable = !me.isError && kc.data?.keycloak === true;

  const runSso = async () => {
    setBusy('sso');
    setNote(null);
    try {
      const r = await api.service(resource, '/', 'sso');
      if (r.status === 401) setNote('Log in with Keycloak first.');
    } catch {
      setNote('SSO baseline unreachable.');
    } finally {
      setBusy(null);
    }
  };
  const runZk = async () => {
    setBusy('zk');
    setNote(null);
    const r = await runZkFlow({ credentialRef: PERSONAS[personaIdx]!.credentialRef, resource });
    if (r.error) setNote(`ZK request: ${r.error.code} — ${r.error.message}`);
    setBusy(null);
  };
  const logoutSso = async () => {
    const r = await api.ssoLogout();
    window.location.href = r.endSessionUrl;
  };

  const rows: Array<{
    label: string;
    sso: ReactNode;
    ssoLeak: boolean;
    zk: ReactNode;
    zkLeak?: boolean;
  }> = [
    { label: 'Username', sso: ssoD?.username, ssoLeak: true, zk: <NotReceived /> },
    { label: 'Email', sso: ssoD?.email, ssoLeak: true, zk: <NotReceived /> },
    { label: 'Full name', sso: ssoD?.name, ssoLeak: true, zk: <NotReceived /> },
    {
      label: 'Stable subject ID',
      sso: ssoL ? short(String(ssoL.claims.sub ?? ''), 8) : undefined,
      ssoLeak: true,
      zk: (
        <span className="text-ok">not received (services get a random per-session pseudonym)</span>
      ),
    },
    {
      label: 'Roles',
      sso: ssoD?.roles.join(', '),
      ssoLeak: true,
      zk: <NotReceived what="only whether the policy holds" />,
    },
    { label: 'Department', sso: ssoD?.department, ssoLeak: true, zk: <NotReceived /> },
    { label: 'Clearance', sso: ssoD?.clearance ?? undefined, ssoLeak: true, zk: <NotReceived /> },
    {
      label: 'Device posture',
      sso: ssoD ? String(ssoD.deviceCompliant) : undefined,
      ssoLeak: true,
      zk: <NotReceived />,
    },
    { label: 'Requested resource', sso: ssoD?.resource, ssoLeak: false, zk: zkV?.resource },
    {
      label: 'Path visited',
      sso: ssoD?.path,
      ssoLeak: true,
      zk: (
        <span className="text-ink-300">only after a session exists (proxy log, pseudonymous)</span>
      ),
    },
    {
      label: 'Evidence',
      sso: ssoD ? `JWT (${ssoD.jwtChecks.length} checks)` : undefined,
      ssoLeak: false,
      zk: zkV
        ? `Groth16 proof, ${zkV.proofBytes} B · ${zkV.publicSignals.length} public signal(s)`
        : undefined,
    },
    {
      label: 'Decision',
      sso: ssoD ? <DecisionBadge decision={ssoD.decision} /> : undefined,
      ssoLeak: false,
      zk: zkV ? (
        <span className="flex items-center gap-2">
          <DecisionBadge decision={zkV.decision} />
          <span className="mono text-[11px] text-ink-400">{zkV.reason}</span>
        </span>
      ) : undefined,
    },
    {
      label: 'Front-door latency',
      sso: ssoD ? ms(ssoD.latencyMs) : undefined,
      ssoLeak: false,
      zk: zkV ? `${ms(zkV.totalMs)} (verify ${ms(zkV.verifyMs)})` : undefined,
    },
  ];

  return (
    <>
      <PageHeader
        eyebrow="Screen 3 · SSO vs ZK"
        title="Same request. Very different knowledge."
        description="Left: what a conventional Keycloak/OIDC front door learns. Right: what the ZK gateway learns for the same service. Red cells are identity data the server received."
      />

      <div className="panel mb-6 flex flex-wrap items-center gap-3 p-4">
        <div
          className="flex items-center gap-1 rounded-lg bg-ink-900 p-1 ring-1 ring-ink-700"
          role="radiogroup"
          aria-label="Resource"
        >
          {(Object.keys(RESOURCE_META) as ResourceId[]).map((r) => (
            <button
              key={r}
              role="radio"
              aria-checked={resource === r}
              onClick={() => setResource(r)}
              className={clsx(
                'rounded-md px-3 py-1.5 text-xs font-medium',
                resource === r ? 'bg-cyan-500/15 text-accent' : 'text-ink-300 hover:text-ink-100',
              )}
            >
              {RESOURCE_META[r].name}
            </button>
          ))}
        </div>
        <span className="mx-1 h-6 w-px bg-ink-700" />
        {ssoLoggedIn ? (
          <>
            <Badge tone="bad">
              <UserRound className="h-3 w-3" /> SSO:{' '}
              {String(me.data?.data?.identity?.username ?? '')}
            </Badge>
            <Button variant="ghost" onClick={() => void logoutSso()}>
              <LogOut className="h-4 w-4" /> Keycloak logout
            </Button>
          </>
        ) : (
          <a
            href={`/sso/login?resource=${resource}&returnTo=/compare`}
            className={clsx(
              'inline-flex items-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium ring-1 ring-inset',
              ssoAvailable
                ? 'text-ink-100 ring-ink-500 hover:bg-ink-800'
                : 'pointer-events-none text-ink-500 ring-ink-700',
            )}
            aria-disabled={!ssoAvailable}
          >
            <LogIn className="h-4 w-4" /> Log in with Keycloak
          </a>
        )}
        <Button
          variant="subtle"
          onClick={() => void runSso()}
          loading={busy === 'sso'}
          disabled={!ssoLoggedIn}
        >
          <KeyRound className="h-4 w-4" /> Open {RESOURCE_META[resource].name} via SSO
        </Button>
        <span className="mx-1 h-6 w-px bg-ink-700" />
        <select
          aria-label="ZK persona"
          value={personaIdx}
          onChange={(e) => setPersonaIdx(Number(e.target.value))}
          className="rounded-lg bg-ink-900 px-2 py-2 text-sm ring-1 ring-ink-600"
        >
          {PERSONAS.map((p, i) => (
            <option key={p.id} value={i}>
              {p.name} ({p.role})
            </option>
          ))}
        </select>
        <Button onClick={() => void runZk()} loading={busy === 'zk'}>
          <Play className="h-4 w-4" /> Request via ZK gateway
        </Button>
        {note && (
          <span role="status" className="text-xs text-warn">
            {note}
          </span>
        )}
      </div>

      {!ssoAvailable && (
        <div
          role="alert"
          className="mb-6 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-warn"
        >
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" /> Keycloak / SSO baseline not reachable
          {ssoState !== 'open' ? ' (SSO event stream disconnected)' : ''}. Start it with{' '}
          <code className="mono">docker compose up keycloak sso-gateway</code>. The left column
          fills only from real captured SSO events.
        </div>
      )}

      <div className="panel overflow-hidden">
        <div className="grid grid-cols-[minmax(120px,0.8fr)_1fr_1fr] border-b border-ink-700 text-xs font-semibold uppercase tracking-wider">
          <div className="px-4 py-3 text-ink-400">Field</div>
          <div className="flex items-center gap-2 border-l border-ink-700 bg-red-500/[0.04] px-4 py-3 text-bad">
            <KeyRound className="h-4 w-4" /> Keycloak SSO front door
          </div>
          <div className="flex items-center gap-2 border-l border-ink-700 bg-emerald-500/[0.04] px-4 py-3 text-ok">
            <Fingerprint className="h-4 w-4" /> ZK gateway
          </div>
        </div>
        {rows.map((r) => (
          <div
            key={r.label}
            className="grid grid-cols-[minmax(120px,0.8fr)_1fr_1fr] border-b border-ink-700/50 text-sm last:border-0"
          >
            <div className="px-4 py-2.5 text-ink-400">{r.label}</div>
            <div
              className={clsx(
                'border-l border-ink-700/50 px-4 py-2.5',
                r.sso !== undefined && r.sso !== null && r.ssoLeak
                  ? 'bg-red-500/10 font-medium text-red-200'
                  : 'text-ink-200',
              )}
            >
              {r.sso === undefined || r.sso === null ? (
                <span className="text-ink-500">no captured SSO event</span>
              ) : (
                r.sso
              )}
            </div>
            <div className="border-l border-ink-700/50 px-4 py-2.5 text-ink-200">
              {r.zk ?? <span className="text-ink-500">no ZK request yet</span>}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        <Card title="What the identity system knows">
          <ul className="space-y-2 text-sm text-ink-200">
            <li>
              <Badge tone="bad">SSO</Badge> Keycloak authenticates the user and learns every login
              and every client used.
            </li>
            <li>
              <Badge tone="warn">ZK</Badge> The issuer (P2) still knows who holds which credential
              at issuance time — but it is not consulted per request and does not see which services
              are accessed.
            </li>
          </ul>
        </Card>
        <Card title="What the resource server receives">
          <ul className="space-y-2 text-sm text-ink-200">
            <li>
              <Badge tone="bad">SSO</Badge> A signed assertion naming the user (subject + username)
              on every request.
            </li>
            <li>
              <Badge tone="ok">ZK</Badge> A random per-session pseudonym and the fact that the
              gateway authorized it.
            </li>
          </ul>
        </Card>
        <Card title="What the front door learns">
          <ul className="space-y-2 text-sm text-ink-200">
            <li>
              <Badge tone="bad">SSO</Badge> Full token claims: identity, roles, attributes.
            </li>
            <li>
              <Badge tone="ok">ZK</Badge> Proof + public signals (registry root
              {zkV && zkV.publicSignals.length > 1 ? ', nonce, policy, nullifier' : ''}) and
              allow/deny.
            </li>
            <li className="flex items-start gap-1.5 text-xs text-ink-400">
              <EyeOff className="mt-0.5 h-3.5 w-3.5 shrink-0" /> Not anonymity against network
              analysis: IP addresses and timing remain visible to both.
            </li>
          </ul>
        </Card>
      </div>

      {(ssoD || zkV) && (
        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <Card title="SSO token validation (captured)">
            {ssoD ? (
              <CheckList checks={ssoD.jwtChecks} />
            ) : (
              <p className="text-sm text-ink-400">No SSO decision for this resource yet.</p>
            )}
          </Card>
          <Card title="ZK verification checks (captured)">
            {zkV ? (
              <CheckList checks={zkV.checks} />
            ) : (
              <p className="text-sm text-ink-400">No ZK request for this resource yet.</p>
            )}
          </Card>
        </div>
      )}
    </>
  );
}

function NotReceived({ what }: { what?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-ok">
      <EyeOff className="h-3.5 w-3.5" /> not received{what ? ` — ${what}` : ''}
    </span>
  );
}
