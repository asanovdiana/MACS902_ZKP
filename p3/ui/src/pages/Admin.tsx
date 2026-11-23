import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, RefreshCcw, RotateCcw, Search, ShieldCheck, Stamp } from 'lucide-react';
import { api, type RegistryView } from '../services/api';
import { useEvents } from '../hooks/useEventStream';
import { useStatus } from '../app/Layout';
import {
  Badge,
  Button,
  Card,
  Dot,
  Empty,
  Field,
  KV,
  PageHeader,
  inputCls,
  short,
} from '../components/ui';

export function AdminPage() {
  const qc = useQueryClient();
  const registry = useQuery({
    queryKey: ['registry'],
    queryFn: api.registry,
    refetchInterval: 4000,
    retry: 0,
  });
  const { data: status } = useStatus();
  const { zk } = useEvents();
  const [lastAction, setLastAction] = useState<string | null>(null);
  const revoke = useMutation({
    mutationFn: api.revoke,
    onSuccess: (_d, id) => {
      setLastAction(
        `Revoked ${id}. Root updated; sessions issued under the previous root were invalidated.`,
      );
      void qc.invalidateQueries({ queryKey: ['registry'] });
    },
    onError: (e) => setLastAction(`Revocation failed: ${(e as Error).message}`),
  });
  const reset = useMutation({
    mutationFn: api.reset,
    onSuccess: (d) => {
      setLastAction(`Demo reset — gateway state cleared, registry reset: ${d.registryReset}.`);
      void qc.invalidateQueries();
    },
  });
  const leaves = registry.data?.leaves?.leaves ?? [];
  const security = [...zk]
    .reverse()
    .filter(
      (e) =>
        [
          'credential.revoked',
          'root.changed',
          'replay.rejected',
          'nullifier.rate_limited',
          'session.revoked',
        ].includes(e.type) ||
        (e.type === 'verification.completed' && e.decision !== 'granted'),
    )
    .slice(0, 8);

  return (
    <>
      <PageHeader
        eyebrow="Screen 4 · Admin Console"
        title="Registry, issuance and revocation"
        description="Issuance and revocation are performed by P2's issuer/registry over the documented HTTP contract. Revoking removes a leaf, which changes the Merkle root the gateway trusts."
        actions={
          <Button variant="ghost" onClick={() => reset.mutate()} loading={reset.isPending}>
            <RotateCcw className="h-4 w-4" /> Reset demo
          </Button>
        }
      />
      {lastAction && (
        <div
          role="status"
          className="mb-6 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-100"
        >
          {lastAction}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
        <Card
          title="Credential registry (Merkle tree)"
          subtitle={
            registry.data
              ? `source: ${registry.data.current.source ?? 'registry'} · depth ${registry.data.current.treeDepth ?? '?'}`
              : undefined
          }
          actions={
            <Button
              variant="ghost"
              className="px-2 py-1 text-xs"
              aria-label="Refresh registry"
              onClick={() => void registry.refetch()}
            >
              <RefreshCcw className="h-3.5 w-3.5" aria-hidden />
            </Button>
          }
        >
          {registry.isError ? (
            <Empty title="Registry unavailable">
              P2's registry could not be reached. The gateway is failing closed for all
              verifications.
            </Empty>
          ) : !registry.data ? (
            <p className="text-sm text-ink-400">Loading…</p>
          ) : (
            <>
              <dl className="mb-4">
                <KV
                  k="Current root"
                  v={
                    <span title={registry.data.current.root}>
                      {short(registry.data.current.root, 14)}
                    </span>
                  }
                  mono
                />
                <KV k="Version" v={registry.data.current.version ?? '—'} mono />
              </dl>
              {leaves.length ? (
                <TreeDiagram data={registry.data} />
              ) : (
                <p className="text-sm text-ink-400">Leaf listing not exposed by this registry.</p>
              )}
              <div className="mt-5 divide-y divide-ink-700/60">
                {leaves
                  .filter((l) => l.credentialId)
                  .map((l) => (
                    <div key={l.index} className="flex items-center gap-3 py-2.5 text-sm">
                      <span className="mono w-6 text-ink-400">#{l.index}</span>
                      <span className="flex-1">
                        {l.label && <span className="mr-2 font-medium">{l.label}</span>}
                        <span className="mono text-ink-400">{l.credentialId}</span>
                      </span>
                      <Badge tone={l.status === 'active' ? 'ok' : 'neutral'}>{l.status}</Badge>
                      <Button
                        variant="danger"
                        className="px-2.5 py-1 text-xs"
                        disabled={l.status !== 'active'}
                        loading={revoke.isPending && revoke.variables === l.credentialId}
                        onClick={() => revoke.mutate(l.credentialId!)}
                      >
                        <Ban className="h-3.5 w-3.5" /> Revoke
                      </Button>
                    </div>
                  ))}
              </div>
            </>
          )}
        </Card>

        <div className="space-y-6">
          <Card title="Integrations">
            <ul className="space-y-2 text-sm">
              {status &&
                Object.entries(status.components).map(([k, v]) => (
                  <li key={k} className="flex items-center gap-2">
                    <Dot ok={v.ok} />{' '}
                    <span className="flex-1 capitalize">{k.replace(/([A-Z])/g, ' $1')}</span>
                    <span className="mono max-w-[55%] truncate text-[11px] text-ink-400">
                      {typeof v.detail === 'string'
                        ? v.detail
                        : v.missing
                          ? `${v.missing.length} guarantee(s) missing`
                          : ''}
                    </span>
                  </li>
                ))}
            </ul>
          </Card>
          <Card
            title="Root history"
            subtitle="Observed by the gateway and published by the registry"
          >
            <ol className="max-h-56 space-y-1.5 overflow-y-auto text-xs">
              {(registry.data?.history?.items ?? []).map((h) => (
                <li key={h.version} className="flex items-center gap-2">
                  <Badge tone="info">v{h.version}</Badge>
                  <span className="mono text-ink-200">{short(h.root, 8)}</span>
                  <span className="flex-1 truncate text-ink-400">{h.reason}</span>
                  <span className="text-ink-500">{new Date(h.changedAt).toLocaleTimeString()}</span>
                </li>
              ))}
              {!registry.data?.history?.items?.length &&
                registry.data?.gatewayRootHistory.map((h) => (
                  <li key={h.observedAt} className="mono text-ink-300">
                    {short(h.root, 8)} · {new Date(h.observedAt).toLocaleTimeString()}
                  </li>
                ))}
            </ol>
          </Card>
          <StatusLookup />
        </div>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-2">
        <IssueForm />
        <Card title="Recent security events">
          {security.length === 0 ? (
            <p className="text-sm text-ink-400">No security events yet.</p>
          ) : (
            <ul className="space-y-1.5 text-xs">
              {security.map((e) => (
                <li key={e.id} className="flex items-center gap-2">
                  <span className="mono text-ink-500">{new Date(e.ts).toLocaleTimeString()}</span>
                  <Badge
                    tone={
                      e.type === 'root.changed' || e.type === 'credential.revoked' ? 'info' : 'bad'
                    }
                  >
                    {e.type}
                  </Badge>
                  <span className="mono truncate text-ink-300">
                    {'reason' in e
                      ? String(e.reason)
                      : 'credentialId' in e
                        ? e.credentialId
                        : 'root' in e
                          ? short(String(e.root), 6)
                          : ''}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}

function TreeDiagram({ data }: { data: RegistryView }) {
  const issued = data.leaves?.leaves ?? [];
  const fullDepth = data.leaves?.treeDepth ?? data.current.treeDepth ?? 2;
  // Draw only the left-most subtree that holds every issued leaf (a depth-16 tree has 65,536 slots).
  const shown = Math.max(4, 2 ** Math.ceil(Math.log2(Math.max(1, issued.length))));
  const leaves = Array.from(
    { length: shown },
    (_, i) =>
      issued.find((l) => l.index === i) ?? {
        index: i,
        credentialId: '',
        label: null,
        status: 'empty',
        leaf: '0',
      },
  );
  const depth = Math.round(Math.log2(shown));
  const W = Math.max(560, shown * 116);
  const H = 70 + depth * 70;
  const levelY = (lvl: number) => 30 + (depth - lvl) * 70;
  const nodes: Array<{ x: number; y: number; lvl: number; i: number }> = [];
  for (let lvl = 0; lvl <= depth; lvl++) {
    const count = shown >> lvl;
    for (let i = 0; i < count; i++)
      nodes.push({ x: ((i + 0.5) * W) / count, y: levelY(lvl), lvl, i });
  }
  const at = (lvl: number, i: number) => nodes.find((n) => n.lvl === lvl && n.i === i)!;
  const truncated = fullDepth > depth;
  return (
    <>
      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width={W > 560 ? W : undefined}
          className={W > 560 ? '' : 'w-full'}
          role="img"
          aria-label="Merkle tree of credential leaves"
        >
          {nodes
            .filter((n) => n.lvl > 0)
            .flatMap((n) =>
              [at(n.lvl - 1, n.i * 2), at(n.lvl - 1, n.i * 2 + 1)].map((c) => (
                <line
                  key={`${n.lvl}-${n.i}-${c.i}`}
                  x1={n.x}
                  y1={n.y}
                  x2={c.x}
                  y2={c.y}
                  stroke="#25324f"
                  strokeWidth={1.5}
                />
              )),
            )}
          {nodes.map((n) => {
            const leaf = n.lvl === 0 ? leaves[n.i] : undefined;
            const revoked = leaf?.status === 'revoked';
            const empty = leaf?.status === 'empty';
            const isTop = n.lvl === depth;
            const full = leaf ? (leaf.label ?? (leaf.credentialId || 'empty')) : '';
            const name = full.length > 14 ? `${full.slice(0, 13)}…` : full;
            return (
              <g key={`${n.lvl}-${n.i}`}>
                <rect
                  x={n.x - 52}
                  y={n.y - 16}
                  width={104}
                  height={32}
                  rx={8}
                  fill={isTop ? 'rgba(34,211,238,.12)' : revoked ? '#121826' : '#111a2d'}
                  stroke={isTop ? '#22d3ee' : revoked ? '#3a4a6b' : empty ? '#25324f' : '#34d399'}
                  strokeDasharray={revoked || empty ? '4 3' : undefined}
                />
                <text
                  x={n.x}
                  y={n.y - 1}
                  textAnchor="middle"
                  fontSize={10}
                  fill={revoked || empty ? '#6b7a99' : '#e6ebf5'}
                  fontFamily="JetBrains Mono, monospace"
                >
                  {isTop
                    ? truncated
                      ? `subtree → root`
                      : 'ROOT'
                    : leaf
                      ? name
                      : `node ${n.lvl}.${n.i}`}
                </text>
                <text
                  x={n.x}
                  y={n.y + 11}
                  textAnchor="middle"
                  fontSize={8.5}
                  fill="#6b7a99"
                  fontFamily="JetBrains Mono, monospace"
                >
                  {isTop
                    ? truncated
                      ? `+${fullDepth - depth} levels`
                      : short(data.current.root, 5)
                    : leaf
                      ? revoked
                        ? 'revoked → 0'
                        : empty
                          ? 'empty'
                          : short(leaf.leaf, 5)
                      : 'poseidon'}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      {truncated && (
        <p className="mt-1 text-xs text-ink-400">
          Showing the {shown} left-most leaves of a depth-{fullDepth} tree (
          {(2 ** fullDepth).toLocaleString()} slots); the rest are empty.
        </p>
      )}
    </>
  );
}

function StatusLookup() {
  const [id, setId] = useState('cred-bob');
  const q = useMutation({ mutationFn: api.credentialStatus });
  return (
    <Card title="Credential status">
      <form className="flex gap-2" onSubmit={(e) => (e.preventDefault(), q.mutate(id))}>
        <input
          aria-label="Credential ID"
          className={inputCls}
          value={id}
          onChange={(e) => setId(e.target.value)}
        />
        <Button
          variant="subtle"
          type="submit"
          aria-label="Look up credential status"
          loading={q.isPending}
        >
          <Search className="h-4 w-4" aria-hidden />
        </Button>
      </form>
      {q.data && (
        <p className="mt-2 text-sm">
          {q.data.credentialId}:{' '}
          <Badge tone={q.data.status === 'active' ? 'ok' : 'neutral'}>{q.data.status}</Badge>
        </p>
      )}
      {q.isError && <p className="mt-2 text-sm text-bad">{(q.error as Error).message}</p>}
    </Card>
  );
}

const ROLES = ['engineer', 'admin', 'contractor', 'finance'];
const DEPTS = ['engineering', 'it', 'operations', 'finance'];

function IssueForm() {
  const [form, setForm] = useState({
    employeeId: 'dave',
    role: 0,
    dept: 0,
    clearance: 2,
    deviceCompliant: 1,
    employeeActive: 1,
    expiry: new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10),
  });
  const [result, setResult] = useState<{ status: number; data: Record<string, unknown> } | null>(
    null,
  );
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      const { employeeId, expiry, ...attrs } = form;
      setResult(
        await api.issue({
          employeeId,
          attributes: { ...attrs, expiry: Math.floor(new Date(expiry).getTime() / 1000) },
        }),
      );
    } finally {
      setBusy(false);
    }
  };
  const err = result?.data?.error as { code?: string; message?: string } | undefined;
  const num = (k: keyof typeof form) => (e: { target: { value: string } }) =>
    setForm({ ...form, [k]: Number(e.target.value) });
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <Stamp className="h-4 w-4 text-accent" /> Enrol an employee (via P2 issuer)
        </span>
      }
      subtitle="The admin assigns attributes; the employee redeems a one-time code with a commitment generated on their own machine."
    >
      <form onSubmit={submit} className="grid gap-3 sm:grid-cols-2">
        <Field label="Employee ID">
          <input
            className={inputCls}
            value={form.employeeId}
            onChange={(e) => setForm({ ...form, employeeId: e.target.value })}
            required
            pattern="[A-Za-z0-9._@-]{1,64}"
          />
        </Field>
        <Field label="Role">
          <select className={inputCls} value={form.role} onChange={num('role')}>
            {ROLES.map((r, i) => (
              <option key={r} value={i}>
                {r}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Department">
          <select className={inputCls} value={form.dept} onChange={num('dept')}>
            {DEPTS.map((r, i) => (
              <option key={r} value={i}>
                {r}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Clearance (0–3)">
          <input
            type="number"
            min={0}
            max={3}
            className={inputCls}
            value={form.clearance}
            onChange={num('clearance')}
          />
        </Field>
        <Field label="Expiry">
          <input
            type="date"
            className={inputCls}
            value={form.expiry}
            onChange={(e) => setForm({ ...form, expiry: e.target.value })}
          />
        </Field>
        <div className="flex items-end gap-4 pb-2 text-sm text-ink-200">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              className="accent-cyan-400"
              checked={form.deviceCompliant === 1}
              onChange={(e) => setForm({ ...form, deviceCompliant: e.target.checked ? 1 : 0 })}
            />{' '}
            Device compliant
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              className="accent-cyan-400"
              checked={form.employeeActive === 1}
              onChange={(e) => setForm({ ...form, employeeActive: e.target.checked ? 1 : 0 })}
            />{' '}
            Active
          </label>
        </div>
        <Button type="submit" className="sm:col-span-2" loading={busy}>
          <ShieldCheck className="h-4 w-4" /> Create enrolment
        </Button>
      </form>
      {result && (
        <div
          className={`mt-3 rounded-lg p-3 text-sm ring-1 ${result.status < 300 ? 'bg-emerald-500/5 text-ok ring-emerald-500/30' : 'bg-amber-500/5 text-warn ring-amber-500/30'}`}
          role="status"
        >
          {result.status < 300 ? (
            <>
              One-time enrolment code (shown once):{' '}
              <span className="mono break-all text-ink-100">{String(result.data.code)}</span>
              <div className="mt-1 text-xs text-ink-300">
                The employee redeems it on their own machine:{' '}
                <span className="mono">zkgate keygen --name {form.employeeId}</span> then{' '}
                <span className="mono">zkgate request --code …</span>
              </div>
            </>
          ) : (
            <>
              Enrolment refused (HTTP {result.status}): <span className="mono">{err?.code}</span> —{' '}
              {err?.message}
            </>
          )}
        </div>
      )}
    </Card>
  );
}
