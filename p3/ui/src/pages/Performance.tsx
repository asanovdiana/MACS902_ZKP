import { useQuery } from '@tanstack/react-query';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Legend,
} from 'recharts';
import { Gauge } from 'lucide-react';
import { api, type BenchMetric } from '../services/api';
import { Badge, Card, Empty, PageHeader, Stat } from '../components/ui';

// Short axis labels for the latency chart; the full label stays in the tooltip and the table.
const SHORT: Record<string, string> = {
  prove: 'Prove (v3)',
  verify: 'Verify (v3)',
  'gateway-e2e': 'Gateway e2e (v3)',
  'gateway-pipeline': 'Gateway pipeline',
  'gateway-reject-invalid': 'Reject: invalid proof',
  'gateway-reject-replay': 'Reject: replay',
  'sso-request': 'SSO request',
  'zk-vs-sso': 'ZK overhead vs SSO',
  'v4-prove': 'Prove (v4)',
  'v4-verify': 'Verify (v4)',
  'v4-e2e': 'End to end (v4)',
  'zk-session-request': 'ZK session request',
};
const shortLabel = (m: BenchMetric) =>
  SHORT[m.id] ?? (m.label.length > 24 ? `${m.label.slice(0, 23)}…` : m.label);

const fmt = (m?: BenchMetric) =>
  m && m.status === 'measured' && m.median !== undefined ? m.median : null;

export function PerformancePage() {
  const q = useQuery({ queryKey: ['bench'], queryFn: api.bench, retry: 0 });
  if (q.isError)
    return (
      <>
        <Header />
        <div className="panel">
          <Empty icon={<Gauge className="h-8 w-8" />} title="No measured results yet">
            Run <code className="mono text-accent">make bench</code> (or{' '}
            <code className="mono">npm run bench</code>). Results are written to
            bench/results/latest.json and shown here — nothing on this page is estimated.
          </Empty>
        </div>
      </>
    );
  if (!q.data) return <Header />;
  const d = q.data;
  const raw = (id: string) => d.metrics.find((m) => m.id === id);
  // Prefer the team v4 measurements when present; fall back to the P1 v3 diagnostic ones.
  const V4: Record<string, string> = {
    verify: 'v4-verify',
    prove: 'v4-prove',
    'proof-size': 'v4-proof-size',
    constraints: 'v4-constraints',
    'gateway-e2e': 'v4-e2e',
  };
  const by = (id: string) =>
    V4[id] && raw(V4[id]!)?.status === 'measured' ? raw(V4[id]!) : raw(id);
  const isV4 = raw('v4-verify')?.status === 'measured';
  const latency = d.metrics.filter(
    (m) => m.status === 'measured' && m.unit === 'ms' && m.median !== undefined,
  );
  const chart = latency.map((m) => ({
    name: shortLabel(m),
    full: m.label,
    median: Number(m.median!.toFixed(2)),
    p95: Number(m.p95!.toFixed(2)),
  }));
  return (
    <>
      <Header />
      <p className="mb-4 text-xs text-ink-400">
        Measured {new Date(d.generatedAt).toLocaleString()} · {String(d.environment.node)} ·{' '}
        {String(d.environment.cpu)} · {String(d.environment.platform)}
      </p>
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat
          label="Verify (median)"
          value={fmt(by('verify'))?.toFixed(2) ?? '—'}
          unit="ms"
          tone="accent"
          hint="target < 10 ms"
        />
        <Stat
          label="Prove (median)"
          value={fmt(by('prove')) !== null ? (fmt(by('prove'))! / 1000).toFixed(2) : '—'}
          unit="s"
          hint="target < 3 s (native)"
        />
        <Stat
          label="Proof size"
          value={fmt(by('proof-size')) ?? '—'}
          unit="bytes"
          hint="Groth16 BN254, uncompressed"
        />
        <Stat
          label="Constraints"
          value={fmt(by('constraints'))?.toLocaleString() ?? '—'}
          hint={isV4 ? 'team integrated_access_v4' : 'P1 integrated_access_v3'}
        />
        <Stat
          label="ZK gateway e2e"
          value={fmt(by('gateway-e2e'))?.toFixed(1) ?? '—'}
          unit="ms"
          hint={isV4 ? 'challenge → prove → admit, HTTP' : 'challenge + verify, HTTP'}
        />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Card
          title="Latency: median vs p95"
          subtitle={`${by('verify')?.samples ?? 0} samples per measurement`}
        >
          <div style={{ height: Math.max(320, chart.length * 34 + 60) }}>
            <ResponsiveContainer>
              <BarChart data={chart} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid stroke="#1a2540" horizontal={false} />
                <XAxis
                  type="number"
                  stroke="#6b7a99"
                  fontSize={11}
                  unit=" ms"
                  scale="log"
                  domain={['auto', 'auto']}
                  allowDataOverflow
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  stroke="#6b7a99"
                  fontSize={11}
                  width={150}
                  interval={0}
                />
                <Tooltip
                  contentStyle={{
                    background: '#0d1424',
                    border: '1px solid #25324f',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  labelFormatter={(_, p) => p?.[0]?.payload?.full ?? ''}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="median" fill="#22d3ee" radius={[0, 4, 4, 0]} />
                <Bar dataKey="p95" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="mt-2 text-xs text-ink-400">Logarithmic axis.</p>
        </Card>
        <Card title="All measurements" padded={false}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[13px]">
              <thead className="text-[11px] uppercase tracking-wider text-ink-400">
                <tr>
                  <th className="px-4 py-2">Metric</th>
                  <th>n</th>
                  <th>Median</th>
                  <th>p95</th>
                  <th>Min</th>
                  <th className="pr-4">Max</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/50">
                {d.metrics.map((m) => (
                  <tr key={m.id}>
                    <td className="px-4 py-2">
                      <div>{m.label}</div>
                      {m.note && <div className="text-[11px] text-ink-400">{m.note}</div>}
                    </td>
                    {m.status === 'measured' ? (
                      <>
                        <td className="tabular-nums">{m.samples}</td>
                        <td className="mono tabular-nums">
                          {m.median?.toFixed(m.unit === 'ms' ? 2 : 0)} {m.unit}
                        </td>
                        <td className="mono tabular-nums">
                          {m.p95?.toFixed(m.unit === 'ms' ? 2 : 0)}
                        </td>
                        <td className="mono tabular-nums">
                          {m.min?.toFixed(m.unit === 'ms' ? 2 : 0)}
                        </td>
                        <td className="mono pr-4 tabular-nums">
                          {m.max?.toFixed(m.unit === 'ms' ? 2 : 0)}
                        </td>
                      </>
                    ) : (
                      <td colSpan={5} className="pr-4">
                        <Badge tone="warn">blocked</Badge>{' '}
                        <span className="text-xs text-ink-400">{m.reason}</span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
      <Card title="Run configuration" className="mt-6">
        <pre className="mono overflow-auto text-[11.5px] text-ink-300">
          {JSON.stringify(
            { environment: d.environment, artifact: d.artifact, config: d.config },
            null,
            2,
          )}
        </pre>
      </Card>
    </>
  );
}

function Header() {
  return (
    <PageHeader
      eyebrow="Evaluation"
      title="Measured performance"
      description="Numbers below are read from the benchmark harness output (100 iterations where applicable). Targets from the Project Scope are targets, not claims."
    />
  );
}
