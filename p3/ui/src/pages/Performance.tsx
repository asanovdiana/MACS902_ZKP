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
  const by = (id: string) => d.metrics.find((m) => m.id === id);
  const latency = d.metrics.filter(
    (m) => m.status === 'measured' && m.unit === 'ms' && m.median !== undefined,
  );
  const chart = latency.map((m) => ({
    name: m.label,
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
          hint="P1 integrated_access_v3"
        />
        <Stat
          label="ZK gateway e2e"
          value={fmt(by('gateway-e2e'))?.toFixed(1) ?? '—'}
          unit="ms"
          hint="challenge + verify, HTTP"
        />
      </div>
      <div className="grid gap-6 xl:grid-cols-2">
        <Card
          title="Latency: median vs p95"
          subtitle={`${by('verify')?.samples ?? 0} samples per measurement`}
        >
          <div className="h-80">
            <ResponsiveContainer>
              <BarChart data={chart} layout="vertical" margin={{ left: 40, right: 16 }}>
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
                <YAxis type="category" dataKey="name" stroke="#6b7a99" fontSize={11} width={170} />
                <Tooltip
                  contentStyle={{
                    background: '#0d1424',
                    border: '1px solid #25324f',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
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
