import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { Activity, EyeOff, Filter, Radio, Trash2 } from 'lucide-react';
import { useEvents } from '../hooks/useEventStream';
import { api } from '../services/api';
import {
  Badge,
  Card,
  CheckList,
  DecisionBadge,
  Empty,
  KV,
  PageHeader,
  Stat,
  ms,
  short,
} from '../components/ui';
import type { GatewayEvent } from '../types/api';

type Verification = Extract<GatewayEvent, { type: 'verification.completed' }>;
const FILTERS = ['all', 'verifications', 'denials', 'registry', 'sessions'] as const;

const typeTone = (e: GatewayEvent): 'ok' | 'bad' | 'warn' | 'info' | 'neutral' | 'accent' => {
  if (e.type === 'verification.completed')
    return e.decision === 'granted' ? 'ok' : e.decision === 'blocked' ? 'warn' : 'bad';
  if (e.type === 'replay.rejected' || e.type === 'nullifier.rate_limited') return 'bad';
  if (e.type === 'root.changed' || e.type === 'credential.revoked') return 'info';
  if (e.type === 'challenge.created') return 'accent';
  return 'neutral';
};

export function LiveViewPage() {
  const { zk, zkState, clear } = useEvents();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const registry = useQuery({
    queryKey: ['registry'],
    queryFn: api.registry,
    refetchInterval: 5000,
    retry: 0,
  });

  const events = useMemo(() => {
    const list = [...zk].reverse();
    return list.filter((e) => {
      if (filter === 'verifications') return e.type === 'verification.completed';
      if (filter === 'denials')
        return (
          (e.type === 'verification.completed' && e.decision !== 'granted') ||
          e.type === 'replay.rejected' ||
          e.type === 'nullifier.rate_limited'
        );
      if (filter === 'registry')
        return e.type === 'root.changed' || e.type === 'credential.revoked';
      if (filter === 'sessions')
        return e.type.startsWith('session.') || e.type === 'proxy.forwarded';
      return true;
    });
  }, [zk, filter]);
  const verifications = zk.filter((e): e is Verification => e.type === 'verification.completed');
  const latestVerification = [...verifications].reverse()[0];
  const selected = zk.find((e) => e.id === selectedId) ?? latestVerification ?? null;
  const verifyTimes = verifications.map((v) => v.verifyMs).filter((x): x is number => x !== null);
  const avgVerify = verifyTimes.length
    ? verifyTimes.reduce((a, b) => a + b, 0) / verifyTimes.length
    : null;

  return (
    <>
      <PageHeader
        eyebrow="Screen 2 · Gateway Live View"
        title="Exactly what the gateway sees"
        description="A live, authenticated stream of gateway events. Every request carries a proof and public signals — no name, no email, no role."
        actions={
          <>
            <span className="flex items-center gap-2 text-xs text-ink-300">
              <Radio className={clsx('h-4 w-4', zkState === 'open' ? 'text-ok' : 'text-warn')} />{' '}
              {zkState}
            </span>
            <button
              onClick={clear}
              className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-ink-300 ring-1 ring-inset ring-ink-600 hover:bg-ink-800"
            >
              <Trash2 className="h-3.5 w-3.5" /> Clear view
            </button>
          </>
        }
      />
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Verifications" value={verifications.length} />
        <Stat
          label="Granted"
          value={verifications.filter((v) => v.decision === 'granted').length}
          tone="ok"
        />
        <Stat
          label="Denied"
          value={verifications.filter((v) => v.decision === 'denied').length}
          tone="bad"
        />
        <Stat
          label="Blocked"
          value={verifications.filter((v) => v.decision === 'blocked').length}
          tone="warn"
          hint="valid math, insufficient circuit"
        />
        <Stat label="Avg verify" value={ms(avgVerify)} tone="accent" hint="snarkjs, this session" />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <Card
          title="Event stream"
          subtitle="Newest first · correlation IDs link related events"
          padded={false}
          actions={
            <div className="flex items-center gap-1" role="tablist" aria-label="Event filter">
              <Filter className="mr-1 h-3.5 w-3.5 text-ink-400" />
              {FILTERS.map((f) => (
                <button
                  key={f}
                  role="tab"
                  aria-selected={filter === f}
                  onClick={() => setFilter(f)}
                  className={clsx(
                    'rounded-md px-2 py-1 text-[11px] font-medium capitalize',
                    filter === f ? 'bg-cyan-500/15 text-accent' : 'text-ink-400 hover:text-ink-200',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          }
        >
          {events.length === 0 ? (
            <Empty icon={<Activity className="h-8 w-8" />} title="Waiting for traffic">
              Request access from the User Portal or run the Attack Lab; events appear here in real
              time.
            </Empty>
          ) : (
            <div className="max-h-[640px] overflow-y-auto">
              <table className="w-full text-left text-[13px]">
                <thead className="sticky top-0 bg-ink-850 text-[11px] uppercase tracking-wider text-ink-400">
                  <tr>
                    <th className="px-4 py-2">Time</th>
                    <th>Event</th>
                    <th>Resource</th>
                    <th>Result</th>
                    <th className="pr-4 text-right">Verify</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-700/50">
                  {events.map((e) => (
                    <tr
                      key={e.id}
                      onClick={() => setSelectedId(e.id)}
                      className={clsx(
                        'slide-in cursor-pointer hover:bg-ink-800/60',
                        selected?.id === e.id && 'bg-cyan-500/5',
                      )}
                    >
                      <td className="mono px-4 py-2 text-[11.5px] text-ink-400">
                        {new Date(e.ts).toLocaleTimeString()}
                      </td>
                      <td>
                        <Badge tone={typeTone(e)}>{e.type}</Badge>
                      </td>
                      <td className="text-ink-300">
                        {'resource' in e && e.resource ? e.resource : '—'}
                      </td>
                      <td className="mono text-[11.5px]">
                        {e.type === 'verification.completed' ? (
                          <span className="flex items-center gap-2">
                            <DecisionBadge decision={e.decision} />{' '}
                            <span className="truncate text-ink-400">{e.reason}</span>
                          </span>
                        ) : e.type === 'root.changed' ? (
                          short(e.root, 6)
                        ) : 'reason' in e ? (
                          String(e.reason)
                        ) : (
                          ''
                        )}
                      </td>
                      <td className="mono pr-4 text-right text-[11.5px] text-ink-300">
                        {e.type === 'verification.completed' ? ms(e.verifyMs) : ''}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <div className="space-y-6">
          <Card
            title="Selected event"
            subtitle={
              selected
                ? `${selected.type} · ${new Date(selected.ts).toLocaleTimeString()}`
                : 'Nothing selected'
            }
          >
            {selected ? (
              <EventDetail e={selected} />
            ) : (
              <p className="text-sm text-ink-400">
                Select an event to inspect the exact data the gateway received.
              </p>
            )}
          </Card>
          <Card
            title="Current Merkle root"
            subtitle="Authoritative root from the registry (P2 contract)"
          >
            {registry.isError ? (
              <p className="text-sm text-warn">Registry unavailable — the gateway fails closed.</p>
            ) : registry.data ? (
              <dl>
                <KV k="root" v={short(registry.data.current.root, 12)} mono />
                <KV k="version" v={registry.data.current.version ?? '—'} mono />
                <KV k="tree depth" v={registry.data.current.treeDepth ?? '—'} />
                <KV k="source" v={registry.data.current.source ?? '—'} />
                <KV k="root changes observed" v={registry.data.gatewayRootHistory.length} />
              </dl>
            ) : (
              <p className="text-sm text-ink-400">Loading…</p>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}

function EventDetail({ e }: { e: GatewayEvent }) {
  if (e.type === 'verification.completed') {
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <DecisionBadge decision={e.decision} />
          <span className="mono text-xs text-ink-300">{e.reason}</span>
          <span className="ml-auto mono text-[11px] text-ink-400">profile {e.profile}</span>
        </div>
        <dl className="grid gap-x-6 sm:grid-cols-2">
          <KV
            k="Groth16"
            v={e.groth16Valid === null ? 'not run' : e.groth16Valid ? 'valid' : 'invalid'}
            tone={e.groth16Valid ? 'ok' : e.groth16Valid === false ? 'bad' : undefined}
          />
          <KV k="verify time" v={ms(e.verifyMs)} mono />
          <KV k="proof size" v={`${e.proofBytes} B`} mono />
          <KV k="total gateway time" v={ms(e.totalMs)} mono />
          <KV
            k="nullifier"
            v={e.nullifier ? short(e.nullifier, 8) : 'not provided by circuit'}
            mono
          />
          <KV k="correlation" v={short(e.correlationId, 6)} mono />
        </dl>
        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-400">
            Public signals received
          </div>
          <div className="rounded-lg bg-ink-950/60 p-3 ring-1 ring-ink-700">
            {e.publicSignals.length ? (
              e.publicSignals.map((s) => (
                <div key={s.name} className="mono flex justify-between gap-4 text-[12px]">
                  <span className="text-accent">{s.name}</span>
                  <span className="truncate text-ink-200">{s.value}</span>
                </div>
              ))
            ) : (
              <span className="text-xs text-ink-400">none (rejected before parsing)</span>
            )}
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-400">
              Fields received
            </div>
            <ul className="space-y-1 text-xs text-ink-200">
              {e.requesterFields.map((f) => (
                <li key={f}>• {f}</li>
              ))}
            </ul>
          </div>
          <div>
            <div className="mb-1 flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wider text-ok">
              <EyeOff className="h-3 w-3" /> Never received
            </div>
            <div className="flex flex-wrap gap-1">
              {[
                'username',
                'email',
                'role',
                'department',
                'clearance',
                'device posture',
                'issuer signature',
                'Merkle path',
                'user secret',
              ].map((f) => (
                <Badge key={f} tone="ok">
                  {f}
                </Badge>
              ))}
            </div>
          </div>
        </div>
        <p className="text-[11px] leading-relaxed text-ink-400">
          Transport metadata (source IP, timing) is still visible to any HTTP server and is not
          anonymised by ZK proofs; it is not recorded in these events.
        </p>
        <CheckList checks={e.checks} />
      </div>
    );
  }
  return (
    <pre className="mono max-h-80 overflow-auto rounded-lg bg-ink-950/60 p-3 text-[11.5px] text-ink-200 ring-1 ring-ink-700">
      {JSON.stringify(e, null, 2)}
    </pre>
  );
}
