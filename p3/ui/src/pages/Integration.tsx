import { useQuery } from '@tanstack/react-query';
import { CircleSlash, CheckCircle2, FileWarning } from 'lucide-react';
import { api } from '../services/api';
import { useStatus } from '../app/Layout';
import { Badge, Card, KV, PageHeader, short } from '../components/ui';

export function IntegrationPage() {
  const { data: s } = useStatus();
  const audit = useQuery({ queryKey: ['audit'], queryFn: api.audit, retry: 0 });
  return (
    <>
      <PageHeader
        eyebrow="Integration status"
        title="What the active circuit actually proves"
        description="The gateway issues sessions only when every required guarantee is enforced cryptographically. This page shows the evidence behind that decision."
      />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card title="Active circuit profile" subtitle={s?.profile.title}>
          {s && (
            <>
              <ul className="space-y-1.5">
                {s.profile.capabilities.map((c) => (
                  <li key={c.id} className="flex items-center gap-2 text-sm">
                    {c.supported ? (
                      <CheckCircle2 className="h-4 w-4 text-ok" />
                    ) : (
                      <CircleSlash className="h-4 w-4 text-warn" />
                    )}
                    <span className={c.supported ? 'text-ink-100' : 'text-ink-300'}>{c.label}</span>
                    <span className="ml-auto">
                      {c.supported ? (
                        <Badge tone="ok">enforced</Badge>
                      ) : (
                        <Badge tone="warn">missing</Badge>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
              <div className="mt-4 rounded-lg bg-ink-900/60 p-3 text-xs text-ink-300 ring-1 ring-ink-700">
                Public signals:{' '}
                <span className="mono text-accent">[{s.profile.signals.join(', ')}]</span>
                <ul className="mt-2 list-disc space-y-1 pl-4 text-ink-400">
                  {s.profile.notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </Card>
        <Card title="Verification artifacts">
          {s && (
            <dl>
              <KV
                k="status"
                v={s.artifacts.status}
                tone={s.artifacts.status === 'ready' ? 'ok' : 'bad'}
              />
              <KV k="circuit" v={s.artifacts.circuitId ?? '—'} mono />
              <KV k="version" v={s.artifacts.version ?? '—'} mono />
              <KV k="security status" v={s.artifacts.securityStatus ?? '—'} tone="warn" />
              <KV
                k="key trust"
                v={s.artifacts.trust ?? '—'}
                tone={s.artifacts.trust === 'reviewed' ? 'ok' : 'warn'}
              />
              <KV k="registry API" v={s.settings.registryApi ?? '—'} mono />
              <KV
                k="issuer key pinned"
                v={s.settings.issuerPinned ? 'yes' : 'no'}
                tone={s.settings.issuerPinned ? 'ok' : 'bad'}
              />
              <KV
                k="security review"
                v={s.artifacts.reviewed ? 'accepted' : 'not accepted'}
                tone={s.artifacts.reviewed ? 'ok' : 'warn'}
              />
              <KV k="vkey sha256" v={short(s.artifacts.vkeySha256 ?? '', 10)} mono />
              <div className="mt-2 text-xs text-warn">{s.artifacts.trustedSetup}</div>
            </dl>
          )}
        </Card>
      </div>
      <Card
        className="mt-6"
        title={
          <span className="flex items-center gap-2">
            <FileWarning className="h-4 w-4 text-warn" /> P1 audit — executed against the real
            compiled circuit
          </span>
        }
        subtitle={
          audit.data
            ? `generated ${new Date(audit.data.generatedAt).toLocaleString()} · ${Object.entries(
                audit.data.summary,
              )
                .map(([k, v]) => `${v} ${k}`)
                .join(' · ')}`
            : 'run npm run p1:audit'
        }
      >
        <ul className="divide-y divide-ink-700/60">
          {audit.data?.findings.map((f) => (
            <li key={f.id} className="grid gap-1 py-3 sm:grid-cols-[110px_1fr]">
              <div className="flex items-start gap-2">
                <span className="mono text-xs text-ink-400">{f.id}</span>
                <Badge
                  tone={
                    f.verdict === 'SECURE'
                      ? 'ok'
                      : f.verdict === 'VULNERABLE'
                        ? 'bad'
                        : f.verdict === 'GAP'
                          ? 'warn'
                          : 'neutral'
                  }
                >
                  {f.verdict}
                </Badge>
              </div>
              <div>
                <div className="text-sm font-medium">{f.question}</div>
                <div className="mt-0.5 text-xs leading-relaxed text-ink-300">{f.evidence}</div>
              </div>
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}
