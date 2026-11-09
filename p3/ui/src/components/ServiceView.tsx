import { useState } from 'react';
import { BookOpen, Download, FileText, Server, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';
import { Badge, Button, KV } from './ui';

type Json = Record<string, unknown>;
interface Viewer {
  frontDoor: string;
  subject: string;
  display: string;
}

/** Renders the JSON returned by the three protected services. */
export function ServiceView({
  status,
  data,
  via,
}: {
  status: number;
  data: Json;
  via: 'zk' | 'sso';
}) {
  if (status !== 200) {
    const err = (data?.error ?? {}) as { code?: string; message?: string };
    return (
      <div className="flex items-start gap-2 text-sm text-bad">
        <ShieldAlert className="mt-0.5 h-4 w-4" /> HTTP {status} ·{' '}
        <span className="mono">{err.code}</span> {err.message}
      </div>
    );
  }
  const viewer = data.viewer as Viewer | undefined;
  return (
    <div className="space-y-4">
      {viewer && (
        <div className="rounded-lg bg-ink-900/60 p-3 ring-1 ring-ink-700">
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-400">
            What this service learned about the requester
          </div>
          <dl className="grid gap-x-6 sm:grid-cols-3">
            <KV k="front door" v={viewer.frontDoor} mono />
            <KV
              k="subject"
              v={viewer.subject}
              mono
              tone={viewer.frontDoor === 'sso-baseline' ? 'bad' : 'ok'}
            />
            <KV
              k="display"
              v={viewer.display}
              tone={viewer.frontDoor === 'sso-baseline' ? 'bad' : 'ok'}
            />
          </dl>
        </div>
      )}
      {data.service === 'wiki' && <Wiki data={data} via={via} />}
      {data.service === 'file-share' && <Files data={data} via={via} />}
      {data.service === 'admin-panel' && <Admin data={data} via={via} />}
    </div>
  );
}

function Wiki({ data, via }: { data: Json; via: 'zk' | 'sso' }) {
  const [article, setArticle] = useState<Json | null>(null);
  const featured = (data.featured ?? []) as Array<{
    slug: string;
    title: string;
    summary: string;
    category: string;
    readMinutes: number;
  }>;
  return (
    <div className="grid gap-4 lg:grid-cols-[1fr_1.2fr]">
      <div>
        <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
          <BookOpen className="h-4 w-4 text-accent" /> {String(data.title)}
        </h3>
        <div className="mb-3 flex flex-wrap gap-1.5">
          {((data.categories ?? []) as string[]).map((c) => (
            <Badge key={c}>{c}</Badge>
          ))}
        </div>
        <ul className="space-y-2">
          {featured.map((a) => (
            <li key={a.slug}>
              <button
                className="w-full rounded-lg p-3 text-left ring-1 ring-ink-700 hover:ring-cyan-400/40"
                onClick={async () =>
                  setArticle(
                    (await api.service('wiki', `/articles/${a.slug}`, via)).data.article as Json,
                  )
                }
              >
                <div className="text-sm font-medium">{a.title}</div>
                <div className="mt-0.5 text-xs text-ink-400">
                  {a.category} · {a.readMinutes} min · {a.summary}
                </div>
              </button>
            </li>
          ))}
        </ul>
      </div>
      <article className="rounded-lg bg-ink-900/60 p-4 ring-1 ring-ink-700">
        {article ? (
          <>
            <h4 className="font-semibold">{String(article.title)}</h4>
            <div className="mt-0.5 text-xs text-ink-400">
              {String(article.author)} · updated {String(article.updated)}
            </div>
            <div className="mt-3 space-y-2 text-sm leading-relaxed text-ink-200">
              {((article.body ?? []) as string[]).map((p, i) => (
                <p key={i}>{p}</p>
              ))}
            </div>
          </>
        ) : (
          <p className="text-sm text-ink-400">Select an article.</p>
        )}
      </article>
    </div>
  );
}

function Files({ data, via }: { data: Json; via: 'zk' | 'sso' }) {
  const files = (data.files ?? []) as Array<{
    id: string;
    name: string;
    category: string;
    sizeBytes: number;
    owner: string;
    classification: string;
    updated: string;
  }>;
  const prefix = via === 'zk' ? '' : '/sso';
  return (
    <div className="overflow-x-auto">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold">
        <FileText className="h-4 w-4 text-accent" /> {String(data.title)}
      </h3>
      <table className="w-full text-left text-sm">
        <thead className="text-[11px] uppercase tracking-wider text-ink-400">
          <tr>
            <th className="py-2">File</th>
            <th>Category</th>
            <th>Classification</th>
            <th>Owner</th>
            <th className="text-right">Size</th>
            <th />
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {files.map((f) => (
            <tr key={f.id}>
              <td className="py-2 mono text-[12.5px]">{f.name}</td>
              <td>{f.category}</td>
              <td>
                <Badge tone={f.classification === 'Confidential' ? 'warn' : 'neutral'}>
                  {f.classification}
                </Badge>
              </td>
              <td className="text-ink-300">{f.owner}</td>
              <td className="text-right tabular-nums text-ink-300">{f.sizeBytes} B</td>
              <td className="text-right">
                <a
                  className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
                  href={`${prefix}/svc/file-share/files/${encodeURIComponent(f.id)}/download`}
                >
                  <Download className="h-3.5 w-3.5" /> Download
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Admin({ data, via }: { data: Json; via: 'zk' | 'sso' }) {
  const [state, setState] = useState(data);
  const ov = state.overview as Record<string, number>;
  const alerts = (state.alerts ?? []) as Array<{
    id: string;
    severity: string;
    title: string;
    acknowledged: boolean;
  }>;
  const services = (state.services ?? []) as Array<{
    name: string;
    status: string;
    p95ms: number;
    uptime: string;
  }>;
  const ack = async (id: string) => {
    await api.servicePost('admin-panel', '/actions/acknowledge-alert', { alertId: id }, via);
    setState((await api.service('admin-panel', '/', via)).data);
  };
  return (
    <div className="space-y-4">
      <h3 className="flex items-center gap-2 text-sm font-semibold">
        <Server className="h-4 w-4 text-accent" /> {String(state.title)}
      </h3>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {Object.entries(ov).map(([k, v]) => (
          <div key={k} className="rounded-lg bg-ink-900/60 p-3 ring-1 ring-ink-700">
            <div className="text-[11px] uppercase tracking-wider text-ink-400">
              {k.replace(/([A-Z])/g, ' $1')}
            </div>
            <div className="text-lg font-semibold tabular-nums">{v}</div>
          </div>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <ul className="space-y-1.5">
          {services.map((s) => (
            <li
              key={s.name}
              className="flex items-center justify-between rounded-lg px-3 py-2 text-sm ring-1 ring-ink-700"
            >
              <span>{s.name}</span>
              <span className="flex items-center gap-2 text-xs text-ink-400">
                p95 {s.p95ms} ms · {s.uptime}{' '}
                <Badge tone={s.status === 'operational' ? 'ok' : 'warn'}>{s.status}</Badge>
              </span>
            </li>
          ))}
        </ul>
        <ul className="space-y-1.5">
          {alerts.map((a) => (
            <li
              key={a.id}
              className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm ring-1 ring-ink-700"
            >
              <Badge
                tone={a.severity === 'high' ? 'bad' : a.severity === 'medium' ? 'warn' : 'neutral'}
              >
                {a.severity}
              </Badge>
              <span className="flex-1 text-ink-200">{a.title}</span>
              {a.acknowledged ? (
                <Badge tone="ok">ack</Badge>
              ) : (
                <Button
                  variant="ghost"
                  className="px-2 py-1 text-xs"
                  onClick={() => void ack(a.id)}
                >
                  Acknowledge
                </Button>
              )}
            </li>
          ))}
        </ul>
      </div>
      <p className="text-xs text-ink-400">{String(state.note)}</p>
    </div>
  );
}
