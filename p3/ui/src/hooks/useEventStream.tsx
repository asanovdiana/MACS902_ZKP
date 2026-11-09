import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { GatewayEvent } from '../types/api';
import { useOperator } from '../state/operator';

type ConnState = 'connecting' | 'open' | 'closed' | 'unauthorized';
interface Streams {
  zk: GatewayEvent[];
  sso: GatewayEvent[];
  zkState: ConnState;
  ssoState: ConnState;
  clear: () => void;
}
const Ctx = createContext<Streams | null>(null);
const MAX = 400;

function useSocket(path: string, enabled: boolean): [GatewayEvent[], ConnState, () => void] {
  const [events, setEvents] = useState<GatewayEvent[]>([]);
  const [state, setState] = useState<ConnState>('closed');
  const retry = useRef(0);
  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const open = () => {
      setState('connecting');
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${proto}://${location.host}${path}`);
      ws.onopen = () => {
        retry.current = 0;
        setState('open');
      };
      ws.onmessage = (m) => {
        try {
          const msg = JSON.parse(String(m.data)) as
            { kind: 'snapshot'; events: GatewayEvent[] } | { kind: 'event'; event: GatewayEvent };
          if (msg.kind === 'snapshot') setEvents(msg.events.slice(-MAX));
          else setEvents((prev) => [...prev.slice(-(MAX - 1)), msg.event]);
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        if (stopped) return;
        setState('closed');
        const delay = Math.min(15000, 500 * 2 ** retry.current++);
        timer = setTimeout(open, delay); // graceful reconnection with backoff
      };
    };
    open();
    return () => {
      stopped = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [path, enabled]);
  return [events, enabled ? state : 'unauthorized', () => setEvents([])];
}

export function EventStreamProvider({ children }: { children: ReactNode }) {
  const { authenticated } = useOperator();
  const [zk, zkState, clearZk] = useSocket('/api/events/ws', authenticated === true);
  const [sso, ssoState, clearSso] = useSocket('/sso/events/ws', authenticated === true);
  return (
    <Ctx.Provider value={{ zk, sso, zkState, ssoState, clear: () => (clearZk(), clearSso()) }}>
      {children}
    </Ctx.Provider>
  );
}

export function useEvents() {
  const v = useContext(Ctx);
  if (!v) throw new Error('useEvents outside provider');
  return v;
}
