import type { Server } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import type { EventBus } from './bus.js';
import type { OperatorAuth } from '../security/operator.js';

/**
 * Authenticated WebSocket stream of safe gateway events. Requires an operator session
 * cookie and an allowlisted Origin (prevents cross-site WebSocket hijacking).
 */
export function attachEventStream(
  server: Server,
  bus: EventBus,
  auth: OperatorAuth,
  allowedOrigins: string[],
) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== '/api/events/ws') return socket.destroy();
    const origin = req.headers.origin;
    if (!origin || !allowedOrigins.includes(origin) || !auth.fromCookieHeader(req.headers.cookie)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      return socket.destroy();
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws));
  });
  wss.on('connection', (ws: WebSocket & { alive?: boolean }) => {
    ws.alive = true;
    ws.on('pong', () => (ws.alive = true));
    ws.on('message', () => undefined); // clients never send commands
    ws.send(JSON.stringify({ kind: 'snapshot', events: bus.recent(200) }));
    const onEvent = (event: unknown) => {
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ kind: 'event', event }));
    };
    bus.on('event', onEvent);
    ws.on('close', () => bus.off('event', onEvent));
  });
  const heartbeat = setInterval(() => {
    for (const ws of wss.clients as Set<WebSocket & { alive?: boolean }>) {
      if (!ws.alive) {
        ws.terminate();
        continue;
      }
      ws.alive = false;
      ws.ping();
    }
  }, 15000);
  heartbeat.unref();
  return wss;
}
