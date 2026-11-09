import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { loadSsoConfig } from './config.js';
import { createSsoApp } from './app.js';

const config = loadSsoConfig();
const { app, bus, history, isOperatorCookie } = createSsoApp({ config });
const server = createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });
server.on('upgrade', (req, socket, head) => {
  const path = new URL(req.url ?? '/', 'http://x').pathname;
  if (
    path !== '/sso/events/ws' ||
    !req.headers.origin ||
    !config.allowedOrigins.includes(req.headers.origin) ||
    !isOperatorCookie(req.headers.cookie)
  ) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.send(JSON.stringify({ kind: 'snapshot', events: history.slice(-200) }));
    const on = (event: unknown) =>
      ws.readyState === ws.OPEN && ws.send(JSON.stringify({ kind: 'event', event }));
    bus.on('event', on);
    ws.on('close', () => bus.off('event', on));
  });
});
server.listen(config.SSO_PORT, config.SSO_HOST, () =>
  console.log(
    `[sso-baseline] listening on http://${config.SSO_HOST}:${config.SSO_PORT} (issuer ${config.issuer})`,
  ),
);
