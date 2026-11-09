import { Router, type RequestHandler } from 'express';
import type { GatewayContext } from '../app/createApp.js';
import { OPERATOR_COOKIE } from '../security/operator.js';
import { clearCookie, readCookie, serializeCookie } from '../utils/cookies.js';

export function operatorRoutes(ctx: GatewayContext, limiter: RequestHandler) {
  const r = Router();
  r.post('/login', limiter, (req, res) => {
    if (!ctx.operator.checkToken(req.body?.token)) {
      return res
        .status(401)
        .json({ error: { code: 'INVALID_OPERATOR_TOKEN', message: 'invalid operator token' } });
    }
    const old = readCookie(req.headers.cookie, OPERATOR_COOKIE);
    ctx.operator.logout(old); // rotate: never reuse a pre-login identifier
    const s = ctx.operator.login();
    res.append(
      'Set-Cookie',
      serializeCookie(OPERATOR_COOKIE, s.id, {
        path: '/',
        maxAgeSeconds: 8 * 3600,
        secure: ctx.config.COOKIE_SECURE,
      }),
    );
    res.json({ ok: true, expiresAt: new Date(s.expiresAt).toISOString() });
  });
  r.post('/logout', (req, res) => {
    ctx.operator.logout(readCookie(req.headers.cookie, OPERATOR_COOKIE));
    res.append('Set-Cookie', clearCookie(OPERATOR_COOKIE, '/', ctx.config.COOKIE_SECURE));
    res.json({ ok: true });
  });
  r.get('/me', (req, res) =>
    res.json({ authenticated: ctx.operator.fromCookieHeader(req.headers.cookie) }),
  );
  r.get('/events', ctx.operator.middleware(), (req, res) => {
    const limit = Math.min(Number(req.query.limit ?? 200) || 200, 500);
    res.json({ items: ctx.bus.recent(limit) });
  });
  return r;
}
