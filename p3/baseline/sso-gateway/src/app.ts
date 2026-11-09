import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import { EventEmitter } from 'node:events';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { createRemoteJWKSet, type JWTVerifyGetKey } from 'jose';
import {
  POLICIES,
  evaluatePolicy,
  forward,
  isResourceId,
  sanitizeUpstreamPath,
  type GatewayEvent,
  type ResourceId,
} from '@zkag/shared';
import type { SsoConfig } from './config.js';
import { mapIdentity, pkcePair, validateToken, type MappedIdentity } from './oidc.js';

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;

interface PendingLogin {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  createdAt: number;
  startedAt: number;
}
interface SsoSession {
  id: string;
  accessToken: string;
  identity: MappedIdentity;
  expiresAt: number;
}

const SESSION_COOKIE = 'zkag_sso';
const STATE_COOKIE = 'zkag_sso_state';
const OPERATOR_COOKIE = 'zkag_sso_operator';
const MAX_PENDING_LOGINS = Number(process.env.SSO_MAX_PENDING_LOGINS ?? 5000);

function cookie(header: string | undefined, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) {
      const value = v.join('=');
      return /^[A-Za-z0-9_-]{1,128}$/.test(value) ? value : undefined;
    }
  }
  return undefined;
}
const setCookie = (
  name: string,
  value: string,
  maxAge: number,
  sameSite: 'Strict' | 'Lax',
  secure: boolean,
) =>
  `${name}=${value}; Path=/sso; Max-Age=${maxAge}; HttpOnly; SameSite=${sameSite}${secure ? '; Secure' : ''}`;

export interface SsoDeps {
  config: SsoConfig;
  /** Test seam: supply a local JWKS instead of fetching the realm certs. */
  keys?: JWTVerifyGetKey;
  /** Test seam: replace the token endpoint call. */
  exchangeCode?: (
    code: string,
    verifier: string,
  ) => Promise<{ id_token: string; access_token: string; expires_in?: number }>;
}

export function createSsoApp(deps: SsoDeps) {
  const { config } = deps;
  const keys =
    deps.keys ??
    createRemoteJWKSet(new URL(config.jwksUri), { timeoutDuration: 3000, cooldownDuration: 30000 });
  const pending = new Map<string, PendingLogin>();
  const sessions = new Map<string, SsoSession>();
  const operatorSessions = new Set<string>();
  const bus = new EventEmitter();
  const history: GatewayEvent[] = [];
  const opDigest = createHash('sha256').update(config.OPERATOR_TOKEN).digest();

  const publish = (e: DistributiveOmit<GatewayEvent, 'id' | 'ts'>) => {
    const full = { ...e, id: randomUUID(), ts: new Date().toISOString() } as GatewayEvent;
    history.push(full);
    if (history.length > 500) history.shift();
    bus.emit('event', full);
  };

  const exchangeCode =
    deps.exchangeCode ??
    (async (code: string, verifier: string) => {
      const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.OIDC_REDIRECT_URI,
        client_id: config.OIDC_CLIENT_ID,
        client_secret: config.OIDC_CLIENT_SECRET,
        code_verifier: verifier,
      });
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 5000);
      try {
        const res = await fetch(config.tokenEndpoint, {
          method: 'POST',
          body,
          signal: ctrl.signal,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          redirect: 'error',
        });
        if (!res.ok) throw new Error(`token endpoint ${res.status}`);
        return (await res.json()) as {
          id_token: string;
          access_token: string;
          expires_in?: number;
        };
      } finally {
        clearTimeout(t);
      }
    });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback');
  app.use(helmet({ contentSecurityPolicy: false, referrerPolicy: { policy: 'no-referrer' } }));
  app.use(express.json({ limit: '16kb' }));
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      const origin = req.get('origin');
      if (origin && !config.allowedOrigins.includes(origin))
        return res.status(403).json({
          error: { code: 'ORIGIN_NOT_ALLOWED', message: 'cross-origin request rejected' },
        });
    }
    next();
  });

  const isOperator = (req: Request) => {
    const id = cookie(req.headers.cookie, OPERATOR_COOKIE);
    return !!id && operatorSessions.has(id);
  };

  app.get('/sso/health', (_req, res) =>
    res.json({ status: 'ok', issuer: config.issuer, clientId: config.OIDC_CLIENT_ID }),
  );
  app.get('/sso/health/keycloak', async (_req, res) => {
    try {
      const r = await fetch(
        `${config.KEYCLOAK_INTERNAL_URL.replace(/\/$/, '')}/realms/${config.KEYCLOAK_REALM}/.well-known/openid-configuration`,
        { signal: AbortSignal.timeout(2000) },
      );
      const doc = r.ok ? ((await r.json()) as { issuer?: string }) : null;
      res.json({
        keycloak: r.ok,
        issuerMatches: doc?.issuer === config.issuer,
        issuer: doc?.issuer ?? null,
      });
    } catch {
      res.json({ keycloak: false });
    }
  });

  /** Start Authorization Code + PKCE (S256). State is bound to the browser via a cookie. */
  app.get('/sso/login', (req, res) => {
    const resource =
      typeof req.query.resource === 'string' && isResourceId(req.query.resource)
        ? req.query.resource
        : 'wiki';
    const rt = typeof req.query.returnTo === 'string' ? req.query.returnTo : '/compare';
    const returnTo = /^\/(?!\/)[A-Za-z0-9/_?=&.-]{0,200}$/.test(rt) ? rt : '/compare';
    const { verifier, challenge, method } = pkcePair();
    const p: PendingLogin = {
      state: randomBytes(18).toString('base64url'),
      nonce: randomBytes(18).toString('base64url'),
      verifier,
      returnTo,
      createdAt: Date.now(),
      startedAt: performance.now(),
    };
    for (const [k, v] of pending) if (Date.now() - v.createdAt > 600_000) pending.delete(k);
    // Unauthenticated endpoint: bound the pending-login state to prevent memory exhaustion.
    if (pending.size >= MAX_PENDING_LOGINS) {
      return res.status(503).json({
        error: { code: 'LOGIN_CAPACITY', message: 'too many pending logins; retry shortly' },
      });
    }
    pending.set(p.state, p);
    const url = new URL(config.authorizationEndpoint);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: config.OIDC_CLIENT_ID,
      redirect_uri: config.OIDC_REDIRECT_URI,
      scope: 'openid profile email',
      state: p.state,
      nonce: p.nonce,
      code_challenge: challenge,
      code_challenge_method: method,
    }).toString();
    void resource;
    res.append('Set-Cookie', setCookie(STATE_COOKIE, p.state, 600, 'Lax', config.COOKIE_SECURE));
    res.redirect(302, url.toString());
  });

  app.get('/sso/callback', async (req, res) => {
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const bound = cookie(req.headers.cookie, STATE_COOKIE);
    const p = pending.get(state);
    pending.delete(state);
    res.append('Set-Cookie', setCookie(STATE_COOKIE, '', 0, 'Lax', config.COOKIE_SECURE));
    if (!p || !bound || bound !== state || !code)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_STATE', message: 'login state invalid or expired' } });
    let tokens: { id_token: string; access_token: string; expires_in?: number };
    try {
      tokens = await exchangeCode(code, p.verifier);
    } catch {
      return res.status(502).json({
        error: {
          code: 'TOKEN_EXCHANGE_FAILED',
          message: 'could not exchange authorization code',
        },
      });
    }
    const idv = await validateToken(tokens.id_token, {
      issuer: config.issuer,
      audience: config.OIDC_CLIENT_ID,
      clientId: config.OIDC_CLIENT_ID,
      keys,
      nonce: p.nonce,
      kind: 'id',
    });
    const atv = await validateToken(tokens.access_token, {
      issuer: config.issuer,
      audience: config.OIDC_CLIENT_ID,
      clientId: config.OIDC_CLIENT_ID,
      keys,
      kind: 'access',
    });
    if (!idv.ok || !atv.ok)
      return res.status(401).json({
        error: {
          code: idv.reason ?? atv.reason ?? 'TOKEN_INVALID',
          message: 'token validation failed',
        },
      });
    const identity = mapIdentity(atv.payload!);
    const sid = randomBytes(24).toString('base64url'); // fresh ID after login: no fixation
    sessions.set(sid, {
      id: sid,
      accessToken: tokens.access_token,
      identity,
      expiresAt: (atv.payload!.exp ?? 0) * 1000,
    });
    publish({
      type: 'sso.login',
      source: 'sso-baseline',
      correlationId: randomUUID(),
      username: identity.username,
      email: identity.email,
      name: identity.name,
      roles: identity.roles,
      claims: {
        sub: identity.subject,
        department: identity.department,
        clearance: identity.clearance,
        device_compliant: identity.deviceCompliant,
        iss: atv.payload!.iss,
        aud: atv.payload!.aud,
      },
      latencyMs: performance.now() - p.startedAt,
    });
    res.append('Set-Cookie', setCookie(SESSION_COOKIE, sid, 1800, 'Lax', config.COOKIE_SECURE));
    res.redirect(302, p.returnTo);
  });

  const session = (req: Request) => {
    const id = cookie(req.headers.cookie, SESSION_COOKIE);
    const s = id ? sessions.get(id) : undefined;
    if (s && Date.now() >= s.expiresAt) {
      sessions.delete(s.id);
      return undefined;
    }
    return s;
  };

  app.get('/sso/me', (req, res) => {
    const s = session(req);
    if (!s) return res.status(401).json({ authenticated: false });
    res.json({
      authenticated: true,
      identity: s.identity,
      expiresAt: new Date(s.expiresAt).toISOString(),
    });
  });

  app.post('/sso/logout', (req, res) => {
    const s = session(req);
    if (s) {
      sessions.delete(s.id);
      publish({
        type: 'sso.logout',
        source: 'sso-baseline',
        correlationId: randomUUID(),
        username: s.identity.username,
      });
    }
    res.append('Set-Cookie', setCookie(SESSION_COOKIE, '', 0, 'Lax', config.COOKIE_SECURE));
    const url = new URL(config.endSessionEndpoint);
    url.search = new URLSearchParams({
      client_id: config.OIDC_CLIENT_ID,
      post_logout_redirect_uri: config.POST_LOGOUT_REDIRECT_URI,
    }).toString();
    res.json({ ok: true, endSessionUrl: url.toString() });
  });

  /** Protected services behind SSO: the access token is re-validated on every request. */
  const upstreams: Record<ResourceId, string> = {
    wiki: config.UPSTREAM_WIKI_URL,
    'file-share': config.UPSTREAM_FILE_SHARE_URL,
    'admin-panel': config.UPSTREAM_ADMIN_PANEL_URL,
  };
  app.all('/sso/svc/:resource/*', async (req, res, next) => {
    try {
      const t0 = performance.now();
      const resource = req.params.resource;
      if (!isResourceId(resource))
        return res
          .status(404)
          .json({ error: { code: 'UNKNOWN_RESOURCE', message: 'unknown resource' } });
      const s = session(req);
      if (!s)
        return res.status(401).json({
          error: {
            code: 'SSO_LOGIN_REQUIRED',
            message: 'log in with Keycloak first',
            loginUrl: `/sso/login?resource=${resource}`,
          },
        });
      const original = req.originalUrl;
      if (!original.startsWith(`/sso/svc/${resource}/`)) {
        return res
          .status(400)
          .json({ error: { code: 'INVALID_PATH', message: 'non-canonical resource path' } });
      }
      const q = original.indexOf('?');
      const rawPath =
        (q === -1 ? original : original.slice(0, q)).slice(`/sso/svc/${resource}`.length) || '/';
      const checked = sanitizeUpstreamPath(rawPath, q === -1 ? '' : original.slice(q + 1));
      if (!checked.ok)
        return res.status(400).json({ error: { code: 'INVALID_PATH', message: checked.reason } });
      const v = await validateToken(s.accessToken, {
        issuer: config.issuer,
        audience: config.OIDC_CLIENT_ID,
        clientId: config.OIDC_CLIENT_ID,
        keys,
        kind: 'access',
      });
      const id = v.ok ? mapIdentity(v.payload!) : s.identity;
      const decision = v.ok
        ? evaluatePolicy(POLICIES[resource], {
            roles: id.roles,
            clearance: id.clearance,
            deviceCompliant: id.deviceCompliant,
          })
        : ({ allowed: false, reason: v.reason } as const);
      publish({
        type: 'sso.decision',
        source: 'sso-baseline',
        correlationId: randomUUID(),
        resource,
        decision: decision.allowed ? 'granted' : 'denied',
        reason: decision.allowed ? 'POLICY_SATISFIED' : String(decision.reason),
        username: id.username,
        email: id.email,
        name: id.name,
        roles: id.roles,
        clearance: id.clearance,
        department: id.department,
        deviceCompliant: id.deviceCompliant,
        jwtChecks: v.checks,
        latencyMs: performance.now() - t0,
        path: rawPath,
      });
      if (!v.ok) {
        sessions.delete(s.id);
        return res.status(401).json({
          error: { code: v.reason, message: 'access token no longer valid; log in again' },
        });
      }
      if (!decision.allowed)
        return res.status(403).json({
          error: {
            code: decision.reason,
            message: `policy not satisfied: ${POLICIES[resource].summary}`,
          },
        });
      await forward(req, res, checked.path, {
        frontDoor: 'sso-baseline',
        resource,
        upstream: upstreams[resource],
        subject: id.subject,
        display: id.username,
        assertionSecret: config.ASSERTION_SECRET_SSO,
      });
    } catch (err) {
      next(err);
    }
  });

  app.post('/sso/operator/login', (req, res) => {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    if (!timingSafeEqual(createHash('sha256').update(token).digest(), opDigest))
      return res
        .status(401)
        .json({ error: { code: 'INVALID_OPERATOR_TOKEN', message: 'invalid operator token' } });
    const id = randomBytes(24).toString('base64url');
    operatorSessions.add(id);
    res.append(
      'Set-Cookie',
      setCookie(OPERATOR_COOKIE, id, 8 * 3600, 'Strict', config.COOKIE_SECURE),
    );
    res.json({ ok: true });
  });
  app.get('/sso/operator/events', (req, res) => {
    if (!isOperator(req))
      return res
        .status(401)
        .json({ error: { code: 'OPERATOR_AUTH_REQUIRED', message: 'operator login required' } });
    res.json({ items: history.slice(-200) });
  });

  app.use((_req: Request, res: Response) =>
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'not found' } }),
  );
  app.use((_err: Error, _req: Request, res: Response, _next: NextFunction) =>
    res.status(500).json({ error: { code: 'INTERNAL', message: 'internal error' } }),
  );

  return {
    app,
    bus,
    history,
    isOperatorCookie: (h: string | undefined) => {
      const id = cookie(h, OPERATOR_COOKIE);
      return !!id && operatorSessions.has(id);
    },
  };
}
