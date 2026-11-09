import { Router, type Request, type Response } from 'express';
import { forward, isResourceId, sanitizeUpstreamPath, type ResourceId } from '@zkag/shared';
import type { GatewayContext } from '../app/createApp.js';
import { sessionCookieName } from '../sessions/sessions.js';
import { clearCookie, readCookie } from '../utils/cookies.js';
import { correlationId } from '../utils/ids.js';

/**
 * /svc/:resource/* — the ONLY route to protected services through the ZK gateway.
 * Upstreams come exclusively from configuration; the client can only select one of the
 * three fixed resource IDs, never a host, port or scheme.
 */
export function serviceProxyRoutes(ctx: GatewayContext) {
  const upstreams: Record<ResourceId, string> = {
    wiki: ctx.config.UPSTREAM_WIKI_URL,
    'file-share': ctx.config.UPSTREAM_FILE_SHARE_URL,
    'admin-panel': ctx.config.UPSTREAM_ADMIN_PANEL_URL,
  };
  const r = Router();

  const resolveSession = async (req: Request, res: Response, resource: ResourceId) => {
    const sid = readCookie(req.headers.cookie, sessionCookieName(resource));
    const found = ctx.sessions.lookup(sid, resource);
    if (!found.ok) {
      res.status(401).json({
        error: {
          code: found.reason,
          message: 'a valid ZK session for this resource is required',
        },
      });
      return null;
    }
    // Revocation: re-check the authoritative root (bounded by ROOT_CACHE_MS staleness).
    try {
      const snap = await ctx.registry.getCurrentRoot();
      if (
        snap.root !== found.session.root &&
        !(await ctx.registry.sessionRootValid(found.session.root))
      ) {
        ctx.sessions.revoke(found.session.id);
        res.append(
          'Set-Cookie',
          clearCookie(sessionCookieName(resource), `/svc/${resource}`, ctx.config.COOKIE_SECURE),
        );
        res.status(401).json({
          error: {
            code: 'SESSION_REVOKED_ROOT_CHANGED',
            message: 'a credential was revoked since authorization; prove again',
          },
        });
        return null;
      }
    } catch {
      res.status(503).json({
        error: {
          code: 'REGISTRY_UNAVAILABLE',
          message: 'cannot confirm registry state; failing closed',
        },
      });
      return null;
    }
    return found.session;
  };

  r.get('/:resource/_zkag/session', async (req, res) => {
    const resource = req.params.resource;
    if (!isResourceId(resource))
      return res
        .status(404)
        .json({ error: { code: 'UNKNOWN_RESOURCE', message: 'unknown resource' } });
    const s = await resolveSession(req, res, resource);
    if (s) res.json({ resource, expiresAt: new Date(s.expiresAt).toISOString() });
  });

  r.post('/:resource/_zkag/logout', (req, res) => {
    const resource = req.params.resource;
    if (!isResourceId(resource))
      return res
        .status(404)
        .json({ error: { code: 'UNKNOWN_RESOURCE', message: 'unknown resource' } });
    const sid = readCookie(req.headers.cookie, sessionCookieName(resource));
    const s = sid ? ctx.sessions.revoke(sid) : undefined;
    if (s)
      ctx.bus.publish({
        type: 'session.revoked',
        source: 'zk-gateway',
        correlationId: correlationId(),
        resource,
        reason: 'LOGOUT',
      });
    res.append(
      'Set-Cookie',
      clearCookie(sessionCookieName(resource), `/svc/${resource}`, ctx.config.COOKIE_SECURE),
    );
    res.json({ ok: true });
  });

  r.all('/:resource/*', async (req, res, next) => {
    try {
      const resource = req.params.resource;
      if (!isResourceId(resource))
        return res
          .status(404)
          .json({ error: { code: 'UNKNOWN_RESOURCE', message: 'unknown resource' } });
      const original = req.originalUrl;
      // The raw URL must literally start with the canonical prefix (no encoded resource segment).
      if (!original.startsWith(`/svc/${resource}/`)) {
        return res
          .status(400)
          .json({ error: { code: 'INVALID_PATH', message: 'non-canonical resource path' } });
      }
      const qIndex = original.indexOf('?');
      const rawPath =
        (qIndex === -1 ? original : original.slice(0, qIndex)).slice(`/svc/${resource}`.length) ||
        '/';
      const rawQuery = qIndex === -1 ? '' : original.slice(qIndex + 1);
      const checked = sanitizeUpstreamPath(rawPath, rawQuery);
      if (!checked.ok)
        return res.status(400).json({ error: { code: 'INVALID_PATH', message: checked.reason } });
      const session = await resolveSession(req, res, resource);
      if (!session) return;
      const status = await forward(req, res, checked.path, {
        frontDoor: 'zk-gateway',
        resource,
        upstream: upstreams[resource],
        subject: session.pseudonym,
        display: 'Anonymous credential holder',
        assertionSecret: ctx.config.ASSERTION_SECRET_ZK,
      });
      ctx.bus.publish({
        type: 'proxy.forwarded',
        source: 'zk-gateway',
        correlationId: correlationId(),
        resource,
        method: req.method,
        path: rawPath,
        status,
      });
    } catch (err) {
      next(err);
    }
  });
  return r;
}
