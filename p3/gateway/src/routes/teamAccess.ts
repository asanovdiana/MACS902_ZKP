import { Router } from 'express';
import { z } from 'zod';
import { POLICIES, RESOURCES, policyPublicParams, type ResourceId } from '@zkag/shared';
import type { GatewayContext } from '../app/createApp.js';
import { sessionCookieName } from '../sessions/sessions.js';
import { serializeCookie } from '../utils/cookies.js';
import { correlationId } from '../utils/ids.js';
import { TEAM_CODES, type TeamCode } from '../verification/pipeline.js';

/**
 * The team client's protocol (client/src/challenge.js, client/attacks/src/runner.js):
 *   GET  /challenge?resource=<wiki|file_share|admin_panel> → {nonce, resourceId, epoch, now, policy}
 *   POST /access {resource, nonce, proof, publicSignals}    → 2xx admitted | 4xx {error:{code}}
 * Both are thin adapters over the same challenge store and verification pipeline as /api/zk/*.
 */
const TEAM_RESOURCE: Record<string, ResourceId> = {
  wiki: 'wiki',
  file_share: 'file-share',
  admin_panel: 'admin-panel',
};

const accessSchema = z
  .object({
    resource: z.string().max(32),
    nonce: z.string().regex(/^(0|[1-9][0-9]{0,77})$/),
    proof: z.unknown(),
    publicSignals: z.unknown(),
  })
  .strict();

const fail = (code: TeamCode, message: string) => ({
  status: TEAM_CODES[code],
  body: { error: { code, message } },
});

export function teamAccessRoutes(ctx: GatewayContext) {
  const r = Router();

  r.get('/challenge', (req, res) => {
    const resource =
      typeof req.query.resource === 'string' ? TEAM_RESOURCE[req.query.resource] : undefined;
    if (!resource) {
      const f = fail('UNKNOWN_RESOURCE', 'resource must be wiki, file_share or admin_panel');
      return res.status(f.status).json(f.body);
    }
    const c = ctx.challenges.create(resource, ctx.profile.id);
    if (!c)
      return res.status(503).json({
        error: { code: 'AUTHORIZATION_UNAVAILABLE', message: 'too many outstanding challenges' },
      });
    ctx.bus.publish({
      type: 'challenge.created',
      source: 'zk-gateway',
      correlationId: correlationId(),
      resource,
      challengeId: c.id,
      nonce: c.nonce,
      epoch: c.epoch,
      expiresAt: new Date(c.expiresAt).toISOString(),
      profile: ctx.profile.id,
    });
    const p = policyPublicParams(POLICIES[resource]);
    res.set('Cache-Control', 'no-store');
    // Exactly the five fields the client accepts (it rejects unknown keys).
    res.json({
      nonce: c.nonce,
      resourceId: Number(RESOURCES[resource].fieldId),
      epoch: Number(c.epoch),
      now: Number(c.now),
      policy: {
        roleMask: Number(p.roleMask),
        deptMask: Number(p.deptMask),
        minClearance: Number(p.minClearance),
        requireDevice: Number(p.requireDevice),
      },
    });
  });

  r.post('/access', async (req, res, next) => {
    try {
      res.set('Cache-Control', 'no-store');
      const parsed = accessSchema.safeParse(req.body);
      if (!parsed.success) {
        const f = fail('MALFORMED_REQUEST', 'body must be {resource, nonce, proof, publicSignals}');
        return res.status(f.status).json(f.body);
      }
      const resource = TEAM_RESOURCE[parsed.data.resource];
      if (!resource) {
        const f = fail('UNKNOWN_RESOURCE', 'no such service');
        return res.status(f.status).json(f.body);
      }
      const challengeId = ctx.challenges.idForNonce(parsed.data.nonce);
      if (!challengeId) {
        const f = fail('NONCE_UNKNOWN', 'nonce was not issued by this gateway');
        return res.status(f.status).json(f.body);
      }
      const out = await ctx.pipeline.verify(
        { challengeId, proof: parsed.data.proof, publicSignals: parsed.data.publicSignals },
        resource,
      );
      if (out.session) {
        res.append(
          'Set-Cookie',
          serializeCookie(sessionCookieName(resource), out.session.id, {
            path: `/svc/${resource}`,
            maxAgeSeconds: ctx.config.SESSION_TTL_SECONDS,
            secure: ctx.config.COOKIE_SECURE,
          }),
        );
        return res.status(200).json({
          admitted: true,
          resource: parsed.data.resource,
          sessionExpiresAt: out.body.session?.expiresAt,
          correlationId: out.body.correlationId,
        });
      }
      const code = out.body.code ?? 'MALFORMED_REQUEST';
      res.status(TEAM_CODES[code]).json({
        error: { code, message: out.body.message, reason: out.body.reason },
        correlationId: out.body.correlationId,
      });
    } catch (err) {
      next(err);
    }
  });
  return r;
}
