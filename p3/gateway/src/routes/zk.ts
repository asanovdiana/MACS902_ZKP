import { Router } from 'express';
import { POLICIES, RESOURCES, policyPublicParams } from '@zkag/shared';
import type { GatewayContext } from '../app/createApp.js';
import { challengeRequestSchema } from '../verification/schema.js';
import { correlationId } from '../utils/ids.js';
import { sessionCookieName } from '../sessions/sessions.js';
import { serializeCookie } from '../utils/cookies.js';

export function zkRoutes(ctx: GatewayContext) {
  const r = Router();

  /** Issue a fresh one-time challenge. Only public data is returned. */
  r.post('/challenges', (req, res) => {
    const parsed = challengeRequestSchema.safeParse(req.body);
    if (!parsed.success)
      return res.status(400).json({
        error: {
          code: 'INVALID_REQUEST',
          message: 'resource must be one of wiki, file-share, admin-panel',
        },
      });
    const { resource } = parsed.data;
    const challenge = ctx.challenges.create(resource, ctx.profile.id);
    if (!challenge)
      return res.status(503).json({
        error: { code: 'CHALLENGE_CAPACITY', message: 'too many outstanding challenges' },
      });
    const p = policyPublicParams(POLICIES[resource]);
    const cid = correlationId();
    ctx.bus.publish({
      type: 'challenge.created',
      source: 'zk-gateway',
      correlationId: cid,
      resource,
      challengeId: challenge.id,
      nonce: challenge.nonce,
      epoch: challenge.epoch,
      expiresAt: new Date(challenge.expiresAt).toISOString(),
      profile: ctx.profile.id,
    });
    res.status(201).json({
      challengeId: challenge.id,
      nonce: challenge.nonce,
      resource,
      resourceField: RESOURCES[resource].fieldId.toString(),
      epoch: challenge.epoch,
      issuedAt: new Date(challenge.createdAt).toISOString(),
      expiresAt: new Date(challenge.expiresAt).toISOString(),
      policy: {
        summary: POLICIES[resource].summary,
        roleMask: p.roleMask.toString(),
        deptMask: p.deptMask.toString(),
        minClearance: p.minClearance.toString(),
        requireDevice: p.requireDevice.toString(),
      },
      scheme: {
        proofSystem: 'groth16',
        curve: 'bn128',
        profile: ctx.profile.id,
        publicSignals: ctx.profile.signals,
      },
      correlationId: cid,
    });
  });

  /** Verify a proof against a challenge; issues a resource-scoped session only when fully authorized. */
  r.post('/verify', async (req, res, next) => {
    try {
      const outcome = await ctx.pipeline.verify(req.body);
      if (outcome.session) {
        const s = outcome.session;
        // Fresh random session ID on every grant (no fixation); cookie scoped to the resource path.
        res.append(
          'Set-Cookie',
          serializeCookie(sessionCookieName(s.resource), s.id, {
            path: `/svc/${s.resource}`,
            maxAgeSeconds: ctx.config.SESSION_TTL_SECONDS,
            secure: ctx.config.COOKIE_SECURE,
          }),
        );
      }
      res.set('Cache-Control', 'no-store');
      res.status(outcome.status).json(outcome.body);
    } catch (err) {
      next(err);
    }
  });

  return r;
}
