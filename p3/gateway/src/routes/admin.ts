import { Router, type Response } from 'express';
import { z } from 'zod';
import type { GatewayContext } from '../app/createApp.js';
import { RegistryUnavailableError } from '../registry/index.js';
import { correlationId } from '../utils/ids.js';

const credentialId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
/** Team enrolment (issuer.admin v1.1): the admin assigns attributes; the employee redeems a one-time code. */
const enrolSchema = z
  .object({
    employeeId: z.string().regex(/^[A-Za-z0-9._@-]{1,64}$/),
    attributes: z
      .object({
        role: z.number().int().min(0).max(3),
        dept: z.number().int().min(0).max(3),
        clearance: z.number().int().min(0).max(3),
        deviceCompliant: z.union([z.literal(0), z.literal(1)]),
        employeeActive: z.union([z.literal(0), z.literal(1)]),
        expiry: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
      })
      .strict(),
    ttlSeconds: z.number().int().min(60).max(604800).optional(),
  })
  .strict();
/** P3 stand-in issuance body (kept for the diagnostic profile). */
const standinIssueSchema = z.object({}).passthrough();

/**
 * Operator-only administration. Issuance and revocation are DELEGATED to P2's issuer over its HTTP
 * contract; the gateway never signs credentials and never sees attributes after enrolment.
 */
export function adminRoutes(ctx: GatewayContext) {
  const r = Router();
  const unavailable = (res: Response, err: unknown) =>
    res.status(503).json({
      error: {
        code: err instanceof RegistryUnavailableError ? err.code : 'REGISTRY_ERROR',
        message: 'P2 registry/issuer unavailable',
      },
    });

  r.get('/registry', async (_req, res) => {
    try {
      const current = await ctx.registry.getCurrentRoot({ maxAgeMs: 0 });
      const [leaves, history] = await Promise.all([
        ctx.registry.listLeaves().catch(() => null),
        ctx.registry.rootHistory().catch(() => null),
      ]);
      res.json({
        api: ctx.registry.api,
        current,
        leaves: leaves
          ? { treeDepth: leaves.treeDepth, root: current.root, leaves: leaves.leaves }
          : { unavailable: true },
        history: history ? { items: history } : { unavailable: true },
        gatewayRootHistory: ctx.rootHistory,
      });
    } catch (err) {
      unavailable(res, err);
    }
  });

  r.post('/credentials', async (req, res) => {
    const parsed =
      ctx.registry.api === 'issuer-v1'
        ? enrolSchema.safeParse(req.body)
        : standinIssueSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: parsed.error.issues[0]?.message ?? 'invalid' },
      });
    }
    try {
      const up = await ctx.registry.issue(parsed.data);
      res.status(up.status).json(up.body);
    } catch (err) {
      unavailable(res, err);
    }
  });

  r.get('/credentials/:id/status', async (req, res) => {
    const id = credentialId.safeParse(req.params.id);
    if (!id.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'invalid credential id' } });
    try {
      const up = await ctx.registry.credentialStatus(id.data);
      res.status(up.status).json(up.body);
    } catch (err) {
      unavailable(res, err);
    }
  });

  r.post('/credentials/:id/revoke', async (req, res) => {
    const id = credentialId.safeParse(req.params.id);
    if (!id.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'invalid credential id' } });
    try {
      const up = await ctx.registry.revoke(id.data);
      if (up.status === 200) {
        const root = (await ctx.registry.getCurrentRoot({ maxAgeMs: 0 })).root; // root.changed + session invalidation
        ctx.bus.publish({
          type: 'credential.revoked',
          source: 'registry',
          correlationId: correlationId(),
          credentialId: id.data,
          root,
        });
      }
      res.status(up.status).json(up.body);
    } catch (err) {
      unavailable(res, err);
    }
  });

  /** Demo reset: clears gateway state; asks the registry to reset only if it supports it. */
  r.post('/demo/reset', async (_req, res) => {
    ctx.challenges.clear();
    ctx.nullifiers.clear();
    ctx.sessions.clear();
    let registryReset = 'not supported (revocation is permanent in the team issuer)';
    try {
      const up = await ctx.registry.reset();
      if (up) registryReset = up.status === 200 ? 'ok' : `status ${up.status}`;
      await ctx.registry.getCurrentRoot({ maxAgeMs: 0 });
    } catch {
      registryReset = 'registry unavailable';
    }
    ctx.bus.clear();
    res.json({ ok: true, registryReset });
  });

  r.post('/artifacts/reload', (_req, res) => {
    const s = ctx.reloadArtifacts();
    res.json({
      status: s.status,
      ...(s.status === 'ready'
        ? { circuitId: s.manifest.circuitId, trust: s.trust }
        : { detail: s.detail }),
    });
  });
  return r;
}
