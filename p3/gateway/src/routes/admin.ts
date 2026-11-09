import { Router, type Response } from 'express';
import { z } from 'zod';
import type { GatewayContext } from '../app/createApp.js';
import { RegistryUnavailableError } from '../registry/registryClient.js';
import { correlationId } from '../utils/ids.js';

const credentialId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const issueSchema = z
  .object({
    role: z.enum(['engineer', 'admin', 'contractor', 'finance']),
    dept: z.enum(['engineering', 'operations', 'finance', 'sales']),
    clearance: z.number().int().min(0).max(3),
    deviceCompliant: z.boolean(),
    expiry: z.string().datetime(),
    secretCommitment: z.string().regex(/^(0|[1-9][0-9]{0,77})$/),
  })
  .strict();

/**
 * Operator-only administration. Credential issuance and revocation are DELEGATED to P2
 * over the documented HTTP contract; the gateway never issues or signs credentials.
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
    const out: Record<string, unknown> = { gatewayRootHistory: ctx.rootHistory };
    try {
      out.current = await ctx.registry.getCurrentRoot({ maxAgeMs: 0 });
    } catch (err) {
      return unavailable(res, err);
    }
    for (const [key, path] of [
      ['leaves', '/v1/registry/leaves'],
      ['history', '/v1/registry/history'],
    ] as const) {
      try {
        const r2 = await ctx.registry.adminRequest('GET', path);
        out[key] = r2.status === 200 ? r2.body : { unavailable: true, status: r2.status };
      } catch {
        out[key] = { unavailable: true };
      }
    }
    res.json(out);
  });

  r.post('/credentials', async (req, res) => {
    const parsed = issueSchema.safeParse(req.body);
    if (!parsed.success)
      return res.status(400).json({
        error: { code: 'INVALID_REQUEST', message: parsed.error.issues[0]?.message ?? 'invalid' },
      });
    try {
      const up = await ctx.registry.adminRequest('POST', '/v1/credentials', parsed.data);
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
      const up = await ctx.registry.adminRequest(
        'GET',
        `/v1/credentials/${encodeURIComponent(id.data)}/status`,
      );
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
      const up = await ctx.registry.adminRequest(
        'POST',
        `/v1/credentials/${encodeURIComponent(id.data)}/revoke`,
        {},
      );
      let root: string | null = null;
      if (up.status === 200) {
        root = (await ctx.registry.getCurrentRoot({ maxAgeMs: 0 })).root; // triggers root.changed + session invalidation
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

  /** Demo reset: clears gateway state and asks the registry (if it supports it) to reset. */
  r.post('/demo/reset', async (_req, res) => {
    ctx.challenges.clear();
    ctx.nullifiers.clear();
    ctx.sessions.clear();
    let registryReset: unknown = 'unsupported';
    try {
      const up = await ctx.registry.adminRequest('POST', '/v1/admin/reset', {});
      registryReset = up.status === 200 ? 'ok' : `status ${up.status}`;
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
      ...(s.status === 'ready' ? { circuitId: s.manifest.circuitId } : { detail: s.detail }),
    });
  });
  return r;
}
