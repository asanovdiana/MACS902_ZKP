import { Router } from 'express';
import type { GatewayContext } from '../app/createApp.js';

async function probe(url: string, timeoutMs = 1500): Promise<boolean> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, redirect: 'manual' });
    return res.status < 500;
  } catch {
    return false;
  } finally {
    clearTimeout(t);
  }
}

export async function readiness(ctx: GatewayContext) {
  const art = ctx.artifacts();
  const registry = await ctx.registry.health();
  const elig = ctx.pipeline.authorizationEligible();
  const [ssoBaseline, keycloak] = await Promise.all([
    probe(new URL('/sso/health', ctx.config.SSO_GATEWAY_URL).toString()),
    probe(new URL('/sso/health/keycloak', ctx.config.SSO_GATEWAY_URL).toString()).then(
      async (ok) => {
        if (!ok) return false;
        try {
          const r = await fetch(new URL('/sso/health/keycloak', ctx.config.SSO_GATEWAY_URL));
          return ((await r.json()) as { keycloak?: boolean }).keycloak === true;
        } catch {
          return false;
        }
      },
    ),
  ]);
  const components = {
    process: { ok: true },
    gateway: { ok: true },
    artifacts: {
      ok: art.status === 'ready',
      detail:
        art.status === 'ready' ? `${art.manifest.circuitId} (${art.manifest.version})` : art.detail,
    },
    registry: { ok: registry.ok, detail: registry.detail },
    cryptographicIntegration: { ok: elig.eligible, profile: ctx.profile.id, missing: elig.missing },
    ssoBaseline: { ok: ssoBaseline },
    keycloak: { ok: keycloak },
  };
  const zkAuthorization = elig.eligible && registry.ok ? 'ready' : 'blocked';
  return {
    status: zkAuthorization === 'ready' ? 'ready' : 'degraded',
    zkAuthorization,
    components,
  };
}

export function healthRoutes(ctx: GatewayContext) {
  const r = Router();
  /** Liveness: the process is running. */
  r.get('/healthz', (_req, res) => res.json({ status: 'ok' }));
  /** Readiness: 200 only when real ZK authorization can be performed end to end. */
  r.get('/readyz', async (_req, res) => {
    const result = await readiness(ctx);
    res.status(result.status === 'ready' ? 200 : 503).json(result);
  });
  return r;
}
