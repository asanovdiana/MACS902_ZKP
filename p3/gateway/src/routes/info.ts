import { Router } from 'express';
import { existsSync, readFileSync } from 'node:fs';
import { POLICIES, RESOURCES, RESOURCE_IDS, policyPublicParams } from '@zkag/shared';
import type { GatewayContext } from '../app/createApp.js';
import { readiness } from './health.js';
import { CAPABILITY_LABELS, REQUIRED_CAPABILITIES } from '../verification/profiles.js';

export function publicInfoRoutes(ctx: GatewayContext) {
  const r = Router();
  r.get('/status', async (_req, res) => {
    const ready = await readiness(ctx);
    const art = ctx.artifacts();
    res.json({
      mode: ctx.profile.id === 'p1-integrated-v3' ? 'diagnostic-p1' : 'real-integration',
      zkAuthorization: ready.zkAuthorization,
      components: ready.components,
      profile: {
        id: ctx.profile.id,
        title: ctx.profile.title,
        signals: ctx.profile.signals,
        notes: ctx.profile.notes,
        capabilities: REQUIRED_CAPABILITIES.map((c) => ({
          id: c,
          label: CAPABILITY_LABELS[c],
          supported: ctx.profile.capabilities[c],
        })),
      },
      artifacts:
        art.status === 'ready'
          ? {
              status: art.status,
              circuitId: art.manifest.circuitId,
              version: art.manifest.version,
              securityStatus: art.manifest.securityStatus,
              trustedSetup: art.manifest.trustedSetup ?? null,
              trust: art.trust,
              vkeySha256: art.vkeySha256,
              reviewed: art.reviewed,
            }
          : { status: art.status, detail: art.detail },
      settings: {
        sessionTtlSeconds: ctx.config.SESSION_TTL_SECONDS,
        challengeTtlSeconds: ctx.config.CHALLENGE_TTL_SECONDS,
        epochSeconds: ctx.config.EPOCH_SECONDS,
        nullifierMaxPerEpoch: ctx.config.NULLIFIER_MAX_PER_EPOCH,
        rootCacheMs: ctx.config.ROOT_CACHE_MS,
        registryApi: ctx.config.REGISTRY_API,
        issuerPinned: ctx.config.trustedIssuer !== null,
        demoKeysAllowed: ctx.config.ALLOW_DEMO_KEYS,
      },
      devSecretsInUse: ctx.config.usingDevSecrets.length > 0,
    });
  });
  r.get('/policies', (_req, res) => {
    res.json({
      items: RESOURCE_IDS.map((id) => {
        const p = policyPublicParams(POLICIES[id]);
        return {
          resource: id,
          name: RESOURCES[id].name,
          description: RESOURCES[id].description,
          resourceField: RESOURCES[id].fieldId.toString(),
          summary: POLICIES[id].summary,
          allowedRoles: POLICIES[id].allowedRoles,
          minClearance: POLICIES[id].minClearance,
          requireDeviceCompliant: POLICIES[id].requireDeviceCompliant,
          proposedPublicParams: {
            roleMask: p.roleMask.toString(),
            deptMask: p.deptMask.toString(),
            minClearance: p.minClearance.toString(),
            requireDevice: p.requireDevice.toString(),
          },
          supportedByActiveCircuit: ctx.profile.policyCoverage.includes(id),
        };
      }),
    });
  });
  r.get('/evidence/p1-audit', (_req, res) => {
    if (!existsSync(ctx.config.auditReportFile))
      return res
        .status(404)
        .json({ error: { code: 'NOT_FOUND', message: 'run npm run p1:audit' } });
    const report = JSON.parse(readFileSync(ctx.config.auditReportFile, 'utf8'));
    res.json({
      generatedAt: report.generatedAt,
      circuit: report.circuit,
      summary: report.summary,
      findings: report.findings,
      trustedSetup: report.trustedSetup,
    });
  });
  r.get('/bench/results', (_req, res) => {
    if (!existsSync(ctx.config.benchResultsFile))
      return res.status(404).json({
        error: { code: 'NO_RESULTS', message: 'no benchmark results yet: run make bench' },
      });
    res.type('application/json').send(readFileSync(ctx.config.benchResultsFile, 'utf8'));
  });
  return r;
}
