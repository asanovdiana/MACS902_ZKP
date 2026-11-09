/**
 * DIAGNOSTIC STAND-IN for P2 (Python FastAPI in the real project). It implements the
 * PROPOSED P2 contract in contracts/p2-registry.openapi.yaml so the gateway and UI can be
 * exercised end-to-end against the REAL P1 v3 circuit. It never issues credentials.
 */
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { timingSafeEqual } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { loadOrCreateFixtures } from './fixtures.js';
import type { FixtureFile, PersonaFixture } from './fixtures.js';
import { DiagnosticRegistry } from './registry.js';
import {
  artifactsAvailable,
  buildV3Input,
  newIssuerKey,
  proveV3,
  signCommitment,
  WitnessError,
} from './p1.js';
import type { P1Attributes } from './p1.js';

const PORT = Number(process.env.STANDIN_PORT ?? 4600);
const HOST = process.env.STANDIN_HOST ?? '127.0.0.1';
const ADMIN_TOKEN = process.env.REGISTRY_ADMIN_TOKEN ?? 'dev-registry-admin-token-change-me-0000';
const UI_ORIGINS = (process.env.UI_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173').split(
  ',',
);

const VARIANTS = ['honest', 'tamper-attributes', 'forged-issuer', 'stale-root'] as const;
const proveSchema = z
  .object({
    credentialRef: z.string().regex(/^cred-[a-z]{1,16}$/),
    variant: z.enum(VARIANTS).default('honest'),
    challenge: z
      .object({
        challengeId: z.string().max(64),
        profile: z.string().max(64),
        nonce: z.string().max(80).optional(),
        resourceField: z.string().max(80).optional(),
        epoch: z.string().max(80).optional(),
      })
      .strict(),
  })
  .strict();

function bearerOk(req: Request): boolean {
  const header = req.get('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(token);
  const b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function createStandin(fixtures: FixtureFile) {
  const registry = new DiagnosticRegistry(fixtures);
  await registry.init();
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.get('origin');
    if (origin && UI_ORIGINS.includes(origin)) {
      res.set('Access-Control-Allow-Origin', origin);
      res.set('Vary', 'Origin');
      res.set('Access-Control-Allow-Headers', 'content-type');
      res.set('Access-Control-Allow-Methods', 'GET,POST');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  });
  const requireAdmin = (req: Request, res: Response, next: NextFunction) =>
    bearerOk(req)
      ? next()
      : res
          .status(401)
          .json({ error: { code: 'UNAUTHORIZED', message: 'registry admin token required' } });

  app.get('/v1/health', (_req, res) =>
    res.json({
      status: 'ok',
      kind: 'p2-diagnostic-standin',
      contractVersion: '0.1.0-proposed',
      proverReady: artifactsAvailable(),
    }),
  );
  app.get('/v1/registry/root', (_req, res) =>
    res.json({
      ...registry.root,
      treeDepth: 2,
      hash: 'poseidon',
      encoding: 'decimal-field-element',
      source: 'p2-diagnostic-standin',
    }),
  );
  app.get('/v1/registry/history', (_req, res) => res.json({ items: registry.history }));
  app.get('/v1/registry/leaves', (_req, res) =>
    res.json({ treeDepth: 2, root: registry.root.root, leaves: registry.leafView() }),
  );
  app.get('/v1/credentials/:id/status', (req, res) => {
    const status = registry.credentialStatus(req.params.id ?? '');
    if (!status)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'unknown credential' } });
    res.json({ credentialId: req.params.id, status, root: registry.root.root });
  });
  app.post('/v1/credentials', requireAdmin, (_req, res) =>
    res.status(501).json({
      error: {
        code: 'NOT_IMPLEMENTED_BY_STANDIN',
        message:
          'Credential issuance is owned by P2 (M1). The P3 diagnostic stand-in deliberately does not issue credentials.',
      },
    }),
  );
  app.post('/v1/credentials/:id/revoke', requireAdmin, async (req, res) => {
    const ok = await registry.revoke(req.params.id ?? '');
    if (!ok)
      return res
        .status(409)
        .json({ error: { code: 'NOT_REVOCABLE', message: 'unknown or already revoked' } });
    res.json({ credentialId: req.params.id, status: 'revoked', ...registry.root });
  });
  app.post('/v1/admin/reset', requireAdmin, async (_req, res) => {
    await registry.reset();
    res.json({ ok: true, ...registry.root });
  });

  /**
   * User-side prover (stand-in for P2's M4 client). Generates a REAL Groth16 proof with
   * the P1 v3 circuit. Note: P1 v3 has no nonce/resource/epoch inputs, so the challenge
   * cannot be bound into the proof; we report that explicitly in `bindings`.
   */
  app.post('/v1/prover/proofs', async (req, res) => {
    const parsed = proveSchema.safeParse(req.body);
    if (!parsed.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'invalid prover request' } });
    const { credentialRef, variant, challenge } = parsed.data;
    if (challenge.profile !== 'p1-integrated-v3') {
      return res.status(409).json({
        error: {
          code: 'PROFILE_UNSUPPORTED',
          message: `stand-in prover only supports p1-integrated-v3, gateway asked for ${challenge.profile}`,
        },
      });
    }
    if (!artifactsAvailable())
      return res
        .status(503)
        .json({ error: { code: 'ARTIFACTS_MISSING', message: 'run npm run p1:build' } });
    const persona = fixtures.personas.find((p) => p.credentialId === credentialRef);
    if (!persona)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'unknown credential' } });
    if (registry.credentialStatus(persona.credentialId) === 'revoked' && variant !== 'stale-root') {
      return res.status(422).json({
        error: {
          code: 'WITNESS_UNSATISFIABLE',
          message:
            'credential leaf is no longer in the current tree — a membership proof cannot be generated',
        },
      });
    }
    try {
      const input = await witnessFor(persona, variant, fixtures, registry);
      const { proof, publicSignals, provingMs } = await proveV3(input);
      res.json({
        proof,
        publicSignals,
        provingMs,
        prover: { kind: 'p2-diagnostic-standin', circuit: 'integrated_access_v3', variant },
        bindings: { nonce: false, resource: false, epoch: false, nullifier: false },
      });
    } catch (err) {
      if (err instanceof WitnessError) {
        return res.status(422).json({
          error: {
            code: 'WITNESS_UNSATISFIABLE',
            message: `circuit constraints not satisfiable: ${err.message}`,
          },
        });
      }
      throw err;
    }
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[p2-standin] error', err instanceof Error ? err.message : err);
    res.status(500).json({ error: { code: 'INTERNAL', message: 'internal error' } });
  });
  return { app, registry };
}

async function witnessFor(
  persona: PersonaFixture,
  variant: (typeof VARIANTS)[number],
  fixtures: FixtureFile,
  registry: DiagnosticRegistry,
) {
  let attributes: P1Attributes = persona.attributes;
  let issuer: { Ax: string; Ay: string } = fixtures.devIssuer;
  let signature = persona.signature;
  let leaves = registry.currentLeaves;
  if (variant === 'tamper-attributes') {
    // Attack 3: holder edits its own attributes to admin / clearance 3 without re-issuance.
    attributes = { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 };
  } else if (variant === 'forged-issuer') {
    // Attack 4: holder signs its own commitment with a self-generated (untrusted) key.
    const rogue = await newIssuerKey();
    issuer = rogue;
    signature = await signCommitment(rogue, BigInt(persona.commitment));
  } else if (variant === 'stale-root') {
    // Attack 2: revoked holder replays its cached Merkle path from before revocation.
    leaves = registry.initialLeaves;
  }
  return buildV3Input({
    secret: BigInt(persona.secret),
    salt: BigInt(persona.salt),
    attributes,
    issuer,
    signature,
    leaves,
    index: persona.slot,
  });
}

const isEntry = (() => {
  try {
    return (
      realpathSync(fileURLToPath(import.meta.url)) === realpathSync(resolve(process.argv[1] ?? ''))
    );
  } catch {
    return false;
  }
})();
if (isEntry) {
  const fixtures = await loadOrCreateFixtures();
  const { app } = await createStandin(fixtures);
  app.listen(PORT, HOST, () => {
    console.log(
      `[p2-standin] DIAGNOSTIC P2 stand-in on http://${HOST}:${PORT} (artifacts ready: ${artifactsAvailable()})`,
    );
  });
}
