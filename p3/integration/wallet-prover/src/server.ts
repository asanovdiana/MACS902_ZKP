/**
 * USER-SIDE prover adapter for the demo UI (stands in for "the holder's machine").
 *  - POST /v1/prover/proofs  → proof from the persona's wallet via the TEAM client library (M4)
 *  - GET  /v1/attacks, POST /v1/attacks/:id/run → the TEAM Attack Lab suite against the gateway
 * Secrets stay in the wallets on this machine; the gateway only ever receives proofs + public signals.
 */
import express, { type NextFunction, type Request, type Response } from 'express';
import { readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
import { P3_ROOT, loadAttacks, loadClient, teamAvailable, type TeamAttacks } from './team.js';

export interface ProverConfig {
  walletRoot: string;
  issuerUrl: string;
  gatewayUrl: string;
  adminToken: string;
  uiOrigins: string[];
  /**
   * Require a valid gateway operator session (cookie `zkag_operator`, checked against
   * GET {gatewayUrl}/api/operator/me) for proving and attack runs. The demo keeps persona wallets
   * server-side, so without this anyone reaching /p2 could prove as a persona. Default true.
   */
  requireOperator: boolean;
}

export function configFromEnv(env = process.env): ProverConfig {
  return {
    walletRoot: resolve(P3_ROOT, env.WALLET_ROOT ?? '.v4-demo/wallets'),
    issuerUrl: env.ISSUER_URL ?? 'http://127.0.0.1:8100',
    gatewayUrl: env.GATEWAY_URL ?? 'http://127.0.0.1:4000',
    adminToken: env.ISSUER_ADMIN_TOKEN ?? 'dev-registry-admin-token-change-me-0000',
    uiOrigins: (env.UI_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173').split(','),
    requireOperator: env.PROVER_REQUIRE_OPERATOR !== 'false',
  };
}

const field = z.string().regex(/^(0|[1-9][0-9]{0,77})$/);
const proveSchema = z
  .object({
    credentialRef: z.string().regex(/^(cred-)?[a-z][a-z0-9_-]{0,31}$/),
    variant: z.literal('honest').optional(),
    challenge: z
      .object({
        challengeId: z.string().max(64).optional(),
        profile: z.string().max(64),
        nonce: field,
        resourceField: field,
        epoch: field,
        now: field,
        policy: z
          .object({ roleMask: field, deptMask: field, minClearance: field, requireDevice: field })
          .passthrough(),
      })
      .strict(),
  })
  .strict();

/* eslint-disable @typescript-eslint/no-explicit-any */
export function createProver(cfg: ProverConfig) {
  const client = loadClient();
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));
  app.use((req: Request, res: Response, next: NextFunction) => {
    const origin = req.get('origin');
    if (origin && cfg.uiOrigins.includes(origin)) {
      res
        .set('Access-Control-Allow-Origin', origin)
        .set('Vary', 'Origin')
        .set('Access-Control-Allow-Headers', 'content-type')
        .set('Access-Control-Allow-Methods', 'GET,POST');
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
  });

  const OPERATOR_COOKIE = /(?:^|;\s*)zkag_operator=([A-Za-z0-9_-]{1,128})/;
  const requireOperator = async (req: Request, res: Response, next: NextFunction) => {
    if (!cfg.requireOperator) return next();
    const m = OPERATOR_COOKIE.exec(req.get('cookie') ?? '');
    if (m) {
      try {
        const r = await fetch(new URL('/api/operator/me', cfg.gatewayUrl), {
          headers: { cookie: `zkag_operator=${m[1]}` },
          signal: AbortSignal.timeout(2000),
        });
        if (r.ok && ((await r.json()) as { authenticated?: boolean }).authenticated === true)
          return next();
      } catch {
        /* fall through: fail closed */
      }
    }
    res.status(401).json({
      error: { code: 'OPERATOR_AUTH_REQUIRED', message: 'sign in to the demo console first' },
    });
  };

  const personas = () =>
    existsSync(cfg.walletRoot)
      ? readdirSync(cfg.walletRoot).filter((n) => /^[a-z][a-z0-9_-]{0,31}$/.test(n))
      : [];

  app.get('/v1/health', (_req, res) => {
    res.json({
      status: 'ok',
      kind: 'team-wallet-prover',
      proverReady: teamAvailable() && personas().length > 0,
      personas: personas(),
      issuerUrl: cfg.issuerUrl,
    });
  });

  app.post('/v1/prover/proofs', requireOperator, async (req, res) => {
    const parsed = proveSchema.safeParse(req.body);
    if (!parsed.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'invalid prover request' } });
    const { credentialRef, challenge } = parsed.data;
    if (challenge.profile !== 'integrated-access-v4') {
      return res.status(409).json({
        error: {
          code: 'PROFILE_UNSUPPORTED',
          message: `the team prover proves integrated_access_v4; the gateway asked for ${challenge.profile}`,
        },
      });
    }
    const name = credentialRef.replace(/^cred-/, '');
    if (!personas().includes(name))
      return res.status(404).json({
        error: { code: 'NO_WALLET', message: `no wallet for ${name}; run npm run v4:setup` },
      });
    const t0 = performance.now();
    try {
      const wallet = new client.Wallet({ home: join(cfg.walletRoot, name) });
      const credential = wallet.load(name);
      const issuer = new client.IssuerClient({ baseUrl: cfg.issuerUrl });
      const out = await client.prove({
        credential,
        issuer,
        challenge: {
          nonce: challenge.nonce,
          resourceId: Number(challenge.resourceField),
          epoch: Number(challenge.epoch),
          now: Number(challenge.now),
          policy: {
            roleMask: Number(challenge.policy.roleMask),
            deptMask: Number(challenge.policy.deptMask),
            minClearance: Number(challenge.policy.minClearance),
            requireDevice: Number(challenge.policy.requireDevice),
          },
        },
      });
      res.json({
        proof: out.proof,
        publicSignals: out.publicSignals,
        provingMs: performance.now() - t0,
        prover: { kind: 'team-client', circuit: 'integrated_access_v4', variant: 'honest' },
        bindings: { nonce: true, resource: true, epoch: true, nullifier: true },
      });
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code) {
        // ClientError: the holder's own client refuses (policy not met, expired, revoked, …): no proof exists.
        return res
          .status(422)
          .json({ error: { code, message: (e as Error).message, stage: 'client' } });
      }
      res.status(500).json({ error: { code: 'INTERNAL', message: 'prover failed' } });
    }
  });

  // ---- Team Attack Lab suite (runs as an attacker client against the gateway) ----
  let lab: TeamAttacks | null = null;
  let world: any = null;
  let running = Promise.resolve();
  const getWorld = async () => {
    lab ??= loadAttacks();
    if (!world) {
      world = await lab.createWorld({ issuerUrl: cfg.issuerUrl, adminToken: cfg.adminToken });
      world.setChallengeSource(lab.httpChallengeSource(cfg.gatewayUrl));
    }
    return { lab, world };
  };

  app.get('/v1/attacks', requireOperator, (_req, res) => {
    try {
      const l = loadAttacks();
      const catalogue = Array.isArray(l.ATTACKS)
        ? l.ATTACKS
        : Object.entries(l.ATTACKS).map(([id, a]) => ({ id, ...(a as object) }));
      res.json({ ids: l.ATTACK_IDS, attacks: catalogue });
    } catch {
      res
        .status(503)
        .json({ error: { code: 'ATTACKS_UNAVAILABLE', message: 'team attack suite not found' } });
    }
  });

  app.post('/v1/attacks/:id/run', requireOperator, async (req, res) => {
    const id = req.params.id ?? '';
    // ?waits=real: really wait (e.g. 125 s for replay_expired) against the live gateway's real clock.
    // Default: steps that need a wait are reported as skipped (the automated suite covers them with
    // an injected clock).
    const realWaits = req.query.waits === 'real';
    const job = running.then(async () => {
      const { lab: l, world: w } = await getWorld();
      if (!l.ATTACK_IDS.includes(id))
        return {
          status: 404,
          body: { error: { code: 'UNKNOWN_ATTACK', message: 'unknown attack' } },
        };
      const t0 = performance.now();
      const built = await l.buildAttack(id, w);
      const run = await l.runAttack(built, {
        send: l.httpSender(cfg.gatewayUrl),
        wait: (s: number) => w.advance(s), // remote issuer: advance() sleeps in real time
        skipWaits: !realWaits,
      });
      return {
        status: 200,
        body: {
          id,
          title: built.title,
          scope: built.scope,
          display: built.display,
          local: built.local,
          evidence: built.evidence,
          steps: run.steps,
          pass: run.pass,
          ms: performance.now() - t0,
        },
      };
    });
    running = job.then(
      () => undefined,
      () => undefined,
    ); // one attack at a time (roots move under proofs)
    try {
      const out = await job;
      res.status(out.status).json(out.body);
    } catch (e) {
      res
        .status(502)
        .json({ error: { code: 'ATTACK_FAILED', message: (e as Error).message.split('\n')[0] } });
    }
  });

  const close = async () => {
    await world?.close?.();
    await lab?.shutdown?.();
    await client.shutdown();
  };
  return { app, close };
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
  const cfg = configFromEnv();
  const { app } = createProver(cfg);
  const port = Number(process.env.PROVER_PORT ?? 4700);
  const host = process.env.PROVER_HOST ?? '127.0.0.1';
  app.listen(port, host, () =>
    console.log(
      `[wallet-prover] team client prover on http://${host}:${port} (wallets: ${cfg.walletRoot})`,
    ),
  );
}
