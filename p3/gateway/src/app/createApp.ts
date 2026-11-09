import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pino, { type Logger } from 'pino';
import { pinoHttp } from 'pino-http';
import type { Config } from '../config/env.js';
import { EventBus } from '../events/bus.js';
import { HttpRegistryClient, type RegistryClient } from '../registry/registryClient.js';
import { ChallengeStore } from '../security/challenges.js';
import { NullifierStore } from '../security/nullifiers.js';
import { OperatorAuth } from '../security/operator.js';
import { originGuard, requireJson } from '../security/origin.js';
import { SessionStore } from '../sessions/sessions.js';
import { systemClock, type Clock } from '../utils/clock.js';
import { correlationId } from '../utils/ids.js';
import { loadArtifacts, type ArtifactState } from '../verification/artifacts.js';
import { SnarkjsGroth16Verifier, type Groth16Verifier } from '../verification/groth16.js';
import { VerificationPipeline } from '../verification/pipeline.js';
import { PROFILES, type CircuitProfile } from '../verification/profiles.js';
import { healthRoutes } from '../routes/health.js';
import { zkRoutes } from '../routes/zk.js';
import { operatorRoutes } from '../routes/operator.js';
import { adminRoutes } from '../routes/admin.js';
import { serviceProxyRoutes } from '../routes/serviceProxy.js';
import { publicInfoRoutes } from '../routes/info.js';

export interface AppDeps {
  config: Config;
  clock?: Clock;
  logger?: Logger;
  registry?: RegistryClient;
  /**
   * TEST SEAMS ONLY. Production code (server.ts) never passes these; they cannot be selected
   * through configuration. They allow unit tests to exercise the session/proxy path for a
   * fully-capable profile before P1 delivers such a circuit.
   */
  testOverrides?: {
    verifier?: Groth16Verifier;
    profile?: CircuitProfile;
    artifacts?: () => ArtifactState;
  };
}

export type GatewayContext = ReturnType<typeof buildContext>;

function buildContext(deps: AppDeps) {
  const { config } = deps;
  const clock = deps.clock ?? systemClock;
  const logger =
    deps.logger ??
    pino({
      level: config.LOG_LEVEL,
      redact: {
        paths: [
          'req.headers.cookie',
          'req.headers.authorization',
          'res.headers["set-cookie"]',
          '*.token',
          '*.secret',
        ],
        censor: '[redacted]',
      },
    });
  const profile = deps.testOverrides?.profile ?? PROFILES[config.ZK_PROFILE];
  let artifactState = loadArtifacts(config.artifactDir, profile);
  const artifacts = deps.testOverrides?.artifacts ?? (() => artifactState);
  const reloadArtifacts = () => {
    artifactState = loadArtifacts(config.artifactDir, profile);
    return artifactState;
  };
  const bus = new EventBus();
  const registry =
    deps.registry ??
    new HttpRegistryClient(
      config.REGISTRY_URL,
      config.REGISTRY_ADMIN_TOKEN,
      config.REGISTRY_TIMEOUT_MS,
      config.ROOT_CACHE_MS,
      clock,
    );
  const challenges = new ChallengeStore(
    clock,
    config.CHALLENGE_TTL_SECONDS * 1000,
    config.EPOCH_SECONDS * 1000,
    config.MAX_OUTSTANDING_CHALLENGES,
  );
  const nullifiers = new NullifierStore(config.NULLIFIER_MAX_PER_EPOCH);
  const sessions = new SessionStore(clock, config.SESSION_TTL_SECONDS * 1000);
  const operator = new OperatorAuth(config.OPERATOR_TOKEN, clock);
  const verifier = deps.testOverrides?.verifier ?? new SnarkjsGroth16Verifier();
  const pipeline = new VerificationPipeline({
    config,
    profile,
    artifacts,
    registry,
    challenges,
    nullifiers,
    sessions,
    verifier,
    bus,
    clock,
  });
  const rootHistory: Array<{ root: string; version: string | null; observedAt: string }> = [];

  registry.onRootChange((prev, next) => {
    rootHistory.unshift({
      root: next.root,
      version: next.version,
      observedAt: new Date(clock.now()).toISOString(),
    });
    rootHistory.splice(50);
    bus.publish({
      type: 'root.changed',
      source: 'registry',
      correlationId: correlationId(),
      previousRoot: prev?.root ?? null,
      root: next.root,
      version: next.version,
    });
    // Revocation semantics: sessions issued under any other root are invalidated immediately.
    for (const s of sessions.revokeStaleRoots(next.root)) {
      bus.publish({
        type: 'session.revoked',
        source: 'zk-gateway',
        correlationId: correlationId(),
        resource: s.resource,
        reason: 'REGISTRY_ROOT_CHANGED',
      });
    }
  });

  return {
    config,
    clock,
    logger,
    profile,
    artifacts,
    reloadArtifacts,
    bus,
    registry,
    challenges,
    nullifiers,
    sessions,
    operator,
    verifier,
    pipeline,
    rootHistory,
  };
}

export function createApp(deps: AppDeps) {
  const ctx = buildContext(deps);
  const { config } = ctx;
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.TRUST_PROXY === 'false' ? false : config.TRUST_PROXY);
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: { defaultSrc: ["'self'"], frameAncestors: ["'none'"], objectSrc: ["'none'"] },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  app.use(
    pinoHttp({
      logger: ctx.logger,
      genReqId: () => correlationId(),
      serializers: {
        req: (r: { method: string; url: string; id: string }) => ({
          id: r.id,
          method: r.method,
          url: r.url.split('?')[0],
        }),
        res: (r: { statusCode: number }) => ({ statusCode: r.statusCode }),
      },
      autoLogging: { ignore: (req) => req.url === '/healthz' },
    }),
  );
  app.use(express.json({ limit: '32kb', strict: true }));
  app.use(originGuard(config.allowedOrigins));

  const limited = (_req: Request, res: Response) =>
    res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'too many requests' } });
  const zkLimiter = rateLimit({
    windowMs: 60_000,
    limit: config.ZK_RATE_LIMIT_PER_MIN,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: limited,
  });
  const loginLimiter = rateLimit({
    windowMs: 60_000,
    limit: 10,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: limited,
  });

  app.use(healthRoutes(ctx));
  app.use('/api', requireJson);
  app.use('/api', publicInfoRoutes(ctx));
  app.use('/api/zk', zkLimiter, zkRoutes(ctx));
  app.use('/api/operator', operatorRoutes(ctx, loginLimiter));
  app.use('/api/admin', ctx.operator.middleware(), adminRoutes(ctx));
  app.use('/svc', serviceProxyRoutes(ctx));

  app.use((_req: Request, res: Response) =>
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'not found' } }),
  );
  app.use(
    (
      err: Error & { type?: string; status?: number },
      req: Request,
      res: Response,
      _next: NextFunction,
    ) => {
      if (err.type === 'entity.too.large')
        return res
          .status(413)
          .json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'request body too large' } });
      if (err.type === 'entity.parse.failed')
        return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'malformed JSON' } });
      req.log?.error({ err: { message: err.message } }, 'unhandled error');
      res.status(500).json({ error: { code: 'INTERNAL', message: 'internal error' } });
    },
  );

  const sweeper = setInterval(() => {
    ctx.challenges.sweep();
    ctx.sessions.sweep();
    ctx.nullifiers.sweep(BigInt(ctx.challenges.epochAt(ctx.clock.now())));
  }, 30_000);
  sweeper.unref();

  return { app, ctx };
}
