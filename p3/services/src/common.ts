import express, { type NextFunction, type Request, type Response } from 'express';
import helmet from 'helmet';
import {
  ASSERTION_HEADER,
  verifyAssertion,
  type AssertionClaims,
  type FrontDoor,
  type ResourceId,
} from '@zkag/shared';

export interface ServiceSecrets {
  zk: string;
  sso: string;
}

export type AuthedRequest = Request & { viewer: AssertionClaims };

/**
 * Backend authorization for every protected service: a request is served only if it carries
 * a valid, unexpired assertion minted by a trusted front door for THIS resource. Services
 * listen on an internal interface only, so this is defence in depth against bypass.
 */
export function createServiceApp(resource: ResourceId, secrets: ServiceSecrets) {
  const app = express();
  app.disable('x-powered-by');
  app.use(
    helmet({
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    }),
  );
  app.use(express.json({ limit: '8kb' }));
  app.get('/healthz', (_req, res) => res.json({ status: 'ok', resource }));
  const trusted: Partial<Record<FrontDoor, string>> = {
    'zk-gateway': secrets.zk,
    'sso-baseline': secrets.sso,
  };
  app.use(async (req: Request, res: Response, next: NextFunction) => {
    const header = req.get(ASSERTION_HEADER);
    const result = await verifyAssertion(header, resource, trusted);
    if (!result.ok) {
      return res.status(401).json({
        error: {
          code: `ASSERTION_${result.reason}`,
          message: 'request did not come through an authorizing front door',
        },
      });
    }
    (req as AuthedRequest).viewer = result.claims;
    res.set('Cache-Control', 'no-store');
    next();
  });
  return app;
}

export function viewerOf(req: Request) {
  const v = (req as AuthedRequest).viewer;
  return { frontDoor: v.frontDoor, subject: v.subject, display: v.display };
}

export function finalize(app: express.Express) {
  app.use((_req: Request, res: Response) =>
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'not found' } }),
  );
  app.use((err: Error & { type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    if (err.type === 'entity.parse.failed')
      return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'malformed JSON' } });
    res.status(500).json({ error: { code: 'INTERNAL', message: 'internal error' } });
  });
  return app;
}
