import type { Request, Response, NextFunction } from 'express';

/**
 * CSRF defence for state-changing requests: session cookies are SameSite=Strict and, in
 * addition, any browser-supplied Origin on an unsafe method must be in the allowlist.
 * JSON APIs also require `Content-Type: application/json`, which cannot be sent cross-origin
 * without a CORS preflight (the gateway answers no CORS preflights).
 */
export function originGuard(allowed: string[]) {
  const set = new Set(allowed);
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
    const origin = req.get('origin');
    if (origin && !set.has(origin)) {
      return res
        .status(403)
        .json({ error: { code: 'ORIGIN_NOT_ALLOWED', message: 'cross-origin request rejected' } });
    }
    const site = req.get('sec-fetch-site');
    if (!origin && site && site !== 'same-origin' && site !== 'none') {
      return res
        .status(403)
        .json({ error: { code: 'ORIGIN_NOT_ALLOWED', message: 'cross-site request rejected' } });
    }
    next();
  };
}

export function requireJson(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'POST' && !req.is('application/json')) {
    return res
      .status(415)
      .json({ error: { code: 'UNSUPPORTED_MEDIA_TYPE', message: 'application/json required' } });
  }
  next();
}
