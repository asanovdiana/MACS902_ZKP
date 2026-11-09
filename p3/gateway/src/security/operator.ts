import { timingSafeEqual, createHash } from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';
import type { Clock } from '../utils/clock.js';
import { randomId } from '../utils/ids.js';
import { readCookie } from '../utils/cookies.js';

export const OPERATOR_COOKIE = 'zkag_operator';
const TTL_MS = 8 * 60 * 60 * 1000;

/**
 * Operator (demo presenter / administrator) authentication for the monitoring and admin
 * APIs and the event WebSocket. Token comparison is constant time over SHA-256 digests.
 */
export class OperatorAuth {
  private readonly sessions = new Map<string, number>();
  private readonly tokenDigest: Buffer;

  constructor(
    token: string,
    private readonly clock: Clock,
  ) {
    this.tokenDigest = createHash('sha256').update(token).digest();
  }

  checkToken(candidate: unknown): boolean {
    if (typeof candidate !== 'string' || candidate.length > 512) return false;
    const d = createHash('sha256').update(candidate).digest();
    return timingSafeEqual(d, this.tokenDigest);
  }

  login(): { id: string; expiresAt: number } {
    const id = randomId(24);
    const expiresAt = this.clock.now() + TTL_MS;
    this.sessions.set(id, expiresAt);
    return { id, expiresAt };
  }

  logout(id: string | undefined) {
    if (id) this.sessions.delete(id);
  }

  isValid(id: string | undefined): boolean {
    if (!id) return false;
    const exp = this.sessions.get(id);
    if (!exp) return false;
    if (this.clock.now() >= exp) {
      this.sessions.delete(id);
      return false;
    }
    return true;
  }

  fromCookieHeader(cookieHeader: string | undefined): boolean {
    return this.isValid(readCookie(cookieHeader, OPERATOR_COOKIE));
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      if (this.fromCookieHeader(req.headers.cookie)) return next();
      res
        .status(401)
        .json({ error: { code: 'OPERATOR_AUTH_REQUIRED', message: 'operator login required' } });
    };
  }
}
