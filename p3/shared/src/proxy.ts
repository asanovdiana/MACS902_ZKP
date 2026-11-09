import http from 'node:http';
import https from 'node:https';
import type { Request, Response } from 'express';
import { ASSERTION_HEADER, signAssertion, type FrontDoor } from './assertion.js';
import type { ResourceId } from './resources.js';

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST']);
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
/** Request headers that must never reach a protected service from the client. */
const STRIPPED_REQUEST = new Set([
  'cookie',
  'authorization',
  'host',
  'origin',
  'referer',
  'content-length',
  ASSERTION_HEADER,
  'forwarded',
]);
const FORWARDED_REQUEST = new Set([
  'accept',
  'accept-language',
  'content-type',
  'if-none-match',
  'if-modified-since',
  'range',
]);
const STRIPPED_RESPONSE = new Set(['set-cookie', 'server', 'x-powered-by']);

export type PathCheck = { ok: true; path: string } | { ok: false; reason: string };

/**
 * Validate and normalise the downstream path. Rejects traversal (including encoded and
 * double-encoded forms), backslashes, control characters, protocol-relative paths and
 * absolute URLs so the resulting URL can never leave the configured upstream origin.
 */
export function sanitizeUpstreamPath(rawPath: string, rawQuery: string): PathCheck {
  if (!rawPath.startsWith('/')) return { ok: false, reason: 'path must be absolute' };
  if (rawPath.length > 512 || rawQuery.length > 1024) return { ok: false, reason: 'path too long' };
  if (rawPath.startsWith('//')) return { ok: false, reason: 'protocol-relative path' };
  let decoded = rawPath;
  for (let i = 0; i < 3; i++) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return { ok: false, reason: 'invalid percent-encoding' };
    }
    if (next === decoded) break;
    decoded = next;
  }
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(decoded)) return { ok: false, reason: 'illegal characters' };
  if (decoded.split('/').some((seg) => seg === '..' || seg === '.'))
    return { ok: false, reason: 'path traversal' };
  if (/^\/?[a-z][a-z0-9+.-]*:/i.test(decoded)) return { ok: false, reason: 'absolute URL' };
  return { ok: true, path: rawPath + (rawQuery ? `?${rawQuery}` : '') };
}

export interface ProxyTarget {
  frontDoor: FrontDoor;
  resource: ResourceId;
  upstream: string; // validated origin from configuration only
  subject: string;
  display: string;
  assertionSecret: string;
  timeoutMs?: number;
}

/** Forward an ALREADY AUTHORIZED request to the configured upstream for `resource`. */
export async function forward(
  req: Request,
  res: Response,
  downstreamPath: string,
  target: ProxyTarget,
): Promise<number> {
  if (!ALLOWED_METHODS.has(req.method)) {
    res.status(405).json({ error: { code: 'METHOD_NOT_ALLOWED', message: 'method not allowed' } });
    return 405;
  }
  const base = new URL(target.upstream);
  const url = new URL(downstreamPath, base);
  if (url.origin !== base.origin) {
    res.status(400).json({ error: { code: 'INVALID_PATH', message: 'invalid upstream path' } });
    return 400;
  }
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || STRIPPED_REQUEST.has(key) || key.startsWith('x-')) continue;
    if (FORWARDED_REQUEST.has(key) && typeof v === 'string') headers[key] = v;
  }
  headers[ASSERTION_HEADER] = await signAssertion(target.assertionSecret, {
    frontDoor: target.frontDoor,
    resource: target.resource,
    subject: target.subject,
    display: target.display,
  });
  let body: Buffer | undefined;
  if (req.method === 'POST') {
    body = Buffer.from(JSON.stringify(req.body ?? {}));
    headers['content-type'] = 'application/json';
    headers['content-length'] = String(body.length);
  }
  const client = url.protocol === 'https:' ? https : http;
  return new Promise<number>((resolve) => {
    const upstreamReq = client.request(
      url,
      { method: req.method, headers, timeout: target.timeoutMs ?? 5000 },
      (up) => {
        const status = up.statusCode ?? 502;
        res.status(status);
        for (const [k, v] of Object.entries(up.headers)) {
          const key = k.toLowerCase();
          if (HOP_BY_HOP.has(key) || STRIPPED_RESPONSE.has(key) || v === undefined) continue;
          res.setHeader(key, v);
        }
        up.pipe(res);
        up.on('end', () => resolve(status));
      },
    );
    upstreamReq.on('timeout', () => upstreamReq.destroy(new Error('timeout')));
    upstreamReq.on('error', () => {
      if (!res.headersSent)
        res.status(502).json({
          error: { code: 'UPSTREAM_UNAVAILABLE', message: 'protected service unavailable' },
        });
      resolve(502);
    });
    if (body) upstreamReq.write(body);
    upstreamReq.end();
  });
}
