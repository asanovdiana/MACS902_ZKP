import { SignJWT, jwtVerify, errors } from 'jose';
import { randomUUID } from 'node:crypto';
import type { ResourceId } from './resources.js';

/**
 * Internal authorization assertion attached by a trusted front door (ZK gateway or SSO
 * baseline) when it forwards an already-authorized request to a protected service.
 * Services reject any request that lacks a valid, unexpired assertion addressed to them,
 * which prevents direct upstream access that bypasses the front door.
 */
export const ASSERTION_HEADER = 'x-zkag-assertion';
export type FrontDoor = 'zk-gateway' | 'sso-baseline';

export interface AssertionClaims {
  frontDoor: FrontDoor;
  resource: ResourceId;
  /** Opaque subject. ZK: random per-session pseudonym. SSO: the IdP subject. */
  subject: string;
  /** Display label safe for the service UI (SSO: username; ZK: "anonymous holder"). */
  display: string;
}

const ALG = 'HS256';
const TTL_SECONDS = 30;

function keyFrom(secret: string): Uint8Array {
  if (secret.length < 32) throw new Error('assertion secret must be at least 32 characters');
  return new TextEncoder().encode(secret);
}

export async function signAssertion(secret: string, claims: AssertionClaims): Promise<string> {
  return new SignJWT({ fd: claims.frontDoor, dsp: claims.display })
    .setProtectedHeader({ alg: ALG, typ: 'JWT' })
    .setIssuer(claims.frontDoor)
    .setAudience(`zkag-service:${claims.resource}`)
    .setSubject(claims.subject)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(keyFrom(secret));
}

export type AssertionResult =
  | { ok: true; claims: AssertionClaims }
  | {
      ok: false;
      reason: 'MISSING' | 'INVALID' | 'EXPIRED' | 'WRONG_AUDIENCE' | 'UNTRUSTED_ISSUER';
    };

/**
 * Verify an assertion against the secrets of all trusted front doors.
 * Each front door has its own secret; the issuer claim selects which key is used.
 */
export async function verifyAssertion(
  token: string | undefined,
  resource: ResourceId,
  secrets: Partial<Record<FrontDoor, string>>,
): Promise<AssertionResult> {
  if (!token) return { ok: false, reason: 'MISSING' };
  let issuer: string | undefined;
  try {
    const [, payloadB64] = token.split('.');
    issuer = JSON.parse(Buffer.from(payloadB64 ?? '', 'base64url').toString('utf8')).iss;
  } catch {
    return { ok: false, reason: 'INVALID' };
  }
  if (issuer !== 'zk-gateway' && issuer !== 'sso-baseline')
    return { ok: false, reason: 'UNTRUSTED_ISSUER' };
  const secret = secrets[issuer];
  if (!secret) return { ok: false, reason: 'UNTRUSTED_ISSUER' };
  try {
    const { payload } = await jwtVerify(token, keyFrom(secret), {
      algorithms: [ALG],
      issuer,
      audience: `zkag-service:${resource}`,
      requiredClaims: ['sub', 'exp', 'iat', 'jti'],
      maxTokenAge: `${TTL_SECONDS + 5}s`,
    });
    return {
      ok: true,
      claims: {
        frontDoor: issuer,
        resource,
        subject: String(payload.sub),
        display: typeof payload.dsp === 'string' ? payload.dsp : 'unknown',
      },
    };
  } catch (err) {
    if (err instanceof errors.JWTExpired) return { ok: false, reason: 'EXPIRED' };
    if (err instanceof errors.JWTClaimValidationFailed && err.claim === 'aud') {
      return { ok: false, reason: 'WRONG_AUDIENCE' };
    }
    return { ok: false, reason: 'INVALID' };
  }
}
