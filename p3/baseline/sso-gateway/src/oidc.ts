import { createHash, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { jwtVerify, errors, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { ROLES, type VerificationCheck } from '@zkag/shared';

export const ALLOWED_ALGS = ['RS256', 'PS256', 'ES256'];

export function pkcePair() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge, method: 'S256' as const };
}

export interface TokenExpectations {
  issuer: string;
  audience: string;
  clientId: string;
  keys: JWTVerifyGetKey;
  nonce?: string;
  kind: 'id' | 'access';
}

export interface ValidatedToken {
  ok: boolean;
  payload: JWTPayload | null;
  checks: VerificationCheck[];
  reason: string | null;
  durationMs: number;
}

/**
 * Full JWT validation: signature against the realm JWKS, algorithm allowlist (no HMAC or "none"),
 * issuer, audience, expiry/nbf with 30 s tolerance, required claims, authorized party, and
 * for ID tokens the login nonce. Token contents are never trusted before this succeeds.
 */
export async function validateToken(
  token: string,
  exp: TokenExpectations,
): Promise<ValidatedToken> {
  const t0 = performance.now();
  const checks: VerificationCheck[] = [];
  const fail = (id: string, label: string, reason: string, detail?: string): ValidatedToken => {
    checks.push({ id, label, status: 'fail', ...(detail ? { detail } : {}) });
    return { ok: false, payload: null, checks, reason, durationMs: performance.now() - t0 };
  };
  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, exp.keys, {
      algorithms: ALLOWED_ALGS,
      issuer: exp.issuer,
      audience: exp.audience,
      clockTolerance: 30,
      requiredClaims: ['exp', 'iat', 'sub', 'iss'],
    });
    payload = result.payload;
    checks.push({
      id: 'signature',
      label: `Signature valid (${result.protectedHeader.alg}, kid ${result.protectedHeader.kid ?? 'n/a'})`,
      status: 'pass',
    });
    checks.push({
      id: 'issuer',
      label: 'Issuer matches realm',
      status: 'pass',
      detail: exp.issuer,
    });
    checks.push({
      id: 'audience',
      label: 'Audience includes client',
      status: 'pass',
      detail: exp.audience,
    });
    checks.push({
      id: 'expiry',
      label: 'Not expired',
      status: 'pass',
      detail: new Date((payload.exp ?? 0) * 1000).toISOString(),
    });
  } catch (err) {
    if (err instanceof errors.JWTExpired) return fail('expiry', 'Not expired', 'TOKEN_EXPIRED');
    if (err instanceof errors.JWTClaimValidationFailed) {
      if (err.claim === 'iss') return fail('issuer', 'Issuer matches realm', 'TOKEN_WRONG_ISSUER');
      if (err.claim === 'aud')
        return fail('audience', 'Audience includes client', 'TOKEN_WRONG_AUDIENCE');
      return fail('claims', 'Required claims present', 'TOKEN_MISSING_CLAIM', err.claim);
    }
    if (err instanceof errors.JOSEAlgNotAllowed)
      return fail('algorithm', 'Algorithm allowed', 'TOKEN_ALG_NOT_ALLOWED');
    if (
      err instanceof errors.JWSSignatureVerificationFailed ||
      err instanceof errors.JWKSNoMatchingKey
    ) {
      return fail('signature', 'Signature valid', 'TOKEN_BAD_SIGNATURE');
    }
    return fail('format', 'Well-formed JWT', 'TOKEN_INVALID', (err as Error).name);
  }
  if (exp.kind === 'access') {
    if (payload.azp !== exp.clientId)
      return fail('azp', 'Authorized party is this client', 'TOKEN_WRONG_AZP');
    checks.push({ id: 'azp', label: 'Authorized party is this client', status: 'pass' });
    if (payload.typ !== undefined && payload.typ !== 'Bearer')
      return fail('typ', 'Token type is Bearer', 'TOKEN_WRONG_TYPE');
  } else {
    if (!exp.nonce || payload.nonce !== exp.nonce)
      return fail('nonce', 'ID token nonce matches login', 'TOKEN_NONCE_MISMATCH');
    checks.push({ id: 'nonce', label: 'ID token nonce matches login', status: 'pass' });
  }
  return { ok: true, payload, checks, reason: null, durationMs: performance.now() - t0 };
}

export interface MappedIdentity {
  subject: string;
  username: string;
  email: string | null;
  name: string | null;
  roles: string[];
  clearance: number | null;
  department: string | null;
  deviceCompliant: boolean | null;
}

/** Map validated Keycloak claims to policy attributes. Unknown roles are dropped. */
export function mapIdentity(p: JWTPayload): MappedIdentity {
  const realmRoles = ((p.realm_access as { roles?: unknown } | undefined)?.roles ??
    []) as unknown[];
  const roles = realmRoles.filter(
    (r): r is string => typeof r === 'string' && (ROLES as readonly string[]).includes(r),
  );
  const clearanceRaw = p.clearance;
  const clearance =
    typeof clearanceRaw === 'number'
      ? clearanceRaw
      : typeof clearanceRaw === 'string' && /^[0-3]$/.test(clearanceRaw)
        ? Number(clearanceRaw)
        : null;
  const dc = p.device_compliant;
  const deviceCompliant =
    dc === true || dc === 'true' ? true : dc === false || dc === 'false' ? false : null;
  return {
    subject: String(p.sub),
    username: typeof p.preferred_username === 'string' ? p.preferred_username : String(p.sub),
    email: typeof p.email === 'string' ? p.email : null,
    name: typeof p.name === 'string' ? p.name : null,
    roles,
    clearance:
      clearance !== null && Number.isInteger(clearance) && clearance >= 0 && clearance <= 3
        ? clearance
        : null,
    department: typeof p.department === 'string' ? p.department : null,
    deviceCompliant,
  };
}
