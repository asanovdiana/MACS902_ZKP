import { describe, expect, it, vi } from 'vitest';
import { SignJWT } from 'jose';
import { signAssertion, verifyAssertion } from '../src/assertion.js';

const zk = 'zk-secret-0123456789abcdef0123456789abcd';
const sso = 'sso-secret-0123456789abcdef0123456789abc';
const claims = {
  frontDoor: 'zk-gateway' as const,
  resource: 'wiki' as const,
  subject: 'zk-x',
  display: 'Anonymous credential holder',
};

describe('front-door assertions', () => {
  it('round-trips for the intended resource', async () => {
    const r = await verifyAssertion(await signAssertion(zk, claims), 'wiki', {
      'zk-gateway': zk,
      'sso-baseline': sso,
    });
    expect(r).toEqual({ ok: true, claims });
  });
  it('rejects missing, wrong audience, unknown issuer and key confusion', async () => {
    const t = await signAssertion(zk, claims);
    expect((await verifyAssertion(undefined, 'wiki', { 'zk-gateway': zk })).ok).toBe(false);
    expect(await verifyAssertion(t, 'admin-panel', { 'zk-gateway': zk })).toEqual({
      ok: false,
      reason: 'WRONG_AUDIENCE',
    });
    expect(await verifyAssertion(t, 'wiki', { 'sso-baseline': sso })).toEqual({
      ok: false,
      reason: 'UNTRUSTED_ISSUER',
    });
    const confused = await signAssertion(sso, claims); // SSO key used to impersonate the ZK gateway
    expect(
      await verifyAssertion(confused, 'wiki', { 'zk-gateway': zk, 'sso-baseline': sso }),
    ).toEqual({ ok: false, reason: 'INVALID' });
    const evil = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuer('evil')
      .setAudience('zkag-service:wiki')
      .setSubject('x')
      .setIssuedAt()
      .setExpirationTime('30s')
      .sign(new TextEncoder().encode(zk));
    expect(await verifyAssertion(evil, 'wiki', { 'zk-gateway': zk })).toEqual({
      ok: false,
      reason: 'UNTRUSTED_ISSUER',
    });
    expect((await verifyAssertion('not.a.jwt', 'wiki', { 'zk-gateway': zk })).ok).toBe(false);
  });
  it('expires after 30 seconds', async () => {
    vi.useFakeTimers();
    const t = await signAssertion(zk, claims);
    vi.setSystemTime(Date.now() + 31_000);
    expect(await verifyAssertion(t, 'wiki', { 'zk-gateway': zk })).toEqual({
      ok: false,
      reason: 'EXPIRED',
    });
    vi.useRealTimers();
  });
  it('refuses short secrets', async () => {
    await expect(signAssertion('short', claims)).rejects.toThrow(/at least 32/);
  });
});
