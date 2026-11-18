import { request, type FullConfig } from '@playwright/test';

/** Sign in ONCE (operator login is rate limited to 10/min) and reuse the cookie jar. */
export default async function globalSetup(config: FullConfig) {
  const baseURL = config.projects[0]!.use.baseURL!;
  const ctx = await request.newContext({ baseURL });
  const token = process.env.E2E_OPERATOR_TOKEN ?? 'dev-operator-token-change-me-000000';
  const res = await ctx.post('/api/operator/login', {
    data: { token },
    headers: { origin: new URL(baseURL).origin },
  });
  if (!res.ok()) throw new Error(`operator login failed: ${res.status()}`);
  await ctx.post('/sso/operator/login', { data: { token } }).catch(() => undefined);
  await ctx.storageState({ path: 'test-results/.auth.json' });
  await ctx.dispose();
}
