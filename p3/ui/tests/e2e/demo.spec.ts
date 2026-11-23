import { expect, test, type Page } from '@playwright/test';

async function open(page: Page) {
  await page.goto('/portal');
  await expect(page.getByRole('heading', { name: /Prove you satisfy the policy/ })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await open(page);
  await page.request.post('/api/admin/demo/reset', { data: {} });
});

test('rejects a wrong operator token', async ({ browser }) => {
  const page = await browser.newPage({ storageState: { cookies: [], origins: [] } });
  await page.goto('/portal');
  await page.getByLabel('Operator token').fill('definitely-not-the-token');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert')).toHaveText(/Invalid operator token/);
});

test('navigates all five demo screens plus evidence pages', async ({ page }) => {
  const screens: Array<[string, RegExp]> = [
    ['Gateway Live View', /Exactly what the gateway sees/],
    ['SSO vs ZK', /Same request\. Very different knowledge/],
    ['Admin Console', /Registry, issuance and revocation/],
    ['Attack Lab', /Attacks that must fail/],
    ['Performance', /Measured performance/],
    ['Integration Status', /What the active circuit actually proves/],
    ['User Portal', /Prove you satisfy the policy/],
  ];
  for (const [nav, heading] of screens) {
    await page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: new RegExp(nav) })
      .click();
    await expect(page.getByRole('heading', { level: 1, name: heading })).toBeVisible();
  }
});

test('User Portal: Alice is GRANTED File Share with a real v4 proof and the service loads anonymously', async ({
  page,
}) => {
  await page.getByRole('radio', { name: /File Share/ }).click();
  await page.getByRole('button', { name: 'Request access as Alice' }).click();
  await expect(page.getByText('ACCESS_GRANTED').first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('mathematically valid', { exact: true })).toBeVisible();
  await expect(page.getByText(/^256\s*bytes$/)).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Engineering File Exchange' })).toBeVisible();
  await expect(page.getByText('Anonymous credential holder')).toBeVisible();
  await expect(page.getByText('no email')).toBeVisible();
});

test('User Portal: Bob (contractor) cannot generate a proof', async ({ page }) => {
  await page.getByRole('radio', { name: /Bob/ }).click();
  await page.getByRole('radio', { name: /File Share/ }).click();
  await page.getByRole('button', { name: 'Request access as Bob' }).click();
  await expect(page.getByText('No proof could be generated')).toBeVisible({ timeout: 30_000 });
});

test('Live View receives events over the authenticated WebSocket', async ({ page }) => {
  await page.getByRole('button', { name: 'Request access as Alice' }).click();
  await expect(page.getByText('ACCESS_GRANTED').first()).toBeVisible({
    timeout: 30_000,
  });
  await page.getByRole('link', { name: /Gateway Live View/ }).click();
  await expect(page.getByText('verification.completed').first()).toBeVisible();
  await expect(page.getByText('Public signals received')).toBeVisible();
});

test('Admin Console: issuer tree with persona labels, and admin enrolment returns a one-time code', async ({
  page,
}) => {
  await page.getByRole('link', { name: /Admin Console/ }).click();
  await expect(page.getByRole('img', { name: 'Merkle tree of credential leaves' })).toBeVisible();
  for (const who of ['alice', 'bob', 'carol'])
    await expect(
      page.locator('span.font-medium', { hasText: new RegExp(`^${who}$`) }).first(),
    ).toBeVisible();
  await page.getByLabel('Employee ID').fill(`e2e-${Date.now()}`);
  await page.getByRole('button', { name: 'Create enrolment' }).click();
  await expect(
    page.getByRole('status').filter({ hasText: 'One-time enrolment code' }),
  ).toBeVisible();
});

test('Attack Lab: team suite attacks and gateway hardening checks pass with real backend responses', async ({
  page,
}) => {
  await page.getByRole('link', { name: /Attack Lab/ }).click();
  for (const title of [
    'Forged credential',
    'Revoked user tries again',
    'Tamper attributes',
    'Malformed / oversized proof',
    'Forged session / direct service access',
  ]) {
    const card = page.locator('article').filter({ hasText: title });
    await card.getByRole('button', { name: 'Run' }).click();
    await expect(card.getByText('PASS · attack defeated')).toBeVisible({ timeout: 60_000 });
  }
});

test('responsive: mobile layout has no horizontal scroll and a menu button', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ['/portal', '/compare', '/attacks', '/admin']) {
    await page.goto(path);
    await expect(page.getByRole('button', { name: 'Open navigation' })).toBeVisible();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, path).toBeLessThanOrEqual(1);
  }
});

test('basic accessibility: every button and form control has an accessible name', async ({
  page,
}) => {
  for (const path of ['/portal', '/admin', '/compare', '/attacks']) {
    await page.goto(path);
    await page.waitForLoadState('networkidle');
    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll('button, input, select, a[href]')]
        .filter((el) => {
          const e = el as HTMLElement;
          const label =
            e.getAttribute('aria-label') ||
            e.innerText?.trim() ||
            (e as HTMLInputElement).labels?.[0]?.innerText ||
            e.getAttribute('title');
          return !label && (e as HTMLInputElement).type !== 'hidden';
        })
        .map((el) => el.outerHTML.slice(0, 80)),
    );
    expect(unnamed, path).toEqual([]);
  }
});

// Real Keycloak login through the UI (requires the Docker demo with Keycloak: E2E_KEYCLOAK=1).
test('SSO vs ZK: real Keycloak login, then the same Wiki request through both front doors', async ({
  page,
}) => {
  test.skip(
    process.env.E2E_KEYCLOAK !== '1',
    'set E2E_KEYCLOAK=1 with the Docker demo (Keycloak) running',
  );
  await page.getByRole('link', { name: /SSO vs ZK/ }).click();
  await page.getByRole('link', { name: 'Log in with Keycloak' }).click();
  await expect(page).toHaveURL(
    /\/realms\/zkag\/protocol\/openid-connect\/auth.*code_challenge_method=S256/,
  );
  await page.locator('#username').fill('alice');
  await page.locator('#password').fill('alice-dev-password');
  await page.locator('#kc-login').click();
  await expect(page).toHaveURL(/\/compare$/);
  await page.getByRole('button', { name: 'Open Wiki via SSO' }).click();
  await expect(page.getByText('alice@northwind.example')).toBeVisible();
  await expect(page.getByText('Signature valid (RS256')).toBeVisible();
  await page.getByRole('button', { name: 'Request via ZK gateway' }).click();
  await expect(page.getByText('ACCESS_GRANTED').first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText('not received').first()).toBeVisible();
});
