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

test('User Portal: Alice gets a REAL valid proof but authorization is blocked; lifecycle shows timings', async ({
  page,
}) => {
  await page.getByRole('radio', { name: /File Share/ }).click();
  await page.getByRole('button', { name: 'Request access as Alice' }).click();
  await expect(page.getByText('PROFILE_NOT_AUTHORIZATION_ELIGIBLE').first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByText('mathematically valid', { exact: true })).toBeVisible();
  await expect(page.getByText(/^256\s*bytes$/)).toBeVisible();
  await expect(page.getByText('Why no session was issued')).toBeVisible();
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
  await expect(page.getByText('PROFILE_NOT_AUTHORIZATION_ELIGIBLE').first()).toBeVisible({
    timeout: 30_000,
  });
  await page.getByRole('link', { name: /Gateway Live View/ }).click();
  await expect(page.getByText('verification.completed').first()).toBeVisible();
  await expect(page.getByText('Public signals received')).toBeVisible();
});

test('Admin Console: revoking a credential changes the root and greys out the leaf', async ({
  page,
}) => {
  const rootOf = async () =>
    (
      (await (await page.request.get('/api/admin/registry')).json()) as {
        current: { root: string };
      }
    ).current.root;
  const initial = await rootOf();
  await page.getByRole('link', { name: /Admin Console/ }).click();
  const row = page.locator('span.mono', { hasText: /^cred-bob$/ }).locator('..');
  await row.getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Revoked cred-bob' })).toBeVisible();
  await expect(row.getByText('revoked', { exact: true })).toBeVisible();
  expect(await rootOf()).not.toBe(initial);
  await page.getByRole('button', { name: 'Reset demo' }).click();
  await expect.poll(rootOf).toBe(initial);
});

test('Attack Lab: gateway hardening checks pass with real backend responses', async ({ page }) => {
  await page.getByRole('link', { name: /Attack Lab/ }).click();
  for (const title of [
    'Malformed / oversized proof',
    'Forged session / direct service access',
    'Tampered public input',
  ]) {
    const card = page.locator('article').filter({ hasText: title });
    await card.getByRole('button', { name: 'Run' }).click();
    await expect(card.getByText('PASS · attack defeated')).toBeVisible({ timeout: 30_000 });
  }
  const tamper = page.locator('article').filter({ hasText: 'Tamper attributes' });
  await tamper.getByRole('button', { name: 'Run' }).click();
  await expect(tamper.getByText(/FAIL · property does not hold/)).toBeVisible({ timeout: 30_000 });
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
