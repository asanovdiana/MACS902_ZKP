import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { signAssertion, type ResourceId } from '@zkag/shared';
import { createWiki } from '../src/wiki.js';
import { createFileShare } from '../src/fileShare.js';
import { createAdminPanel } from '../src/adminPanel.js';

const secrets = {
  zk: 'zk-secret-0123456789abcdef0123456789ab',
  sso: 'sso-secret-0123456789abcdef0123456789a',
};
const wiki = createWiki(secrets);
const files = createFileShare(secrets);
const admin = createAdminPanel(secrets);
const assert = (resource: ResourceId, fd: 'zk-gateway' | 'sso-baseline' = 'zk-gateway') =>
  signAssertion(fd === 'zk-gateway' ? secrets.zk : secrets.sso, {
    frontDoor: fd,
    resource,
    subject: 'zk-abc',
    display: 'Anonymous credential holder',
  });

describe('protected services enforce backend authorization', () => {
  it('reject direct access without an assertion', async () => {
    for (const app of [wiki, files, admin]) expect((await request(app).get('/')).status).toBe(401);
  });
  it('reject assertions for another resource and from the wrong signer', async () => {
    expect(
      (
        await request(wiki)
          .get('/')
          .set('x-zkag-assertion', await assert('admin-panel'))
      ).body.error.code,
    ).toBe('ASSERTION_WRONG_AUDIENCE');
    const swapped = await signAssertion(secrets.sso, {
      frontDoor: 'zk-gateway',
      resource: 'wiki',
      subject: 's',
      display: 'd',
    });
    expect((await request(wiki).get('/').set('x-zkag-assertion', swapped)).status).toBe(401);
  });
  it('serve wiki articles, search and categories', async () => {
    const h = await assert('wiki', 'sso-baseline');
    const home = await request(wiki).get('/').set('x-zkag-assertion', h);
    expect(home.body.categories).toContain('Security');
    const search = await request(wiki).get('/articles?q=incident').set('x-zkag-assertion', h);
    expect(search.body.items[0].slug).toBe('incident-response-runbook');
    const art = await request(wiki).get('/articles/device-compliance').set('x-zkag-assertion', h);
    expect(art.body.article.body.length).toBeGreaterThan(2);
  });
  it('file share lists metadata without storage paths and downloads by catalogue id only', async () => {
    const h = await assert('file-share');
    const list = await request(files).get('/').set('x-zkag-assertion', h);
    expect(list.body.files).toHaveLength(4);
    expect(JSON.stringify(list.body)).not.toContain('storedAs');
    const dl = await request(files).get('/files/f-ops-002/download').set('x-zkag-assertion', h);
    expect(dl.status).toBe(200);
    expect(dl.text).toContain('cluster,cpu_cores');
    expect(
      (
        await request(files)
          .get('/files/..%2f..%2fpackage.json/download')
          .set('x-zkag-assertion', h)
      ).status,
    ).toBe(404);
    expect(
      (await request(files).get('/files/capacity-plan-q4.csv/download').set('x-zkag-assertion', h))
        .status,
    ).toBe(404);
  });
  it('admin panel performs only safe in-memory actions and validates input', async () => {
    const h = await assert('admin-panel');
    expect(
      (await request(admin).get('/').set('x-zkag-assertion', h)).body.overview.openAlerts,
    ).toBe(3);
    expect(
      (
        await request(admin)
          .post('/actions/acknowledge-alert')
          .set('x-zkag-assertion', h)
          .send({ alertId: 'rm -rf' })
      ).status,
    ).toBe(400);
    const ok = await request(admin)
      .post('/actions/maintenance-banner')
      .set('x-zkag-assertion', h)
      .send({ enabled: true, message: 'Patch window 22:00' });
    expect(ok.body.banner.enabled).toBe(true);
  });
});
