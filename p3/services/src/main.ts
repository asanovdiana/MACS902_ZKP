import { createWiki } from './wiki.js';
import { createFileShare } from './fileShare.js';
import { createAdminPanel } from './adminPanel.js';

const host = process.env.SERVICES_HOST ?? '127.0.0.1';
const secrets = {
  zk: process.env.ASSERTION_SECRET_ZK ?? 'dev-zk-gateway-assertion-secret-change-me-0000',
  sso: process.env.ASSERTION_SECRET_SSO ?? 'dev-sso-baseline-assertion-secret-change-me-000',
};
if (
  process.env.NODE_ENV === 'production' &&
  (secrets.zk.startsWith('dev-') || secrets.sso.startsWith('dev-'))
) {
  throw new Error(
    'refusing to start protected services with development assertion secrets in production',
  );
}
const apps = [
  ['wiki', createWiki(secrets), Number(process.env.WIKI_PORT ?? 4101)],
  ['file-share', createFileShare(secrets), Number(process.env.FILE_SHARE_PORT ?? 4102)],
  ['admin-panel', createAdminPanel(secrets), Number(process.env.ADMIN_PANEL_PORT ?? 4103)],
] as const;
for (const [name, app, port] of apps) {
  app.listen(port, host, () =>
    console.log(
      `[services] ${name} listening on http://${host}:${port} (internal; front-door assertion required)`,
    ),
  );
}
