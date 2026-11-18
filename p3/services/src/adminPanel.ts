import { z } from 'zod';
import { createServiceApp, finalize, viewerOf, type ServiceSecrets } from './common.js';

/** Safe, in-memory administrative demo. No real infrastructure is touched. */
export function createAdminPanel(secrets: ServiceSecrets) {
  const app = createServiceApp('admin-panel', secrets);
  const started = Date.now();
  const alerts = [
    {
      id: 'ALR-1042',
      severity: 'high',
      title: 'Certificate for vpn.northwind.example expires in 9 days',
      acknowledged: false,
    },
    {
      id: 'ALR-1043',
      severity: 'medium',
      title: 'Backup job "finance-ledger" exceeded its 2 h window',
      acknowledged: false,
    },
    {
      id: 'ALR-1044',
      severity: 'low',
      title: 'Disk usage on build-runner-03 at 81 %',
      acknowledged: false,
    },
  ];
  const audit: Array<{
    at: string;
    action: string;
    target: string;
    frontDoor: string;
    actor: string;
  }> = [];
  let banner = { enabled: false, message: '' };
  const services = [
    { name: 'Wiki', status: 'operational', p95ms: 42, uptime: '99.98 %' },
    { name: 'File Share', status: 'operational', p95ms: 77, uptime: '99.95 %' },
    { name: 'Build Farm', status: 'degraded', p95ms: 310, uptime: '99.41 %' },
    { name: 'Mail Relay', status: 'operational', p95ms: 18, uptime: '100 %' },
  ];
  app.get('/', (req, res) =>
    res.json({
      service: 'admin-panel',
      title: 'Operations Control',
      viewer: viewerOf(req),
      overview: {
        uptimeSeconds: Math.round((Date.now() - started) / 1000),
        openAlerts: alerts.filter((a) => !a.acknowledged).length,
        managedHosts: 148,
        pendingPatches: 12,
      },
      services,
      alerts,
      banner,
      audit: audit.slice(-10).reverse(),
      note: 'Demonstration data. Actions only change in-memory demo state.',
    }),
  );
  app.post('/actions/acknowledge-alert', (req, res) => {
    const body = z
      .object({ alertId: z.string().regex(/^ALR-\d{4}$/) })
      .strict()
      .safeParse(req.body);
    if (!body.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'alertId required' } });
    const alert = alerts.find((a) => a.id === body.data.alertId);
    if (!alert)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'unknown alert' } });
    alert.acknowledged = true;
    const v = viewerOf(req);
    audit.push({
      at: new Date().toISOString(),
      action: 'acknowledge-alert',
      target: alert.id,
      frontDoor: v.frontDoor,
      actor: v.display,
    });
    res.json({ ok: true, alert });
  });
  app.post('/actions/maintenance-banner', (req, res) => {
    const body = z
      .object({ enabled: z.boolean(), message: z.string().max(140) })
      .strict()
      .safeParse(req.body);
    if (!body.success)
      return res
        .status(400)
        .json({ error: { code: 'INVALID_REQUEST', message: 'enabled and message required' } });
    banner = body.data;
    const v = viewerOf(req);
    audit.push({
      at: new Date().toISOString(),
      action: 'maintenance-banner',
      target: banner.enabled ? 'on' : 'off',
      frontDoor: v.frontDoor,
      actor: v.display,
    });
    res.json({ ok: true, banner });
  });
  return finalize(app);
}
