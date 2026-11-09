import { readFileSync, createReadStream } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createServiceApp, finalize, viewerOf, type ServiceSecrets } from './common.js';

interface FileEntry {
  id: string;
  name: string;
  category: string;
  sizeBytes: number;
  mime: string;
  owner: string;
  classification: string;
  updated: string;
  storedAs: string;
  description: string;
}
const dataDir = fileURLToPath(new URL('./data/', import.meta.url));

export function createFileShare(secrets: ServiceSecrets) {
  const files = JSON.parse(readFileSync(join(dataDir, 'files.json'), 'utf8')) as FileEntry[];
  const downloads: Array<{ fileId: string; at: string; frontDoor: string; subject: string }> = [];
  const app = createServiceApp('file-share', secrets);
  const pub = ({ storedAs: _s, ...f }: FileEntry) => f;
  app.get('/', (req, res) =>
    res.json({
      service: 'file-share',
      title: 'Engineering File Exchange',
      viewer: viewerOf(req),
      categories: [...new Set(files.map((f) => f.category))],
      files: files.map(pub),
      recentDownloads: downloads.slice(-5).reverse(),
    }),
  );
  app.get('/files/:id', (req, res) => {
    const f = files.find((x) => x.id === req.params.id);
    if (!f)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'file not found' } });
    res.json({ viewer: viewerOf(req), file: pub(f) });
  });
  /** Downloads are looked up by catalogue ID only; the client never supplies a filesystem path. */
  app.get('/files/:id/download', (req, res) => {
    const f = files.find((x) => x.id === req.params.id);
    if (!f)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'file not found' } });
    const v = viewerOf(req);
    downloads.push({
      fileId: f.id,
      at: new Date().toISOString(),
      frontDoor: v.frontDoor,
      subject: v.subject,
    });
    res.setHeader('Content-Type', f.mime);
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="${f.name.replace(/[^A-Za-z0-9._-]/g, '_')}"`,
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    createReadStream(join(dataDir, 'files', f.storedAs)).pipe(res);
  });
  return finalize(app);
}
