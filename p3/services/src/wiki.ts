import { readFileSync } from 'node:fs';
import { createServiceApp, finalize, viewerOf, type ServiceSecrets } from './common.js';

interface Article {
  slug: string;
  title: string;
  category: string;
  summary: string;
  updated: string;
  author: string;
  readMinutes: number;
  body: string[];
}
const dataUrl = new URL('./data/wiki.json', import.meta.url);

export function createWiki(secrets: ServiceSecrets) {
  const articles = JSON.parse(readFileSync(dataUrl, 'utf8')) as Article[];
  const app = createServiceApp('wiki', secrets);
  const categories = [...new Set(articles.map((a) => a.category))].sort();
  app.get('/', (req, res) =>
    res.json({
      service: 'wiki',
      title: 'Northwind Knowledge Base',
      viewer: viewerOf(req),
      categories,
      featured: articles.slice(0, 3).map(({ body: _b, ...a }) => a),
      total: articles.length,
    }),
  );
  app.get('/articles', (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q.slice(0, 64).toLowerCase() : '';
    const category = typeof req.query.category === 'string' ? req.query.category : '';
    const items = articles
      .filter(
        (a) =>
          (!category || a.category === category) &&
          (!q || `${a.title} ${a.summary}`.toLowerCase().includes(q)),
      )
      .map(({ body: _b, ...a }) => a);
    res.json({ viewer: viewerOf(req), items });
  });
  app.get('/articles/:slug', (req, res) => {
    const a = articles.find((x) => x.slug === req.params.slug);
    if (!a)
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'article not found' } });
    res.json({ viewer: viewerOf(req), article: a });
  });
  return finalize(app);
}
