import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(here, '../../..');

const DEV_DEFAULTS = {
  OPERATOR_TOKEN: 'dev-operator-token-change-me-000000',
  ASSERTION_SECRET_ZK: 'dev-zk-gateway-assertion-secret-change-me-0000',
  REGISTRY_ADMIN_TOKEN: 'dev-registry-admin-token-change-me-0000',
} as const;

const bool = z.enum(['true', 'false', '1', '0']).transform((v) => v === 'true' || v === '1');

const upstream = z
  .string()
  .url()
  .refine((u) => {
    const url = new URL(u);
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      url.pathname === '/' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash
    );
  }, 'upstream must be an origin like http://host:port with no path, credentials, query or fragment');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  GATEWAY_HOST: z.string().default('127.0.0.1'),
  GATEWAY_PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  TRUST_PROXY: z.string().default('loopback'),
  ALLOWED_ORIGINS: z
    .string()
    .default('http://localhost:5173,http://127.0.0.1:5173,http://localhost:8088'),
  COOKIE_SECURE: bool.default('false'),

  ZK_PROFILE: z.enum(['p1-integrated-v3', 'zkag-access-v1']).default('p1-integrated-v3'),
  ARTIFACT_DIR: z.string().optional(),
  TRUSTED_ISSUER_AX: z.string().optional(),
  TRUSTED_ISSUER_AY: z.string().optional(),
  /** Per-IP request budget for /api/zk/* per minute. */
  ZK_RATE_LIMIT_PER_MIN: z.coerce.number().int().min(10).max(1_000_000).default(240),
  MAX_PROOF_BYTES: z.coerce.number().int().min(512).max(65536).default(8192),

  REGISTRY_URL: z.string().url().default('http://127.0.0.1:4600'),
  REGISTRY_ADMIN_TOKEN: z.string().min(16).default(DEV_DEFAULTS.REGISTRY_ADMIN_TOKEN),
  REGISTRY_TIMEOUT_MS: z.coerce.number().int().min(100).max(10000).default(2000),
  /** Project Scope M2: root pulled on every request or at most every 30 s (staleness window). */
  ROOT_CACHE_MS: z.coerce.number().int().min(0).max(30000).default(2000),

  CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(10).max(600).default(120),
  MAX_OUTSTANDING_CHALLENGES: z.coerce.number().int().min(10).max(1_000_000).default(10000),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(600),
  EPOCH_SECONDS: z.coerce.number().int().min(30).max(86400).default(600),
  NULLIFIER_MAX_PER_EPOCH: z.coerce.number().int().min(1).max(100).default(1),
  CLOCK_SKEW_SECONDS: z.coerce.number().int().min(0).max(600).default(120),

  OPERATOR_TOKEN: z.string().min(24).default(DEV_DEFAULTS.OPERATOR_TOKEN),
  ASSERTION_SECRET_ZK: z.string().min(32).default(DEV_DEFAULTS.ASSERTION_SECRET_ZK),

  UPSTREAM_WIKI_URL: upstream.default('http://127.0.0.1:4101'),
  UPSTREAM_FILE_SHARE_URL: upstream.default('http://127.0.0.1:4102'),
  UPSTREAM_ADMIN_PANEL_URL: upstream.default('http://127.0.0.1:4103'),

  SSO_GATEWAY_URL: z.string().url().default('http://127.0.0.1:4200'),
  BENCH_RESULTS_FILE: z.string().optional(),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
});

export type Env = z.infer<typeof schema>;

export interface Config extends Env {
  allowedOrigins: string[];
  artifactDir: string;
  benchResultsFile: string;
  auditReportFile: string;
  usingDevSecrets: string[];
}

export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid gateway configuration: ${issues}`);
  }
  const env = parsed.data;
  const usingDevSecrets = (Object.keys(DEV_DEFAULTS) as Array<keyof typeof DEV_DEFAULTS>).filter(
    (k) => env[k] === DEV_DEFAULTS[k],
  );
  if (env.NODE_ENV === 'production') {
    if (usingDevSecrets.length)
      throw new Error(
        `Refusing to start in production with dev secrets: ${usingDevSecrets.join(', ')}`,
      );
    if (!env.COOKIE_SECURE) throw new Error('COOKIE_SECURE must be true in production');
  }
  const artifactDefault =
    env.ZK_PROFILE === 'p1-integrated-v3'
      ? 'artifacts/p1-integrated-v3'
      : 'artifacts/zkag-access-v1';
  return {
    ...env,
    allowedOrigins: env.ALLOWED_ORIGINS.split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    artifactDir: resolve(REPO_ROOT, env.ARTIFACT_DIR ?? artifactDefault),
    benchResultsFile: resolve(REPO_ROOT, env.BENCH_RESULTS_FILE ?? 'bench/results/latest.json'),
    auditReportFile: resolve(REPO_ROOT, 'evidence/p1-audit-report.json'),
    usingDevSecrets,
  };
}
