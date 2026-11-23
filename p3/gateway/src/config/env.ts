import { z } from 'zod';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));
/** The p3/ directory. */
export const REPO_ROOT = resolve(here, '../../..');
/** The team repository root (P1 circuits, P2 issuer and client live here). */
export const TEAM_ROOT = resolve(REPO_ROOT, '..');

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

  ZK_PROFILE: z.enum(['p1-integrated-v3', 'integrated-access-v4']).default('integrated-access-v4'),
  /** Path to the circuit manifest (P1/P2 format or P3 format). Defaults per profile. */
  ARTIFACT_MANIFEST: z.string().optional(),
  /** Pinned issuer key (contract obligation 2): explicit values, or a JSON file {Ax, Ay}. */
  TRUSTED_ISSUER_AX: z.string().optional(),
  TRUSTED_ISSUER_AY: z.string().optional(),
  TRUSTED_ISSUER_FILE: z.string().optional(),
  /**
   * Accept circuit keys whose manifest status is DEV-ONLY or DEMO-ONLY (single-party phase 2, or the
   * simulated multi-party ceremony of 2026-11-23) for authorization. Required for the classroom demo;
   * refused in production. Surfaced in /api/status and the UI.
   */
  ALLOW_DEMO_KEYS: bool.default('false'),
  /** Per-IP request budget for /api/zk/* per minute. */
  ZK_RATE_LIMIT_PER_MIN: z.coerce.number().int().min(10).max(1_000_000).default(240),
  MAX_PROOF_BYTES: z.coerce.number().int().min(512).max(65536).default(8192),

  /** Registry wire format: the team issuer (issuer.api v1/v2) or the P3 diagnostic stand-in. */
  REGISTRY_API: z.enum(['issuer-v1', 'p3-standin']).optional(),
  REGISTRY_URL: z.string().url().optional(),
  /** issuer.api v1 staleness rule: a root superseded only by inserts stays acceptable this long. */
  ROOT_STALENESS_SECONDS: z.coerce.number().int().min(0).max(30).default(30),
  REGISTRY_ADMIN_TOKEN: z.string().min(16).default(DEV_DEFAULTS.REGISTRY_ADMIN_TOKEN),
  REGISTRY_TIMEOUT_MS: z.coerce.number().int().min(100).max(10000).default(2000),
  /** Project Scope M2: root pulled on every request or at most every 30 s (staleness window). */
  ROOT_CACHE_MS: z.coerce.number().int().min(0).max(30000).default(2000),

  CHALLENGE_TTL_SECONDS: z.coerce.number().int().min(10).max(600).default(120),
  MAX_OUTSTANDING_CHALLENGES: z.coerce.number().int().min(10).max(1_000_000).default(10000),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(600),
  EPOCH_SECONDS: z.coerce.number().int().min(30).max(86400).default(600),
  NULLIFIER_MAX_PER_EPOCH: z.coerce.number().int().min(1).max(100).default(1),

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

export interface Config extends Omit<Env, 'REGISTRY_API' | 'REGISTRY_URL'> {
  REGISTRY_API: 'issuer-v1' | 'p3-standin';
  REGISTRY_URL: string;
  allowedOrigins: string[];
  artifactManifest: string;
  trustedIssuer: { Ax: string; Ay: string } | null;
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
    if (env.ALLOW_DEMO_KEYS) throw new Error('ALLOW_DEMO_KEYS must not be enabled in production');
  }
  const v4 = env.ZK_PROFILE === 'integrated-access-v4';
  if (v4 && env.EPOCH_SECONDS !== 600) {
    throw new Error(
      'EPOCH_SECONDS must be 600 for integrated-access-v4 (access.public_signals v4)',
    );
  }
  const registryApi = env.REGISTRY_API ?? (v4 ? 'issuer-v1' : 'p3-standin');
  const registryUrl =
    env.REGISTRY_URL ??
    (registryApi === 'issuer-v1' ? 'http://127.0.0.1:8100' : 'http://127.0.0.1:4600');
  const manifestDefault = v4
    ? resolve(TEAM_ROOT, 'circuits/setup/integrated_access_v4.manifest.json')
    : resolve(REPO_ROOT, 'artifacts/p1-integrated-v3/manifest.json');
  let trustedIssuer: Config['trustedIssuer'] = null;
  if (env.TRUSTED_ISSUER_AX && env.TRUSTED_ISSUER_AY) {
    trustedIssuer = { Ax: env.TRUSTED_ISSUER_AX, Ay: env.TRUSTED_ISSUER_AY };
  } else if (env.TRUSTED_ISSUER_FILE) {
    const file = resolve(REPO_ROOT, env.TRUSTED_ISSUER_FILE);
    if (existsSync(file)) {
      const k = JSON.parse(readFileSync(file, 'utf8')) as { Ax?: unknown; Ay?: unknown };
      if (typeof k.Ax === 'string' && typeof k.Ay === 'string')
        trustedIssuer = { Ax: k.Ax, Ay: k.Ay };
    }
  }
  return {
    ...env,
    REGISTRY_API: registryApi,
    REGISTRY_URL: registryUrl,
    artifactManifest: env.ARTIFACT_MANIFEST
      ? resolve(REPO_ROOT, env.ARTIFACT_MANIFEST)
      : manifestDefault,
    trustedIssuer,
    allowedOrigins: env.ALLOWED_ORIGINS.split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    benchResultsFile: resolve(REPO_ROOT, env.BENCH_RESULTS_FILE ?? 'bench/results/latest.json'),
    auditReportFile: resolve(REPO_ROOT, 'evidence/p1-audit-report.json'),
    usingDevSecrets,
  };
}
