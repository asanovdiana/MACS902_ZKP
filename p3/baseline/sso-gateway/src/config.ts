import { z } from 'zod';

const DEV = {
  OIDC_CLIENT_SECRET: 'dev-sso-baseline-client-secret-change-me',
  ASSERTION_SECRET_SSO: 'dev-sso-baseline-assertion-secret-change-me-000',
  OPERATOR_TOKEN: 'dev-operator-token-change-me-000000',
};

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  SSO_HOST: z.string().default('127.0.0.1'),
  SSO_PORT: z.coerce.number().int().default(4200),
  /** Browser-facing Keycloak base URL; also the `iss` prefix Keycloak puts in tokens (KC_HOSTNAME). */
  KEYCLOAK_PUBLIC_URL: z.string().url().default('http://localhost:8080'),
  /** Back-channel URL used by this server for token exchange and JWKS. */
  KEYCLOAK_INTERNAL_URL: z.string().url().default('http://127.0.0.1:8080'),
  KEYCLOAK_REALM: z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .default('zkag'),
  OIDC_CLIENT_ID: z.string().default('zkag-sso-baseline'),
  OIDC_CLIENT_SECRET: z.string().min(16).default(DEV.OIDC_CLIENT_SECRET),
  /** Public URL of /sso/callback as seen by the browser (via the UI origin). */
  OIDC_REDIRECT_URI: z.string().url().default('http://localhost:5173/sso/callback'),
  POST_LOGOUT_REDIRECT_URI: z.string().url().default('http://localhost:5173/compare'),
  ASSERTION_SECRET_SSO: z.string().min(32).default(DEV.ASSERTION_SECRET_SSO),
  OPERATOR_TOKEN: z.string().min(24).default(DEV.OPERATOR_TOKEN),
  ALLOWED_ORIGINS: z
    .string()
    .default('http://localhost:5173,http://127.0.0.1:5173,http://localhost:8088'),
  COOKIE_SECURE: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  UPSTREAM_WIKI_URL: z.string().url().default('http://127.0.0.1:4101'),
  UPSTREAM_FILE_SHARE_URL: z.string().url().default('http://127.0.0.1:4102'),
  UPSTREAM_ADMIN_PANEL_URL: z.string().url().default('http://127.0.0.1:4103'),
});

export type SsoConfig = z.infer<typeof schema> & {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  endSessionEndpoint: string;
  allowedOrigins: string[];
};

export function loadSsoConfig(src: NodeJS.ProcessEnv = process.env): SsoConfig {
  const env = schema.parse(src);
  if (env.NODE_ENV === 'production') {
    const dev = (Object.keys(DEV) as Array<keyof typeof DEV>).filter((k) => env[k] === DEV[k]);
    if (dev.length)
      throw new Error(`refusing to start in production with dev secrets: ${dev.join(', ')}`);
  }
  const realmPublic = `${env.KEYCLOAK_PUBLIC_URL.replace(/\/$/, '')}/realms/${env.KEYCLOAK_REALM}`;
  const realmInternal = `${env.KEYCLOAK_INTERNAL_URL.replace(/\/$/, '')}/realms/${env.KEYCLOAK_REALM}`;
  return {
    ...env,
    issuer: realmPublic,
    authorizationEndpoint: `${realmPublic}/protocol/openid-connect/auth`,
    endSessionEndpoint: `${realmPublic}/protocol/openid-connect/logout`,
    tokenEndpoint: `${realmInternal}/protocol/openid-connect/token`,
    jwksUri: `${realmInternal}/protocol/openid-connect/certs`,
    allowedOrigins: env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()),
  };
}
