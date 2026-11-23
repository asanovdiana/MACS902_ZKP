/**
 * Benchmark harness. Every number written here is MEASURED in this process with
 * performance.now(); anything that cannot be measured in the current environment is
 * emitted with status "blocked" and a reason. Output: bench/results/latest.json + CSV.
 */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  existsSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { cpus, platform, release, tmpdir, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import * as snarkjs from 'snarkjs';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { summarize } from './stats.js';
import { createApp } from '../../gateway/src/app/createApp.js';
import { loadConfig, REPO_ROOT } from '../../gateway/src/config/env.js';
import { generateFixtures } from '../../integration/p2-standin/src/fixtures.js';
import { createStandin } from '../../integration/p2-standin/src/server.js';
import {
  buildV3Input,
  proveV3,
  verifyV3,
  artifactsAvailable,
  shutdown,
} from '../../integration/p2-standin/src/p1.js';
import { createSsoApp } from '../../baseline/sso-gateway/src/app.js';
import { loadSsoConfig } from '../../baseline/sso-gateway/src/config.js';
import { createWiki } from '../../services/src/wiki.js';

const N = Number(process.env.BENCH_ITERATIONS ?? 100);
const N_PROVE = Number(process.env.BENCH_PROVE_ITERATIONS ?? N);
const OUT = resolve(REPO_ROOT, 'bench/results');
const ART = resolve(REPO_ROOT, 'artifacts/p1-integrated-v3');

type Metric = Record<string, unknown> & {
  id: string;
  label: string;
  unit: string;
  status: 'measured' | 'blocked';
};
const metrics: Metric[] = [];
const measured = (id: string, label: string, unit: string, samples: number[], note?: string) => {
  metrics.push({
    id,
    label,
    unit,
    status: 'measured',
    ...summarize(samples),
    ...(note ? { note } : {}),
  });
  const m = metrics.at(-1)!;
  console.log(
    `  ${label.padEnd(58)} n=${String(m.samples).padStart(3)} median=${(m.median as number).toFixed(2)} p95=${(m.p95 as number).toFixed(2)} ${unit}`,
  );
};
const blocked = (id: string, label: string, unit: string, reason: string) => {
  metrics.push({ id, label, unit, status: 'blocked', reason });
  console.log(`  ${label.padEnd(58)} BLOCKED: ${reason}`);
};
const listen = (s: Server) =>
  new Promise<string>((r) =>
    s.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)),
  );
async function post(url: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

console.log(`[bench] iterations=${N} prove-iterations=${N_PROVE}`);
if (!artifactsAvailable(ART)) {
  console.error(
    '[bench] P1 artifacts missing — run `npm run p1:build`. Cryptographic metrics will be blocked.',
  );
}
const servers: Server[] = [];
let manifest: Record<string, unknown> = {};

if (artifactsAvailable(ART)) {
  manifest = JSON.parse(readFileSync(join(ART, 'manifest.json'), 'utf8'));
  const r1cs = await snarkjs.r1cs.info(join(ART, 'integrated_access_v3.r1cs'), undefined);
  metrics.push({
    id: 'constraints',
    label: 'Circuit size (R1CS constraints)',
    unit: 'constraints',
    status: 'measured',
    samples: 1,
    median: r1cs.nConstraints,
    p95: r1cs.nConstraints,
    min: r1cs.nConstraints,
    max: r1cs.nConstraints,
    note: `${r1cs.nPrvInputs} private inputs, ${r1cs.nPubInputs} public input(s)`,
  });
  console.log(`  constraints: ${r1cs.nConstraints}`);

  const fx = await generateFixtures();
  const alice = fx.personas[0]!;
  const input = await buildV3Input({
    secret: BigInt(alice.secret),
    salt: BigInt(alice.salt),
    attributes: alice.attributes,
    issuer: fx.devIssuer,
    signature: alice.signature,
    leaves: fx.leaves.map(BigInt),
    index: alice.slot,
  });

  // Proving (native Node, snarkjs fullProve = witness generation + Groth16 prove).
  const proveT: number[] = [];
  const sizes: number[] = [];
  let sample: Awaited<ReturnType<typeof proveV3>> | null = null;
  await proveV3(input, ART); // warm-up (curve + wasm instantiation), excluded
  for (let i = 0; i < N_PROVE; i++) {
    const r = await proveV3(input, ART);
    proveT.push(r.provingMs);
    sizes.push(Buffer.byteLength(JSON.stringify(r.proof)));
    sample = r;
  }
  measured(
    'prove',
    'Proving time, native Node (witness + Groth16)',
    'ms',
    proveT,
    'snarkjs.groth16.fullProve, P1 integrated_access_v3, depth-2 tree; 1 warm-up excluded',
  );
  measured('proof-json', 'Proof size as JSON (decimal strings)', 'bytes', sizes);
  metrics.push({
    id: 'proof-size',
    label: 'Proof size (BN254 Groth16, uncompressed affine)',
    unit: 'bytes',
    status: 'measured',
    samples: sizes.length,
    median: 256,
    p95: 256,
    min: 256,
    max: 256,
    note: 'A,C ∈ G1 (64 B each) + B ∈ G2 (128 B); fixed by the proof system, structure checked on every sample',
  });

  // Verification (warm), plus one cold measurement in a fresh curve.
  const verifyT: number[] = [];
  for (let i = 0; i < N; i++)
    verifyT.push((await verifyV3(sample!.proof, sample!.publicSignals, ART)).verifyMs);
  measured('verify', 'Verify time at gateway (snarkjs groth16.verify, warm)', 'ms', verifyT);

  // Gateway end-to-end over HTTP with the P2 stand-in as registry (real network hops on loopback).
  const { app: standin } = await createStandin(fx);
  const sSrv = createServer(standin);
  servers.push(sSrv);
  const registryUrl = await listen(sSrv);
  const config = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    ZK_PROFILE: 'p1-integrated-v3',
    REGISTRY_URL: registryUrl,
    ROOT_CACHE_MS: process.env.BENCH_ROOT_CACHE_MS ?? '2000',
    MAX_OUTSTANDING_CHALLENGES: '100000',
    CHALLENGE_TTL_SECONDS: '600',
    ZK_RATE_LIMIT_PER_MIN: '1000000',
  });
  const { app: gwApp, ctx } = createApp({ config });
  const gSrv = createServer(gwApp);
  servers.push(gSrv);
  const gw = await listen(gSrv);
  const body = { proof: sample!.proof, publicSignals: sample!.publicSignals };
  const e2e: number[] = [];
  const gwVerify: number[] = [];
  for (let i = 0; i < N + 1; i++) {
    const t0 = performance.now();
    const c = await post(`${gw}/api/zk/challenges`, { resource: 'file-share' });
    const v = await post(`${gw}/api/zk/verify`, { challengeId: c.body.challengeId, ...body });
    const dt = performance.now() - t0;
    if (i === 0) continue; // warm-up
    if (v.body.groth16 && (v.body.groth16 as { valid: boolean }).valid !== true)
      throw new Error('bench proof did not verify');
    e2e.push(dt);
    gwVerify.push((v.body.timings as { totalMs: number }).totalMs);
  }
  measured(
    'gateway-e2e',
    'ZK gateway: challenge + verify, HTTP round trips',
    'ms',
    e2e,
    `decision=${ctx.pipeline.authorizationEligible().eligible ? 'granted' : 'blocked (diagnostic P1 profile)'}; root cache ${config.ROOT_CACHE_MS} ms`,
  );
  measured(
    'gateway-pipeline',
    'ZK gateway: server-side verification pipeline',
    'ms',
    gwVerify,
    'schema → challenge → registry root → Groth16 → decision',
  );
  const rejInvalid: number[] = [];
  const bad = structuredClone(sample!.proof);
  bad.pi_c[0] = (BigInt(bad.pi_c[0]!) + 1n).toString();
  for (let i = 0; i < N; i++) {
    const c = await post(`${gw}/api/zk/challenges`, { resource: 'file-share' });
    const t0 = performance.now();
    const v = await post(`${gw}/api/zk/verify`, {
      challengeId: c.body.challengeId,
      proof: bad,
      publicSignals: sample!.publicSignals,
    });
    rejInvalid.push(performance.now() - t0);
    if (v.body.reason !== 'PROOF_INVALID')
      throw new Error(`expected PROOF_INVALID got ${v.body.reason}`);
  }
  measured(
    'gateway-reject-invalid',
    'Rejected request: invalid proof (verify HTTP)',
    'ms',
    rejInvalid,
  );
  const rejReplay: number[] = [];
  const c0 = await post(`${gw}/api/zk/challenges`, { resource: 'file-share' });
  await post(`${gw}/api/zk/verify`, { challengeId: c0.body.challengeId, ...body });
  for (let i = 0; i < N; i++) {
    const t0 = performance.now();
    const v = await post(`${gw}/api/zk/verify`, { challengeId: c0.body.challengeId, ...body });
    rejReplay.push(performance.now() - t0);
    if (v.status !== 409) throw new Error('expected replay rejection');
  }
  measured(
    'gateway-reject-replay',
    'Rejected request: replayed challenge (verify HTTP)',
    'ms',
    rejReplay,
  );
} else {
  for (const [id, label] of [
    ['prove', 'Proving time'],
    ['verify', 'Verify time'],
    ['proof-size', 'Proof size'],
    ['gateway-e2e', 'ZK gateway end-to-end'],
  ])
    blocked(id!, label!, 'ms', 'P1 artifacts missing');
}

// SSO baseline per-request authorization (real RS256 JWT validation + policy + proxy to the real Wiki service).
{
  const kp = await generateKeyPair('RS256');
  const jwks = createLocalJWKSet({
    keys: [{ ...(await exportJWK(kp.publicKey)), kid: 'b', alg: 'RS256' }],
  });
  const ISS = 'http://localhost:8080/realms/zkag';
  const secrets = {
    zk: 'bench-zk-secret-0123456789abcdef012345',
    sso: 'bench-sso-secret-0123456789abcdef01234',
  };
  const wSrv = createServer(createWiki(secrets));
  servers.push(wSrv);
  const wiki = await listen(wSrv);
  const ssoCfg = loadSsoConfig({
    NODE_ENV: 'test',
    ASSERTION_SECRET_SSO: secrets.sso,
    UPSTREAM_WIKI_URL: wiki,
  });
  let nonce = '';
  const tok = (extra: Record<string, unknown>) =>
    new SignJWT({
      azp: ssoCfg.OIDC_CLIENT_ID,
      typ: 'Bearer',
      preferred_username: 'alice',
      email: 'alice@northwind.example',
      realm_access: { roles: ['engineer'] },
      clearance: 2,
      device_compliant: true,
      ...extra,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'b' })
      .setIssuer(ISS)
      .setAudience(ssoCfg.OIDC_CLIENT_ID)
      .setSubject('alice')
      .setIssuedAt()
      .setExpirationTime('30m')
      .sign(kp.privateKey);
  const sso = createSsoApp({
    config: ssoCfg,
    keys: jwks,
    exchangeCode: async () => ({ id_token: await tok({ nonce }), access_token: await tok({}) }),
  });
  const ssoSrv = createServer(sso.app);
  servers.push(ssoSrv);
  const base = await listen(ssoSrv);
  const start = await fetch(`${base}/sso/login`, { redirect: 'manual' });
  const loc = new URL(start.headers.get('location')!);
  nonce = loc.searchParams.get('nonce')!;
  const stateCookie = start.headers.get('set-cookie')!.split(';')[0]!;
  const cb = await fetch(`${base}/sso/callback?code=x&state=${loc.searchParams.get('state')}`, {
    redirect: 'manual',
    headers: { cookie: stateCookie },
  });
  const sess = cb.headers
    .getSetCookie()
    .find((c) => c.startsWith('zkag_sso='))!
    .split(';')[0]!;
  const ssoT: number[] = [];
  for (let i = 0; i < N + 1; i++) {
    const t0 = performance.now();
    const r = await fetch(`${base}/sso/svc/wiki/`, { headers: { cookie: sess } });
    await r.arrayBuffer();
    if (r.status !== 200) throw new Error(`sso ${r.status}`);
    if (i > 0) ssoT.push(performance.now() - t0);
  }
  measured(
    'sso-request',
    'SSO baseline: per-request JWT validation + policy + proxy',
    'ms',
    ssoT,
    'local JWKS; excludes the Keycloak login round trip',
  );
  const e2e = metrics.find((m) => m.id === 'gateway-e2e');
  if (e2e?.status === 'measured') {
    metrics.push({
      id: 'zk-vs-sso',
      label: 'ZK authorization overhead vs SSO request (median difference)',
      unit: 'ms',
      status: 'measured',
      samples: Math.min(e2e.samples as number, ssoT.length),
      median: (e2e.median as number) - summarize(ssoT).median,
      p95: (e2e.p95 as number) - summarize(ssoT).p95,
      min: NaN,
      max: NaN,
      note: 'ZK challenge+verify (excluding client proving) minus SSO per-request validation. Not like-for-like: ZK re-proves per session, SSO validates a token per request.',
    });
  }
}

// ---- Team v4 stack (her issuer + her client prover + this gateway, real proofs) ----
{
  const TEAM = resolve(REPO_ROOT, '..');
  const req = createRequire(import.meta.url);
  const has = [
    'issuer/src/server.js',
    'client/src/index.js',
    'circuits/setup/integrated_access_v4.zkey',
  ].every((f) => existsSync(resolve(TEAM, f)));
  if (!has) {
    blocked(
      'v4-prove',
      'v4 proving time (team client)',
      'ms',
      'team issuer/client/circuit not present',
    );
  } else {
    const v4m = JSON.parse(
      readFileSync(resolve(TEAM, 'circuits/setup/integrated_access_v4.manifest.json'), 'utf8'),
    );
    metrics.push({
      id: 'v4-constraints',
      label: 'v4 circuit size (R1CS constraints, --O2)',
      unit: 'constraints',
      status: 'measured',
      samples: 1,
      median: v4m.constraints,
      p95: v4m.constraints,
      min: v4m.constraints,
      max: v4m.constraints,
      note: `${v4m.n_public} public signals, depth 16 (from the team manifest)`,
    });
    const ADMIN = 'bench-admin-token-0123456789abcdef01';
    const { loadConfig: issuerConfig } = req(resolve(TEAM, 'issuer/src/config.js'));
    const { buildServer } = req(resolve(TEAM, 'issuer/src/server.js'));
    const keyDir = mkdtempSync(join(tmpdir(), 'zkag-bk-'));
    chmodSync(keyDir, 0o700);
    const issuerApp = await buildServer({
      config: issuerConfig({
        ISSUER_PROFILE: 'v4',
        ISSUER_ADMIN_TOKEN: ADMIN,
        ISSUER_KEY_DIR: keyDir,
        ISSUER_DATA_DIR: mkdtempSync(join(tmpdir(), 'zkag-bd-')),
        ISSUER_LOG_LEVEL: 'silent',
      }),
    });
    const issuerUrl: string = await issuerApp.listen({ host: '127.0.0.1', port: 0 });
    const walletRoot = mkdtempSync(join(tmpdir(), 'zkag-bw-'));
    await req(resolve(TEAM, 'issuer/scripts/seed-personas.js')).seedPersonas({
      issuerUrl,
      adminToken: ADMIN,
      homeRoot: walletRoot,
      only: ['alice'],
    });
    const key = (await (await fetch(`${issuerUrl}/issuer`)).json()).issuer;
    const wikiSecret = 'bench-zk-secret-v4-0123456789abcdef012';
    const w4 = createServer(
      createWiki({ zk: wikiSecret, sso: 'bench-sso-secret-v4-0123456789abcdef01' }),
    );
    servers.push(w4);
    const wiki4 = await listen(w4);
    const cfg4 = loadConfig({
      ASSERTION_SECRET_ZK: wikiSecret,
      UPSTREAM_WIKI_URL: wiki4,
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      ZK_PROFILE: 'integrated-access-v4',
      REGISTRY_URL: issuerUrl,
      REGISTRY_ADMIN_TOKEN: ADMIN,
      TRUSTED_ISSUER_AX: key.Ax,
      TRUSTED_ISSUER_AY: key.Ay,
      ALLOW_DEMO_KEYS: 'true',
      NULLIFIER_MAX_PER_EPOCH: '100',
      ZK_RATE_LIMIT_PER_MIN: '1000000',
      MAX_OUTSTANDING_CHALLENGES: '100000',
    });
    const { app: gw4 } = createApp({ config: cfg4 });
    const g4 = createServer(gw4);
    servers.push(g4);
    const gw4Url = await listen(g4);
    const client = req(resolve(TEAM, 'client/src/index.js'));
    const credential = new client.Wallet({ home: join(walletRoot, 'alice') }).load('alice');
    const issuer = new client.IssuerClient({ baseUrl: issuerUrl });
    const n4 = Number(process.env.BENCH_V4_ITERATIONS ?? N);
    const proveT: number[] = [];
    const verifyT: number[] = [];
    const e2eT: number[] = [];
    const vkey4 = JSON.parse(
      readFileSync(
        resolve(TEAM, 'circuits/setup/integrated_access_v4.verification_key.json'),
        'utf8',
      ),
    );
    let last: { proof: unknown; publicSignals: string[] } | null = null;
    for (let i = 0; i < n4 + 1; i++) {
      const t0 = performance.now();
      // Alternate services: a nullifier is capped at NULLIFIER_MAX_PER_EPOCH per (resource, epoch).
      const res4 = i % 2 ? 'wiki' : 'file_share';
      const c = await (await fetch(`${gw4Url}/challenge?resource=${res4}`)).json();
      const tp = performance.now();
      const p = await client.prove({ credential, issuer, challenge: c });
      const provedAt = performance.now();
      const v = await post(`${gw4Url}/access`, {
        resource: res4,
        nonce: c.nonce,
        proof: p.proof,
        publicSignals: p.publicSignals,
      });
      const t1 = performance.now();
      if (v.status !== 200)
        throw new Error(`v4 bench: gateway answered ${v.status} ${JSON.stringify(v.body)}`);
      if (i === 0) continue; // warm-up
      proveT.push(provedAt - tp);
      e2eT.push(t1 - t0);
      last = p;
    }
    for (let i = 0; i < N; i++) {
      const t0 = performance.now();
      const ok = await snarkjs.groth16.verify(vkey4, last!.publicSignals, last!.proof);
      verifyT.push(performance.now() - t0);
      if (!ok) throw new Error('v4 verify failed');
    }
    measured(
      'v4-prove',
      'v4 proving, native Node (team client: path fetch + witness + Groth16 + local verify)',
      'ms',
      proveT,
      'client.prove() incl. Merkle path fetch from the issuer and the client-side verification it performs',
    );
    measured(
      'v4-verify',
      'v4 verify time (snarkjs groth16.verify, warm, 12 public signals)',
      'ms',
      verifyT,
    );
    measured(
      'v4-e2e',
      'v4 end to end: challenge → prove → /access ADMIT (HTTP)',
      'ms',
      e2eT,
      'real issuer (in-process), real proofs, session issued every time',
    );
    metrics.push({
      id: 'v4-proof-size',
      label: 'v4 proof size (BN254 Groth16, uncompressed affine)',
      unit: 'bytes',
      status: 'measured',
      samples: proveT.length,
      median: 256,
      p95: 256,
      min: 256,
      max: 256,
      note: `${Buffer.byteLength(JSON.stringify(last!.proof))} B as JSON`,
    });
    // Session-authorized proxied request (like-for-like with the SSO per-request measurement).
    const cs = await (await fetch(`${gw4Url}/challenge?resource=wiki`)).json();
    const ps = await client.prove({ credential, issuer, challenge: cs });
    const adm = await fetch(`${gw4Url}/access`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        resource: 'wiki',
        nonce: cs.nonce,
        proof: ps.proof,
        publicSignals: ps.publicSignals,
      }),
    });
    const cookie = adm.headers
      .getSetCookie()
      .find((c) => c.startsWith('zkag_wiki='))
      ?.split(';')[0];
    if (adm.status !== 200 || !cookie)
      throw new Error(`v4 bench: session admit failed (${adm.status})`);
    const sessT: number[] = [];
    for (let i = 0; i < N + 1; i++) {
      const t0 = performance.now();
      const r = await fetch(`${gw4Url}/svc/wiki/`, { headers: { cookie } });
      await r.arrayBuffer();
      if (r.status !== 200) throw new Error(`v4 session request ${r.status}`);
      if (i > 0) sessT.push(performance.now() - t0);
    }
    measured(
      'zk-session-request',
      'ZK gateway: per-request with a session (registry root check + proxy)',
      'ms',
      sessT,
      'like-for-like with the SSO per-request row',
    );
    await client.shutdown();
    await issuerApp.close();
  }
}

blocked(
  'keycloak-login',
  'Keycloak login round trip (Authorization Code + PKCE)',
  'ms',
  'not automated: needs an interactive Keycloak browser login (measure manually with docker compose up keycloak)',
);
blocked(
  'prove-browser',
  'Proving time, browser (N1)',
  'ms',
  'in-browser proving (nice-to-have N1) not implemented',
);
blocked(
  'prove-vs-depth',
  'Proving time vs Merkle depth (8, 16, 20)',
  'ms',
  'team depth-8/20 benchmark mains exist (circuits/integrated_access_v4_d8/_d20) but have no committed keys; see npm run perf:v4 at the repo root',
);

const result = {
  generatedAt: new Date().toISOString(),
  environment: {
    node: process.version,
    platform: `${platform()} ${release()}`,
    cpu: cpus()[0]?.model ?? 'unknown',
    cores: cpus().length,
    memoryGiB: Math.round(totalmem() / 2 ** 30),
  },
  artifact: {
    circuitId: manifest.circuitId ?? null,
    version: manifest.version ?? null,
    trustedSetup: manifest.trustedSetup ?? null,
    vkeySha256:
      (manifest.files as { verificationKey?: { sha256: string } } | undefined)?.verificationKey
        ?.sha256 ?? null,
  },
  config: {
    iterations: N,
    proveIterations: N_PROVE,
    timer: 'performance.now()',
    warmupExcluded: true,
    gatewayRateLimit: 'raised for benchmarking only',
    transport: 'HTTP/1.1 over loopback',
  },
  metrics,
};
mkdirSync(OUT, { recursive: true });
const stamp = result.generatedAt.replace(/[:.]/g, '-');
writeFileSync(join(OUT, 'latest.json'), JSON.stringify(result, null, 2) + '\n');
writeFileSync(join(OUT, `bench-${stamp}.json`), JSON.stringify(result, null, 2) + '\n');
const csv = [
  'id,label,unit,status,samples,median,p95,min,max,mean,note_or_reason',
  ...metrics.map((m) =>
    [
      m.id,
      m.label,
      m.unit,
      m.status,
      m.samples ?? '',
      m.median ?? '',
      m.p95 ?? '',
      m.min ?? '',
      m.max ?? '',
      m.mean ?? '',
      m.note ?? m.reason ?? '',
    ]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(','),
  ),
];
writeFileSync(join(OUT, 'latest.csv'), csv.join('\n') + '\n');
console.log(`[bench] wrote ${join(OUT, 'latest.json')} and latest.csv`);
servers.forEach((s) => s.close());
await shutdown();
process.exit(existsSync(join(OUT, 'latest.json')) ? 0 : 1);
