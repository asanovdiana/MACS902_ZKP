// One-time local setup for the team v4 stack:
//  1. starts the team issuer (profile v4) with its key/data under p3/.v4-demo/issuer (unless one is
//     already running at ISSUER_URL),
//  2. enrols Alice, Bob and Carol with the team's seed script (admin enrolment + wallet redemption;
//     secrets stay in p3/.v4-demo/wallets/<name>),
//  3. pins the issuer's public key for the gateway in p3/.v4-demo/issuer-pin.json (obligation 2).
// Re-running is safe: existing personas are skipped and the issuer key persists.
import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const P3 = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TEAM = resolve(P3, '..');
const DEMO = join(P3, '.v4-demo');
const ISSUER_URL = process.env.ISSUER_URL ?? 'http://127.0.0.1:8100';
const TOKEN = process.env.ISSUER_ADMIN_TOKEN ?? 'dev-registry-admin-token-change-me-0000';

const keyDir = join(DEMO, 'issuer/keys');
mkdirSync(keyDir, { recursive: true });
chmodSync(keyDir, 0o700);
mkdirSync(join(DEMO, 'issuer/data'), { recursive: true });
mkdirSync(join(DEMO, 'wallets'), { recursive: true });

const getIssuer = async () => {
  try {
    const r = await fetch(`${ISSUER_URL}/issuer`);
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
};

let child = null;
let info = await getIssuer();
if (!info) {
  console.log('[v4-setup] starting the team issuer (profile v4)');
  child = spawn(process.execPath, [join(TEAM, 'issuer/src/main.js')], {
    env: {
      ...process.env,
      ISSUER_PROFILE: 'v4',
      ISSUER_ADMIN_TOKEN: TOKEN,
      ISSUER_KEY_DIR: keyDir,
      ISSUER_DATA_DIR: join(DEMO, 'issuer/data'),
      ISSUER_LOG_LEVEL: 'warn',
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let i = 0; i < 60 && !info; i++) {
    await new Promise((r) => setTimeout(r, 250));
    info = await getIssuer();
  }
  if (!info) throw new Error('team issuer did not start');
}
if (info.profile !== 'v4')
  throw new Error(`issuer at ${ISSUER_URL} serves profile ${info.profile}, expected v4`);

await new Promise((res, rej) => {
  const s = spawn(
    process.execPath,
    [
      join(TEAM, 'issuer/scripts/seed-personas.js'),
      '--issuer',
      ISSUER_URL,
      '--home',
      join(DEMO, 'wallets'),
    ],
    {
      env: { ...process.env, ISSUER_ADMIN_TOKEN: TOKEN },
      stdio: 'inherit',
    },
  );
  s.on('exit', (code) => (code === 0 ? res() : rej(new Error(`seed-personas exited ${code}`))));
});

writeFileSync(
  join(DEMO, 'issuer-pin.json'),
  JSON.stringify(
    {
      Ax: info.issuer.Ax,
      Ay: info.issuer.Ay,
      issuerUrl: ISSUER_URL,
      pinnedAt: new Date().toISOString(),
    },
    null,
    2,
  ) + '\n',
);
console.log(`[v4-setup] pinned issuer key in ${join('p3/.v4-demo', 'issuer-pin.json')}`);
child?.kill('SIGTERM');
