// Writes artifacts/p1-integrated-v3/manifest.json describing the compiled P1 artifacts.
// Hashes bind the verification key, wasm, zkey and r1cs to the exact P1 source files.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const [p1Dir, outDir] = process.argv.slice(2);
if (!p1Dir || !outDir) throw new Error('usage: p1-manifest.mjs <p1Dir> <outDir>');
const sha256 = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
const walk = (d) =>
  readdirSync(d).flatMap((f) => {
    const p = join(d, f);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
const sources = Object.fromEntries(
  walk(join(p1Dir, 'circuits'))
    .filter((p) => p.endsWith('.circom'))
    .sort()
    .map((p) => [relative(p1Dir, p), sha256(p)]),
);
const vkey = JSON.parse(readFileSync(join(outDir, 'verification_key.json'), 'utf8'));
const manifest = {
  circuitId: 'integrated_access_v3',
  profile: 'p1-integrated-v3',
  version: 'development',
  proofSystem: 'groth16',
  curve: 'bn128',
  compiler: 'circom 2.2.3 (circom2 npm WASM build 0.2.23)',
  trustedSetup:
    'DEVELOPMENT ONLY: locally generated powers of tau + single P3 phase-2 contribution',
  nPublic: vkey.nPublic,
  publicSignals: ['root'],
  securityStatus: 'insecure-diagnostic-only',
  generatedAt: new Date().toISOString(),
  files: {
    verificationKey: {
      path: 'verification_key.json',
      sha256: sha256(join(outDir, 'verification_key.json')),
    },
    wasm: {
      path: 'integrated_access_v3.wasm',
      sha256: sha256(join(outDir, 'integrated_access_v3.wasm')),
    },
    zkey: {
      path: 'integrated_access_v3.zkey',
      sha256: sha256(join(outDir, 'integrated_access_v3.zkey')),
    },
    r1cs: {
      path: 'integrated_access_v3.r1cs',
      sha256: sha256(join(outDir, 'integrated_access_v3.r1cs')),
    },
  },
  p1Sources: sources,
};
writeFileSync(join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(
  `[p1-manifest] nPublic=${manifest.nPublic} files hashed: ${Object.keys(manifest.files).length}`,
);
