// Prints which required tools / artifacts are available. Exit code 0 always (informational).
import { existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
const has = (cmd) => {
  try {
    execSync(`${cmd} --version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
};
const rows = [
  ['node >= 20', Number(process.versions.node.split('.')[0]) >= 20],
  ['docker', has('docker')],
  ['P1 artifacts (make p1-build)', existsSync('artifacts/p1-integrated-v3/manifest.json')],
  ['P1 audit report', existsSync('evidence/p1-audit-report.json')],
  ['benchmark results', existsSync('bench/results/latest.json')],
];
for (const [k, ok] of rows) console.log(`${ok ? '✔' : '✘'} ${k}`);
