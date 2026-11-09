import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(here, '../../..');
export const P1_ARTIFACT_DIR = resolve(
  process.env.P1_ARTIFACT_DIR ?? resolve(REPO_ROOT, 'artifacts/p1-integrated-v3'),
);
export const FIXTURE_FILE = resolve(
  process.env.P1_FIXTURE_FILE ?? resolve(REPO_ROOT, 'artifacts/fixtures/p1-personas.json'),
);
