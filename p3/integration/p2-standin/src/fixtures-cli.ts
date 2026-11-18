import { rmSync } from 'node:fs';
import { FIXTURE_FILE } from './paths.js';
import { loadOrCreateFixtures } from './fixtures.js';

if (process.argv.includes('--regenerate')) rmSync(FIXTURE_FILE, { force: true });
const f = await loadOrCreateFixtures();
console.log(`[fixtures] ${f.personas.length} diagnostic personas at ${FIXTURE_FILE}`);
process.exit(0);
