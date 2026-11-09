/**
 * Diagnostic persona fixtures for the P1 v3 circuit. These contain PRIVATE witness
 * material (secrets, salts) and a throwaway development issuer key, mirroring what
 * P1's generate_integrated_v3.js does. They exist only so P3 can exercise the real
 * circuit before P2 delivers its issuer/prover. They are not credentials of a real issuer.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { FIXTURE_FILE } from './paths.js';
import type { IssuerKey, P1Attributes, Signature } from './p1.js';
import { commitmentOf, newIssuerKey, randomField, signCommitment, P1_TREE_SIZE } from './p1.js';

export interface PersonaFixture {
  credentialId: string;
  persona: 'alice' | 'bob' | 'carol';
  label: string;
  /** P1 attribute encoding is UNCONFIRMED. Values chosen against FileShareAccess(): role∈{2,3}, clearance∈{2,3}. */
  attributes: P1Attributes;
  secret: string;
  salt: string;
  commitment: string;
  signature: Signature;
  slot: number;
}

export interface FixtureFile {
  warning: string;
  createdAt: string;
  devIssuer: IssuerKey;
  personas: PersonaFixture[];
  /** Initial leaf values (decimal) of the depth-2 tree. */
  leaves: string[];
}

const SPECS: Array<Pick<PersonaFixture, 'persona' | 'label' | 'attributes'>> = [
  {
    persona: 'alice',
    label: 'Alice — Engineer',
    attributes: { role: 2, clearance: 2, deviceCompliant: 1, employeeActive: 1 },
  },
  {
    persona: 'bob',
    label: 'Bob — Contractor',
    attributes: { role: 1, clearance: 1, deviceCompliant: 1, employeeActive: 1 },
  },
  {
    persona: 'carol',
    label: 'Carol — Admin',
    attributes: { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
  },
];

export async function generateFixtures(): Promise<FixtureFile> {
  const devIssuer = await newIssuerKey();
  const personas: PersonaFixture[] = [];
  for (const [slot, spec] of SPECS.entries()) {
    const secret = randomField();
    const salt = randomField();
    const commitment = await commitmentOf(secret, salt);
    personas.push({
      ...spec,
      credentialId: `cred-${spec.persona}`,
      secret: secret.toString(),
      salt: salt.toString(),
      commitment: commitment.toString(),
      signature: await signCommitment(devIssuer, commitment),
      slot,
    });
  }
  const leaves = Array.from(
    { length: P1_TREE_SIZE },
    (_, i) => personas.find((p) => p.slot === i)?.commitment ?? '0',
  );
  return {
    warning:
      'DIAGNOSTIC FIXTURES — private witness data and a throwaway dev issuer key. Never use outside local testing.',
    createdAt: new Date().toISOString(),
    devIssuer,
    personas,
    leaves,
  };
}

export async function loadOrCreateFixtures(file = FIXTURE_FILE): Promise<FixtureFile> {
  if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf8')) as FixtureFile;
  const fixtures = await generateFixtures();
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(fixtures, null, 2), { mode: 0o600 });
  return fixtures;
}
