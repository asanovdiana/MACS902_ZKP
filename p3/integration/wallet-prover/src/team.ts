import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** The team repository root (p3/integration/wallet-prover/src → ../../../..). */
export const TEAM_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
export const P3_ROOT = resolve(TEAM_ROOT, 'p3');
const require = createRequire(import.meta.url);

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface TeamClient {
  Wallet: new (o: { home: string }) => { load(name: string): any };
  IssuerClient: new (o: { baseUrl: string }) => any;
  prove(o: {
    credential: any;
    issuer: any;
    challenge: unknown;
  }): Promise<{ profile: string; proof: unknown; publicSignals: string[] }>;
  ClientError: new (...a: any[]) => Error & { code: string };
  shutdown(): Promise<void>;
}
export interface TeamAttacks {
  ATTACKS:
    | Record<string, { title: string; scope?: string; floor?: unknown }>
    | Array<{ id: string; title: string }>;
  ATTACK_IDS: string[];
  createWorld(o: { issuerUrl: string; adminToken: string }): Promise<any>;
  buildAttack(id: string, world: any): Promise<any>;
  runAttack(built: any, o: { send: any; wait?: any; skipWaits?: boolean }): Promise<any>;
  httpSender(gatewayUrl: string): any;
  httpChallengeSource(gatewayUrl: string): any;
  shutdown(): Promise<void>;
}

export const teamAvailable = () =>
  existsSync(resolve(TEAM_ROOT, 'client/src/index.js')) &&
  existsSync(resolve(TEAM_ROOT, 'circuits/setup/integrated_access_v4.zkey'));
export const loadClient = (): TeamClient => require(resolve(TEAM_ROOT, 'client/src/index.js'));
export const loadAttacks = (): TeamAttacks =>
  require(resolve(TEAM_ROOT, 'client/attacks/src/index.js'));
