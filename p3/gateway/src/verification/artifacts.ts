import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import type { CircuitProfile } from './profiles.js';

/**
 * Normalised view of a circuit manifest. Two on-disk formats are accepted:
 *  - the team format (circuits/setup/<name>.manifest.json: name, public_signals, n_public,
 *    verification_key_sha256, status), and
 *  - the P3 diagnostic format (artifacts/<profile>/manifest.json: circuitId, publicSignals, nPublic,
 *    files.verificationKey, securityStatus, securityReview).
 */
export interface ArtifactManifest {
  circuitId: string;
  version: string;
  proofSystem: string;
  curve: string;
  nPublic: number;
  publicSignals: string[];
  securityStatus: string;
  trustedSetup?: string;
  securityReview?: { status: 'accepted' | 'rejected' | 'pending' };
  vkeyPath: string;
  vkeySha256: string;
  manifestPath: string;
}

export interface VerificationKey {
  protocol: string;
  curve: string;
  nPublic: number;
  [k: string]: unknown;
}

export type KeyTrust = 'reviewed' | 'demo-accepted' | 'unreviewed';

export type ArtifactState =
  | {
      status: 'ready';
      manifest: ArtifactManifest;
      vkey: VerificationKey;
      vkeySha256: string;
      /** true when sessions may be issued under this key (reviewed, or demo keys explicitly allowed). */
      reviewed: boolean;
      trust: KeyTrust;
    }
  | { status: 'missing' | 'invalid'; detail: string };

const sha256 = (buf: Buffer) => createHash('sha256').update(buf).digest('hex');
type Raw = Record<string, unknown>;

function normalise(raw: Raw, manifestPath: string): ArtifactManifest | string {
  const dir = dirname(manifestPath);
  if (typeof raw.name === 'string' && Array.isArray(raw.public_signals)) {
    // Team format.
    const ptau = raw.ptau as Raw | undefined;
    return {
      circuitId: raw.name,
      version: String(raw.status ?? 'unknown'),
      proofSystem: String(raw.protocol ?? ''),
      curve: String(raw.curve ?? ''),
      nPublic: Number(raw.n_public),
      publicSignals: raw.public_signals as string[],
      securityStatus: String(raw.status_detail ?? raw.status ?? 'unknown'),
      trustedSetup: ptau
        ? `phase 1: ${String(ptau.source)}; ${String(raw.status_detail ?? '')}`
        : undefined,
      securityReview:
        String(raw.status ?? '').toUpperCase() === 'REVIEWED' ? { status: 'accepted' } : undefined,
      vkeyPath: join(dir, `${raw.name}.verification_key.json`),
      vkeySha256: String(raw.verification_key_sha256 ?? ''),
      manifestPath,
    };
  }
  if (typeof raw.circuitId === 'string' && Array.isArray(raw.publicSignals)) {
    const files = raw.files as { verificationKey?: { path?: string; sha256?: string } } | undefined;
    return {
      circuitId: raw.circuitId,
      version: String(raw.version ?? 'unknown'),
      proofSystem: String(raw.proofSystem ?? ''),
      curve: String(raw.curve ?? ''),
      nPublic: Number(raw.nPublic),
      publicSignals: raw.publicSignals as string[],
      securityStatus: String(raw.securityStatus ?? 'unknown'),
      trustedSetup: typeof raw.trustedSetup === 'string' ? raw.trustedSetup : undefined,
      securityReview: raw.securityReview as ArtifactManifest['securityReview'],
      vkeyPath: join(dir, files?.verificationKey?.path ?? 'verification_key.json'),
      vkeySha256: String(files?.verificationKey?.sha256 ?? ''),
      manifestPath,
    };
  }
  return 'unrecognised manifest format';
}

const isDemoKey = (m: ArtifactManifest) =>
  /DEV-ONLY|DEMO-ONLY/i.test(`${m.version} ${m.securityStatus}`);

/**
 * Load and integrity-check verification artifacts for a profile. Any mismatch between manifest,
 * verification key and profile signal layout makes the artifacts unusable (fail closed).
 */
export function loadArtifacts(
  manifestPath: string,
  profile: CircuitProfile,
  opts: { allowDemoKeys?: boolean } = {},
): ArtifactState {
  if (!existsSync(manifestPath))
    return { status: 'missing', detail: `no manifest at ${manifestPath}` };
  let raw: Raw;
  try {
    raw = JSON.parse(readFileSync(manifestPath, 'utf8')) as Raw;
  } catch {
    return { status: 'invalid', detail: `${basename(manifestPath)} is not valid JSON` };
  }
  const m = normalise(raw, manifestPath);
  if (typeof m === 'string') return { status: 'invalid', detail: m };
  if (m.circuitId !== profile.circuitId) {
    return {
      status: 'invalid',
      detail: `manifest is for ${m.circuitId}, expected ${profile.circuitId}`,
    };
  }
  if (m.proofSystem !== 'groth16' || m.curve !== 'bn128') {
    return { status: 'invalid', detail: 'only groth16/bn128 artifacts are supported' };
  }
  const expected = profile.signals.join(',');
  if (m.publicSignals.join(',') !== expected) {
    return {
      status: 'invalid',
      detail: `public signal layout mismatch: manifest [${m.publicSignals}] vs profile [${expected}]`,
    };
  }
  if (!existsSync(m.vkeyPath))
    return { status: 'missing', detail: 'verification key file missing' };
  const bytes = readFileSync(m.vkeyPath);
  const digest = sha256(bytes);
  if (!/^[0-9a-f]{64}$/.test(m.vkeySha256) || digest !== m.vkeySha256) {
    return {
      status: 'invalid',
      detail: 'verification key sha256 does not match manifest (artifact/circuit version mismatch)',
    };
  }
  let vkey: VerificationKey;
  try {
    vkey = JSON.parse(bytes.toString('utf8')) as VerificationKey;
  } catch {
    return { status: 'invalid', detail: 'verification key is not valid JSON' };
  }
  if (vkey.protocol !== 'groth16' || vkey.curve !== 'bn128')
    return { status: 'invalid', detail: 'verification key is not groth16/bn128' };
  if (vkey.nPublic !== profile.signals.length || m.nPublic !== vkey.nPublic) {
    return {
      status: 'invalid',
      detail: `nPublic mismatch: vkey ${vkey.nPublic}, manifest ${m.nPublic}, profile ${profile.signals.length}`,
    };
  }
  const trust: KeyTrust =
    m.securityReview?.status === 'accepted'
      ? 'reviewed'
      : opts.allowDemoKeys && isDemoKey(m)
        ? 'demo-accepted'
        : 'unreviewed';
  return {
    status: 'ready',
    manifest: m,
    vkey,
    vkeySha256: digest,
    reviewed: trust !== 'unreviewed',
    trust,
  };
}
