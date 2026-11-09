import { performance } from 'node:perf_hooks';
import {
  POLICIES,
  RESOURCES,
  policyPublicParams,
  type Decision,
  type ResourceId,
  type VerificationCheck,
} from '@zkag/shared';
import type { Config } from '../config/env.js';
import type { EventBus } from '../events/bus.js';
import type { RegistryClient } from '../registry/registryClient.js';
import { RegistryUnavailableError } from '../registry/registryClient.js';
import type { ChallengeStore, Challenge } from '../security/challenges.js';
import type { NullifierStore } from '../security/nullifiers.js';
import type { SessionStore, ZkSession } from '../sessions/sessions.js';
import type { Clock } from '../utils/clock.js';
import { correlationId as newCorrelationId, digest } from '../utils/ids.js';
import type { ArtifactState } from './artifacts.js';
import type { Groth16Verifier } from './groth16.js';
import {
  CAPABILITY_LABELS,
  missingCapabilities,
  type CircuitProfile,
  type SignalName,
} from './profiles.js';
import { GROTH16_BN254_PROOF_BYTES, verifyRequestSchema } from './schema.js';

export interface VerifyResponse {
  decision: Decision;
  reason: string;
  message: string;
  correlationId: string;
  challengeId: string | null;
  resource: ResourceId | null;
  policy: string | null;
  profile: { id: string; title: string; authorizationEligible: boolean };
  groth16: { valid: boolean | null; verifyMs: number | null; verifier: string };
  checks: VerificationCheck[];
  publicSignals: { name: string; value: string }[];
  proof: { bytes: number; jsonBytes: number; digest: string } | null;
  timings: { totalMs: number; verifyMs: number | null; registryMs: number | null };
  root: { trusted: string | null; version: string | null } | null;
  session?: { resource: ResourceId; expiresAt: string };
  missingGuarantees?: string[];
}

export interface VerifyOutcome {
  status: number;
  body: VerifyResponse;
  session?: ZkSession;
}

export interface PipelineDeps {
  config: Config;
  profile: CircuitProfile;
  artifacts: () => ArtifactState;
  registry: RegistryClient;
  challenges: ChallengeStore;
  nullifiers: NullifierStore;
  sessions: SessionStore;
  verifier: Groth16Verifier;
  bus: EventBus;
  clock: Clock;
}

const REQUESTER_FIELDS = ['challengeId', 'proof (Groth16 π_a, π_b, π_c)', 'publicSignals'];

/**
 * The authorization pipeline. Cheap structural checks run first; Groth16 verification
 * runs only once the request is well formed and bound to a live challenge. A session is
 * issued only when EVERY required security property is established cryptographically.
 */
export class VerificationPipeline {
  constructor(private readonly d: PipelineDeps) {}

  authorizationEligible(): { eligible: boolean; missing: string[] } {
    const missing: string[] = missingCapabilities(this.d.profile).map((c) => CAPABILITY_LABELS[c]);
    const art = this.d.artifacts();
    if (art.status !== 'ready') missing.push(`Verification artifacts (${art.status})`);
    else if (!art.reviewed) missing.push('Accepted security review of circuit artifacts');
    if (
      this.d.profile.capabilities.issuerBinding &&
      !(this.d.config.TRUSTED_ISSUER_AX && this.d.config.TRUSTED_ISSUER_AY)
    ) {
      missing.push('Trusted issuer public key configured at gateway');
    }
    return { eligible: missing.length === 0, missing };
  }

  async verify(raw: unknown): Promise<VerifyOutcome> {
    const t0 = performance.now();
    const cid = newCorrelationId();
    const { profile, config } = this.d;
    const checks: VerificationCheck[] = [];
    const add = (id: string, label: string, status: VerificationCheck['status'], detail?: string) =>
      checks.push({ id, label, status, ...(detail ? { detail } : {}) });

    let challenge: Challenge | null = null;
    let named: { name: string; value: string }[] = [];
    let proofInfo: VerifyResponse['proof'] = null;
    let groth: VerifyResponse['groth16'] = {
      valid: null,
      verifyMs: null,
      verifier: this.d.verifier.kind,
    };
    let registryMs: number | null = null;
    let trustedRoot: VerifyResponse['root'] = null;
    let nullifier: string | null = null;

    const finish = (
      status: number,
      decision: Decision,
      reason: string,
      message: string,
      extra: Partial<VerifyResponse> = {},
      session?: ZkSession,
    ): VerifyOutcome => {
      const resource = challenge?.resource ?? null;
      const body: VerifyResponse = {
        decision,
        reason,
        message,
        correlationId: cid,
        challengeId: challenge?.id ?? null,
        resource,
        policy: resource ? POLICIES[resource].summary : null,
        profile: {
          id: profile.id,
          title: profile.title,
          authorizationEligible: this.authorizationEligible().eligible,
        },
        groth16: groth,
        checks,
        publicSignals: named,
        proof: proofInfo,
        timings: { totalMs: performance.now() - t0, verifyMs: groth.verifyMs, registryMs },
        root: trustedRoot,
        ...extra,
      };
      this.d.bus.publish({
        type: 'verification.completed',
        source: 'zk-gateway',
        correlationId: cid,
        resource,
        challengeId: body.challengeId ?? 'n/a',
        decision,
        reason,
        groth16Valid: groth.valid,
        verifyMs: groth.verifyMs,
        totalMs: body.timings.totalMs,
        checks,
        profile: profile.id,
        proofBytes: proofInfo?.bytes ?? 0,
        publicSignals: named,
        nullifier,
        requesterFields: REQUESTER_FIELDS,
      });
      return { status, body, ...(session ? { session } : {}) };
    };

    // 1–2. Structure and size.
    const jsonBytes = Buffer.byteLength(JSON.stringify(raw ?? null));
    if (jsonBytes > config.MAX_PROOF_BYTES) {
      add(
        'size',
        'Request within proof size limit',
        'fail',
        `${jsonBytes} B > ${config.MAX_PROOF_BYTES} B`,
      );
      return finish(413, 'denied', 'PROOF_TOO_LARGE', 'Proof payload exceeds the size limit.');
    }
    const parsed = verifyRequestSchema.safeParse(raw);
    if (!parsed.success) {
      add('schema', 'Request matches strict schema', 'fail', parsed.error.issues[0]?.message);
      return finish(400, 'denied', 'INVALID_REQUEST', 'Malformed verification request.');
    }
    add('schema', 'Request matches strict schema', 'pass');
    const req = parsed.data;
    proofInfo = {
      bytes: GROTH16_BN254_PROOF_BYTES,
      jsonBytes: Buffer.byteLength(JSON.stringify(req.proof)),
      digest: digest(JSON.stringify(req.proof)),
    };

    // 3. Challenge: atomic one-time consumption (also defines the resource authoritatively).
    const consumed = this.d.challenges.consume(req.challengeId);
    if (!consumed.ok) {
      challenge = consumed.challenge ?? null;
      add('challenge', 'Challenge fresh and unused', 'fail', consumed.reason);
      if (consumed.reason === 'CHALLENGE_REPLAYED') {
        this.d.bus.publish({
          type: 'replay.rejected',
          source: 'zk-gateway',
          correlationId: cid,
          resource: challenge?.resource ?? null,
          challengeId: req.challengeId,
          reason: consumed.reason,
        });
      }
      const msg = {
        CHALLENGE_UNKNOWN: 'Unknown challenge.',
        CHALLENGE_EXPIRED: 'Challenge expired; request a new one.',
        CHALLENGE_REPLAYED: 'Challenge already used: replay rejected.',
      }[consumed.reason];
      return finish(
        consumed.reason === 'CHALLENGE_REPLAYED' ? 409 : 403,
        'denied',
        consumed.reason,
        msg,
      );
    }
    challenge = consumed.challenge;
    add(
      'challenge',
      'Challenge fresh and unused',
      'pass',
      `consumed one-time challenge for ${challenge.resource}`,
    );
    const resource = challenge.resource;
    const policy = POLICIES[resource];

    this.d.bus.publish({
      type: 'proof.submitted',
      source: 'zk-gateway',
      correlationId: cid,
      resource,
      challengeId: challenge.id,
      proofBytes: GROTH16_BN254_PROOF_BYTES,
      proofDigest: proofInfo.digest,
      publicSignals: req.publicSignals.map((value, i) => ({
        name: profile.signals[i] ?? `signal${i}`,
        value,
      })),
    });

    // 5. Profile/artifacts.
    if (challenge.profile !== profile.id) {
      add('profile', 'Challenge issued for active circuit profile', 'fail');
      return finish(
        403,
        'denied',
        'PROFILE_MISMATCH',
        'Challenge was issued for a different circuit profile.',
      );
    }
    const art = this.d.artifacts();
    if (art.status !== 'ready') {
      add('artifacts', 'Verification key loaded and integrity-checked', 'fail', art.detail);
      return finish(
        424,
        'blocked',
        'ARTIFACTS_UNAVAILABLE',
        'Verification artifacts are unavailable; failing closed.',
      );
    }
    add(
      'artifacts',
      'Verification key loaded and integrity-checked',
      'pass',
      `vkey sha256 ${art.vkeySha256.slice(0, 16)}…`,
    );

    // 8. Public-signal layout.
    if (req.publicSignals.length !== profile.signals.length) {
      add(
        'layout',
        'Public-signal count/order matches profile',
        'fail',
        `got ${req.publicSignals.length}, expected ${profile.signals.length}`,
      );
      return finish(
        400,
        'denied',
        'PUBLIC_SIGNAL_LAYOUT_MISMATCH',
        'Public signals do not match the circuit layout.',
      );
    }
    named = req.publicSignals.map((value, i) => ({ name: profile.signals[i]!, value }));
    const sig = (n: SignalName) => named.find((s) => s.name === n)?.value;
    add('layout', 'Public-signal count/order matches profile', 'pass', profile.signals.join(', '));

    // 7/9. Authoritative registry root (fail closed).
    const tr = performance.now();
    try {
      const snap = await this.d.registry.getCurrentRoot();
      registryMs = performance.now() - tr;
      trustedRoot = { trusted: snap.root, version: snap.version };
    } catch (err) {
      registryMs = performance.now() - tr;
      add(
        'root',
        'Root equals authoritative registry root',
        'fail',
        err instanceof RegistryUnavailableError ? err.code : 'REGISTRY_ERROR',
      );
      return finish(
        503,
        'blocked',
        'REGISTRY_UNAVAILABLE',
        'Registry root could not be established; failing closed.',
      );
    }
    if (sig('root') !== trustedRoot.trusted) {
      add(
        'root',
        'Root equals authoritative registry root',
        'fail',
        'proof root is not the current registry root (revoked or stale)',
      );
      return finish(
        403,
        'denied',
        'ROOT_MISMATCH',
        'Proof is not against the current credential registry root (revoked or stale credential).',
      );
    }
    add(
      'root',
      'Root equals authoritative registry root',
      'pass',
      `registry version ${trustedRoot.version ?? 'n/a'}`,
    );

    // 10. Policy parameters.
    if (profile.capabilities.policyBinding) {
      const p = policyPublicParams(policy);
      const expect: Array<[SignalName, bigint]> = [
        ['roleMask', p.roleMask],
        ['deptMask', p.deptMask],
        ['minClearance', p.minClearance],
        ['requireDevice', p.requireDevice],
      ];
      const bad = expect.filter(([n, v]) => sig(n) !== v.toString());
      if (bad.length) {
        add(
          'policy',
          `Policy parameters match ${policy.resource} policy`,
          'fail',
          `mismatch: ${bad.map(([n]) => n).join(', ')}`,
        );
        return finish(
          403,
          'denied',
          'POLICY_PARAMS_MISMATCH',
          'Proof was generated for different policy parameters.',
        );
      }
      add('policy', `Policy parameters match ${policy.resource} policy`, 'pass', policy.summary);
    } else {
      add(
        'policy',
        `Policy parameters match ${policy.resource} policy`,
        'not-supported',
        'circuit has no policy public inputs; attributes are not issuer-bound',
      );
    }

    // 11–14. Nonce, resource, epoch, time.
    if (profile.capabilities.nonceBinding) {
      if (sig('nonce') !== challenge.nonce) {
        add('nonce', 'Proof bound to challenge nonce', 'fail');
        return finish(
          403,
          'denied',
          'NONCE_MISMATCH',
          'Proof is not bound to this challenge (replayed or precomputed proof).',
        );
      }
      add('nonce', 'Proof bound to challenge nonce', 'pass');
    } else
      add(
        'nonce',
        'Proof bound to challenge nonce',
        'not-supported',
        'no nonce public input in circuit',
      );

    if (profile.capabilities.resourceBinding) {
      if (sig('resourceId') !== RESOURCES[resource].fieldId.toString()) {
        add('resource', 'Proof bound to resource ID', 'fail');
        return finish(
          403,
          'denied',
          'RESOURCE_MISMATCH',
          'Proof was generated for a different resource.',
        );
      }
      add('resource', 'Proof bound to resource ID', 'pass');
    } else
      add('resource', 'Proof bound to resource ID', 'not-supported', 'no resource_id public input');

    if (profile.capabilities.epochBinding) {
      if (sig('epoch') !== challenge.epoch) {
        add('epoch', 'Proof bound to current epoch', 'fail');
        return finish(
          403,
          'denied',
          'EPOCH_MISMATCH',
          'Proof epoch does not match the challenge epoch.',
        );
      }
      add('epoch', 'Proof bound to current epoch', 'pass');
    } else add('epoch', 'Proof bound to current epoch', 'not-supported');

    if (profile.capabilities.expiryCheck) {
      const t = Number(sig('currentTime'));
      const nowS = Math.floor(this.d.clock.now() / 1000);
      if (!Number.isFinite(t) || Math.abs(t - nowS) > config.CLOCK_SKEW_SECONDS) {
        add('time', 'Expiry evaluated at current time', 'fail', 'currentTime outside allowed skew');
        return finish(
          403,
          'denied',
          'TIME_OUT_OF_RANGE',
          'Proof time input is outside the allowed clock skew.',
        );
      }
      add('time', 'Expiry evaluated at current time', 'pass');
    } else add('time', 'Credential expiry enforced', 'not-supported', 'no expiry/now input');

    if (profile.capabilities.issuerBinding) {
      if (!config.TRUSTED_ISSUER_AX || !config.TRUSTED_ISSUER_AY) {
        add('issuer', 'Issuer key equals trusted issuer', 'fail', 'no trusted issuer configured');
        return finish(
          424,
          'blocked',
          'ISSUER_NOT_CONFIGURED',
          'No trusted issuer key configured; failing closed.',
        );
      }
      if (
        sig('issuerAx') !== config.TRUSTED_ISSUER_AX ||
        sig('issuerAy') !== config.TRUSTED_ISSUER_AY
      ) {
        add('issuer', 'Issuer key equals trusted issuer', 'fail');
        return finish(
          403,
          'denied',
          'ISSUER_UNTRUSTED',
          'Credential was not signed by the trusted issuer.',
        );
      }
      add('issuer', 'Issuer key equals trusted issuer', 'pass');
    } else
      add(
        'issuer',
        'Issuer key equals trusted issuer',
        'not-supported',
        'issuer key is a private witness in this circuit',
      );

    // 15. Groth16.
    const v = await this.d.verifier.verify(art.vkey, req.publicSignals, req.proof);
    groth = { valid: v.valid, verifyMs: v.durationMs, verifier: this.d.verifier.kind };
    if (!v.valid) {
      add('groth16', 'Groth16 proof verifies (snarkjs)', 'fail');
      return finish(403, 'denied', 'PROOF_INVALID', 'Cryptographic proof verification failed.');
    }
    add('groth16', 'Groth16 proof verifies (snarkjs)', 'pass', `${v.durationMs.toFixed(1)} ms`);

    add(
      'attributes',
      CAPABILITY_LABELS.attributeBinding,
      profile.capabilities.attributeBinding ? 'pass' : 'not-supported',
    );

    // 16. Authorization gate: every required guarantee must be cryptographically established.
    //     Runs BEFORE the nullifier is recorded so a blocked attempt never consumes rate-limit budget.
    const eligibility = this.authorizationEligible();
    if (!eligibility.eligible) {
      add(
        'authorization',
        'All required security guarantees established',
        'fail',
        eligibility.missing.join('; '),
      );
      return finish(
        424,
        'blocked',
        'PROFILE_NOT_AUTHORIZATION_ELIGIBLE',
        'Proof is mathematically valid, but this circuit does not establish the required authorization statement. No session issued.',
        { missingGuarantees: eligibility.missing },
      );
    }
    add('authorization', 'All required security guarantees established', 'pass');

    // 17. Nullifier (only values from a verified proof of an eligible circuit are recorded).
    if (profile.capabilities.nullifier) {
      nullifier = sig('nullifier') ?? null;
      const r = this.d.nullifiers.record(resource, challenge.epoch, nullifier ?? '');
      if (!r.ok) {
        add(
          'nullifier',
          'Nullifier within epoch rate limit',
          'fail',
          `${r.uses} prior use(s) this epoch`,
        );
        this.d.bus.publish({
          type: 'nullifier.rate_limited',
          source: 'zk-gateway',
          correlationId: cid,
          resource,
          nullifier: nullifier ?? '',
          epoch: challenge.epoch,
        });
        return finish(
          429,
          'denied',
          'NULLIFIER_RATE_LIMITED',
          'Same nullifier already used in this epoch: rate limited.',
        );
      }
      add(
        'nullifier',
        'Nullifier within epoch rate limit',
        'pass',
        `use ${r.uses}/${config.NULLIFIER_MAX_PER_EPOCH}`,
      );
    } else
      add(
        'nullifier',
        'Nullifier within epoch rate limit',
        'not-supported',
        'circuit has no nullifier output',
      );

    const session = this.d.sessions.issue(resource, trustedRoot.trusted!);
    this.d.bus.publish({
      type: 'session.issued',
      source: 'zk-gateway',
      correlationId: cid,
      resource,
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
    return finish(
      200,
      'granted',
      'ACCESS_GRANTED',
      `Access to ${RESOURCES[resource].name} granted for ${config.SESSION_TTL_SECONDS / 60} minutes.`,
      {
        session: { resource, expiresAt: new Date(session.expiresAt).toISOString() },
      },
      session,
    );
  }
}
