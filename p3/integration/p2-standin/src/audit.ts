/**
 * P1 SECURITY AUDIT — executes the REAL compiled P1 v3 circuit (unmodified sources) and
 * records, with evidence, which authorization properties actually hold.
 * Output: evidence/p1-audit-report.json
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateFixtures } from './fixtures.js';
import {
  artifactPaths,
  artifactsAvailable,
  buildV3Input,
  computeTree,
  newIssuerKey,
  proveV3,
  randomField,
  commitmentOf,
  shutdown,
  signCommitment,
  verifyV3,
  WitnessError,
} from './p1.js';
import type { Groth16Proof, V3Witness } from './p1.js';
import { REPO_ROOT, P1_ARTIFACT_DIR } from './paths.js';

type Verdict = 'SECURE' | 'VULNERABLE' | 'GAP' | 'INFO';
interface Finding {
  id: string;
  question: string;
  verdict: Verdict;
  evidence: string;
}
const findings: Finding[] = [];
const add = (f: Finding) => {
  findings.push(f);
  console.log(`${f.verdict.padEnd(10)} ${f.id} ${f.question}\n           ${f.evidence}`);
};

async function tryProve(input: V3Witness) {
  try {
    return { ok: true as const, ...(await proveV3(input)) };
  } catch (e) {
    if (e instanceof WitnessError) return { ok: false as const, error: e.message };
    throw e;
  }
}

if (!artifactsAvailable()) {
  console.error('P1 artifacts missing: run `npm run p1:build` first');
  process.exit(2);
}
const manifest = JSON.parse(readFileSync(join(P1_ARTIFACT_DIR, 'manifest.json'), 'utf8'));
const vkey = JSON.parse(readFileSync(artifactPaths().vkey, 'utf8'));
const fx = await generateFixtures();
const alice = fx.personas.find((p) => p.persona === 'alice')!;
const bob = fx.personas.find((p) => p.persona === 'bob')!;
const leaves = fx.leaves.map(BigInt);
const base = { issuer: fx.devIssuer, leaves };

add({
  id: 'P1-01',
  question: 'Does the circuit compile?',
  verdict: 'INFO',
  evidence: `Compiled unmodified sources with ${manifest.compiler}; nPublic=${vkey.nPublic}. Note: components/integrated_access.circom is a 2-line fragment that does not compile on its own (not included by v3).`,
});

const honest = await tryProve(
  await buildV3Input({
    ...base,
    secret: BigInt(alice.secret),
    salt: BigInt(alice.salt),
    attributes: alice.attributes,
    signature: alice.signature,
    index: alice.slot,
  }),
);
if (!honest.ok) throw new Error('honest witness failed: ' + honest.error);
const v = await verifyV3(honest.proof, honest.publicSignals);
add({
  id: 'P1-02',
  question: 'Witness generation + real Groth16 prove/verify work?',
  verdict: v.ok ? 'INFO' : 'GAP',
  evidence: `fullProve ${honest.provingMs.toFixed(0)} ms, verify=${v.ok} in ${v.verifyMs.toFixed(1)} ms (dev trusted setup).`,
});
add({
  id: 'P1-03',
  question: 'Which signals are public?',
  verdict: 'GAP',
  evidence: `publicSignals=[root] only (length ${honest.publicSignals.length}). No nonce, resource_id, epoch, policy parameters, issuer key, expiry/now or nullifier output.`,
});

const contractor = await tryProve(
  await buildV3Input({
    ...base,
    secret: BigInt(bob.secret),
    salt: BigInt(bob.salt),
    attributes: bob.attributes,
    signature: bob.signature,
    index: bob.slot,
  }),
);
add({
  id: 'P1-04',
  question: 'Are claimed attributes checked against the hard-coded FileShare policy?',
  verdict: contractor.ok ? 'VULNERABLE' : 'SECURE',
  evidence: contractor.ok
    ? 'contractor attributes produced a proof'
    : `honest contractor witness (role=1, clearance=1) rejected: ${contractor.error}`,
});

const tampered = await tryProve(
  await buildV3Input({
    ...base,
    secret: BigInt(bob.secret),
    salt: BigInt(bob.salt),
    attributes: { role: 3, clearance: 3, deviceCompliant: 1, employeeActive: 1 },
    signature: bob.signature,
    index: bob.slot,
  }),
);
const tamperedOk = tampered.ok && (await verifyV3(tampered.proof, tampered.publicSignals)).ok;
add({
  id: 'P1-05',
  question: 'Are role/clearance/device/active bound to the issuer-signed credential?',
  verdict: tamperedOk ? 'VULNERABLE' : 'SECURE',
  evidence: tamperedOk
    ? 'Contractor (issued role=1, clearance=1) set role=3, clearance=3 with the SAME issuer signature → valid proof against the trusted root. Signed message M is Poseidon(secret, salt) only; attributes are free witness values.'
    : `tampered witness rejected: ${tampered.ok ? 'verify failed' : tampered.error}`,
});

const rogue = await newIssuerKey();
const forged = await tryProve(
  await buildV3Input({
    ...base,
    issuer: rogue,
    secret: BigInt(alice.secret),
    salt: BigInt(alice.salt),
    attributes: alice.attributes,
    signature: await signCommitment(rogue, BigInt(alice.commitment)),
    index: alice.slot,
  }),
);
const forgedOk = forged.ok && (await verifyV3(forged.proof, forged.publicSignals)).ok;
add({
  id: 'P1-06',
  question: 'Is the issuer public key bound to the trusted issuer?',
  verdict: forgedOk ? 'VULNERABLE' : 'SECURE',
  evidence: forgedOk
    ? 'Signature by a freshly generated rogue key over the holder commitment → valid proof. Ax/Ay are private witness inputs and are not compared with any constant or public input.'
    : `rogue-key witness rejected: ${forged.ok ? 'verify failed' : forged.error}`,
});

const replay = await verifyV3(honest.proof, honest.publicSignals);
add({
  id: 'P1-07',
  question: 'Can a valid proof be replayed?',
  verdict: replay.ok ? 'VULNERABLE' : 'SECURE',
  evidence:
    'The same proof verifies again; with no public nonce the proof cannot be tied to a gateway challenge. Gateway one-time challenges only stop re-use of the same challenge ID, not presentation of a captured proof under a fresh challenge.',
});
add({
  id: 'P1-08',
  question: 'Can a proof be reused across resources?',
  verdict: 'VULNERABLE',
  evidence: 'No resource_id public input; the statement is identical for every resource.',
});

const wrongRoot = [(BigInt(honest.publicSignals[0]!) + 1n).toString()];
add({
  id: 'P1-09',
  question: 'Is the proof bound to its Merkle root?',
  verdict: (await verifyV3(honest.proof, wrongRoot)).ok ? 'VULNERABLE' : 'SECURE',
  evidence:
    'Verifying the proof with root+1 fails, so the gateway can enforce current-root equality.',
});

// Outsider holds a correctly signed credential (even from the real dev issuer) but is not in the tree.
const oSecret = randomField();
const oSalt = randomField();
const outsider = await commitmentOf(oSecret, oSalt);
const outsiderSig = await signCommitment(fx.devIssuer, outsider);
const nm = await buildV3Input({
  ...base,
  secret: oSecret,
  salt: oSalt,
  attributes: alice.attributes,
  signature: outsiderSig,
  index: 0,
});
nm.root = (await computeTree(leaves)).root.toString(); // trusted root; path elements are from the real tree
const nonMember = await tryProve(nm);
add({
  id: 'P1-10',
  question: 'Can a non-member prove membership under the trusted root?',
  verdict: nonMember.ok ? 'VULNERABLE' : 'SECURE',
  evidence: nonMember.ok
    ? 'non-member proved'
    : `rejected during witness generation: ${nonMember.error}`,
});

const revokedLeaves = [...leaves];
revokedLeaves[alice.slot] = 0n;
const newRoot = (await computeTree(revokedLeaves)).root.toString();
add({
  id: 'P1-11',
  question: 'Is a revoked credential rejected under the updated root?',
  verdict:
    newRoot !== honest.publicSignals[0] && !(await verifyV3(honest.proof, [newRoot])).ok
      ? 'SECURE'
      : 'VULNERABLE',
  evidence:
    'After zeroing the leaf the root changes; the old proof does not verify against the new root. Requires the gateway to use the authoritative current root.',
});

const bad = JSON.parse(JSON.stringify(honest.proof)) as Groth16Proof;
bad.pi_c[0] = (BigInt(bad.pi_c[0]!) + 1n).toString();
add({
  id: 'P1-12',
  question: 'Are tampered proofs rejected?',
  verdict: (await verifyV3(bad, honest.publicSignals).catch(() => ({ ok: false }))).ok
    ? 'VULNERABLE'
    : 'SECURE',
  evidence: 'Modifying pi_c makes groth16.verify return false.',
});
add({
  id: 'P1-13',
  question: 'Does the circuit support all three resource policies?',
  verdict: 'GAP',
  evidence:
    'FileShareAccess() is hard-coded: role∈{2,3}, clearance∈{2,3}, device=1, active=1. No Wiki/Admin policies, no role_mask/dept_mask/min_clearance public inputs. Clearance check is set-membership, not ≥.',
});
add({
  id: 'P1-14',
  question: 'Nullifier, epoch, expiry present?',
  verdict: 'GAP',
  evidence:
    'No nullifier output, no epoch, no expiry/now input. Merkle depth is 2 (4 leaves), not 16.',
});
add({
  id: 'P1-15',
  question: 'Knowledge of the secret behind the commitment?',
  verdict: 'SECURE',
  evidence:
    'leaf === M === Poseidon(credentialSecret, credentialSalt) is enforced, so only a holder of secret+salt for a registered leaf can prove.',
});

const summary = findings.reduce<Record<string, number>>(
  (acc, f) => ({ ...acc, [f.verdict]: (acc[f.verdict] ?? 0) + 1 }),
  {},
);
mkdirSync(join(REPO_ROOT, 'evidence'), { recursive: true });
writeFileSync(
  join(REPO_ROOT, 'evidence/p1-audit-report.json'),
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      circuit: 'integrated_access_v3',
      artifactManifest: { files: manifest.files, p1Sources: manifest.p1Sources },
      trustedSetup: manifest.trustedSetup,
      summary,
      findings,
    },
    null,
    2,
  ) + '\n',
);
console.log('\nsummary', summary);
await shutdown();
process.exit(0);
