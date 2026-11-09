import type { ResourceId } from '../../types/api';

/**
 * Local demonstration personas. The persona label and credential handle are only ever sent to
 * the USER-SIDE prover (which holds the credential); the gateway receives a proof and public
 * signals only.
 */
export interface Persona {
  id: 'alice' | 'bob' | 'carol';
  name: string;
  role: string;
  credentialRef: string;
  attributes: { role: string; clearance: number; device: boolean; department: string };
  accent: string;
}

export const PERSONAS: Persona[] = [
  {
    id: 'alice',
    name: 'Alice',
    role: 'Engineer',
    credentialRef: 'cred-alice',
    attributes: { role: 'engineer', clearance: 2, device: true, department: 'engineering' },
    accent: 'from-cyan-400 to-blue-500',
  },
  {
    id: 'bob',
    name: 'Bob',
    role: 'Contractor',
    credentialRef: 'cred-bob',
    attributes: { role: 'contractor', clearance: 1, device: true, department: 'operations' },
    accent: 'from-amber-400 to-orange-500',
  },
  {
    id: 'carol',
    name: 'Carol',
    role: 'Admin',
    credentialRef: 'cred-carol',
    attributes: { role: 'admin', clearance: 3, device: true, department: 'operations' },
    accent: 'from-fuchsia-400 to-violet-500',
  },
];

export const RESOURCE_META: Record<ResourceId, { name: string; blurb: string }> = {
  wiki: { name: 'Wiki', blurb: 'Knowledge base' },
  'file-share': { name: 'File Share', blurb: 'Engineering documents' },
  'admin-panel': { name: 'Admin Panel', blurb: 'Operations control' },
};
