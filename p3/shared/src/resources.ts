/**
 * Protected resources. The gateway and the SSO baseline protect the same three services.
 * `fieldId` is the PROPOSED numeric resource identifier used as a circuit public input
 * (see contracts/public-signals.zkag-access-v1.json). It is not confirmed by P1.
 */
export const RESOURCE_IDS = ['wiki', 'file-share', 'admin-panel'] as const;
export type ResourceId = (typeof RESOURCE_IDS)[number];

export interface ResourceDescriptor {
  id: ResourceId;
  name: string;
  fieldId: bigint;
  description: string;
}

export const RESOURCES: Record<ResourceId, ResourceDescriptor> = {
  wiki: {
    id: 'wiki',
    name: 'Wiki',
    fieldId: 1n,
    description: 'Internal knowledge base',
  },
  'file-share': {
    id: 'file-share',
    name: 'File Share',
    fieldId: 2n,
    description: 'Engineering document exchange',
  },
  'admin-panel': {
    id: 'admin-panel',
    name: 'Admin Panel',
    fieldId: 3n,
    description: 'Operations administration console',
  },
};

export function isResourceId(value: unknown): value is ResourceId {
  return typeof value === 'string' && (RESOURCE_IDS as readonly string[]).includes(value);
}
