/**
 * Protected resources. The gateway and the SSO baseline protect the same three services.
 * `fieldId` is the circuit's `resourceId` public input (team docs/CONTRACTS.md, access.public_signals v4:
 * 1 wiki, 2 file share, 3 admin panel).
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
