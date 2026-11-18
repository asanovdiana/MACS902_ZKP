import type { Config } from '../config/env.js';
import type { Clock } from '../utils/clock.js';
import { IssuerV1Registry } from './issuerV1.js';
import { StandinRegistry } from './standin.js';
import type { RegistryClient } from './types.js';

export * from './types.js';
export { IssuerV1Registry } from './issuerV1.js';
export { StandinRegistry } from './standin.js';

export function createRegistry(config: Config, clock: Clock): RegistryClient {
  if (config.REGISTRY_API === 'issuer-v1') {
    return new IssuerV1Registry(
      config.REGISTRY_URL,
      config.REGISTRY_ADMIN_TOKEN,
      config.REGISTRY_TIMEOUT_MS,
      config.ROOT_CACHE_MS,
      clock,
      { profile: 'v4', depth: 16 },
      config.ROOT_STALENESS_SECONDS,
    );
  }
  return new StandinRegistry(
    config.REGISTRY_URL,
    config.REGISTRY_ADMIN_TOKEN,
    config.REGISTRY_TIMEOUT_MS,
    config.ROOT_CACHE_MS,
    clock,
  );
}
