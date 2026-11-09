import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type { GatewayEvent } from '@zkag/shared';

type DistributiveOmit<T, K extends keyof T> = T extends unknown ? Omit<T, K> : never;
export type NewEvent = DistributiveOmit<GatewayEvent, 'id' | 'ts'>;

const FORBIDDEN_KEYS = /secret|salt|witness|password|token|cookie|session[_-]?id|private/i;

/** In-memory event bus with a bounded history, used for the live view and audit trail. */
export class EventBus extends EventEmitter {
  private readonly history: GatewayEvent[] = [];

  constructor(private readonly capacity = 500) {
    super();
    this.setMaxListeners(100);
  }

  publish(event: NewEvent): GatewayEvent {
    assertSafe(event);
    const full = { ...event, id: randomUUID(), ts: new Date().toISOString() } as GatewayEvent;
    this.history.push(full);
    if (this.history.length > this.capacity)
      this.history.splice(0, this.history.length - this.capacity);
    this.emit('event', full);
    return full;
  }

  recent(limit = 200): GatewayEvent[] {
    return this.history.slice(-limit);
  }

  clear() {
    this.history.length = 0;
  }
}

/** Defence in depth: refuse to publish events containing keys that look like secrets. */
function assertSafe(value: unknown, path = ''): void {
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.test(k))
        throw new Error(`refusing to publish event with sensitive key ${path}${k}`);
      assertSafe(v, `${path}${k}.`);
    }
  }
}
