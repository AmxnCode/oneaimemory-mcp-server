import {
  decryptEvent,
  DecryptionError,
  type ConsciousnessEvent,
  type EncryptedEnvelope,
} from '@oneconscious/shared';
import type { ResolvedConfig } from './config.js';

export interface SummaryResponse {
  totalEvents: number;
  last24h: Record<string, number>;
  last7d: Record<string, number>;
  lastActivity: string | null;
  deviceCount: number;
  activeDevices: number;
  preferences: { timezone: string; language: string; collectionEnabled: boolean } | null;
}

export interface DeviceInfo {
  deviceId: string;
  deviceName: string;
  deviceType: string;
  lastSync: string | null;
  active: boolean;
}

/** Hard ceiling on how many events one tool call will pull and decrypt. */
const MAX_FETCH = 2000;
const CACHE_TTL_MS = 30_000;

export class ConsciousnessClient {
  private cache = new Map<string, { at: number; events: ConsciousnessEvent[] }>();
  /** Counted, not thrown: a few undecryptable rows shouldn't fail a whole query. */
  public lastDecryptFailures = 0;

  constructor(private cfg: ResolvedConfig) {}

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.cfg.apiUrl}${path}`, {
      headers: {
        authorization: `Bearer ${this.cfg.token}`,
        // Advisory only. The backend records this as unverified — it cannot
        // confirm which model is calling (docs/PRD-REVIEW.md #2).
        'x-ai-model': process.env.ONECON_CLIENT_LABEL ?? 'mcp-client',
      },
    });

    if (res.status === 401) throw new Error('Token rejected. Re-issue it from the desktop app.');
    if (res.status === 403) {
      const body = (await res.json().catch(() => ({}))) as { missing?: string[] };
      throw new Error(
        `This integration token lacks required scope(s): ${body.missing?.join(', ') ?? 'unknown'}. ` +
          `Re-issue the token with broader scopes in the desktop app.`,
      );
    }
    if (!res.ok) throw new Error(`Backend error ${res.status}: ${await res.text()}`);

    return (await res.json()) as T;
  }

  async summary(): Promise<SummaryResponse> {
    return this.get<SummaryResponse>('/api/consciousness/summary');
  }

  async devices(): Promise<DeviceInfo[]> {
    const r = await this.get<{ devices: DeviceInfo[] }>('/api/consciousness/devices');
    return r.devices;
  }

  /**
   * Fetch and decrypt a window of events.
   *
   * Decryption happens here because the backend holds only ciphertext. That is
   * the deliberate cost of end-to-end encryption: search and summarization are
   * local. It is fine at personal scale; a local index would be required to hit
   * the PRD's "<100ms over 1-year history" target.
   */
  async fetchEvents(opts: {
    since?: string;
    until?: string;
    types?: string[];
    deviceId?: string;
    max?: number;
  }): Promise<ConsciousnessEvent[]> {
    const max = Math.min(opts.max ?? 500, MAX_FETCH);
    const cacheKey = JSON.stringify({ ...opts, max });

    const hit = this.cache.get(cacheKey);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit.events;

    const out: ConsciousnessEvent[] = [];
    let cursor: string | null = null;
    let failures = 0;

    while (out.length < max) {
      const params = new URLSearchParams({ limit: String(Math.min(500, max - out.length)) });
      if (opts.since) params.set('since', opts.since);
      if (opts.until) params.set('until', opts.until);
      if (opts.types?.length) params.set('types', opts.types.join(','));
      if (opts.deviceId) params.set('deviceId', opts.deviceId);
      if (cursor) params.set('cursor', cursor);

      const page: { events: EncryptedEnvelope[]; nextCursor: string | null } = await this.get(
        `/api/consciousness/events?${params}`,
      );

      for (const env of page.events) {
        try {
          out.push(decryptEvent(env, this.cfg.key));
        } catch (err) {
          // Wrong passphrase on one device, or a corrupted row. Skip it.
          if (err instanceof DecryptionError) failures++;
          else throw err;
        }
      }

      if (!page.nextCursor) break;
      cursor = page.nextCursor;
    }

    this.lastDecryptFailures = failures;
    this.cache.set(cacheKey, { at: Date.now(), events: out });
    return out;
  }

  clearCache(): void {
    this.cache.clear();
  }
}
