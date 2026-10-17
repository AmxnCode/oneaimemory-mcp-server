import type { ConsciousnessEvent, Interest, Project } from '@oneconscious/shared';
import { env } from './config.js';

/**
 * Thin proxy to the backend's /api/remote/* routes — the same pattern
 * mcp-server/src/client.ts uses for the local server's /api/consciousness/*
 * routes, except here the backend does the decrypting (this process never
 * sees ciphertext or a key at all, only the JSON these calls return).
 */

export class BackendError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

async function call<T>(path: string, token: string): Promise<T> {
  const res = await fetch(env.BACKEND_API_URL + path, {
    headers: { authorization: `Bearer ${token}` },
  });
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new BackendError(res.status, (data.error as string) ?? 'request_failed');
  return data as T;
}

export interface WhoAmI {
  userId: number;
  integrationId: number;
  scopes: string[];
}

export async function whoami(token: string): Promise<WhoAmI> {
  return call('/api/remote/whoami', token);
}

export interface ConsciousnessSummary {
  windowHours: number;
  eventCount: number;
  activityLevel: 'idle' | 'low' | 'moderate' | 'high';
  activeDevices: number;
  lastActivity: string | null;
  preferences: { timezone: string; language: string; collectionEnabled: boolean } | null;
  projects: Project[];
  interests: Interest[];
  recentSearches: string[];
  eventMix: Record<string, number>;
  decryptFailures: number;
}

export async function getConsciousness(token: string, hours: number): Promise<ConsciousnessSummary> {
  return call(`/api/remote/consciousness?hours=${hours}`, token);
}

export async function getActivity(
  token: string,
  params: { hours: number; types?: string[]; deviceId?: string; limit: number },
): Promise<{ events: ConsciousnessEvent[]; decryptFailures: number }> {
  const q = new URLSearchParams({ hours: String(params.hours), limit: String(params.limit) });
  if (params.types?.length) q.set('types', params.types.join(','));
  if (params.deviceId) q.set('deviceId', params.deviceId);
  return call(`/api/remote/activity?${q}`, token);
}

export async function search(
  token: string,
  params: { query: string; hours: number; limit: number },
): Promise<{ events: ConsciousnessEvent[]; searched: number; decryptFailures: number }> {
  const q = new URLSearchParams({ query: params.query, hours: String(params.hours), limit: String(params.limit) });
  return call(`/api/remote/search?${q}`, token);
}

export async function getInterests(
  token: string,
  params: { hours: number; limit: number },
): Promise<{ interests: Interest[]; topApps: Array<{ name: string; minutes: number }>; eventCount: number; decryptFailures: number }> {
  const q = new URLSearchParams({ hours: String(params.hours), limit: String(params.limit) });
  return call(`/api/remote/interests?${q}`, token);
}

export interface DeviceInfo {
  deviceId: string;
  deviceName: string;
  deviceType: string;
  lastSync: string | null;
  active: boolean;
}

export async function getDevices(token: string): Promise<{ devices: DeviceInfo[] }> {
  return call('/api/remote/devices', token);
}
