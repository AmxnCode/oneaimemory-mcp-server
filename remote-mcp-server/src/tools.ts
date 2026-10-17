import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { fenceUntrusted, sanitizeUntrusted, type ConsciousnessEvent } from '@oneconscious/shared';
import * as backend from './backendClient.js';

/**
 * Same 5 tools as mcp-server/src/server.ts (the local stdio server), same
 * input schemas — a client shouldn't be able to tell which transport it's
 * using. The difference is entirely on the inside: these proxy to the
 * backend's /api/remote/* routes (already-decrypted JSON) instead of
 * decrypting ciphertext locally, since this process never holds a key.
 *
 * SECURITY: identical to the local server — every string here originated on
 * the open web and is attacker-controlled. All of it is sanitized and fenced
 * before it leaves a tool.
 */

const text = (body: string) => ({ content: [{ type: 'text' as const, text: body }] });
const fenced = (body: string) => text(fenceUntrusted(body));

function decryptNote(failures: number): string {
  return failures > 0
    ? `\n\nNote: ${failures} event(s) could not be decrypted — likely synced from a device using a different passphrase.`
    : '';
}

function describe(ev: ConsciousnessEvent): string {
  const t = ev.timestamp.slice(0, 16).replace('T', ' ');
  switch (ev.type) {
    case 'browsing':
      return `[${t}] visited ${sanitizeUntrusted(ev.payload.domain, { maxLength: 100 })} — ` +
        `${sanitizeUntrusted(ev.payload.title ?? ev.payload.url, { maxLength: 160 })}`;
    case 'search':
      return `[${t}] searched ${ev.payload.engine}: "${sanitizeUntrusted(ev.payload.query, { maxLength: 200 })}"`;
    case 'youtube':
      return `[${t}] watched "${sanitizeUntrusted(ev.payload.title, { maxLength: 160 })}"` +
        (ev.payload.channel ? ` by ${sanitizeUntrusted(ev.payload.channel, { maxLength: 80 })}` : '');
    case 'file':
      return `[${t}] opened file ${sanitizeUntrusted(ev.payload.name, { maxLength: 120 })}`;
    case 'app': {
      const mins = ev.payload.durationMs ? ` (${Math.round(ev.payload.durationMs / 60000)}m)` : '';
      return `[${t}] used ${sanitizeUntrusted(ev.payload.name, { maxLength: 80 })}${mins}`;
    }
    case 'code':
      return `[${t}] edited ${sanitizeUntrusted(ev.payload.file ?? '(file)', { maxLength: 120 })}` +
        (ev.payload.language ? ` [${sanitizeUntrusted(ev.payload.language, { maxLength: 40 })}]` : '') +
        (ev.payload.project ? ` in ${sanitizeUntrusted(ev.payload.project, { maxLength: 80 })}` : '');
    case 'ai_session':
      return `[${t}] ${ev.payload.role === 'user' ? 'said to' : 'from'} ${sanitizeUntrusted(ev.payload.tool, { maxLength: 40 })}: ` +
        `${sanitizeUntrusted(ev.payload.content, { maxLength: 160 })}`;
    default:
      return `[${t}] ${ev.type}`;
  }
}

function requireToken(extra: { authInfo?: { token: string } }): string {
  const token = extra.authInfo?.token;
  if (!token) throw new Error('Missing credentials.');
  return token;
}

export function registerTools(server: McpServer): void {
  server.registerTool(
    'get_consciousness',
    {
      title: 'Get consciousness summary',
      description:
        'Bounded snapshot of what the user is currently working on: active projects, ' +
        'top interests, recent searches, activity level, and device status. Start here — ' +
        'it is the cheapest way to get context. Output is capped to stay small enough ' +
        'to include in every conversation.',
      inputSchema: {
        hours: z.number().int().min(1).max(168).default(24)
          .describe('Look-back window in hours (default 24, max 168 = 7 days).'),
      },
    },
    async ({ hours }, extra) => {
      const token = requireToken(extra);
      const summary = await backend.getConsciousness(token, hours);

      const searches = summary.recentSearches.slice(0, 8);
      const lines = [
        `ACTIVITY WINDOW: last ${hours}h  (${summary.eventCount} events across ${summary.activeDevices} active device(s))`,
        `ACTIVITY LEVEL: ${summary.activityLevel}`,
        summary.lastActivity ? `LAST SYNC: ${summary.lastActivity}` : 'LAST SYNC: never',
        summary.preferences ? `TIMEZONE: ${summary.preferences.timezone}  LANGUAGE: ${summary.preferences.language}` : '',
        '',
        summary.projects.length
          ? `CURRENT PROJECTS:\n${summary.projects.map((p) => `  - ${sanitizeUntrusted(p.name, { maxLength: 80 })}` +
              `${p.languages.length ? ` (${p.languages.join(', ')})` : ''} — ${p.files} file(s)`).join('\n')}`
          : 'CURRENT PROJECTS: none detected (no code activity in window)',
        '',
        summary.interests.length
          ? `TOP INTERESTS:\n${summary.interests.map((i) => `  - ${i.topic} (${i.weight}, from ${i.sources.join('/')})`).join('\n')}`
          : 'TOP INTERESTS: not enough activity to infer',
        '',
        searches.length ? `RECENT SEARCHES:\n${searches.map((s) => `  - "${s}"`).join('\n')}` : 'RECENT SEARCHES: none',
        '',
        `EVENT MIX: ${Object.entries(summary.eventMix).map(([k, v]) => `${k}=${v}`).join(' ') || 'none'}`,
        '',
        'Interests and projects are derived by frequency heuristics, not by a language ' +
          'model — treat them as rough signals, not conclusions.',
      ];

      return fenced(lines.filter(Boolean).join('\n') + decryptNote(summary.decryptFailures));
    },
  );

  server.registerTool(
    'get_activity_history',
    {
      title: 'Get activity history',
      description:
        'Chronological list of raw activity events. Prefer get_consciousness or ' +
        'search_consciousness first — this returns detail and consumes far more context. ' +
        'Results are hard-capped; narrow with `types` and `hours` rather than raising `limit`.',
      inputSchema: {
        hours: z.number().int().min(1).max(720).default(24)
          .describe('Look-back window in hours (default 24, max 720 = 30 days).'),
        types: z.array(z.enum(['browsing', 'search', 'youtube', 'file', 'app', 'code', 'ai_session'])).optional()
          .describe('Restrict to these event types. ai_session is real AI coding-assistant conversation content.'),
        deviceId: z.string().optional().describe('Restrict to one device.'),
        limit: z.number().int().min(1).max(200).default(50)
          .describe('Max events to return (default 50, hard cap 200).'),
      },
    },
    async ({ hours, types, deviceId, limit }, extra) => {
      const token = requireToken(extra);
      const { events, decryptFailures } = await backend.getActivity(token, { hours, types, deviceId, limit });

      if (events.length === 0) return fenced(`No activity in the last ${hours}h matching that filter.`);

      return fenced(
        `${events.length} event(s), newest first:\n\n${events.map(describe).join('\n')}${decryptNote(decryptFailures)}`,
      );
    },
  );

  server.registerTool(
    'search_consciousness',
    {
      title: 'Search activity',
      description:
        'Full-text search across the user\'s collected activity — page titles, URLs, ' +
        'search queries, filenames, app and project names. Use this to answer ' +
        '"what was that thing I was looking at about X".',
      inputSchema: {
        query: z.string().min(1).max(200).describe('Search terms. Matched case-insensitively across all fields.'),
        hours: z.number().int().min(1).max(8760).default(720)
          .describe('Look-back window in hours (default 720 = 30 days).'),
        limit: z.number().int().min(1).max(100).default(25).describe('Max results (default 25, hard cap 100).'),
      },
    },
    async ({ query, hours, limit }, extra) => {
      const token = requireToken(extra);
      const { events, searched, decryptFailures } = await backend.search(token, { query, hours, limit });

      if (events.length === 0) {
        return fenced(`No activity matching "${sanitizeUntrusted(query, { maxLength: 100 })}" in the last ${hours}h.`);
      }

      return fenced(
        `${events.length} match(es) for "${sanitizeUntrusted(query, { maxLength: 100 })}" ` +
          `(searched ${searched} events):\n\n${events.map(describe).join('\n')}${decryptNote(decryptFailures)}`,
      );
    },
  );

  server.registerTool(
    'get_interests',
    {
      title: 'Get inferred interests',
      description:
        'Topics the user has engaged with, recency-weighted (roughly a 7-day half-life). ' +
        'Derived from frequency analysis of searches, domains, and code activity — not ' +
        'from a language model, so treat these as signals rather than conclusions.',
      inputSchema: {
        hours: z.number().int().min(1).max(2160).default(168)
          .describe('Look-back window in hours (default 168 = 7 days).'),
        limit: z.number().int().min(1).max(50).default(20).describe('Max topics (default 20).'),
      },
    },
    async ({ hours, limit }, extra) => {
      const token = requireToken(extra);
      const { interests, topApps, eventCount, decryptFailures } = await backend.getInterests(token, { hours, limit });

      if (interests.length === 0) {
        return fenced(`Not enough activity in the last ${hours}h to infer interests.`);
      }

      return fenced(
        [
          `INTERESTS (last ${hours}h, from ${eventCount} events):`,
          ...interests.map((i, n) => `${n + 1}. ${i.topic} — weight ${i.weight} (${i.sources.join(', ')})`),
          topApps.length ? `\nMOST-USED APPS:\n${topApps.map((a) => `  - ${a.name}: ${a.minutes}m`).join('\n')}` : '',
        ].filter(Boolean).join('\n') + decryptNote(decryptFailures),
      );
    },
  );

  server.registerTool(
    'get_device_status',
    {
      title: 'Get device status',
      description:
        'Which of the user\'s devices are registered, their type, and when each last ' +
        'synced. Useful for judging whether the activity picture is complete or whether ' +
        'a device has been offline.',
      inputSchema: {},
    },
    async (_args, extra) => {
      const token = requireToken(extra);
      const { devices } = await backend.getDevices(token);
      if (devices.length === 0) return text('No devices registered yet.');

      const now = Date.now();
      const lines = devices.map((d) => {
        const ago = d.lastSync ? `${Math.round((now - Date.parse(d.lastSync)) / 60000)}m ago` : 'never';
        return `  - ${sanitizeUntrusted(d.deviceName, { maxLength: 80 })} (${d.deviceType}) — ` +
          `last sync ${ago}${d.active ? '' : ' [inactive]'}`;
      });

      // Device names are user-chosen, not web-derived, so no untrusted fence.
      return text(`${devices.length} device(s):\n${lines.join('\n')}`);
    },
  );
}
