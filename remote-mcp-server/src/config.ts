import { z } from 'zod';

/**
 * Remote (HTTP) MCP server — lets ChatGPT and other remote-only MCP clients
 * connect over the internet. Unlike mcp-server (stdio, local, holds the
 * user's key directly), this process holds NO key material and NO database
 * credentials at all: every tool call is a proxy to the backend's
 * /api/remote/* routes, which decrypt server-side only for accounts that
 * explicitly opted in (see backend/src/services/remoteKek.ts).
 */
const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(4100),
  // Where this server calls to fetch decrypted data and verify tokens.
  BACKEND_API_URL: z.string().default('http://localhost:4000'),
  // Where the OAuth consent screen lives (the web dashboard).
  DASHBOARD_URL: z.string().default('http://localhost:5173'),
  // This server's own public URL — the OAuth issuer identifier.
  PUBLIC_URL: z.string().default('http://localhost:4100'),
});

const parsed = envSchema.safeParse(process.env);
if (!parsed.success) {
  console.error('Invalid environment configuration:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
