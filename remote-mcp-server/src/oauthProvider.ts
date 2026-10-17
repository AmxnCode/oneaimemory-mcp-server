import { randomUUID } from 'node:crypto';
import type { Response } from 'express';
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InvalidRequestError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { whoami, BackendError } from './backendClient.js';

/**
 * OAuth 2.1 authorization server for remote MCP clients (ChatGPT etc.),
 * backed by the SAME bearer tokens the desktop app's local "AI access" tab
 * already issues (backend's integrations table) — not a second token system.
 *
 * The "authorize" step doesn't do a login/consent UI itself: it hands off to
 * the web dashboard (see consent.ts's endpoints), which already has the
 * user's real login. This class only tracks in-memory state for the handoff
 * (pending authorization requests, single-use codes) — no key material, no
 * DB credentials, nothing sensitive survives a restart of this process.
 */

interface PendingAuth {
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
  createdAt: number;
}

interface PendingCode {
  clientId: string;
  codeChallenge: string;
  integrationToken: string;
  scopes: string[];
  createdAt: number;
}

const PENDING_TTL_MS = 10 * 60_000;
const CODE_TTL_MS = 2 * 60_000;

function sweep<T extends { createdAt: number }>(map: Map<string, T>, ttlMs: number) {
  const cutoff = Date.now() - ttlMs;
  for (const [key, val] of map) if (val.createdAt < cutoff) map.delete(key);
}

export class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.clients.get(clientId);
  }

  registerClient(
    client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>,
  ): OAuthClientInformationFull {
    const full: OAuthClientInformationFull = {
      ...client,
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    this.clients.set(full.client_id, full);
    return full;
  }
}

export class OneConsciousOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientsStore();
  private pendingAuth = new Map<string, PendingAuth>();
  private pendingCodes = new Map<string, PendingCode>();

  /** Called by consent.ts's GET /oauth/pending/:reqId. */
  getPendingAuth(reqId: string): PendingAuth | undefined {
    sweep(this.pendingAuth, PENDING_TTL_MS);
    return this.pendingAuth.get(reqId);
  }

  /** Called by consent.ts once the user approves, with a real backend-issued token. */
  completePendingAuth(reqId: string, integrationToken: string, scopes: string[]): string {
    const pending = this.pendingAuth.get(reqId);
    if (!pending) throw new Error('Unknown or expired authorization request.');
    this.pendingAuth.delete(reqId);

    const code = randomUUID();
    this.pendingCodes.set(code, {
      clientId: pending.client.client_id,
      codeChallenge: pending.params.codeChallenge,
      integrationToken,
      scopes,
      createdAt: Date.now(),
    });

    const redirect = new URL(pending.params.redirectUri);
    redirect.searchParams.set('code', code);
    if (pending.params.state !== undefined) redirect.searchParams.set('state', pending.params.state);
    return redirect.toString();
  }

  /** Called by consent.ts when the user clicks Deny. */
  denyPendingAuth(reqId: string): string {
    const pending = this.pendingAuth.get(reqId);
    if (!pending) throw new Error('Unknown or expired authorization request.');
    this.pendingAuth.delete(reqId);

    const redirect = new URL(pending.params.redirectUri);
    redirect.searchParams.set('error', 'access_denied');
    if (pending.params.state !== undefined) redirect.searchParams.set('state', pending.params.state);
    return redirect.toString();
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    if (!client.redirect_uris.includes(params.redirectUri)) {
      throw new InvalidRequestError('Unregistered redirect_uri');
    }
    sweep(this.pendingAuth, PENDING_TTL_MS);
    const reqId = randomUUID();
    this.pendingAuth.set(reqId, { client, params, createdAt: Date.now() });

    // /app, not /: the dashboard app lives there, / is the marketing landing page.
    const dashboard = new URL('/app', process.env.DASHBOARD_URL ?? 'http://localhost:5173');
    dashboard.searchParams.set('oauth_request', reqId);
    res.redirect(dashboard.toString());
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const code = this.pendingCodes.get(authorizationCode);
    if (!code || code.clientId !== client.client_id) throw new Error('Invalid authorization code');
    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
  ): Promise<OAuthTokens> {
    sweep(this.pendingCodes, CODE_TTL_MS);
    const code = this.pendingCodes.get(authorizationCode);
    if (!code || code.clientId !== client.client_id) throw new Error('Invalid or expired authorization code');
    this.pendingCodes.delete(authorizationCode); // single-use

    // No expires_in: the underlying integration token has no server-side TTL
    // (revocation is via the existing "Active tokens" UI, not expiry).
    return {
      access_token: code.integrationToken,
      token_type: 'bearer',
      scope: code.scopes.join(' '),
    };
  }

  async exchangeRefreshToken(): Promise<OAuthTokens> {
    // Access tokens don't expire, so there is nothing to refresh — the token
    // response never includes a refresh_token, so a compliant client should
    // never call this.
    throw new Error('Refresh is not supported: access tokens do not expire.');
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    try {
      const who = await whoami(token);
      return {
        token,
        clientId: 'oneconscious',
        scopes: who.scopes,
        // The SDK's requireBearerAuth middleware hard-requires a numeric
        // expiresAt (rejects tokens without one) — but the underlying
        // integrations token genuinely has no TTL, only revocation (see
        // backend/src/repositories/integrations.ts). This is recomputed as
        // "far in the future" on every call rather than cached, so it's not
        // a real expiry — the actual, authoritative check is `whoami()`
        // above hitting the live, revocation-aware backend on every request.
        expiresAt: Math.floor(Date.now() / 1000) + 365 * 24 * 3600,
        extra: { userId: who.userId, integrationId: who.integrationId },
      };
    } catch (err) {
      if (err instanceof BackendError) throw new Error(`Invalid or revoked token (${err.code})`);
      throw err;
    }
  }
}
