import { Router } from 'express';
import { z } from 'zod';
import { whoami, BackendError } from './backendClient.js';
import type { OneConsciousOAuthProvider } from './oauthProvider.js';

/**
 * Backs the web dashboard's OAuth consent screen. Public (no auth of its
 * own) — the actual credential check happens inside /complete, which
 * requires a real backend-issued integration token the dashboard obtained
 * by the user logging in there first.
 *
 * v1 scope model: the dashboard always requests every scope this server's
 * tools need (consciousness:summary, activity:read, activity:search,
 * devices:read, plus remote:mcp), rather than negotiating per the OAuth
 * client's requested `scope` string — approve/deny the whole set, no
 * per-scope picker. See the plan's "deferred" list.
 */
export function consentRouter(provider: OneConsciousOAuthProvider): Router {
  const router = Router();

  router.get('/oauth/pending/:reqId', (req, res) => {
    const pending = provider.getPendingAuth(req.params.reqId!);
    if (!pending) {
      res.status(404).json({ error: 'unknown_or_expired_request' });
      return;
    }
    res.json({
      clientName: pending.client.client_name ?? pending.client.client_id,
      scopes: pending.params.scopes ?? [],
      redirectUriOrigin: new URL(pending.params.redirectUri).origin,
    });
  });

  const completeSchema = z.object({ integrationToken: z.string().min(1) });

  router.post('/oauth/pending/:reqId/complete', async (req, res) => {
    const body = completeSchema.safeParse(req.body);
    if (!body.success) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }

    let scopes: string[];
    try {
      scopes = (await whoami(body.data.integrationToken)).scopes;
    } catch (err) {
      const code = err instanceof BackendError ? err.code : 'token_verification_failed';
      res.status(400).json({ error: code });
      return;
    }

    try {
      const redirectUrl = provider.completePendingAuth(req.params.reqId!, body.data.integrationToken, scopes);
      res.json({ redirectUrl });
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'unknown_or_expired_request' });
    }
  });

  router.post('/oauth/pending/:reqId/deny', (req, res) => {
    try {
      const redirectUrl = provider.denyPendingAuth(req.params.reqId!);
      res.json({ redirectUrl });
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'unknown_or_expired_request' });
    }
  });

  return router;
}
