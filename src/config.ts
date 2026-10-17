import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { deriveKey, type DataKey } from '@oneconscious/shared';

/**
 * The MCP server runs LOCALLY and holds the decryption key — that is what makes
 * the end-to-end architecture work (docs/PRD-REVIEW.md #1). The backend never
 * sees the key, so it can neither search nor summarize; this process does.
 *
 * A stdio MCP server has no UI and cannot prompt, so key material must resolve
 * non-interactively. Order of preference:
 *   1. ONECON_PASSPHRASE env var       (explicit, good for dev)
 *   2. macOS Keychain                  (written by the desktop app)
 * The config file itself never contains the passphrase or the key.
 */

export const CONFIG_DIR = join(homedir(), '.oneconscious');
export const CONFIG_PATH = join(CONFIG_DIR, 'mcp.json');

const KEYCHAIN_SERVICE = 'oneconscious-data-key';

export interface McpConfig {
  apiUrl: string;
  token: string;
  dataKeySalt: string;
  email: string;
}

export interface ResolvedConfig extends McpConfig {
  key: DataKey;
}

function readConfigFile(): McpConfig {
  let raw: string;
  try {
    raw = readFileSync(CONFIG_PATH, 'utf8');
  } catch {
    throw new Error(
      `No OneConscious config at ${CONFIG_PATH}.\n` +
        `Open the OneConscious desktop app, sign in, and click "Connect an AI tool" ` +
        `to generate it.`,
    );
  }

  // The file holds a bearer token. Refuse it if it is group/world readable.
  try {
    const mode = statSync(CONFIG_PATH).mode & 0o077;
    if (mode !== 0) {
      throw new Error(
        `${CONFIG_PATH} is readable by other users. Fix with:\n  chmod 600 ${CONFIG_PATH}`,
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes('readable by other users')) throw err;
  }

  const parsed = JSON.parse(raw) as Partial<McpConfig>;
  for (const field of ['apiUrl', 'token', 'dataKeySalt', 'email'] as const) {
    if (!parsed[field]) throw new Error(`Config at ${CONFIG_PATH} is missing "${field}".`);
  }
  return parsed as McpConfig;
}

function passphraseFromKeychain(email: string): string | null {
  if (process.platform !== 'darwin') return null;
  try {
    return execFileSync(
      'security',
      ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', email, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
    ).trim();
  } catch {
    return null;
  }
}

export function loadConfig(): ResolvedConfig {
  const cfg = readConfigFile();

  const passphrase = process.env.ONECON_PASSPHRASE ?? passphraseFromKeychain(cfg.email);
  if (!passphrase) {
    throw new Error(
      'Could not resolve the encryption passphrase.\n' +
        'Either set ONECON_PASSPHRASE in the MCP server env, or unlock the ' +
        'desktop app once so it can store the passphrase in your Keychain.',
    );
  }

  return {
    ...cfg,
    apiUrl: process.env.ONECON_API_URL ?? cfg.apiUrl,
    key: deriveKey(passphrase, cfg.dataKeySalt),
  };
}

export const KEYCHAIN = { service: KEYCHAIN_SERVICE };
