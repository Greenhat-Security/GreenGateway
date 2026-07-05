import { adminFetchJson } from './api';
import { adminApiUrl } from './config';

export type TokenRecord = {
  id: string;
  token_prefix: string;
  scopes: string[];
  created_by: string;
  created_at: string;
  expires_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
};

export type TokenPage = {
  tokens: TokenRecord[];
  next_cursor: string | null;
};

export type CreatedToken = {
  plaintext_token: string;
  plaintext_token_notice: string;
  token: TokenRecord;
};

export function fetchTokens(
  cursor?: string,
  limit?: number,
): Promise<TokenPage> {
  const params = new URLSearchParams();
  if (cursor) {
    params.set('cursor', cursor);
  }
  if (typeof limit === 'number') {
    params.set('limit', String(limit));
  }

  const query = params.toString();
  return adminFetchJson<TokenPage>(
    `${adminApiUrl('/tokens')}${query ? `?${query}` : ''}`,
  );
}

export function createToken(
  scopes: string[],
  expiresAt?: string,
): Promise<CreatedToken> {
  const body: { scopes: string[]; expires_at?: string } = { scopes };
  if (expiresAt) {
    body.expires_at = expiresAt;
  }

  return adminFetchJson<CreatedToken>(adminApiUrl('/tokens'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

export function getToken(id: string): Promise<TokenRecord> {
  return adminFetchJson<TokenRecord>(
    adminApiUrl(`/tokens/${encodeURIComponent(id)}`),
  );
}

export function revokeToken(id: string): Promise<TokenRecord> {
  return adminFetchJson<TokenRecord>(
    adminApiUrl(`/tokens/${encodeURIComponent(id)}`),
    {
      method: 'DELETE',
    },
  );
}

export function rotateToken(id: string): Promise<CreatedToken> {
  return adminFetchJson<CreatedToken>(
    adminApiUrl(`/tokens/${encodeURIComponent(id)}/rotate`),
    {
      method: 'POST',
    },
  );
}
