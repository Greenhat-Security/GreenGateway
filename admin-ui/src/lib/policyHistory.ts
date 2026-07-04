import { AdminApiError, adminFetchJson } from './api';
import { authHeaders } from './auth';
import { adminApiUrl } from './config';
import type { PolicyDocument } from './policy';

export type PolicyDiffSummary =
  | {
      action: 'policy_replaced';
    }
  | {
      action: 'policy_rolled_back';
      target_version: number;
    }
  | {
      action: 'rule_created';
      rule_id: string;
      position: number;
    }
  | {
      action: 'rule_updated';
      rule_id: string;
      changed_fields: string[];
    }
  | {
      action: 'rule_deleted';
      rule_id: string;
      position: number;
    }
  | {
      action: 'rules_reordered';
      new_order: string[];
    };

export type PolicyVersion = {
  version: number;
  actor: string;
  created_at: string;
  diff_summary: PolicyDiffSummary;
  policy?: PolicyDocument;
};

export type PolicyHistoryPage = {
  versions: PolicyVersion[];
  next_cursor: string | null;
};

type FetchPolicyHistoryOptions = {
  cursor?: string;
  limit?: number;
};

type AdminFetchWithMetaOptions = Omit<RequestInit, 'headers'> & {
  headers?: Record<string, string>;
};

export async function fetchPolicyHistory(
  options: FetchPolicyHistoryOptions = {},
): Promise<PolicyHistoryPage> {
  const params = new URLSearchParams();
  if (options.cursor) {
    params.set('cursor', options.cursor);
  }
  if (typeof options.limit === 'number') {
    params.set('limit', String(options.limit));
  }

  const query = params.toString();
  return adminFetchJson<PolicyHistoryPage>(
    `${adminApiUrl('/policy/history')}${query ? `?${query}` : ''}`,
  );
}

export async function rollbackPolicy(
  version: number,
  etag: string,
): Promise<{
  policy: PolicyDocument;
  etag: string | null;
  historyAppendWarning: boolean;
}> {
  const response = await adminFetchJsonWithHeaders<PolicyDocument>(
    adminApiUrl(`/policy/rollback/${encodeURIComponent(String(version))}`),
    {
      method: 'POST',
      headers: {
        'If-Match': etag,
      },
    },
  );

  return {
    policy: response.value,
    etag: response.etag,
    historyAppendWarning:
      response.headers.get('X-GreenGateway-Policy-History-Warning') ===
      'policy_history_append_failed',
  };
}

async function adminFetchJsonWithHeaders<T>(
  input: string,
  options: AdminFetchWithMetaOptions = {},
): Promise<{
  value: T;
  etag: string | null;
  headers: Headers;
}> {
  const headers = {
    Accept: 'application/json',
    ...authHeaders(),
    ...options.headers,
  };
  const response = await fetch(input, { ...options, headers });
  const body = await parseJsonBody(response);

  if (!response.ok) {
    throw new AdminApiError(response.status, errorMessage(body, response));
  }

  return {
    value: body as T,
    etag: response.headers.get('etag'),
    headers: response.headers,
  };
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.trim().length === 0) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function errorMessage(body: unknown, response: Response): string {
  if (
    body &&
    typeof body === 'object' &&
    'error' in body &&
    typeof body.error === 'string'
  ) {
    return body.error;
  }

  if (typeof body === 'string' && body.trim().length > 0) {
    return body;
  }

  return response.statusText || `Request failed with status ${response.status}`;
}
