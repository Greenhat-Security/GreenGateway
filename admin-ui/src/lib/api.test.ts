import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  AdminApiError,
  adminFetchJson,
  adminFetchResource,
} from './api';
import { ADMIN_TOKEN_STORAGE_KEY } from './auth';

afterEach(() => {
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
  document.cookie = 'custom_csrf=; Max-Age=0; Path=/';
  document
    .querySelectorAll(
      'meta[name="greengateway-csrf-cookie-name"], meta[name="greengateway-csrf-header-name"]',
    )
    .forEach((element) => element.remove());
});

describe('admin API transport', () => {
  it('captures resource and collection ETags without exposing response bodies', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            200,
            { id: 'connection-1' },
            {
              ETag: '"connection:v2"',
              'x-greengateway-connections-etag': '"connections:v4"',
            },
          ),
        ),
      ),
    );

    await expect(adminFetchResource<{ id: string }>('/resource')).resolves.toEqual({
      value: { id: 'connection-1' },
      etag: '"connection:v2"',
      collectionEtag: '"connections:v4"',
    });
  });

  it('uses the secret collection ETag header for conditional secret workflows', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            201,
            { id: 'secret-1' },
            {
              ETag: '"connection-secret:secret-1:v1"',
              'x-greengateway-connection-secrets-etag':
                '"connection-secrets:v2"',
            },
          ),
        ),
      ),
    );

    const resource = await adminFetchResource<{ id: string }>('/secret', {
      method: 'POST',
    });
    expect(resource.etag).toBe('"connection-secret:secret-1:v1"');
    expect(resource.collectionEtag).toBe('"connection-secrets:v2"');
  });

  it.each([
    [409, 'conflict'],
    [412, 'precondition_failed'],
    [428, 'precondition_required'],
  ])('preserves the distinct %i concurrency response', async (status, code) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(
            status,
            {
              error: `safe ${code} message`,
              problems: [
                { field: 'endpoint.base_url', code: 'invalid_scheme' },
                { malformed: true },
              ],
              details: {
                dependency_count: 2,
                value: 'UNEXPECTED_ERROR_PLAINTEXT_CANARY',
                ciphertext: 'UNEXPECTED_ERROR_CIPHERTEXT_CANARY',
                locator: 'UNEXPECTED_ERROR_LOCATOR_CANARY',
              },
            },
            { ETag: '"current"' },
          ),
        ),
      ),
    );

    const error = await adminFetchJson('/mutation').catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(AdminApiError);
    expect(error).toMatchObject({
      status,
      code,
      message: `safe ${code} message`,
      problems: [{ field: 'endpoint.base_url', code: 'invalid_scheme' }],
      details: { dependency_count: 2 },
      etag: '"current"',
    });
    expect((error as AdminApiError).details).toEqual({
      dependency_count: 2,
    });
  });

  it('preserves bounded transform problems without confusing legacy validation fields', async () => {
    const canary = 'UNEXPECTED_TRANSFORM_PROBLEM_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(422, {
            error: 'tool arguments were rejected',
            reason: 'invalid_params',
            problems: [
              {
                path: '/amount',
                keyword: 'codec',
                reason: 'value has 7 fraction digits, codec allows 6',
                wire_value: canary,
              },
              { malformed: canary },
            ],
          }),
        ),
      ),
    );

    const error = await adminFetchJson('/transform').catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(AdminApiError);
    expect((error as AdminApiError).problems).toEqual([]);
    expect((error as AdminApiError).transformProblems).toEqual([
      {
        path: '/amount',
        keyword: 'codec',
        reason: 'value has 7 fraction digits, codec allows 6',
      },
    ]);
    expect(
      JSON.stringify((error as AdminApiError).transformProblems),
    ).not.toContain(canary);
  });

  it('projects only bounded composite failure details and safe orphan fields', async () => {
    const canary = 'UNEXPECTED_COMPOSITE_ERROR_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(502, {
            error: 'tool execution failed',
            tool_name: 'create_note_for_records',
            request_id: 'request-composite-1',
            reason: 'composite_failed_compensation_incomplete',
            failed_step: 'attach',
            failed_iteration: 2,
            failure_reason: canary,
            compensation: 'incomplete',
            orphans_truncated: true,
            orphans: [
              {
                step: 'attach',
                iteration: 1,
                tool: 'attach_note',
                certainty: 'possible',
                reason: 'ambiguous_status:502',
                upstream_status: 502,
                response_body: canary,
              },
              {
                step: 'note',
                tool: 'create_note',
                certainty: 'confirmed',
                reason: 'compensation_timeout',
                credential: canary,
              },
            ],
            body: canary,
          }),
        ),
      ),
    );

    const error = await adminFetchJson('/composite').catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(AdminApiError);
    expect((error as AdminApiError).details).toEqual({
      request_id: 'request-composite-1',
      reason: 'composite_failed_compensation_incomplete',
      failed_step: 'attach',
      failed_iteration: 2,
      compensation: 'incomplete',
      orphans_truncated: true,
      orphans: [
        {
          step: 'attach',
          iteration: 1,
          tool: 'attach_note',
          certainty: 'possible',
          reason: 'ambiguous_status:502',
          upstream_status: 502,
        },
        {
          step: 'note',
          tool: 'create_note',
          certainty: 'confirmed',
          reason: 'compensation_timeout',
        },
      ],
    });
    expect(JSON.stringify((error as AdminApiError).details)).not.toContain(
      canary,
    );
  });

  it('projects the bounded pending-compensation marker for interrupted composites', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(504, {
            error: 'tool execution timed out',
            reason: 'timeout',
            request_id: 'request-composite-timeout',
            composite: 'pending_compensation',
            untrusted: 'UNEXPECTED_PENDING_COMPOSITE_CANARY',
          }),
        ),
      ),
    );

    const error = await adminFetchJson('/composite').catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(AdminApiError);
    expect((error as AdminApiError).details).toEqual({
      request_id: 'request-composite-timeout',
      reason: 'timeout',
      composite: 'pending_compensation',
    });
  });

  it.each([
    {
      label: 'too many orphans',
      override: {
        orphans: Array.from({ length: 81 }, () => ({
          step: 'note',
          tool: 'create_note',
          certainty: 'confirmed',
          reason: 'no_compensation',
        })),
      },
    },
    {
      label: 'unbounded orphan reason',
      override: {
        orphans: [
          {
            step: 'note',
            tool: 'create_note',
            certainty: 'confirmed',
            reason: 'upstream said credential=UNEXPECTED_ORPHAN_CANARY',
          },
        ],
      },
    },
  ])('drops all composite details for $label', async ({ override }) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(502, {
            error: 'tool execution failed',
            request_id: 'request-composite-invalid',
            reason: 'composite_failed_compensation_incomplete',
            failed_step: 'note',
            failed_iteration: null,
            compensation: 'incomplete',
            ...override,
          }),
        ),
      ),
    );

    const error = await adminFetchJson('/composite').catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(AdminApiError);
    expect((error as AdminApiError).details).toEqual({});
  });

  it('reads dynamic CSRF names and sends the matching cookie on session mutations', async () => {
    appendMeta('greengateway-csrf-cookie-name', 'custom_csrf');
    appendMeta('greengateway-csrf-header-name', 'x-custom-csrf');
    document.cookie = 'custom_csrf=token-123; Path=/';

    const fetch = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('x-custom-csrf')).toBe('token-123');
      expect(init?.credentials).toBe('same-origin');
      return Promise.resolve(jsonResponse(200, { ok: true }));
    });
    vi.stubGlobal('fetch', fetch);

    await adminFetchJson('/mutation', { method: 'POST' });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it('does not copy a CSRF cookie into safe or bearer-authenticated requests', async () => {
    document.cookie = 'csrf_token=token-123; Path=/';
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, 'admin-token');
    const observed: Headers[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        observed.push(new Headers(init?.headers));
        return Promise.resolve(jsonResponse(200, { ok: true }));
      }),
    );

    await adminFetchJson('/read');
    await adminFetchJson('/mutation', { method: 'POST' });

    expect(observed[0].has('x-csrf-token')).toBe(false);
    expect(observed[1].get('Authorization')).toBe('Bearer admin-token');
    expect(observed[1].has('x-csrf-token')).toBe(false);
  });
});

function appendMeta(name: string, content: string): void {
  const meta = document.createElement('meta');
  meta.name = name;
  meta.content = content;
  document.head.append(meta);
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}
