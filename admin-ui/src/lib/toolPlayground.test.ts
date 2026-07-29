import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ToolExecutionContractError,
  executeCapability,
} from './toolPlayground';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('tool playground API client', () => {
  it('sends only opaque ID, arguments, and the exact validator and safely projects HTTP output', async () => {
    const canary = 'UNEXPECTED_EXECUTION_ENVELOPE_CANARY';
    const fetchMock = vi.fn(
      (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input), 'http://localhost');
        expect(url.pathname).toBe('/v1/admin/tools/cap_abc%2Fdef/execute');
        expect(init?.method).toBe('POST');
        expect(init?.cache).toBe('no-store');
        expect(new Headers(init?.headers).get('If-Match')).toBe(
          '"capability:v7"',
        );
        expect(JSON.parse(String(init?.body))).toEqual({
          arguments: { invoice_id: 'inv-1' },
        });
        expect(String(init?.body)).not.toContain('url');
        expect(String(init?.body)).not.toContain('headers');
        return Promise.resolve(
          jsonResponse(
            200,
            {
              kind: 'http',
              status: 200,
              body: {
                type: 'json',
                value: { invoice_id: 'inv-1', paid: true },
                ciphertext: canary,
              },
              private_key_value: canary,
            },
            { ETag: '"capability:v7"' },
          ),
        );
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    const resource = await executeCapability(
      'cap_abc/def',
      { invoice_id: 'inv-1' },
      '"capability:v7"',
    );

    expect(resource).toEqual({
      value: {
        kind: 'http',
        status: 200,
        body: {
          type: 'json',
          value: { invoice_id: 'inv-1', paid: true },
        },
      },
      etag: '"capability:v7"',
      collectionEtag: null,
    });
    expect(JSON.stringify(resource)).not.toContain(canary);
  });

  it('projects every allowlisted MCP content block and strips annotations and unknown fields', async () => {
    const canary = 'UNEXPECTED_MCP_BLOCK_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          {
            kind: 'mcp',
            content: [
              { type: 'text', text: 'done', annotations: { canary } },
              {
                type: 'image',
                data: 'aW1hZ2U=',
                mime_type: 'image/png',
                _meta: { canary },
              },
              {
                type: 'audio',
                data: 'YXVkaW8=',
                mime_type: 'audio/wav',
                locator: canary,
              },
              {
                type: 'resource',
                resource: {
                  uri: 'safe://text',
                  mime_type: 'text/plain',
                  text: 'safe resource',
                  ciphertext: canary,
                },
              },
              {
                type: 'resource',
                resource: {
                  uri: 'safe://blob',
                  blob: 'YmxvYg==',
                },
              },
              {
                type: 'resource_link',
                uri: 'safe://link',
                name: 'Safe link',
                title: 'Title',
                description: 'Description',
                mime_type: 'application/json',
                size: 12,
                private_key_value: canary,
              },
            ],
            structured_content: {
              nested: { ok: true },
            },
            is_error: false,
            raw_result: canary,
          },
          { ETag: '"capability:v1"' },
        ),
      ),
    );

    const resource = await executeCapability(
      'cap_abc',
      {},
      '"capability:v1"',
    );

    expect(resource.value).toMatchObject({
      kind: 'mcp',
      is_error: false,
      structured_content: { nested: { ok: true } },
    });
    expect(
      (resource.value as Extract<typeof resource.value, { kind: 'mcp' }>)
        .content,
    ).toHaveLength(6);
    expect(JSON.stringify(resource.value)).not.toContain(canary);
    expect(
      Object.getPrototypeOf(
        (
          resource.value as Extract<
            typeof resource.value,
            { kind: 'mcp' }
          >
        ).structured_content as object,
      ),
    ).toBe(Object.prototype);
  });

  it('refuses invalid request and missing or mismatched response validators without retrying', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(
      executeCapability('cap_abc', {}, 'W/"weak"'),
    ).rejects.toBeInstanceOf(ToolExecutionContractError);
    expect(fetchMock).not.toHaveBeenCalled();

    for (const responseEtag of [undefined, '"capability:other"']) {
      fetchMock.mockReset();
      fetchMock.mockResolvedValue(
        jsonResponse(
          200,
          {
            kind: 'http',
            status: 200,
            body: { type: 'text', value: 'ok' },
          },
          responseEtag === undefined ? {} : { ETag: responseEtag },
        ),
      );
      const error = await executeCapability(
        'cap_abc',
        {},
        '"capability:v1"',
      ).catch((caught: unknown) => caught);
      expect(error).toMatchObject({
        name: 'ToolExecutionContractError',
        requiresReload: true,
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    }
  });

  it.each([
    {
      label: 'unknown result kind',
      body: { kind: 'raw', value: 'unsafe' },
    },
    {
      label: 'unknown MCP block',
      body: {
        kind: 'mcp',
        content: [{ type: 'html', html: '<script>bad()</script>' }],
        is_error: false,
      },
    },
    {
      label: 'oversized output',
      body: {
        kind: 'http',
        status: 200,
        body: { type: 'text', value: 'x'.repeat(65_537) },
      },
    },
  ])('fails closed on $label', async ({ body }) => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, body, { ETag: '"capability:v1"' }),
      ),
    );
    await expect(
      executeCapability('cap_abc', {}, '"capability:v1"'),
    ).rejects.toBeInstanceOf(ToolExecutionContractError);
  });
});

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}
