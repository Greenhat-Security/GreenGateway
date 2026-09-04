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
              warnings: [
                {
                  path: '/amount',
                  reason: 'wire value was left unchanged',
                  wire_value: canary,
                },
              ],
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
      '{"invoice_id":"inv-1"}',
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
          warnings: [
            {
              path: '/amount',
              reason: 'wire value was left unchanged',
            },
          ],
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
      '{}',
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

  it('projects a bounded composite result and strips unknown step metadata', async () => {
    const canary = 'UNEXPECTED_COMPOSITE_RESULT_CANARY';
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(
          200,
          {
            kind: 'composite',
            status: 200,
            body: {
              note_id: 'note-1',
              nested: { complete: true },
            },
            steps_summary: [
              {
                index: 0,
                id: 'note',
                tool: 'create_note',
                method: 'POST',
                path_template: '/v1/notes',
                outcome: 'succeeded',
                upstream_status: 201,
                latency_ms: 12,
                response_body: canary,
              },
              {
                index: 1,
                id: 'attach',
                iteration: 0,
                tool: 'attach_note',
                method: 'POST',
                path_template: '/v1/attachments/{target}',
                outcome: 'succeeded',
                upstream_status: 201,
                latency_ms: 8,
                credential: canary,
              },
            ],
            internal: canary,
          },
          { ETag: '"capability:v1"' },
        ),
      ),
    );

    const resource = await executeCapability(
      'cap_composite',
      '{}',
      '"capability:v1"',
    );

    expect(resource.value).toEqual({
      kind: 'composite',
      status: 200,
      body: {
        note_id: 'note-1',
        nested: { complete: true },
      },
      steps_summary: [
        {
          index: 0,
          id: 'note',
          tool: 'create_note',
          method: 'POST',
          path_template: '/v1/notes',
          outcome: 'succeeded',
          upstream_status: 201,
          latency_ms: 12,
        },
        {
          index: 1,
          id: 'attach',
          iteration: 0,
          tool: 'attach_note',
          method: 'POST',
          path_template: '/v1/attachments/{target}',
          outcome: 'succeeded',
          upstream_status: 201,
          latency_ms: 8,
        },
      ],
    });
    expect(JSON.stringify(resource.value)).not.toContain(canary);
  });

  it('refuses invalid request and missing or mismatched response validators without retrying', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(
      executeCapability('cap_abc', '{}', 'W/"weak"'),
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
        '{}',
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
    {
      label: 'too many transform warnings',
      body: {
        kind: 'http',
        status: 200,
        body: { type: 'text', value: 'ok' },
        warnings: Array.from({ length: 33 }, () => ({
          path: '/amount',
          reason: 'wire value was left unchanged',
        })),
      },
    },
    {
      label: 'invalid composite step outcome',
      body: {
        kind: 'composite',
        status: 200,
        body: { ok: true },
        steps_summary: [
          {
            index: 0,
            id: 'create',
            tool: 'create_record',
            method: 'POST',
            path_template: '/v1/records',
            outcome: 'unknown',
            latency_ms: 1,
          },
        ],
      },
    },
    {
      label: 'too many composite step summaries',
      body: {
        kind: 'composite',
        status: 200,
        body: { ok: true },
        steps_summary: Array.from({ length: 81 }, (_, index) => ({
          index,
          id: 'create',
          tool: 'create_record',
          method: 'POST',
          path_template: '/v1/records',
          outcome: 'succeeded',
          latency_ms: 1,
        })),
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
      executeCapability('cap_abc', '{}', '"capability:v1"'),
    ).rejects.toBeInstanceOf(ToolExecutionContractError);
  });

  it('preserves large integers and overflowing exponents exactly on the wire', async () => {
    const argumentsJson =
      '{"large":9007199254740993,"exponent":1e400}';
    const fetchMock = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) => {
        expect(init?.body).toBe(`{"arguments":${argumentsJson}}`);
        return Promise.resolve(
          jsonResponse(
            200,
            {
              kind: 'http',
              status: 200,
              body: { type: 'text', value: 'ok' },
            },
            { ETag: '"capability:v1"' },
          ),
        );
      },
    );
    vi.stubGlobal('fetch', fetchMock);

    await executeCapability(
      'cap_abc',
      argumentsJson,
      '"capability:v1"',
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['malformed JSON', '{"value":'],
    ['an array', '[1,2]'],
    ['a scalar', '"value"'],
    ['null', 'null'],
    ['an oversized object', `{"value":"${'x'.repeat(65_536)}"}`],
  ])('does not request execution for %s', async (_label, argumentsJson) => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(
      executeCapability(
        'cap_abc',
        argumentsJson,
        '"capability:v1"',
      ),
    ).rejects.toBeInstanceOf(ToolExecutionContractError);
    expect(fetchMock).not.toHaveBeenCalled();
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
