import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { CapabilityDetail } from '../lib/capabilityInventory';
import { ToolPlayground } from './ToolPlayground';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe('ToolPlayground', () => {
  it('runs only the registered opaque tool, clears arguments, renders text safely, and explicitly clears the result', async () => {
    const argumentCanary = 'PLAYGROUND_ARGUMENT_CANARY';
    const resultCanary =
      '<img src=x onerror=PLAYGROUND_RESULT_CANARY><script>bad()</script>';
    const consoleLog = vi.spyOn(console, 'log').mockImplementation(() => {});
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const argumentsJson =
      `{"value":"${argumentCanary}",` +
      '"large":9007199254740993,"exponent":1e400}';
    const requests: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (!init?.method) {
          return Promise.resolve(
            jsonResponse(200, capabilityDetail(), {
              ETag: '"capability:v1"',
            }),
          );
        }
        expect(url.pathname).toBe('/v1/admin/tools/cap_abc/execute');
        requests.push(init);
        return Promise.resolve(
          jsonResponse(
            200,
            {
              kind: 'http',
              status: 200,
              body: { type: 'text', value: resultCanary },
            },
            { ETag: '"capability:v1"' },
          ),
        );
      }),
    );

    renderPlayground('/tools/cap_abc/playground');
    const editor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    expect(editor.value).toBe('{}');
    fireEvent.change(editor, {
      target: { value: argumentsJson },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));

    expect(editor.value).toBe('{}');
    const output = await screen.findByText(resultCanary);
    expect(output.closest('pre')).toBeTruthy();
    const resultRegion = screen.getByRole('region', { name: 'Tool result' });
    await waitFor(() => expect(document.activeElement).toBe(resultRegion));
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
    expect(requests).toHaveLength(1);
    expect(new Headers(requests[0].headers).get('If-Match')).toBe(
      '"capability:v1"',
    );
    expect(String(requests[0].body)).toBe(
      `{"arguments":${argumentsJson}}`,
    );
    expect(String(requests[0].body)).not.toContain('url');
    expect(String(requests[0].body)).not.toContain('headers');
    expect(JSON.stringify(window.localStorage)).not.toContain(argumentCanary);
    expect(JSON.stringify(window.sessionStorage)).not.toContain(argumentCanary);
    expect(JSON.stringify(consoleLog.mock.calls)).not.toContain(argumentCanary);
    expect(JSON.stringify(consoleWarn.mock.calls)).not.toContain(argumentCanary);

    fireEvent.click(screen.getByRole('button', { name: 'Clear result' }));
    expect(screen.queryByText(resultCanary)).toBeNull();
    expect(document.body.textContent).not.toContain('PLAYGROUND_RESULT_CANARY');
  });

  it('clears an old result and submitted text when local validation fails without sending another request', async () => {
    let executions = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (!init?.method) {
          return Promise.resolve(
            jsonResponse(200, capabilityDetail(), {
              ETag: '"capability:v1"',
            }),
          );
        }
        executions += 1;
        return Promise.resolve(
          jsonResponse(
            200,
            {
              kind: 'http',
              status: 200,
              body: { type: 'text', value: 'old result' },
            },
            { ETag: '"capability:v1"' },
          ),
        );
      }),
    );

    renderPlayground('/tools/cap_abc/playground');
    const editor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    fireEvent.change(editor, { target: { value: '{}' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));
    expect(await screen.findByText('old result')).toBeTruthy();

    fireEvent.change(editor, { target: { value: '[1, 2]' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));

    expect(await screen.findByText('JSON object required')).toBeTruthy();
    expect(editor.value).toBe('{}');
    expect(screen.queryByText('old result')).toBeNull();
    expect(executions).toBe(1);

    fireEvent.change(editor, { target: { value: '{"value":' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));

    expect(
      await screen.findByText('Valid JSON object required'),
    ).toBeTruthy();
    expect(editor.value).toBe('{}');
    expect(executions).toBe(1);
  });

  it.each([
    { status: 401, title: 'Authentication required', code: undefined },
    { status: 403, title: 'Tool execution denied', code: undefined },
    { status: 404, title: 'Tool no longer available', code: undefined },
    { status: 412, title: 'Tool changed before execution', code: undefined },
    { status: 428, title: 'Execution validator required', code: undefined },
    {
      status: 413,
      title: 'Tool output limit exceeded',
      code: 'output_limit_exceeded',
    },
  ])(
    'clears state and reports a stable $status execution failure without retrying',
    async ({ status, title, code }) => {
      let executions = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
          if (!init?.method) {
            return Promise.resolve(
              jsonResponse(200, capabilityDetail(), {
                ETag: '"capability:v1"',
              }),
            );
          }
          executions += 1;
          return Promise.resolve(
            jsonResponse(status, {
              error: 'sanitized error',
              ...(code ? { code } : {}),
            }),
          );
        }),
      );

      renderPlayground('/tools/cap_abc/playground');
      const editor = await screen.findByLabelText(
        'Arguments (JSON)',
      ) as HTMLTextAreaElement;
      fireEvent.change(editor, {
        target: { value: '{"canary":"failure-canary"}' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));

      expect(await screen.findByText(title)).toBeTruthy();
      expect(editor.value).toBe('{}');
      expect(screen.queryByRole('heading', { name: 'Tool result' })).toBeNull();
      expect(executions).toBe(1);
      if (status === 404 || status === 412 || status === 428) {
        expect(
          screen.getByRole('button', { name: 'Reload current tool' }),
        ).toBeTruthy();
        expect(
          (screen.getByRole('button', {
            name: 'Run tool',
          }) as HTMLButtonElement).disabled,
        ).toBe(true);
      }
    },
  );

  it('clears state on a network failure and does not retry', async () => {
    let executions = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (!init?.method) {
          return Promise.resolve(
            jsonResponse(200, capabilityDetail(), {
              ETag: '"capability:v1"',
            }),
          );
        }
        executions += 1;
        return Promise.reject(new Error('network canary'));
      }),
    );

    renderPlayground('/tools/cap_abc/playground');
    const editor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    fireEvent.change(editor, {
      target: { value: '{"canary":"network-canary"}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));

    expect(await screen.findByText('Tool execution failed')).toBeTruthy();
    expect(editor.value).toBe('{}');
    expect(document.body.textContent).not.toContain('network canary');
    expect(executions).toBe(1);
  });

  it('fails closed when tool detail has no strong execution validator', async () => {
    let executions = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method) {
          executions += 1;
        }
        return Promise.resolve(jsonResponse(200, capabilityDetail()));
      }),
    );

    renderPlayground('/tools/cap_abc/playground');

    const alert = await screen.findByRole('alert', {
      name: 'Execution validator unavailable',
    });
    await waitFor(() => expect(document.activeElement).toBe(alert));
    expect(
      (screen.getByRole('button', {
        name: 'Run tool',
      }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      screen.getByRole('button', { name: 'Reload current tool' }),
    ).toBeTruthy();
    expect(executions).toBe(0);
  });

  it.each([
    'permission_denied',
    'metadata_only',
    'disabled',
    'unavailable',
    'stale',
    'policy_denied',
    'executor_unavailable',
  ] as const)(
    'obeys the server-derived %s disabled state',
    async (reason) => {
      let executions = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
          if (init?.method) {
            executions += 1;
          }
          return Promise.resolve(
            jsonResponse(
              200,
              capabilityDetail({
                actions: { can_execute: false, reason },
              }),
              { ETag: '"capability:v1"' },
            ),
          );
        }),
      );

      renderPlayground('/tools/cap_abc/playground');
      const editor = await screen.findByLabelText('Arguments (JSON)');
      expect((editor as HTMLTextAreaElement).disabled).toBe(true);
      expect(
        (screen.getByRole('button', {
          name: 'Run tool',
        }) as HTMLButtonElement).disabled,
      ).toBe(true);
      expect(screen.getByText('Run unavailable:')).toBeTruthy();
      fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));
      expect(executions).toBe(0);
    },
  );

  it('clears result and arguments on tool change and aborts in-flight work on unmount', async () => {
    let pendingSignal: AbortSignal | undefined;
    const pending = deferred<Response>();
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (!init?.method) {
          const id = decodeURIComponent(
            url.pathname.split('/').filter(Boolean).at(-1) ?? '',
          );
          return Promise.resolve(
            jsonResponse(
              200,
              capabilityDetail({
                id,
                name: id === 'cap_two' ? 'second.tool' : 'first.tool',
              }),
              { ETag: `"${id}:v1"` },
            ),
          );
        }
        pendingSignal = init.signal ?? undefined;
        return pending.promise;
      }),
    );

    const rendered = renderPlayground(
      '/tools/cap_one/playground',
      '/tools/cap_two/playground',
    );
    const editor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    fireEvent.change(editor, {
      target: { value: '{"canary":"route-canary"}' },
    });
    fireEvent.click(screen.getByRole('link', { name: 'Switch tool' }));

    const nextEditor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    await waitFor(() => expect(nextEditor.value).toBe('{}'));
    expect(document.body.textContent).not.toContain('route-canary');

    fireEvent.change(nextEditor, {
      target: { value: '{"canary":"unmount-canary"}' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));
    await waitFor(() => expect(pendingSignal).toBeTruthy());
    expect(nextEditor.value).toBe('{}');
    rendered.unmount();
    expect(pendingSignal?.aborted).toBe(true);
    pending.resolve(
      jsonResponse(
        200,
        {
          kind: 'http',
          status: 200,
          body: { type: 'text', value: 'late result' },
        },
        { ETag: '"cap_two:v1"' },
      ),
    );
  });

  it('clears the old result before a new run and prevents double submission', async () => {
    let executions = 0;
    const second = deferred<Response>();
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        if (!init?.method) {
          return Promise.resolve(
            jsonResponse(200, capabilityDetail(), {
              ETag: '"capability:v1"',
            }),
          );
        }
        executions += 1;
        if (executions === 1) {
          return Promise.resolve(
            jsonResponse(
              200,
              {
                kind: 'http',
                status: 200,
                body: { type: 'text', value: 'first result' },
              },
              { ETag: '"capability:v1"' },
            ),
          );
        }
        return second.promise;
      }),
    );

    renderPlayground('/tools/cap_abc/playground');
    const editor = await screen.findByLabelText(
      'Arguments (JSON)',
    ) as HTMLTextAreaElement;
    fireEvent.click(screen.getByRole('button', { name: 'Run tool' }));
    expect(await screen.findByText('first result')).toBeTruthy();
    fireEvent.change(editor, { target: { value: '{"next":true}' } });
    const run = screen.getByRole('button', { name: 'Run tool' });
    fireEvent.click(run);
    fireEvent.click(run);

    expect(screen.queryByText('first result')).toBeNull();
    expect(executions).toBe(2);
    expect(editor.value).toBe('{}');
    second.resolve(
      jsonResponse(
        200,
        {
          kind: 'http',
          status: 200,
          body: { type: 'text', value: 'second result' },
        },
        { ETag: '"capability:v1"' },
      ),
    );
    expect(await screen.findByText('second result')).toBeTruthy();
  });
});

function renderPlayground(initialEntry: string, switchTo?: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      {switchTo ? <Link to={switchTo}>Switch tool</Link> : null}
      <Routes>
        <Route path="/tools/:id/playground" element={<ToolPlayground />} />
        <Route path="/tools/:id" element={<div>Tool detail route</div>} />
        <Route path="/tools" element={<div>Tool inventory route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

function capabilityDetail(
  overrides: Partial<CapabilityDetail> = {},
): CapabilityDetail {
  return {
    id: 'cap_abc',
    kind: 'tool',
    name: 'billing.lookup',
    title: 'Look up invoice',
    description: 'Safely looks up one invoice.',
    description_truncated: false,
    source: { type: 'manual_file' },
    schema_digest: 'sha256:schema',
    state: {
      enabled: true,
      available: true,
      stale: false,
      reason: 'available',
    },
    policy: { eligible: true, reason: 'eligible' },
    input_json_schema: {
      type: 'object',
      properties: { invoice_id: { type: 'string' } },
    },
    mapping: {
      type: 'mcp',
      remote_tool_name: 'billing.lookup',
    },
    actions: { can_execute: true, reason: 'allowed' },
    ...overrides,
  };
}

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(String(input), 'http://localhost');
}

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

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}
