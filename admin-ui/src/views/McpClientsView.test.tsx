import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, onTestFinished, vi } from 'vitest';

import { clearMemoryToken, setMemoryToken } from '../lib/auth';
import type { McpClientConfigs, McpClientTemplate } from '../lib/mcpClients';
import { readMcpClientConfigs } from '../lib/mcpClients';
import { McpClientsView } from './McpClientsView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  clearMemoryToken();
});

const MCP_URL = 'https://gateway.example.test/base/mcp';

describe('McpClientsView', () => {
  it('shows the server-computed URL and each client template as text', async () => {
    const fetcher = clientsFetchMock({ configs: configs() });
    vi.stubGlobal('fetch', fetcher.fetch);
    renderView();

    expect((await screen.findByTestId('mcp-url')).textContent).toBe(MCP_URL);
    expect(window.location.origin).not.toBe('https://gateway.example.test');
    expect(templateText().value).toBe(template('generic', 'oauth').content);

    fireEvent.click(screen.getByLabelText('Cursor'));
    expect(templateText().value).toBe(template('cursor', 'oauth').content);
    expect(screen.getByText('~/.cursor/mcp.json')).toBeTruthy();
    expect(screen.getByText('%USERPROFILE%\\.cursor\\mcp.json')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Service token from the environment'));
    expect(templateText().value).toBe(template('cursor', 'token').content);
    expect(templateText().value).toContain('${env:GREENGATEWAY_MCP_TOKEN}');
    expect(screen.getByText(/whose scopes include mcp:tools/)).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Claude Desktop'));
    expect(templateText().value).toBe(`${MCP_URL}\n`);
    expect(screen.queryByRole('group', { name: 'Authentication' })).toBeNull();

    fireEvent.click(screen.getByLabelText('VS Code'));
    expect(templateText().value).toBe(template('vscode', 'oauth').content);

    expect(fetcher.paths()).toEqual(['/v1/admin/capabilities', '/v1/admin/mcp/client-configs']);
  });

  it('selects the template for a manual copy and never touches the clipboard', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const readText = vi.fn(() => Promise.resolve(''));
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText, readText },
    });
    onTestFinished(() => {
      Reflect.deleteProperty(navigator, 'clipboard');
    });
    vi.stubGlobal('fetch', clientsFetchMock({ configs: configs() }).fetch);
    renderView();
    await screen.findByTestId('mcp-url');

    fireEvent.click(screen.getByRole('button', { name: 'Select all' }));

    const area = templateText();
    expect(document.activeElement).toBe(area);
    expect(area.selectionStart).toBe(0);
    expect(area.selectionEnd).toBe(area.value.length);
    expect(area.readOnly).toBe(true);
    expect(screen.getByText('Template selected. Press Ctrl+C (or Cmd+C) to copy it.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull();
    expect(writeText).not.toHaveBeenCalled();
    expect(readText).not.toHaveBeenCalled();
  });

  it('offers only token templates when the gateway advertises no authorization server', async () => {
    vi.stubGlobal('fetch', clientsFetchMock({ configs: configs({ oauth: false }) }).fetch);
    renderView();
    expect((await screen.findByTestId('mcp-oauth')).textContent).toMatch(/^Not available/);
    expect(templateText().value).toBe(template('generic', 'token').content);
    expect(screen.queryByRole('group', { name: 'Authentication' })).toBeNull();

    fireEvent.click(screen.getByLabelText('Claude Desktop'));
    expect(screen.queryByLabelText(/Claude Desktop template/)).toBeNull();
    expect(screen.getByText(/advertises no authorization server\.$/)).toBeTruthy();
  });

  it.each([
    ['public_url_not_configured', /has no GATEWAY_PUBLIC_URL/],
    ['public_url_not_templatable', /would interpolate/],
  ])('explains a %s refusal instead of guessing a URL', async (reason, message) => {
    vi.stubGlobal(
      'fetch',
      clientsFetchMock({ status: 409, body: { error: 'refused', reason } }).fetch,
    );
    renderView();
    expect(await screen.findByText('GATEWAY_PUBLIC_URL is needed')).toBeTruthy();
    expect(screen.getByText(message)).toBeTruthy();
    expect(screen.queryByRole('textbox')).toBeNull();
    expect(document.body.textContent).not.toContain(window.location.host);
  });

  it('asks for the permission and reads nothing without it', async () => {
    const fetcher = clientsFetchMock({ configs: configs(), permissions: ['admin:config:read'] });
    vi.stubGlobal('fetch', fetcher.fetch);
    renderView();
    expect(await screen.findByText('MCP client template permission required')).toBeTruthy();
    expect(fetcher.paths()).toEqual(['/v1/admin/capabilities']);
  });

  it('refuses a document of another shape whole and renders hostile content as text', async () => {
    vi.stubGlobal(
      'fetch',
      clientsFetchMock({ body: { ...configs(), extra: true } }).fetch,
    );
    renderView();
    expect(await screen.findByText('Unreadable templates')).toBeTruthy();
    cleanup();

    const hostile = '<img src="x" onerror="globalThis.pwned = true">\n';
    const hostileConfigs = configs();
    hostileConfigs.templates[0] = { ...hostileConfigs.templates[0], content: hostile };
    vi.stubGlobal('fetch', clientsFetchMock({ configs: hostileConfigs }).fetch);
    renderView();
    await screen.findByTestId('mcp-url');
    expect(templateText().value).toBe(hostile);
    expect(document.querySelector('img')).toBeNull();
    expect((globalThis as { pwned?: boolean }).pwned).toBeUndefined();
  });
});

describe('readMcpClientConfigs', () => {
  it('accepts exactly this version and shape', () => {
    expect(readMcpClientConfigs(configs())).toEqual(configs());
    for (const change of [
      { apiVersion: 'greengateway.dev/v1beta1' },
      { kind: 'GatewayCapabilities' },
      { oauth: 'yes' },
      { templates: [{ ...template('generic', 'oauth'), client: 'other' }] },
      { templates: [{ ...template('generic', 'oauth'), note: 'x' }] },
      { templates: [{ ...template('generic', 'oauth'), locations: [1] }] },
    ]) {
      expect(() => readMcpClientConfigs({ ...configs(), ...change })).toThrow(
        'MCP client templates this console does not read',
      );
    }
    expect(() => readMcpClientConfigs(null)).toThrow();
    expect(() => readMcpClientConfigs([])).toThrow();
  });
});

function renderView() {
  clearMemoryToken();
  setMemoryToken('generated-opaque-test-token');
  render(
    <MemoryRouter>
      <McpClientsView />
    </MemoryRouter>,
  );
}

function templateText(): HTMLTextAreaElement {
  return screen.getByRole('textbox') as HTMLTextAreaElement;
}

function template(client: McpClientTemplate['client'], auth: McpClientTemplate['auth']): McpClientTemplate {
  const header = (placeholder: string) => ({ Authorization: `Bearer ${placeholder}` });
  const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
  switch (client) {
    case 'generic':
      return {
        client,
        auth,
        format: 'json',
        locations: [],
        content: json({
          transport: 'streamable-http',
          url: MCP_URL,
          ...(auth === 'token' ? { headers: header('${GREENGATEWAY_MCP_TOKEN}') } : {}),
        }),
      };
    case 'claude-desktop':
      return { client, auth, format: 'url', locations: [], content: `${MCP_URL}\n` };
    case 'cursor':
      return {
        client,
        auth,
        format: 'json',
        locations: ['.cursor/mcp.json', '~/.cursor/mcp.json', '%USERPROFILE%\\.cursor\\mcp.json'],
        content: json({
          mcpServers: {
            greengateway: {
              url: MCP_URL,
              ...(auth === 'token' ? { headers: header('${env:GREENGATEWAY_MCP_TOKEN}') } : {}),
            },
          },
        }),
      };
    case 'vscode':
      return {
        client,
        auth,
        format: 'json',
        locations: ['.vscode/mcp.json'],
        content: json({
          servers: {
            greengateway: {
              type: 'http',
              url: MCP_URL,
              ...(auth === 'token' ? { headers: header('${env:GREENGATEWAY_MCP_TOKEN}') } : {}),
            },
          },
        }),
      };
  }
}

function configs(overrides: Partial<McpClientConfigs> = {}): McpClientConfigs {
  const oauth = overrides.oauth ?? true;
  const templates: McpClientTemplate[] = [];
  for (const client of ['generic', 'claude-desktop', 'cursor', 'vscode'] as const) {
    for (const auth of ['oauth', 'token'] as const) {
      if (client === 'claude-desktop' && auth === 'token') continue;
      if (auth === 'oauth' && !oauth) continue;
      templates.push(template(client, auth));
    }
  }
  return {
    apiVersion: 'greengateway.dev/v1alpha1',
    kind: 'McpClientConfigs',
    mcpUrl: MCP_URL,
    serverName: 'greengateway',
    oauth,
    tokenVariable: 'GREENGATEWAY_MCP_TOKEN',
    templates,
    ...overrides,
  };
}

function clientsFetchMock({
  configs: document,
  body,
  status = 200,
  permissions = ['admin:mcp:clients:read'],
}: {
  configs?: McpClientConfigs;
  body?: unknown;
  status?: number;
  permissions?: string[];
}) {
  const seen: string[] = [];
  const fetch = vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    seen.push(url.pathname);
    if (url.pathname === '/v1/admin/capabilities') {
      return Promise.resolve(jsonResponse(200, { permissions }));
    }
    if (url.pathname === '/v1/admin/mcp/client-configs') {
      return Promise.resolve(jsonResponse(status, body ?? document));
    }
    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
  return { fetch, paths: () => [...new Set(seen)] };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
