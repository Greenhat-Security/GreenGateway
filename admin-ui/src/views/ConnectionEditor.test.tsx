import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import {
  MemoryRouter,
  Route,
  Routes,
} from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type {
  ConnectionDetail,
  ConnectionListPage,
} from '../lib/connections';
import type {
  ConnectionSecretListResponse,
  ConnectionSecretMetadata,
} from '../lib/secrets';
import { ConnectionEditor } from './ConnectionEditor';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

describe('ConnectionEditor', () => {
  it('gates direct creation with server actions and creates a disabled draft with the collection ETag', async () => {
    const calls: Array<{ url: URL; init?: RequestInit }> = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        calls.push({ url, init });
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(false), {
              ETag: '"connections-entity"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections' &&
          init?.method === 'POST'
        ) {
          return Promise.resolve(
            jsonResponse(201, managedDetail(), {
              ETag: '"connection-created"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection-2"',
            }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    const displayName = await screen.findByLabelText('Display name');
    expect(
      screen.getByText(/production DNS, egress, TLS, credential, and policy checks/),
    ).toBeTruthy();
    expect(
      (screen.getByLabelText('Authentication type') as HTMLSelectElement)
        .disabled,
    ).toBe(true);
    fireEvent.change(displayName, { target: { value: 'Billing API' } });
    fireEvent.change(screen.getByLabelText('Base URL'), {
      target: { value: 'https://billing.example.test' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save disabled draft' }),
    );

    expect(await screen.findByText('Connection detail route')).toBeTruthy();
    const create = calls.find(({ init }) => init?.method === 'POST');
    expect(headerValue(create?.init?.headers, 'If-Match')).toBe(
      '"connections-collection"',
    );
    expect(JSON.parse(String(create?.init?.body))).toMatchObject({
      display_name: 'Billing API',
      enabled: false,
      kind: 'http_api',
      endpoint: {
        base_url: 'https://billing.example.test',
        base_path: '/',
      },
      authentication: { type: 'none' },
    });
  });

  it('resets and hard-locks an accepted create whose response cannot be verified', async () => {
    let creates = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(false), {
              ETag: '"connections-entity"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections' &&
          init?.method === 'POST'
        ) {
          creates += 1;
          return Promise.resolve(
            jsonResponse(201, managedDetail(), {
              'X-GreenGateway-Connections-ETag':
                '"connections-collection-2"',
            }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    fireEvent.change(await screen.findByLabelText('Display name'), {
      target: { value: 'Possibly created API' },
    });
    fireEvent.change(screen.getByLabelText('Base URL'), {
      target: { value: 'https://possibly-created.example.test' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save disabled draft' }),
    );

    expect(
      await screen.findByText('Connection creation outcome unknown'),
    ).toBeTruthy();
    const save = screen.getByRole('button', {
      name: 'Save disabled draft',
    }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    expect((screen.getByLabelText('Display name') as HTMLInputElement).value)
      .toBe('');
    expect((screen.getByLabelText('Base URL') as HTMLInputElement).value)
      .toBe('');
    fireEvent.click(save);
    expect(creates).toBe(1);

    fireEvent.click(
      screen.getByRole('button', { name: 'Return to connections' }),
    );
    expect(await screen.findByText('Connections route')).toBeTruthy();
    expect(creates).toBe(1);
  });

  it('hard-locks an accepted update whose response cannot be verified until detail reload', async () => {
    let detailReads = 0;
    let updates = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          detailReads += 1;
          return Promise.resolve(
            jsonResponse(
              200,
              managedDetail({
                displayName:
                  detailReads === 1
                    ? 'Billing API'
                    : 'Reloaded Billing API',
              }),
              { ETag: detailReads === 1 ? '"record-7"' : '"record-8"' },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          init?.method === 'PUT'
        ) {
          updates += 1;
          return Promise.resolve(
            jsonResponse(200, managedDetail()),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    fireEvent.change(await screen.findByDisplayValue('Billing API'), {
      target: { value: 'Possibly saved edit' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save connection' }));

    expect(
      await screen.findByText('Connection save outcome unknown'),
    ).toBeTruthy();
    const save = screen.getByRole('button', {
      name: 'Save connection',
    }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(save);
    expect(updates).toBe(1);

    fireEvent.click(
      screen.getByRole('button', { name: 'Reload latest connection' }),
    );
    expect(
      await screen.findByDisplayValue('Reloaded Billing API'),
    ).toBeTruthy();
    expect(detailReads).toBe(2);
    expect(updates).toBe(1);
  });

  it('requires explicit confirmation before an enabled create', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections') {
          return Promise.resolve(
            jsonResponse(200, connectionList(false), {
              ETag: '"connections-1"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection-1"',
            }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Display name');
    fireEvent.click(screen.getByLabelText('Enabled'));

    const create = screen.getByRole('button', {
      name: 'Create and enable',
    }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    expect(
      screen.getByText(/eligible for production traffic/),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByLabelText(/I understand that enabling this connection/),
    );
    expect(create.disabled).toBe(false);
  });

  it('preserves redacted credential and TLS markers on exact-ETag update', async () => {
    const puts: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, managedDetail({ canBindSecret: true }), {
              ETag: '"record-7"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList(), {
              ETag: '"secret-entity"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          init?.method === 'PUT'
        ) {
          puts.push(init);
          return Promise.resolve(
            jsonResponse(200, managedDetail({ canBindSecret: true }), {
              ETag: '"record-8"',
            }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    const name = await screen.findByLabelText('Display name');
    fireEvent.change(name, { target: { value: 'Billing API updated' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save connection' }));

    expect(await screen.findByText('Connection detail route')).toBeTruthy();
    expect(headerValue(puts[0]?.headers, 'If-Match')).toBe('"record-7"');
    const body = JSON.parse(String(puts[0]?.body));
    expect(body.authentication).toEqual({
      type: 'header_api_key',
      header_name: 'X-API-Key',
      secret_configured: true,
    });
    expect(body.tls).toEqual({
      ca_bundle_configured: true,
      client_certificate_configured: true,
      client_private_key_configured: true,
    });
    expect(JSON.stringify(body)).not.toContain('secret_id');
  });

  it('lets an ordinary writer edit presentation fields but locks credential authority and targets', async () => {
    let secretInventoryCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          return Promise.resolve(jsonResponse(200, managedDetail(), {
            ETag: '"record-7"',
          }));
        }
        if (url.pathname === '/v1/admin/connection-secrets') {
          secretInventoryCalls += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    await screen.findByDisplayValue('Billing API');

    expect((screen.getByLabelText('Display name') as HTMLInputElement).disabled)
      .toBe(false);
    expect((screen.getByLabelText('Description') as HTMLTextAreaElement).disabled)
      .toBe(false);
    expect((screen.getByLabelText('Base URL') as HTMLInputElement).disabled)
      .toBe(true);
    expect(
      (screen.getByLabelText('Authentication type') as HTMLSelectElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText('Discovery profile') as HTMLSelectElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText('OpenAPI document path') as HTMLInputElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText(
        "Use this connection's authentication for discovery",
      ) as HTMLInputElement).disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText(
        'Configure a safe HTTP test request',
      ) as HTMLInputElement).disabled,
    ).toBe(true);
    expect((screen.getByLabelText('Method') as HTMLSelectElement).disabled)
      .toBe(true);
    expect((screen.getByLabelText('Path') as HTMLInputElement).disabled)
      .toBe(true);
    const expectedStatuses = screen.getByLabelText(
      'Expected statuses',
    ) as HTMLInputElement;
    expect(expectedStatuses.disabled).toBe(false);
    fireEvent.change(expectedStatuses, { target: { value: '200, 204' } });
    expect(expectedStatuses.value).toBe('200, 204');
    expect(
      (screen.getByLabelText('Response idle timeout (ms)') as HTMLInputElement)
        .disabled,
    ).toBe(false);
    expect(secretInventoryCalls).toBe(0);
  });

  it('lets an ordinary writer edit an unauthenticated discovery target but not attach credentials', async () => {
    let secretInventoryCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              managedDetail({ discoveryUsesAuthentication: false }),
              { ETag: '"record-7"' },
            ),
          );
        }
        if (url.pathname === '/v1/admin/connection-secrets') {
          secretInventoryCalls += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    await screen.findByDisplayValue('Billing API');

    const discovery = screen.getByLabelText(
      'Discovery profile',
    ) as HTMLSelectElement;
    const discoveryPath = screen.getByLabelText(
      'OpenAPI document path',
    ) as HTMLInputElement;
    const useAuthentication = screen.getByLabelText(
      "Use this connection's authentication for discovery",
    ) as HTMLInputElement;
    expect(discovery.disabled).toBe(false);
    expect(discoveryPath.disabled).toBe(false);
    expect(useAuthentication.disabled).toBe(true);
    fireEvent.change(discoveryPath, {
      target: { value: '/safe-openapi.json' },
    });
    expect(discoveryPath.value).toBe('/safe-openapi.json');
    expect(secretInventoryCalls).toBe(0);
  });

  it('does not let authenticated discovery over-lock unrelated safe targets', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              managedDetail({
                authentication: 'none',
                discoveryUsesAuthentication: true,
              }),
              { ETag: '"record-7"' },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    await screen.findByDisplayValue('Billing API');

    expect((screen.getByLabelText('Base URL') as HTMLInputElement).disabled)
      .toBe(false);
    expect(
      (screen.getByLabelText(
        'Configure a safe HTTP test request',
      ) as HTMLInputElement).disabled,
    ).toBe(false);
    expect((screen.getByLabelText('Method') as HTMLSelectElement).disabled)
      .toBe(false);
    expect((screen.getByLabelText('Path') as HTMLInputElement).disabled)
      .toBe(false);
    expect(
      (screen.getByLabelText('Discovery profile') as HTMLSelectElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText('OpenAPI document path') as HTMLInputElement)
        .disabled,
    ).toBe(true);
    expect(
      (screen.getByLabelText(
        "Use this connection's authentication for discovery",
      ) as HTMLInputElement).disabled,
    ).toBe(true);
  });

  it('hard-locks a stale draft until explicit reload and focuses recovery', async () => {
    let detailReads = 0;
    let puts = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          detailReads += 1;
          return Promise.resolve(
            jsonResponse(
              200,
              managedDetail({
                authentication: 'none',
                displayName:
                  detailReads === 1 ? 'Billing API' : 'Latest Billing API',
              }),
              { ETag: detailReads === 1 ? '"record-1"' : '"record-2"' },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          init?.method === 'PUT'
        ) {
          puts += 1;
          return Promise.resolve(
            jsonResponse(
              412,
              { error: 'connection changed' },
              { ETag: '"record-2"' },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/billing/edit');
    const name = await screen.findByDisplayValue('Billing API');
    fireEvent.change(name, { target: { value: 'Stale edit' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save connection' }));

    const reload = await screen.findByRole('button', {
      name: 'Reload latest connection',
    });
    await waitFor(() => expect(document.activeElement).toBe(reload));
    const save = screen.getByRole('button', {
      name: 'Save connection',
    }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.change(name, { target: { value: 'Still stale' } });
    expect(save.disabled).toBe(true);
    fireEvent.click(save);
    expect(puts).toBe(1);

    fireEvent.click(reload);
    expect(await screen.findByDisplayValue('Latest Billing API')).toBeTruthy();
    expect(detailReads).toBe(2);
  });

  it('creates a local secret with the secret collection ETag and never redisplays plaintext', async () => {
    const secretPosts: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections-entity"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ canCreate: true }), {
              ETag: '"secret-representation"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-precondition"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          init?.method === 'POST'
        ) {
          secretPosts.push(init);
          return Promise.resolve(
            jsonResponse(
              201,
              localSecret({
                id: 'local-created',
                etag: '"local-created-etag"',
                label: 'Billing CA',
                compatible_purposes: ['tls_ca_bundle'],
              }),
              {
              ETag: '"local-created-etag"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-precondition-2"',
              },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Safe label');
    fireEvent.change(await screen.findByLabelText('Safe label'), {
      target: { value: 'Billing CA' },
    });
    fireEvent.change(screen.getByLabelText('Purpose'), {
      target: { value: 'tls_ca_bundle' },
    });
    fireEvent.change(screen.getByLabelText('Secret value'), {
      target: { value: 'plaintext-canary' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create and select' }),
    );

    expect(await screen.findByText('Local secret created')).toBeTruthy();
    expect(headerValue(secretPosts[0]?.headers, 'If-Match')).toBe(
      '"secret-precondition"',
    );
    expect(JSON.parse(String(secretPosts[0]?.body))).toEqual({
      label: 'Billing CA',
      purpose: 'tls_ca_bundle',
      value: 'plaintext-canary',
    });
    expect(document.body.textContent).not.toContain('plaintext-canary');
    expect(window.location.href).not.toContain('plaintext-canary');
    expect(JSON.stringify(window.localStorage)).not.toContain(
      'plaintext-canary',
    );
    expect(JSON.stringify(window.sessionStorage)).not.toContain(
      'plaintext-canary',
    );
    expect(
      (screen.getByLabelText('Custom CA bundle') as HTMLSelectElement).value,
    ).toBe('secret:local-created');
  });

  it('focuses a descriptive secret delete confirmation and restores focus on Escape or cancel', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              secretList({
                secrets: [
                  localSecret(),
                  localSecret({
                    id: 'local-2',
                    etag: '"local-etag-2"',
                    label: 'Payments token',
                  }),
                ],
              }),
              {
                ETag: '"secrets"',
                'X-GreenGateway-Connection-Secrets-ETag':
                  '"secret-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets/local-2' &&
          init?.method === 'DELETE'
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              { deleted_secret_id: 'local-2' },
              {
                'X-GreenGateway-Connection-Secrets-ETag':
                  '"secret-collection-2"',
              },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    const selection = await screen.findByLabelText('Local secret');
    fireEvent.change(selection, { target: { value: 'local-2' } });
    const plaintext = screen.getByLabelText(
      'New secret value',
    ) as HTMLInputElement;
    fireEvent.change(plaintext, { target: { value: 'delete-canary' } });

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(plaintext.value).toBe('');
    expect(document.body.textContent).not.toContain('delete-canary');
    const confirmName = 'Confirm delete Payments token (local-2)';
    const cancelName = 'Cancel delete Payments token (local-2)';
    const confirm = screen.getByRole('button', { name: confirmName });
    await waitFor(() => expect(document.activeElement).toBe(confirm));

    fireEvent.keyDown(confirm, { key: 'Escape' });
    const deleteAfterEscape = screen.getByRole('button', { name: 'Delete' });
    await waitFor(() =>
      expect(document.activeElement).toBe(deleteAfterEscape),
    );
    expect(screen.queryByRole('button', { name: confirmName })).toBeNull();

    fireEvent.click(deleteAfterEscape);
    const confirmAgain = screen.getByRole('button', { name: confirmName });
    await waitFor(() => expect(document.activeElement).toBe(confirmAgain));
    fireEvent.click(screen.getByRole('button', { name: cancelName }));
    const deleteAfterCancel = screen.getByRole('button', { name: 'Delete' });
    await waitFor(() =>
      expect(document.activeElement).toBe(deleteAfterCancel),
    );
    expect(screen.queryByRole('button', { name: confirmName })).toBeNull();

    fireEvent.click(deleteAfterCancel);
    fireEvent.click(screen.getByRole('button', { name: confirmName }));
    const successTitle = await screen.findByText('Local secret deleted');
    const success = successTitle.closest('[role="status"]');
    expect(success).not.toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(success));
  });

  it('lets a secrets-only principal manage local aliases without exposing a dead connection form', async () => {
    const secretPosts: RequestInit[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionList(false, {
                canCreate: false,
                canManageSecrets: true,
              }),
              {
                ETag: '"connections"',
                'X-GreenGateway-Connections-ETag':
                  '"connections-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ canCreate: true }), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection-1"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          init?.method === 'POST'
        ) {
          secretPosts.push(init);
          return Promise.resolve(
            jsonResponse(
              201,
              localSecret({
                id: 'local-pem',
                etag: '"local-pem-1"',
                label: 'Partner CA',
                compatible_purposes: ['tls_ca_bundle'],
              }),
              {
                ETag: '"local-pem-1"',
                'X-GreenGateway-Connection-Secrets-ETag':
                  '"secret-collection-2"',
              },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    expect(
      await screen.findByRole('heading', { name: 'Manage secrets' }),
    ).toBeTruthy();
    expect(screen.queryByText('Create permission required')).toBeNull();
    expect(screen.queryByLabelText('Display name')).toBeNull();

    fireEvent.change(await screen.findByLabelText('Safe label'), {
      target: { value: 'Partner CA' },
    });
    fireEvent.change(screen.getByLabelText('Purpose'), {
      target: { value: 'tls_ca_bundle' },
    });
    const pem = '-----BEGIN CERTIFICATE-----\nline-two\n-----END CERTIFICATE-----';
    const value = screen.getByLabelText('Secret value') as HTMLTextAreaElement;
    expect(value.tagName).toBe('TEXTAREA');
    fireEvent.change(value, { target: { value: pem } });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create local secret' }),
    );

    expect(await screen.findByText('Local secret created')).toBeTruthy();
    expect(JSON.parse(String(secretPosts[0]?.body))).toEqual({
      label: 'Partner CA',
      purpose: 'tls_ca_bundle',
      value: pem,
    });
    expect(screen.queryByLabelText('Secret value')).toBeNull();
    expect(document.body.textContent).not.toContain(pem);
  });

  it('loads operator aliases for binding without granting local secret management', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionList(true, { canManageSecrets: false }),
              {
                ETag: '"connections"',
                'X-GreenGateway-Connections-ETag':
                  '"connections-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              secretList({
                secrets: [
                  localSecret({
                    id: 'operator-ca',
                    label: 'Operator CA',
                    provider: 'operator_environment',
                    compatible_purposes: ['tls_ca_bundle'],
                    actions: { can_rotate: false, can_delete: false },
                  }),
                ],
              }),
              {
                ETag: '"secrets"',
                'X-GreenGateway-Connection-Secrets-ETag':
                  '"secret-collection"',
              },
            ),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    const caBundle = (await screen.findByLabelText(
      'Custom CA bundle',
    )) as HTMLSelectElement;
    await waitFor(() =>
      expect(
        Array.from(caBundle.options).some(
          (option) => option.value === 'secret:operator-ca',
        ),
      ).toBe(true),
    );
    expect(
      Array.from(caBundle.options).some(
        (option) =>
          option.value === 'secret:operator-ca' &&
          option.textContent?.includes('Operator CA'),
      ),
    ).toBe(true);
    fireEvent.change(caBundle, {
      target: { value: 'secret:operator-ca' },
    });
    expect(caBundle.value).toBe('secret:operator-ca');
    expect(screen.queryByText('Local encrypted secrets')).toBeNull();
    expect(screen.queryByLabelText('Safe label')).toBeNull();
  });

  it('fails closed on confidential transport, enabled auth binding, and incomplete mTLS before writing', async () => {
    let writes = 0;
    const aliases = [
      localSecret({
        id: 'auth-header',
        label: 'Header credential',
        provider: 'operator_environment',
        compatible_purposes: ['header_api_key'],
        actions: { can_rotate: false, can_delete: false },
      }),
      localSecret({
        id: 'client-cert',
        label: 'Client certificate',
        provider: 'operator_file',
        compatible_purposes: ['tls_certificate'],
        actions: { can_rotate: false, can_delete: false },
      }),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionList(true, { canManageSecrets: false }),
              {
                ETag: '"connections"',
                'X-GreenGateway-Connections-ETag':
                  '"connections-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ secrets: aliases }), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (init?.method === 'POST') {
          writes += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Custom CA bundle');
    await waitFor(() =>
      expect(
        Array.from(
          (screen.getByLabelText(
            'Client certificate',
          ) as HTMLSelectElement).options,
        ).some((option) => option.value === 'secret:client-cert'),
      ).toBe(true),
    );
    fireEvent.change(screen.getByLabelText('Display name'), {
      target: { value: 'Credentialed API' },
    });
    const baseUrl = screen.getByLabelText('Base URL') as HTMLInputElement;
    fireEvent.change(baseUrl, {
      target: { value: 'http://api.example.test' },
    });
    fireEvent.change(screen.getByLabelText('Authentication type'), {
      target: { value: 'header_api_key' },
    });
    const authenticationSecret = screen.getByLabelText(
      'Authentication secret',
    ) as HTMLSelectElement;
    fireEvent.change(authenticationSecret, {
      target: { value: 'secret:auth-header' },
    });
    fireEvent.click(screen.getByLabelText('Enabled'));
    fireEvent.click(
      screen.getByLabelText(/I understand that enabling this connection/),
    );
    fireEvent.click(
      screen.getByRole('button', { name: 'Create and enable' }),
    );

    expect(
      await screen.findByText(/must use an HTTPS origin/),
    ).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(baseUrl));
    expect(writes).toBe(0);

    fireEvent.change(baseUrl, {
      target: { value: 'https://api.example.test' },
    });
    fireEvent.change(authenticationSecret, {
      target: { value: 'intent:none' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create and enable' }),
    );
    expect(
      await screen.findByText(
        /require a configured compatible secret alias/,
      ),
    ).toBeTruthy();
    await waitFor(() =>
      expect(document.activeElement).toBe(authenticationSecret),
    );
    expect(writes).toBe(0);

    fireEvent.change(authenticationSecret, {
      target: { value: 'secret:auth-header' },
    });
    fireEvent.change(screen.getByLabelText('Client certificate'), {
      target: { value: 'secret:client-cert' },
    });
    const privateKey = screen.getByLabelText(
      'Client private key',
    ) as HTMLSelectElement;
    fireEvent.click(
      screen.getByRole('button', { name: 'Create and enable' }),
    );
    expect(
      await screen.findByText(/requires both a client certificate and private key/),
    ).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(privateKey));
    expect(writes).toBe(0);
  });

  it('clears plaintext and distinguishes unavailable secret storage', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ canCreate: true }), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          init?.method === 'POST'
        ) {
          return Promise.resolve(
            jsonResponse(503, { error: 'secret provider unavailable' }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Safe label');
    fireEvent.change(screen.getByLabelText('Safe label'), {
      target: { value: 'Billing token' },
    });
    const value = screen.getByLabelText('Secret value') as HTMLInputElement;
    fireEvent.change(value, { target: { value: 'failure-canary' } });
    fireEvent.click(
      screen.getByRole('button', { name: 'Create and select' }),
    );

    expect(await screen.findByText('Secret service unavailable')).toBeTruthy();
    expect(value.value).toBe('');
    expect(document.body.textContent).not.toContain('failure-canary');
  });

  it('uses exact item ETags and blocks connection save while a rotation is in flight', async () => {
    const rotation = deferred<Response>();
    let rotateInit: RequestInit | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (
          url.pathname === '/v1/admin/connections/billing' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, managedDetail({ canBindSecret: true }), {
              ETag: '"record-7"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(
              200,
              secretList({
                secrets: [localSecret()],
              }),
              {
                ETag: '"secrets"',
                'X-GreenGateway-Connection-Secrets-ETag':
                  '"secret-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets/local-1' &&
          init?.method === 'PUT'
        ) {
          rotateInit = init;
          return rotation.promise;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    const rendered = renderEditor('/connections/billing/edit');
    fireEvent.change(await screen.findByLabelText('Operation'), {
      target: { value: 'manage' },
    });
    fireEvent.change(screen.getByLabelText('New secret value'), {
      target: { value: 'rotation-canary' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));

    await waitFor(() => expect(rotateInit).toBeTruthy());
    expect(headerValue(rotateInit?.headers, 'If-Match')).toBe(
      '"local-etag-1"',
    );
    expect(
      (screen.getByRole('button', {
        name: 'Save connection',
      }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(
      screen.getByRole('link', { name: 'Cancel' }).getAttribute(
        'aria-disabled',
      ),
    ).toBe('true');

    rendered.unmount();
    expect((rotateInit?.signal as AbortSignal | undefined)?.aborted).toBe(true);
    rotation.resolve(
      jsonResponse(200, localSecret({ etag: '"local-etag-2"' }), {
        ETag: '"local-etag-2"',
      }),
    );
  });

  it('clears one-time plaintext on any connection submit and intercepts password Enter', async () => {
    let connectionWrites = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ canCreate: true }), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections' &&
          init?.method === 'POST'
        ) {
          connectionWrites += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Safe label');
    // Both initial reads must settle before typing. The form's secret bindings
    // are derived from those lists, and a list that lands mid-edit re-derives
    // them -- this test is about what submitting does to a draft, not about
    // surviving initialization.
    await waitFor(() => {
      expect(screen.getByLabelText('Secret value')).toBeTruthy();
      expect(
        (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length,
      ).toBeGreaterThanOrEqual(2);
    });
    const value = screen.getByLabelText('Secret value') as HTMLInputElement;
    fireEvent.change(value, { target: { value: 'one-time-canary' } });

    expect(fireEvent.keyDown(value, { key: 'Enter' })).toBe(false);
    expect(value.value).toBe('one-time-canary');
    expect(connectionWrites).toBe(0);

    const connectionForm = screen
      .getByLabelText('Display name')
      .closest('form');
    expect(connectionForm).not.toBeNull();
    fireEvent.submit(connectionForm as HTMLFormElement);

    expect(
      await screen.findByText('One-time secret value cleared'),
    ).toBeTruthy();
    expect(value.value).toBe('');
    expect(connectionWrites).toBe(0);
    expect(document.body.textContent).not.toContain('one-time-canary');
  });

  it.each(['ambiguous accepted', 'stale'] as const)(
    'requires an explicit refetch and never retries after an %s secret mutation',
    async (failure) => {
      let secretReads = 0;
      let rotateWrites = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
          const url = requestUrl(input);
          if (
            url.pathname === '/v1/admin/connections/billing' &&
            !init?.method
          ) {
            return Promise.resolve(
              jsonResponse(
                200,
                managedDetail({
                  canBindSecret: true,
                  canManageSecrets: true,
                }),
                { ETag: '"record-7"' },
              ),
            );
          }
          if (
            url.pathname === '/v1/admin/connection-secrets' &&
            !init?.method
          ) {
            secretReads += 1;
            return Promise.resolve(
              jsonResponse(
                200,
                secretList({ secrets: [localSecret()] }),
                {
                  ETag: '"secrets"',
                  'X-GreenGateway-Connection-Secrets-ETag':
                    secretReads === 1
                      ? '"secret-collection-1"'
                      : '"secret-collection-2"',
                },
              ),
            );
          }
          if (
            url.pathname === '/v1/admin/connection-secrets/local-1' &&
            init?.method === 'PUT'
          ) {
            rotateWrites += 1;
            return Promise.resolve(
              failure === 'stale'
                ? jsonResponse(412, { error: 'secret changed' })
                : jsonResponse(
                    200,
                    localSecret({
                      etag: '"local-etag-2"',
                      version: 2,
                    }),
                    {
                      ETag: '"local-etag-2"',
                    },
                  ),
            );
          }
          return Promise.reject(
            new Error(`unexpected request: ${url.pathname}`),
          );
        }),
      );

      renderEditor('/connections/billing/edit');
      fireEvent.change(await screen.findByLabelText('Operation'), {
        target: { value: 'manage' },
      });
      fireEvent.change(screen.getByLabelText('New secret value'), {
        target: { value: 'rotation-canary' },
      });
      fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));

      const reloadRequired = await screen.findByText(
        'Secret inventory reload required',
      );
      const focusedAlert = reloadRequired.closest('[tabindex="-1"]');
      expect(focusedAlert).not.toBeNull();
      await waitFor(() =>
        expect(document.activeElement).toBe(focusedAlert),
      );
      expect(rotateWrites).toBe(1);
      expect(screen.queryByRole('button', { name: 'Rotate' })).toBeNull();

      fireEvent.click(
        screen.getByRole('button', {
          name: 'Reload secret inventory',
        }),
      );
      expect(await screen.findByLabelText('New secret value')).toBeTruthy();
      expect(secretReads).toBe(2);
      expect(rotateWrites).toBe(1);
      expect(document.body.textContent).not.toContain('rotation-canary');
    },
  );

  it('renders server OAuth, binding, and TLS field problems with ARIA and focuses the first field', async () => {
    const aliases = [
      localSecret({
        id: 'oauth-secret',
        label: 'OAuth secret',
        provider: 'operator_environment',
        compatible_purposes: ['oauth_client_secret'],
        actions: { can_rotate: false, can_delete: false },
      }),
      localSecret({
        id: 'ca-secret',
        label: 'CA secret',
        provider: 'operator_environment',
        compatible_purposes: ['tls_ca_bundle'],
        actions: { can_rotate: false, can_delete: false },
      }),
      localSecret({
        id: 'cert-secret',
        label: 'Certificate secret',
        provider: 'operator_file',
        compatible_purposes: ['tls_certificate'],
        actions: { can_rotate: false, can_delete: false },
      }),
      localSecret({
        id: 'key-secret',
        label: 'Private key secret',
        provider: 'operator_file',
        compatible_purposes: ['tls_private_key'],
        actions: { can_rotate: false, can_delete: false },
      }),
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(
              200,
              connectionList(true, { canManageSecrets: false }),
              {
                ETag: '"connections"',
                'X-GreenGateway-Connections-ETag':
                  '"connections-collection"',
              },
            ),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList({ secrets: aliases }), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connections' &&
          init?.method === 'POST'
        ) {
          return Promise.resolve(
            jsonResponse(422, {
              error: 'connection validation failed',
              problems: [
                { field: 'authentication.scopes', code: 'too_many' },
                {
                  field: 'authentication.audience',
                  code: 'too_large',
                },
                {
                  field: 'authentication.resource',
                  code: 'too_large',
                },
                {
                  field: 'authentication.client_secret_id',
                  code: 'wrong_secret_purpose',
                },
                {
                  field: 'tls.ca_bundle_alias',
                  code: 'invalid_secret_id',
                },
                {
                  field: 'tls.client_certificate_id',
                  code: 'invalid_secret_id',
                },
                {
                  field: 'tls.client_private_key_id',
                  code: 'invalid_secret_id',
                },
              ],
            }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Custom CA bundle');
    fireEvent.change(screen.getByLabelText('Display name'), {
      target: { value: 'OAuth API' },
    });
    fireEvent.change(screen.getByLabelText('Base URL'), {
      target: { value: 'https://api.example.test' },
    });
    fireEvent.change(screen.getByLabelText('Authentication type'), {
      target: { value: 'oauth2_client_credentials' },
    });
    fireEvent.change(screen.getByLabelText('OAuth client ID'), {
      target: { value: 'client-id' },
    });
    fireEvent.change(screen.getByLabelText('OAuth token URL'), {
      target: { value: 'https://idp.example.test/token' },
    });
    fireEvent.change(screen.getByLabelText('OAuth client secret'), {
      target: { value: 'secret:oauth-secret' },
    });
    fireEvent.change(screen.getByLabelText('Custom CA bundle'), {
      target: { value: 'secret:ca-secret' },
    });
    fireEvent.change(screen.getByLabelText('Client certificate'), {
      target: { value: 'secret:cert-secret' },
    });
    fireEvent.change(screen.getByLabelText('Client private key'), {
      target: { value: 'secret:key-secret' },
    });
    const serverProblemControls = [
      screen.getByLabelText('OAuth scopes'),
      screen.getByLabelText('OAuth audience'),
      screen.getByLabelText('OAuth resource'),
      screen.getByLabelText('OAuth client secret'),
      screen.getByLabelText('Custom CA bundle'),
      screen.getByLabelText('Client certificate'),
      screen.getByLabelText('Client private key'),
    ];
    fireEvent.click(
      screen.getByRole('button', { name: 'Save disabled draft' }),
    );

    const scopes = serverProblemControls[0] as HTMLInputElement;
    expect(await screen.findByText('Too many.')).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(scopes));
    for (const control of serverProblemControls) {
      expect(control.getAttribute('aria-invalid')).toBe('true');
      const errorId = control.getAttribute('aria-describedby');
      expect(errorId).toBeTruthy();
      expect(document.getElementById(String(errorId))?.textContent).toBeTruthy();
    }
  });

  it.each([
    {
      value: '200, nope',
      expectedMessage: /whole-number HTTP status codes/,
    },
    {
      value: '200, 200',
      expectedMessage: /statuses must be unique/,
    },
    {
      value: Array.from({ length: 17 }, (_, index) => 100 + index).join(
        ', ',
      ),
      expectedMessage: /no more than 16 expected HTTP statuses/,
    },
  ])(
    'rejects an invalid expected-status list before saving: $value',
    async ({ value, expectedMessage }) => {
      let writes = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
          const url = requestUrl(input);
          if (
            url.pathname === '/v1/admin/connections' &&
            !init?.method
          ) {
            return Promise.resolve(
              jsonResponse(200, connectionList(false), {
                ETag: '"connections"',
                'X-GreenGateway-Connections-ETag':
                  '"connections-collection"',
              }),
            );
          }
          if (init?.method === 'POST') {
            writes += 1;
          }
          return Promise.reject(
            new Error(`unexpected request: ${url.pathname}`),
          );
        }),
      );

      renderEditor('/connections/new');
      fireEvent.change(await screen.findByLabelText('Display name'), {
        target: { value: 'Status validation' },
      });
      fireEvent.change(screen.getByLabelText('Base URL'), {
        target: { value: 'https://api.example.test' },
      });
      fireEvent.click(
        screen.getByLabelText('Configure a safe HTTP test request'),
      );
      const statuses = screen.getByLabelText(
        'Expected statuses',
      ) as HTMLInputElement;
      fireEvent.change(statuses, { target: { value } });
      fireEvent.click(
        screen.getByRole('button', { name: 'Save disabled draft' }),
      );

      expect(await screen.findByText(expectedMessage)).toBeTruthy();
      expect(statuses.getAttribute('aria-invalid')).toBe('true');
      expect(writes).toBe(0);
    },
  );

  it('rejects duplicate OAuth scopes instead of silently deduplicating them', async () => {
    let writes = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList(), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (init?.method === 'POST') {
          writes += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    fireEvent.change(await screen.findByLabelText('Display name'), {
      target: { value: 'OAuth validation' },
    });
    fireEvent.change(screen.getByLabelText('Base URL'), {
      target: { value: 'https://api.example.test' },
    });
    fireEvent.change(screen.getByLabelText('Authentication type'), {
      target: { value: 'oauth2_client_credentials' },
    });
    fireEvent.change(screen.getByLabelText('OAuth client ID'), {
      target: { value: 'client-id' },
    });
    fireEvent.change(screen.getByLabelText('OAuth token URL'), {
      target: { value: 'https://idp.example.test/token' },
    });
    const scopes = screen.getByLabelText('OAuth scopes') as HTMLInputElement;
    fireEvent.change(scopes, { target: { value: 'read write read' } });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save disabled draft' }),
    );

    expect(await screen.findByText('OAuth scopes must be unique.')).toBeTruthy();
    expect(scopes.getAttribute('aria-invalid')).toBe('true');
    expect(writes).toBe(0);
  });

  it('rejects encoded traversal and separator spellings before any save request', async () => {
    let writes = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections' && !init?.method) {
          return Promise.resolve(
            jsonResponse(200, connectionList(true), {
              ETag: '"connections"',
              'X-GreenGateway-Connections-ETag':
                '"connections-collection"',
            }),
          );
        }
        if (
          url.pathname === '/v1/admin/connection-secrets' &&
          !init?.method
        ) {
          return Promise.resolve(
            jsonResponse(200, secretList(), {
              ETag: '"secrets"',
              'X-GreenGateway-Connection-Secrets-ETag':
                '"secret-collection"',
            }),
          );
        }
        if (init?.method === 'POST') {
          writes += 1;
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/new');
    await screen.findByLabelText('Display name');
    fireEvent.change(screen.getByLabelText('Display name'), {
      target: { value: 'Unsafe draft' },
    });
    fireEvent.change(screen.getByLabelText('Base URL'), {
      target: { value: 'https://api.example.test' },
    });
    fireEvent.change(screen.getByLabelText('Base path'), {
      target: { value: '/safe%2Fchild' },
    });
    fireEvent.change(screen.getByLabelText('Authentication type'), {
      target: { value: 'oauth2_client_credentials' },
    });
    fireEvent.change(screen.getByLabelText('OAuth client ID'), {
      target: { value: 'client-id' },
    });
    fireEvent.change(screen.getByLabelText('OAuth token URL'), {
      target: { value: 'https://idp.example.test/%2e%2e/token' },
    });
    fireEvent.click(
      screen.getByRole('button', { name: 'Save disabled draft' }),
    );

    expect(
      await screen.findByText(/safe origin-relative path/),
    ).toBeTruthy();
    expect(
      screen.getByText(/Enter an HTTPS token URL/),
    ).toBeTruthy();
    expect(writes).toBe(0);
  });

  it('renders legacy projections as read only without an editor form', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = requestUrl(input);
        if (url.pathname === '/v1/admin/connections/legacy') {
          return Promise.resolve(
            jsonResponse(200, legacyDetail(), { ETag: '"legacy-list"' }),
          );
        }
        return Promise.reject(new Error(`unexpected request: ${url.pathname}`));
      }),
    );

    renderEditor('/connections/legacy/edit');
    expect(
      await screen.findByText('Read-only legacy connection'),
    ).toBeTruthy();
    expect(screen.queryByLabelText('Display name')).toBeNull();
  });
});

function renderEditor(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/connections/new" element={<ConnectionEditor />} />
        <Route
          path="/connections/:id/edit"
          element={<ConnectionEditor />}
        />
        <Route
          path="/connections/:id"
          element={<div>Connection detail route</div>}
        />
        <Route path="/connections" element={<div>Connections route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

function connectionList(
  canBindSecret: boolean,
  {
    canCreate = true,
    canManageSecrets = canBindSecret,
  }: {
    canCreate?: boolean;
    canManageSecrets?: boolean;
  } = {},
): ConnectionListPage {
  return {
    connections: [],
    omitted_legacy_projection_count: 0,
    actions: {
      can_create: canCreate,
      can_bind_secret: canBindSecret,
      can_manage_secrets: canManageSecrets,
    },
  };
}

function managedDetail({
  canBindSecret = false,
  canManageSecrets = canBindSecret,
  authentication = 'header',
  displayName = 'Billing API',
  discoveryUsesAuthentication,
}: {
  canBindSecret?: boolean;
  canManageSecrets?: boolean;
  authentication?: 'header' | 'none';
  displayName?: string;
  discoveryUsesAuthentication?: boolean;
} = {}): ConnectionDetail {
  return {
    id: 'billing',
    display_name: displayName,
    enabled: false,
    kind: 'http_api',
    source: 'managed',
    read_only: false,
    authentication:
      authentication === 'header' ? 'header_api_key' : 'none',
    endpoint_count: 2,
    revisions: {
      connection: 1,
      credential: 1,
      tls: 1,
      discovery: 1,
      status: 1,
    },
    status: { state: 'disabled', reason: 'disabled' },
    configuration: {
      description: 'Safe description',
      endpoint: {
        base_url: 'https://billing.example.test',
        base_path: '/',
      },
      authentication:
        authentication === 'header'
          ? {
              type: 'header_api_key',
              header_name: 'X-API-Key',
              secret_configured: true,
            }
          : { type: 'none' },
      tls: {
        ca_bundle_configured: authentication === 'header',
        client_certificate_configured: authentication === 'header',
        client_private_key_configured: authentication === 'header',
      },
      timeouts: {
        connect_timeout_ms: 1000,
        request_timeout_ms: 2000,
        response_idle_timeout_ms: 3000,
      },
      discovery: {
        type: 'managed_openapi',
        path: '/openapi.json',
        use_connection_authentication:
          discoveryUsesAuthentication ?? authentication === 'header',
      },
      test_profile: {
        method: 'GET',
        path: '/health',
        expected_statuses: [200],
      },
    },
    dependencies: [],
    actions: {
      can_update: true,
      can_bind_secret: canBindSecret,
      can_manage_secrets: canManageSecrets,
      can_test: true,
      can_refresh: false,
      can_delete: true,
    },
  };
}

function legacyDetail(): ConnectionDetail {
  return {
    id: 'legacy',
    display_name: 'Legacy route',
    enabled: true,
    kind: 'http_api',
    source: 'legacy_route',
    read_only: true,
    authentication: 'legacy_configured',
    endpoint_count: 1,
    revisions: {
      connection: 0,
      credential: 0,
      tls: 0,
      discovery: 0,
      status: 0,
    },
    status: { state: 'configured', reason: 'legacy_configured' },
    dependencies: [],
    actions: {
      can_update: false,
      can_bind_secret: false,
      can_manage_secrets: false,
      can_test: false,
      can_refresh: false,
      can_delete: false,
    },
  };
}

function secretList({
  canCreate = false,
  secrets = [],
}: {
  canCreate?: boolean;
  secrets?: ConnectionSecretMetadata[];
} = {}): ConnectionSecretListResponse {
  return {
    secrets,
    actions: { can_create: canCreate },
    providers: {
      operator_aliases: false,
      local_encrypted: true,
    },
  };
}

function localSecret(
  overrides: Partial<ConnectionSecretMetadata> = {},
): ConnectionSecretMetadata {
  return {
    id: 'local-1',
    etag: '"local-etag-1"',
    label: 'Billing token',
    provider: 'local_encrypted',
    configured: true,
    compatible_purposes: ['static_bearer'],
    dependency_count: 0,
    version: 1,
    actions: { can_rotate: true, can_delete: true },
    ...overrides,
  };
}

function requestUrl(input: RequestInfo | URL): URL {
  return new URL(String(input), 'http://localhost');
}

function headerValue(
  headers: HeadersInit | undefined,
  name: string,
): string | null {
  return new Headers(headers).get(name);
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
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}
