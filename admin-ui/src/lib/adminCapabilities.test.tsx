import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { adminFetchJson, fetchAdminCapabilities } from './api';
import { clearMemoryToken, setMemoryToken } from './auth';
import { AdminCapabilitiesNotice } from './AdminCapabilitiesNotice';
import { hasAdminPermission, refreshAdminCapabilities, useAdminCapabilities } from './adminCapabilities';
import { adminIdentityChanged, adminNavigationChanged } from './adminSession';

const WRITE = 'admin:tokens:write';
function Consumer() {
  const state = useAdminCapabilities();
  return <><output data-testid="state">{state.status}</output>
    <button disabled={!hasAdminPermission(state, WRITE)}>Protected mutation</button>
    <AdminCapabilitiesNotice state={state} /></>;
}
function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
function deferred() {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((done) => { resolve = done; });
  return { promise, resolve };
}
async function settle(action?: () => void) {
  await act(async () => { action?.(); });
}
async function advance(ms: number) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms); });
}
function expectState(status: string, enabled = false) {
  expect(screen.getByTestId('state').textContent).toBe(status);
  expect((screen.getByRole('button', { name: 'Protected mutation' }) as HTMLButtonElement).disabled).toBe(!enabled);
}

beforeEach(() => { vi.useFakeTimers(); clearMemoryToken(); });
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  clearMemoryToken();
  window.sessionStorage.clear();
});

describe('shared server capabilities', () => {
  it('shares one request and fails closed until the response arrives', async () => {
    const request = deferred();
    const fetch = vi.fn(() => request.promise);
    vi.stubGlobal('fetch', fetch);
    render(<><Consumer /><Consumer /></>);
    expect(fetch).toHaveBeenCalledTimes(1);
    for (const button of screen.getAllByRole('button', { name: 'Protected mutation' })) {
      expect((button as HTMLButtonElement).disabled).toBe(true);
    }
    await settle(() => request.resolve(json({ permissions: [WRITE] })));
    for (const button of screen.getAllByRole('button', { name: 'Protected mutation' })) {
      expect((button as HTMLButtonElement).disabled).toBe(false);
    }
    expect(fetch.mock.calls[0]).toEqual(['/v1/admin/capabilities', expect.objectContaining({ cache: 'no-store', credentials: 'same-origin' })]);
  });

  it.each([401, 403, 503])('distinguishes HTTP %i and does not immediately retry it', async (status) => {
    const fetch = vi.fn(() => Promise.resolve(json({ error: 'rejected' }, status)));
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />);
    await settle();
    expectState(status === 401 ? 'unauthenticated' : status === 403 ? 'forbidden' : 'unavailable');
    expect(screen.getByRole('alert')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Retry permissions' })).toBeTruthy();
    await advance(10_000);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([[], { permissions: '*' }, { permissions: [WRITE, null] }, { permissions: ['*'] }])('rejects malformed capabilities %j', async (body) => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(json(body))));
    render(<Consumer />); await settle(); expectState('unavailable');
  });

  it('accepts the existing nested secret permission and deduplicates grants', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(json({ permissions: ['admin:connections:secrets:write', WRITE, WRITE] }))));
    await expect(fetchAdminCapabilities()).resolves.toEqual({ permissions: ['admin:connections:secrets:write', WRITE] });
  });

  it('times out a hanging request, offers retry, and ignores its late response', async () => {
    const old = deferred();
    const fetch = vi.fn().mockReturnValueOnce(old.promise).mockResolvedValue(json({ permissions: [] }));
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />);
    await advance(10_000); expectState('unavailable');
    await settle(() => fireEvent.click(screen.getByRole('button', { name: 'Retry permissions' })));
    expectState('ready');
    await settle(() => old.resolve(json({ permissions: [WRITE] })));
    expectState('ready');
  });

  it.each([200, 401, 403])('ignores a previous identity response with HTTP %i', async (status) => {
    const old = deferred();
    const current = deferred();
    const fetch = vi.fn().mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise);
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />);
    await settle(() => { setMemoryToken('generated-test-opaque-identity'); });
    expectState('loading');
    await settle(() => current.resolve(json({ permissions: [] })));
    expectState('ready');
    await settle(() => old.resolve(json({ permissions: [WRITE] }, status)));
    expectState('ready'); expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('clears grants synchronously on bearer replacement and clearing', async () => {
    const next = deferred();
    const fetch = vi.fn().mockResolvedValueOnce(json({ permissions: [WRITE] })).mockReturnValue(next.promise);
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />); await settle(); expectState('ready', true);
    await settle(() => { setMemoryToken('generated-test-new-identity'); });
    expectState('loading');
    await settle(() => { clearMemoryToken(); });
    expectState('loading'); expect(fetch).toHaveBeenCalledTimes(3);
    const options = fetch.mock.calls[2][1] as RequestInit;
    expect(new Headers(options.headers).has('Authorization')).toBe(false);
  });

  it('clears a recovered cookie session again when it expires a second time', async () => {
    let status = 401;
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(json({ permissions: [WRITE] }, status))));
    render(<Consumer />); await settle(); expectState('unauthenticated');
    status = 200;
    await settle(() => refreshAdminCapabilities()); await advance(5_000);
    expectState('ready', true);
    status = 401;
    await act(async () => { await expect(adminFetchJson('/resource')).rejects.toMatchObject({ status: 401 }); });
    expectState('unauthenticated');
  });

  it('ignores an aborted request even when a transport returns 401 after cancellation', async () => {
    const response = deferred();
    vi.stubGlobal('fetch', vi.fn((input: string) => input.endsWith('/capabilities')
      ? Promise.resolve(json({ permissions: [WRITE] })) : response.promise));
    render(<Consumer />); await settle(); expectState('ready', true);
    const controller = new AbortController();
    const request = adminFetchJson('/resource', { signal: controller.signal });
    const rejected = expect(request).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort(); response.resolve(json({}, 401));
    await rejected; expectState('ready', true);
  });

  it('invalidates on 401 and does not let late resources restore identity data', async () => {
    const resource = deferred();
    vi.stubGlobal('fetch', vi.fn((input: string) => input.endsWith('/capabilities')
      ? Promise.resolve(json({ permissions: [WRITE] }))
      : input === '/slow' ? resource.promise : Promise.resolve(json({ error: 'expired' }, 401))));
    render(<Consumer />); await settle(); expectState('ready', true);
    const late = adminFetchJson('/slow');
    const rejected = expect(late).rejects.toThrow('Admin identity changed');
    await act(async () => { await expect(adminFetchJson('/resource')).rejects.toMatchObject({ status: 401 }); });
    expectState('unauthenticated');
    resource.resolve(json({ protected: true })); await rejected;
  });

  it('refreshes after a resource 403 without repeating the failed resource call', async () => {
    const fetch = vi.fn((input: string) => Promise.resolve(input.endsWith('/capabilities')
      ? json({ permissions: [WRITE] }) : json({ error: 'denied' }, 403)));
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />); await settle();
    await act(async () => { await expect(adminFetchJson('/resource')).rejects.toMatchObject({ status: 403 }); });
    expectState('loading'); await advance(5_000); expectState('ready', true);
    await advance(10_000);
    expect(fetch.mock.calls.filter(([url]) => url === '/resource')).toHaveLength(1);
    expect(fetch.mock.calls.filter(([url]) => url.endsWith('/capabilities'))).toHaveLength(2);
  });

  it('keeps resource 503 separate from authentication and invalidates only successful policy mutations', async () => {
    const fetch = vi.fn((input: string) => Promise.resolve(input.endsWith('/capabilities')
      ? json({ permissions: [WRITE] }) : input === '/unavailable' ? json({}, 503) : json({})));
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />); await settle();
    await act(async () => { await expect(adminFetchJson('/unavailable')).rejects.toMatchObject({ status: 503 }); });
    expectState('ready', true);
    await act(async () => { await adminFetchJson('/v1/admin/policy/rules/preview', { method: 'POST' }); });
    expectState('ready', true);
    await act(async () => { await adminFetchJson('/v1/admin/policy', { method: 'PUT' }); });
    expectState('loading'); await advance(5_000); expectState('ready', true);
    await act(async () => { await adminFetchJson('/v1/admin/auth/logout', { method: 'POST' }); });
    expect(fetch.mock.calls.filter(([url]) => url.endsWith('/capabilities'))).toHaveLength(3);
  });

  it('coalesces focus, navigation and retries; polls visible pages and suspends hidden ones', async () => {
    const fetch = vi.fn((_input: RequestInfo | URL) => Promise.resolve(json({ permissions: [WRITE] })));
    vi.stubGlobal('fetch', fetch);
    render(<Consumer />); await settle();
    await settle(() => {
      window.dispatchEvent(new Event('focus'));
      adminNavigationChanged(); refreshAdminCapabilities(); refreshAdminCapabilities();
    });
    expectState('loading'); expect(fetch).toHaveBeenCalledTimes(1);
    await advance(5_000); expect(fetch).toHaveBeenCalledTimes(2);
    await advance(55_000); expect(fetch).toHaveBeenCalledTimes(3);
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    await settle(() => document.dispatchEvent(new Event('visibilitychange')));
    expectState('loading'); await advance(120_000); expect(fetch).toHaveBeenCalledTimes(3);
    visibility.mockReturnValue('visible');
    await settle(() => document.dispatchEvent(new Event('visibilitychange')));
    expectState('ready', true); expect(fetch).toHaveBeenCalledTimes(4);
  });

  it('uses the configured management prefix without requesting policy', async () => {
    const meta = document.createElement('meta');
    meta.name = 'greengateway-admin-api-base'; meta.content = '/v1/operations'; document.head.append(meta);
    try {
      const fetch = vi.fn((_input: RequestInfo | URL) => Promise.resolve(json({ permissions: [WRITE] })));
      vi.stubGlobal('fetch', fetch); render(<Consumer />); await settle();
      expect(fetch.mock.calls[0][0]).toBe('/v1/operations/capabilities');
      expectState('ready', true);
    } finally { meta.remove(); }
  });
});
