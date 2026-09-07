import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchAdminCapabilities } from './api';
import { AdminCapabilitiesNotice } from './AdminCapabilitiesNotice';
import { hasAdminPermission, refreshAdminCapabilities, useAdminCapabilities } from './adminCapabilities';

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

beforeEach(() => { vi.useFakeTimers(); });
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
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
