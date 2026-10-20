import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAdminAuthDiscovery, discoverAdminAuth } from './adminAuthDiscovery';

const OFFER = {
  storage: 'standalone_memory',
  completion_mode: 'cookie',
  login_url: '/v1/admin/auth/login',
  completion_url: '/v1/admin/auth/callback',
  logout_url: '/v1/admin/auth/logout',
  max_age_seconds: 3600,
};
const SESSION = {
  loginUrl: '/v1/admin/auth/login',
  completionUrl: '/v1/admin/auth/callback',
  logoutUrl: '/v1/admin/auth/logout',
};

afterEach(() => {
  vi.unstubAllGlobals();
});

type Answer = Response | Error;

/** `/version` answers first; `auth/config` is the split-listener fallback. */
function discoveryFetch(version: () => Answer, config: () => Answer = () => json({ error: 'unexpected' }, 500)) {
  const fetch = vi.fn((input: string) => {
    const answer = input === '/version' ? version() : input === '/v1/admin/auth/config' ? config() : new Error(`unexpected fetch: ${input}`);
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  });
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const notFound = () => json({ error: 'not found' }, 404);

describe('admin session discovery', () => {
  it.each([
    ['admin login configured', true],
    ['admin login not configured', false],
  ])('treats a /version answer without a session as the explicit bearer answer (%s)', async (_case, loginConfigured) => {
    const fetch = discoveryFetch(() => json({ version: '0.5.0', admin_login_configured: loginConfigured }));
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'bearer', loginConfigured });
    expect(fetch.mock.calls).toEqual([['/version', { cache: 'no-store' }]]);
  });

  it('accepts a cookie offer for this prefix from /version or the split-listener route', async () => {
    discoveryFetch(() => json({ admin_login_configured: true, admin_session: OFFER }));
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'cookie', session: SESSION });

    const fetch = discoveryFetch(notFound, () => json({ bearer_completion: true, admin_session: OFFER }));
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'cookie', session: SESSION });
    expect(fetch.mock.calls[1]).toEqual([
      '/v1/admin/auth/config',
      { credentials: 'omit', cache: 'no-store', redirect: 'error' },
    ]);
  });

  it.each([401, 403, 404])('does not read a %s from the split-listener route as "no session offered"', async (status) => {
    discoveryFetch(notFound, () => json({ error: 'rejected' }, status));
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'unconfirmed' });
  });

  it.each([
    ['a malformed /version advertisement', () => json({ admin_login_configured: true, admin_session: { ...OFFER, completion_mode: 'bearer' } }), notFound],
    ['an advertisement for another prefix', () => json({ admin_login_configured: true, admin_session: { ...OFFER, logout_url: '/v1/other/auth/logout' } }), notFound],
    ['a split-listener success without an offer', notFound, () => json({ bearer_completion: true, admin_session: null })],
    ['a split-listener success that is not JSON', notFound, () => new Response('<html></html>')],
    ['a rate-limited split-listener route', notFound, () => json({ error: 'rate_limited' }, 429)],
    ['an unavailable gateway', () => json({ error: 'unavailable' }, 503), () => json({ error: 'unavailable' }, 503)],
    ['a network failure or refused redirect', () => new TypeError('offline'), () => new TypeError('redirect')],
  ])('reports %s as unavailable', async (_case, version, config) => {
    discoveryFetch(version, config);
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'unavailable' });
  });

  it('never falls back after a malformed /version advertisement', async () => {
    const fetch = discoveryFetch(() => json({ admin_login_configured: true, admin_session: 'cookie' }), notFound);
    await expect(discoverAdminAuth()).resolves.toEqual({ kind: 'unavailable' });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('one discovery answer per page load', () => {
  it('shares one request between every caller and keeps an explicit answer final', async () => {
    let offered = true;
    const fetch = discoveryFetch(() => offered
      ? json({ admin_login_configured: true, admin_session: OFFER })
      : json({ error: 'unavailable' }, 503));
    const discovery = createAdminAuthDiscovery();

    const [completion, panel] = await Promise.all([discovery.current(), discovery.current()]);
    offered = false;

    expect(completion).toEqual({ kind: 'cookie', session: SESSION });
    expect(panel).toBe(completion);
    // A later failure cannot change the mode the completion already used.
    await expect(discovery.current()).resolves.toBe(completion);
    await expect(discovery.retry()).resolves.toBe(completion);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('keeps an unconfirmed answer final', async () => {
    const fetch = discoveryFetch(notFound, () => json({ error: 'unauthenticated' }, 401));
    const discovery = createAdminAuthDiscovery();
    await expect(discovery.current()).resolves.toEqual({ kind: 'unconfirmed' });
    await expect(discovery.retry()).resolves.toEqual({ kind: 'unconfirmed' });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('asks again only on an explicit retry after an unavailable answer', async () => {
    let available = false;
    const fetch = discoveryFetch(() => available
      ? json({ admin_login_configured: true, admin_session: OFFER })
      : json({ error: 'unavailable' }, 503), () => json({ error: 'unavailable' }, 503));
    const discovery = createAdminAuthDiscovery();

    const unavailable = await discovery.current();
    expect(unavailable).toEqual({ kind: 'unavailable' });
    const requests = fetch.mock.calls.length;
    await expect(discovery.current()).resolves.toBe(unavailable);
    expect(fetch.mock.calls.length).toBe(requests);

    available = true;
    // Concurrent retries replace the unavailable answer once.
    const [first, second] = await Promise.all([discovery.retry(), discovery.retry()]);
    expect(first).toEqual({ kind: 'cookie', session: SESSION });
    expect(second).toBe(first);
    await expect(discovery.current()).resolves.toBe(first);
    expect(fetch.mock.calls.length).toBe(requests + 1);
  });
});
