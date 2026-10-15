import { afterEach, describe, expect, it, vi } from 'vitest';
import { adminFetchJson } from './api';
import { adminAuthorizationFailed, getAdminIdentityVersion, isAdminUnauthenticated } from './adminSession';
import { ADMIN_TOKEN_STORAGE_KEY, adminRequestCredentials, authHeaders, clearMemoryToken, getCredentialSelection, getMemoryToken, isBearerSelected, removeLegacyAdminToken, selectBearerMode, setMemoryToken } from './auth';

const canary = () => `test-${crypto.randomUUID()}`;
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  clearMemoryToken();
  sessionStorage.clear();
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
});

describe('memory-only admin credentials', () => {
  it('deletes legacy storage without reading it or promoting it to an active credential', () => {
    sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, canary());
    const read = vi.spyOn(Storage.prototype, 'getItem');
    const write = vi.spyOn(Storage.prototype, 'setItem');
    removeLegacyAdminToken();
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(sessionStorage.length).toBe(0);
    expect(getMemoryToken()).toBeNull();
  });

  it('holds replacement credentials only in memory, including when storage is disabled', () => {
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('disabled'); });
    const read = vi.spyOn(Storage.prototype, 'getItem');
    const write = vi.spyOn(Storage.prototype, 'setItem');
    const first = canary();
    const second = canary();
    const identity = getAdminIdentityVersion();
    setMemoryToken(` ${first} `);
    expect(authHeaders()).toEqual({ Authorization: `Bearer ${first}` });
    setMemoryToken(second);
    expect(getAdminIdentityVersion()).toBe(identity + 2);
    expect(authHeaders()).toEqual({ Authorization: `Bearer ${second}` });
    clearMemoryToken();
    expect(authHeaders()).toEqual({});
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
  });

  it('clears a rejected bearer and does not fall back to an ambient cookie', async () => {
    setMemoryToken(canary());
    const fetch = vi.fn().mockResolvedValue(new Response('{}', { status: 401 }));
    vi.stubGlobal('fetch', fetch);
    await expect(adminFetchJson('/v1/admin/capabilities')).rejects.toMatchObject({ status: 401 });
    expect(getMemoryToken()).toBeNull();
    expect(isAdminUnauthenticated()).toBe(true);
    expect(adminRequestCredentials()).toBe('omit');
    fetch.mockResolvedValue(new Response('{}', { status: 401 }));
    await expect(adminFetchJson('/v1/admin/capabilities')).rejects.toMatchObject({ status: 401 });
    const init = fetch.mock.calls[1][1];
    expect(init.credentials).toBe('omit');
    expect(new Headers(init.headers).has('Authorization')).toBe(false);
  });

  it('does not clear a replacement credential because an older request returned 401', () => {
    setMemoryToken(canary());
    const oldIdentity = getAdminIdentityVersion();
    const current = canary();
    setMemoryToken(current);
    adminAuthorizationFailed(401, oldIdentity, false);
    expect(getMemoryToken()).toBe(current);
    expect(isAdminUnauthenticated()).toBe(false);
  });

  it('clears memory and invalidates identity when a page is hidden for navigation or bfcache', () => {
    setMemoryToken(canary());
    const identity = getAdminIdentityVersion();
    window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    expect(getMemoryToken()).toBeNull();
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    expect(isAdminUnauthenticated()).toBe(true);
    window.dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    expect(getMemoryToken()).toBeNull();
  });

  it('invalidates pending login work on pagehide even when already signed out', () => {
    adminAuthorizationFailed(401, getAdminIdentityVersion(), false);
    const identity = getAdminIdentityVersion();
    window.dispatchEvent(new PageTransitionEvent('pagehide'));
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    expect(isAdminUnauthenticated()).toBe(true);
  });

  it('switches to explicit bearer mode without a token or ambient session cookie', async () => {
    setMemoryToken(canary());
    const identity = getAdminIdentityVersion();
    const read = vi.spyOn(Storage.prototype, 'getItem');
    const write = vi.spyOn(Storage.prototype, 'setItem');
    selectBearerMode();
    expect(getMemoryToken()).toBeNull();
    expect(isBearerSelected()).toBe(true);
    expect(getAdminIdentityVersion()).toBe(identity + 1);
    const fetch = vi.fn().mockResolvedValue(new Response('{}'));
    vi.stubGlobal('fetch', fetch);
    await adminFetchJson('/v1/admin/capabilities');
    expect(fetch.mock.calls[0][1].credentials).toBe('omit');
    expect(new Headers(fetch.mock.calls[0][1].headers).has('Authorization')).toBe(false);
    clearMemoryToken();
    expect(isBearerSelected()).toBe(false);
    expect(adminRequestCredentials()).toBe('same-origin');
    expect(getAdminIdentityVersion()).toBe(identity + 2);
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
  });

  it('changes the credential selection only when this tab chooses credentials', async () => {
    const selection = getCredentialSelection();
    // A rejection or a page hide changes the identity, not the chosen credentials.
    adminAuthorizationFailed(401, getAdminIdentityVersion(), true);
    window.dispatchEvent(new PageTransitionEvent('pagehide'));
    expect(isAdminUnauthenticated()).toBe(true);
    expect(getCredentialSelection()).toBe(selection);
    setMemoryToken(canary());
    selectBearerMode();
    clearMemoryToken();
    expect(getCredentialSelection()).toBe(selection + 3);
    // Cookie logout through the shared client counts only once it succeeds.
    document.cookie = 'csrf_token=test-csrf; Path=/';
    const fetch = vi.fn().mockResolvedValue(new Response('{"error":"invalid_origin_or_csrf"}', { status: 403 }));
    vi.stubGlobal('fetch', fetch);
    await expect(adminFetchJson('/v1/admin/auth/logout', { method: 'POST' })).rejects.toMatchObject({ status: 403 });
    expect(getCredentialSelection()).toBe(selection + 3);
    fetch.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(adminFetchJson('/v1/admin/auth/logout', { method: 'POST' })).resolves.toBeNull();
    expect(getCredentialSelection()).toBe(selection + 4);
    expect(isBearerSelected()).toBe(false);
  });

  it('refuses cross-origin requests before attaching any credentials', async () => {
    setMemoryToken(canary());
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    await expect(adminFetchJson('https://other.example.test/v1/admin/tokens')).rejects.toThrow('current origin');
    expect(fetch).not.toHaveBeenCalled();
  });
});
