import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { StrictMode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminShell } from './App';
import { adminFetchJson } from './lib/api';
import { getAdminIdentityVersion, isAdminUnauthenticated } from './lib/adminSession';
import { ADMIN_TOKEN_STORAGE_KEY, getMemoryToken, clearMemoryToken, isBearerSelected, setMemoryToken } from './lib/auth';

const ADMIN_SESSION = {
  storage: 'standalone_memory',
  completion_mode: 'cookie',
  login_url: '/v1/admin/auth/login',
  completion_url: '/v1/admin/auth/callback',
  logout_url: '/v1/admin/auth/logout',
  max_age_seconds: 3600,
};

const UNCONFIRMED_COMPLETION =
  'SSO sign-in was not completed: the gateway did not confirm whether it issues a session cookie, so no token was requested. ' +
  'Use a bearer token, or ask an operator to check that the admin auth/config route reaches the gateway.';
const UNAVAILABLE_COMPLETION =
  'SSO sign-in was not completed: sign-in options are unavailable, so no token was requested. Start sign-in again.';

afterEach(() => {
  cleanup();
  clearMemoryToken();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.removeItem('greengateway_admin_theme');
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  window.history.replaceState(null, '', '/');
  document.cookie = 'csrf_token=; Max-Age=0; Path=/';
  document.cookie = 'ops_csrf=; Max-Age=0; Path=/';
  document.querySelectorAll('meta[data-auth-test]').forEach((meta) => meta.remove());
  delete document.documentElement.dataset.theme;
});

describe('AdminShell', () => {
  it('clears protected route drafts and grants immediately when the identity changes', async () => {
    let permissions = ['admin:tokens:write'];
    vi.stubGlobal('fetch', vi.fn((input: string) => Promise.resolve(new Response(JSON.stringify(
      input.endsWith('/capabilities') ? { permissions } : { tokens: [], next_cursor: null },
    )))));
    render(<MemoryRouter initialEntries={['/tokens']}><AdminShell /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText('Scopes'), { target: { value: 'admin:tokens:read' } });
    await waitFor(() => expect((screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement).disabled).toBe(false));
    permissions = [];
    await act(async () => { setMemoryToken('generated-replacement-identity'); });
    expect((screen.getByLabelText('Scopes') as HTMLInputElement).value).toBe('');
    expect((screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('clears protected data on 401, keeps the error visible, and explicitly recovers a cookie session', async () => {
    let capabilityStatus = 200;
    const fetch = vi.fn((input: string) => Promise.resolve(new Response(JSON.stringify(
      input.endsWith('/capabilities') ? { permissions: ['admin:tokens:write'] } : { tokens: [], next_cursor: null },
    ), { status: input === '/expired' ? 401 : input.endsWith('/capabilities') ? capabilityStatus : 200 })));
    vi.stubGlobal('fetch', fetch);
    render(<MemoryRouter initialEntries={['/tokens']}><AdminShell /></MemoryRouter>);
    fireEvent.change(screen.getByLabelText('Scopes'), { target: { value: 'admin:tokens:read' } });
    await waitFor(() => expect((screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement).disabled).toBe(false));
    await act(async () => { await expect(adminFetchJson('/expired')).rejects.toMatchObject({ status: 401 }); });
    expect(screen.queryByLabelText('Scopes')).toBeNull();
    expect(screen.getByRole('alert').textContent).toContain('Admin session expired');
    expect(document.activeElement).toBe(screen.getByRole('alert'));
    expect(fetch.mock.calls.filter(([url]) => url.startsWith('/v1/admin/tokens'))).toHaveLength(1);
    capabilityStatus = 503;
    fireEvent.click(screen.getByRole('button', { name: 'Check session' }));
    await screen.findByText('Admin permissions are temporarily unavailable. Try checking your session again.');
    expect(screen.queryByLabelText('Scopes')).toBeNull();
    capabilityStatus = 200;
    fireEvent.click(screen.getByRole('button', { name: 'Check session' }));
    expect((await screen.findByLabelText('Scopes') as HTMLInputElement).value).toBe('');
    expect(fetch.mock.calls.filter(([url]) => url === '/expired')).toHaveLength(1);
  });

  it('keeps token values out of attributes and clears the draft on save, replacement and expiry', async () => {
    vi.stubGlobal('fetch', versionFetchMock(false));
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    const input = screen.getByLabelText('Token', { exact: true }) as HTMLInputElement;
    const canary = `test-${crypto.randomUUID()}`;
    fireEvent.change(input, { target: { value: canary } });
    expect(input.getAttribute('value')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Show token' }));
    expect(input.type).toBe('text');
    expect(screen.getByRole('button', { name: 'Hide token' }).getAttribute('aria-pressed')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(input.value).toBe('');
    expect(input.type).toBe('password');
    expect(getMemoryToken() === canary).toBe(true);
    expect(document.documentElement.outerHTML.includes(canary)).toBe(false);
    expect(sessionStorage.getItem(ADMIN_TOKEN_STORAGE_KEY)).toBeNull();
    fireEvent.change(input, { target: { value: 'unsaved-draft' } });
    await act(async () => { setMemoryToken('replacement'); });
    expect(input.value).toBe('');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 401 })));
    fireEvent.change(input, { target: { value: 'another-draft' } });
    await act(async () => { await expect(adminFetchJson('/expired')).rejects.toMatchObject({ status: 401 }); });
    expect(input.value).toBe('');
    expect(getMemoryToken()).toBeNull();
    await screen.findByText('Session ended. Sign in again.');
  });

  it('does not restore an SSO token after the active identity changed during completion', async () => {
    let complete!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => { complete = resolve; });
    const fallback = versionFetchMock(true);
    vi.stubGlobal('fetch', vi.fn((url: string) => url.endsWith('/auth/callback') ? pending : fallback(url)));
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await act(async () => { setMemoryToken('new-identity'); });
    await act(async () => { complete(new Response(JSON.stringify({ access_token: 'old-identity' }))); });
    await screen.findByText('SSO completion discarded because the session changed. Start sign-in again.');
    expect(getMemoryToken()).toBe('new-identity');
  });

  it('persists the selected color theme on the document element', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('light');

    fireEvent.click(
      screen.getByRole('button', { name: 'Switch to dark theme' }),
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(window.localStorage.getItem('greengateway_admin_theme')).toBe(
      'dark',
    );
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('rehydrates the selected color theme from localStorage on mount', () => {
    window.localStorage.setItem('greengateway_admin_theme', 'dark');

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('exchanges completion once with browser cookies and clears the fragment before fetching', async () => {
    document.cookie = 'csrf_token=browser-csrf; Path=/';
    const fallback = versionFetchMock(false);
    const completionCalls: RequestInit[] = [];
    vi.stubGlobal('fetch', vi.fn((url: string, options?: RequestInit) => {
      if (url !== '/v1/admin/auth/callback') return fallback(url);
      expect(window.location.hash).toBe('');
      completionCalls.push(options!);
      return Promise.resolve(new Response(JSON.stringify({
        access_token: 'oidc-exchanged-token',
      })));
    }));
    window.history.replaceState(
      null,
      '',
      '/admin/#/auth/complete?code=authorization-code&state=browser-bound-state',
    );

    render(
      <StrictMode>
        <MemoryRouter initialEntries={['/']}>
          <AdminShell />
        </MemoryRouter>
      </StrictMode>,
    );

    await waitFor(() => {
      expect(getMemoryToken()).toBe(
        'oidc-exchanged-token',
      );
    });
    expect(window.location.hash).toBe('');
    expect(
      await screen.findByText('Signed in with SSO in this tab until reload or session expiry.'),
    ).toBeTruthy();
    expect(completionCalls).toHaveLength(1);
    expect(completionCalls[0]).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      body: JSON.stringify({
        code: 'authorization-code', state: 'browser-bound-state',
      }),
    });
    const headers = new Headers(completionCalls[0].headers);
    expect(headers.get('x-csrf-token')).toBe('browser-csrf');
    expect(headers.has('authorization')).toBe(false);
  });

  it.each([
    'token=unbound-token', 'code=code', 'state=state',
    'code=code&state=state&token=unbound-token',
    'code=one&code=two&state=state',
  ])('rejects incomplete or legacy completion fragments: %s', async (fragment) => {
    vi.stubGlobal('fetch', versionFetchMock(false));
    setMemoryToken('existing-session');
    window.history.replaceState(null, '', `/admin/#/auth/complete?${fragment}`);
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await screen.findByText('SSO sign-in did not complete. Start sign-in again.');
    expect(getMemoryToken()).toBe('existing-session');
    expect(window.location.hash).toBe('');
    expect(vi.mocked(fetch).mock.calls.some(([url]) => url === '/v1/admin/auth/callback')).toBe(false);
  });

  it.each(['denied', 'network', 'missing-token', 'invalid-json'])('keeps the session unchanged when completion fails: %s', async (failure) => {
    const fallback = versionFetchMock(false);
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url !== '/v1/admin/auth/callback') return fallback(url);
      if (failure === 'network') return Promise.reject(new Error('offline'));
      return Promise.resolve(new Response(failure === 'invalid-json' ? 'invalid' : '{}', { status: failure === 'denied' ? 400 : 200 }));
    }));
    setMemoryToken('existing-session');
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await screen.findByText('SSO sign-in did not complete. Start sign-in again.');
    expect(getMemoryToken()).toBe('existing-session');
    expect(window.location.hash).toBe('');
  });

  it('hides the SSO login link when admin login is not configured', async () => {
    vi.stubGlobal('fetch', versionFetchMock(false));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/version', { cache: 'no-store' }));
    expect(screen.queryByRole('link', { name: 'Log in with SSO' })).toBeNull();
  });

  it('shows the SSO login link when admin login is configured', async () => {
    vi.stubGlobal('fetch', versionFetchMock(true));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    const link = await screen.findByRole('link', { name: 'Log in with SSO' });
    expect(link.getAttribute('href')).toBe('/v1/admin/auth/login');
  });

  it('completes an offered cookie session without reading, storing or rendering a token', async () => {
    document.cookie = 'csrf_token=browser-csrf; Path=/';
    const canary = `test-${crypto.randomUUID()}`;
    const read = vi.spyOn(Storage.prototype, 'getItem');
    const write = vi.spyOn(Storage.prototype, 'setItem');
    const fetch = sessionFetchMock({
      '/version': offeredVersion,
      // Even a token-shaped field in a cookie completion is never read.
      '/v1/admin/auth/callback': () => jsonResponse({ authenticated: true, expires_in: 3600, access_token: canary }),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=authorization-code&state=browser-bound-state');
    const identity = getAdminIdentityVersion();

    render(<StrictMode><MemoryRouter><AdminShell /></MemoryRouter></StrictMode>);

    await screen.findByText('Signed in with SSO. The session cookie lasts until logout or session expiry.');
    const completions = fetch.mock.calls.filter(([url]) => url === '/v1/admin/auth/callback');
    expect(completions).toHaveLength(1);
    expect(completions[0][1]).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      body: JSON.stringify({ code: 'authorization-code', state: 'browser-bound-state', mode: 'cookie' }),
    });
    const headers = new Headers(completions[0][1]?.headers);
    expect(headers.get('x-csrf-token')).toBe('browser-csrf');
    expect(headers.has('authorization')).toBe(false);
    expect(getMemoryToken()).toBeNull();
    expect(isBearerSelected()).toBe(false);
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    expect(document.documentElement.outerHTML.includes(canary)).toBe(false);
    expect(read.mock.calls.every(([key]) => key === 'greengateway_admin_theme')).toBe(true);
    expect(write.mock.calls.every(([key]) => key === 'greengateway_admin_theme')).toBe(true);
    expect(window.sessionStorage.length).toBe(0);
    expect(screen.queryByLabelText('Token', { exact: true })).toBeNull();
    expect(screen.getByRole('link', { name: 'Log in with SSO' }).getAttribute('href')).toBe('/v1/admin/auth/login');
    // The completion and the panel share one discovery answer.
    expect(fetch.mock.calls.filter(([url]) => url === '/version')).toHaveLength(1);
  });

  it.each([false, true])('signs in when admin requests are rejected before the session cookie exists (StrictMode %s)', async (strict) => {
    const server = cookieSessionServer();
    vi.stubGlobal('fetch', server.fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    const shell = <MemoryRouter><AdminShell /></MemoryRouter>;

    render(strict ? <StrictMode>{shell}</StrictMode> : shell);
    // The dashboard asks for permissions before the completion answers, and
    // the gateway rejects that cookie-less request.
    await waitFor(() => expect(isAdminUnauthenticated()).toBe(true));
    await waitFor(() => expect(server.completions()).toHaveLength(1));
    const identity = getAdminIdentityVersion();
    await act(async () => { server.complete(); });

    await screen.findByText('Signed in with SSO. The session cookie lasts until logout or session expiry.');
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    expect(isAdminUnauthenticated()).toBe(false);
    expect(await screen.findByLabelText('Endpoint')).toBeTruthy();
    expect(server.active()).toBe(true);
    expect(server.logouts()).toHaveLength(0);
    expect(getMemoryToken()).toBeNull();
  });

  it('ends a cookie session issued after the operator switched to a bearer token', async () => {
    document.cookie = 'csrf_token=browser-csrf; Path=/';
    const server = cookieSessionServer();
    vi.stubGlobal('fetch', server.fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await waitFor(() => expect(server.completions()).toHaveLength(1));
    const toggle = await screen.findByRole('button', { name: 'Use bearer token' });

    await act(async () => { fireEvent.click(toggle); });
    const token = `test-${crypto.randomUUID()}`;
    fireEvent.change(screen.getByLabelText('Token', { exact: true }), { target: { value: token } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await act(async () => { server.complete(); });

    await screen.findByText('SSO completion discarded because the session changed. Start sign-in again.');
    expect(server.active()).toBe(false);
    const logouts = server.logouts();
    expect(logouts).toHaveLength(1);
    // Revocation sends the session cookie even though bearer mode omits it,
    // and leaves the bearer selection alone.
    expect(logouts[0]).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(new Headers(logouts[0]?.headers).get('x-csrf-token')).toBe('browser-csrf');
    expect(new Headers(logouts[0]?.headers).has('authorization')).toBe(false);
    expect(getMemoryToken()).toBe(token);
    expect(isBearerSelected()).toBe(true);

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Use SSO session' })); });
    await screen.findByText('Sign in with traffic read permission to view gateway observations.');
    expect(screen.queryByLabelText('Endpoint')).toBeNull();
    expect(server.cookieGrants()).toBe(0);
  });

  it.each([
    {
      outcome: 'a discarded session it could not end', body: { authenticated: true, expires_in: 3600 },
      switchToBearer: true, logoutStatus: 503,
      message: 'The SSO session could not be ended and may still be active. Log out from SSO session mode to end it.',
    },
    {
      outcome: 'an unexpected success body', body: { authenticated: false },
      switchToBearer: false, logoutStatus: 204,
      message: 'SSO sign-in did not complete. Start sign-in again.',
    },
  ])('reports $outcome instead of claiming the completion was discarded', async ({ body, switchToBearer, logoutStatus, message }) => {
    const server = cookieSessionServer({ body, logoutStatus });
    vi.stubGlobal('fetch', server.fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await waitFor(() => expect(server.completions()).toHaveLength(1));
    const toggle = await screen.findByRole('button', { name: 'Use bearer token' });
    if (switchToBearer) {
      await act(async () => { fireEvent.click(toggle); });
    }
    await act(async () => { server.complete(); });

    await screen.findByText(message);
    expect(server.logouts()).toHaveLength(1);
    expect(server.active()).toBe(logoutStatus !== 204);
    expect(getMemoryToken()).toBeNull();
  });

  it('offers retry and log out when session discovery is unavailable', async () => {
    let offered = false;
    const fetch = sessionFetchMock({
      '/version': () => offered ? offeredVersion() : jsonResponse({ error: 'unavailable' }, 503),
      '/v1/admin/auth/config': () => jsonResponse({ error: 'unavailable' }, 503),
    });
    vi.stubGlobal('fetch', fetch);
    render(<MemoryRouter><AdminShell /></MemoryRouter>);

    const retry = await screen.findByRole('button', { name: 'Retry sign-in options' });
    expect(screen.getByRole('button', { name: 'Log out' })).toBeTruthy();
    expect(screen.getByText('Sign-in options are unavailable. An SSO session may still be active; retry or log out.')).toBeTruthy();

    offered = true;
    fireEvent.click(retry);

    expect(await screen.findByRole('heading', { level: 2, name: 'SSO session' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Retry sign-in options' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Log out' })).toBeTruthy();
  });

  it('logs out of the cookie session through the shared client with the CSRF header', async () => {
    document.cookie = 'csrf_token=browser-csrf; Path=/';
    let logoutStatus = 403;
    const fetch = sessionFetchMock({
      '/version': offeredVersion,
      '/v1/admin/auth/logout': () => logoutStatus === 204
        ? new Response(null, { status: 204 })
        : jsonResponse({ error: 'invalid_origin_or_csrf' }, logoutStatus),
    });
    vi.stubGlobal('fetch', fetch);
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    const logout = await screen.findByRole('button', { name: 'Log out' });
    const identity = getAdminIdentityVersion();

    fireEvent.click(logout);
    await screen.findByText('Log out did not complete. The session may still be active; try again.');
    expect(getAdminIdentityVersion()).toBe(identity);

    logoutStatus = 204;
    fireEvent.click(screen.getByRole('button', { name: 'Log out' }));
    await screen.findByText('Logged out. Sign in again to continue.');
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    const logouts = fetch.mock.calls.filter(([url]) => url === '/v1/admin/auth/logout');
    expect(logouts).toHaveLength(2);
    for (const [, init] of logouts) {
      expect(init).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
      const headers = new Headers(init?.headers);
      expect(headers.get('x-csrf-token')).toBe('browser-csrf');
      expect(headers.has('authorization')).toBe(false);
    }
  });

  it('clears credentials, grants and drafts when switching between cookie and bearer modes', async () => {
    const fetch = sessionFetchMock({
      '/version': offeredVersion,
      '/v1/admin/capabilities': (init) => init?.credentials === 'omit' && !new Headers(init.headers).has('Authorization')
        ? jsonResponse({ error: 'unauthenticated' }, 401)
        : jsonResponse({ permissions: ['admin:traffic:read'] }),
      '/v1/admin/traffic/endpoints': () => jsonResponse({ endpoints: [], next_cursor: null }),
    });
    vi.stubGlobal('fetch', fetch);
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    const search = await screen.findByLabelText('Endpoint');
    fireEvent.change(search, { target: { value: 'unsaved-draft' } });
    const toggle = screen.getByRole('button', { name: 'Use bearer token' });
    toggle.focus();
    const capabilityRequests = () => fetch.mock.calls.filter(([url]) => url === '/v1/admin/capabilities');
    const before = capabilityRequests().length;

    await act(async () => { fireEvent.click(toggle); });

    expect(isBearerSelected()).toBe(true);
    expect(getMemoryToken()).toBeNull();
    expect(screen.queryByLabelText('Endpoint')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Log out' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Log in with SSO' })).toBeNull();
    expect(document.activeElement?.textContent).toBe('Use SSO session');
    await screen.findByText('Sign in with traffic read permission to view gateway observations.');
    const bearerRequest = capabilityRequests()[before][1];
    expect(bearerRequest?.credentials).toBe('omit');
    expect(new Headers(bearerRequest?.headers).has('Authorization')).toBe(false);

    const input = screen.getByLabelText('Token', { exact: true }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: `test-${crypto.randomUUID()}` } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(getMemoryToken()).not.toBeNull();
    fireEvent.change(input, { target: { value: 'another-draft' } });
    const identity = getAdminIdentityVersion();

    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Use SSO session' })); });

    expect(getMemoryToken()).toBeNull();
    expect(isBearerSelected()).toBe(false);
    expect(getAdminIdentityVersion()).toBeGreaterThan(identity);
    expect(screen.queryByLabelText('Token', { exact: true })).toBeNull();
    expect((await screen.findByLabelText('Endpoint') as HTMLInputElement).value).toBe('');
    expect(capabilityRequests().at(-1)?.[1]?.credentials).toBe('same-origin');
  });

  it('keeps an explicit bearer selection when its token is cleared or saved empty', async () => {
    vi.stubGlobal('fetch', sessionFetchMock({ '/version': offeredVersion }));
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Use bearer token' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(isBearerSelected()).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(isBearerSelected()).toBe(true);
    expect(screen.getByRole('button', { name: 'Use SSO session' })).toBeTruthy();
  });

  it('discovers sessions on a split management listener with a custom prefix and CSRF names', async () => {
    for (const [name, content] of [
      ['greengateway-admin-api-base', '/v1/ops'],
      ['greengateway-csrf-cookie-name', 'ops_csrf'],
      ['greengateway-csrf-header-name', 'x-ops-csrf'],
    ]) {
      const meta = document.createElement('meta');
      meta.name = name; meta.content = content; meta.dataset.authTest = '';
      document.head.append(meta);
    }
    document.cookie = 'ops_csrf=ops-csrf; Path=/';
    const fetch = sessionFetchMock({
      // The data listener owns /version; the management origin answers 404.
      '/version': () => jsonResponse({ error: 'not found' }, 404),
      '/v1/ops/auth/config': () => jsonResponse({
        bearer_completion: true,
        admin_session: {
          ...ADMIN_SESSION,
          login_url: '/v1/ops/auth/login',
          completion_url: '/v1/ops/auth/callback',
          logout_url: '/v1/ops/auth/logout',
        },
      }),
      '/v1/ops/auth/callback': () => jsonResponse({ authenticated: true, expires_in: 60 }),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');

    render(<MemoryRouter><AdminShell /></MemoryRouter>);

    await screen.findByText('Signed in with SSO. The session cookie lasts until logout or session expiry.');
    expect((await screen.findByRole('link', { name: 'Log in with SSO' })).getAttribute('href')).toBe('/v1/ops/auth/login');
    const discovery = fetch.mock.calls.find(([url]) => url === '/v1/ops/auth/config');
    expect(discovery?.[1]).toMatchObject({ credentials: 'omit', cache: 'no-store', redirect: 'error' });
    const completion = fetch.mock.calls.find(([url]) => url === '/v1/ops/auth/callback');
    expect(completion?.[1]?.body).toBe(JSON.stringify({ code: 'code', state: 'state', mode: 'cookie' }));
    expect(new Headers(completion?.[1]?.headers).get('x-ops-csrf')).toBe('ops-csrf');
    expect(getMemoryToken()).toBeNull();
  });

  it('keeps the existing bearer completion and panel when no admin session is advertised', async () => {
    const fetch = sessionFetchMock({
      '/version': () => jsonResponse({ version: '0.5.0', admin_login_configured: true }),
      '/v1/admin/auth/callback': () => jsonResponse({ access_token: 'oidc-exchanged-token' }),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');

    render(<MemoryRouter><AdminShell /></MemoryRouter>);

    await screen.findByText('Signed in with SSO in this tab until reload or session expiry.');
    expect(getMemoryToken()).toBe('oidc-exchanged-token');
    const completion = fetch.mock.calls.find(([url]) => url === '/v1/admin/auth/callback');
    expect(completion?.[1]?.body).toBe(JSON.stringify({ code: 'code', state: 'state' }));
    expect(fetch.mock.calls.some(([url]) => String(url).endsWith('/auth/config'))).toBe(false);
    expect(screen.getByRole('heading', { level: 2, name: 'Bearer token' })).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Log in with SSO' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Log out' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Use bearer token' })).toBeNull();
  });

  it.each([false, true])('signs in with a bearer token that answers after admin requests were rejected (StrictMode %s)', async (strict) => {
    const server = bearerCompletionServer();
    vi.stubGlobal('fetch', server.fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    const shell = <MemoryRouter><AdminShell /></MemoryRouter>;

    render(strict ? <StrictMode>{shell}</StrictMode> : shell);
    // The dashboard asks for permissions before the gateway's token exchange
    // answers, and the gateway rejects that request without a token.
    await waitFor(() => expect(isAdminUnauthenticated()).toBe(true));
    await waitFor(() => expect(server.completions()).toHaveLength(1));
    await act(async () => { server.complete(); });

    await screen.findByText('Signed in with SSO in this tab until reload or session expiry.');
    expect(getMemoryToken() === server.token).toBe(true);
    expect(isBearerSelected()).toBe(true);
    expect(isAdminUnauthenticated()).toBe(false);
    expect(await screen.findByLabelText('Endpoint')).toBeTruthy();
    expect(server.completions()).toHaveLength(1);
    expect(document.documentElement.outerHTML.includes(server.token)).toBe(false);
  });

  it('does not apply a bearer SSO token that answers after the page was hidden', async () => {
    const server = bearerCompletionServer();
    vi.stubGlobal('fetch', server.fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    // Already signed out by the rejected permissions request.
    await waitFor(() => expect(isAdminUnauthenticated()).toBe(true));
    await waitFor(() => expect(server.completions()).toHaveLength(1));

    await act(async () => { window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })); });
    await act(async () => { server.complete(); });

    await screen.findByText('SSO completion discarded because the session changed. Start sign-in again.');
    expect(getMemoryToken()).toBeNull();
    expect(isBearerSelected()).toBe(false);
  });

  it.each([
    ['a mismatched logout route', () => jsonResponse({ version: '0.5.0', admin_login_configured: true, admin_session: { ...ADMIN_SESSION, logout_url: '/v1/other/auth/logout' } })],
    ['a non-cookie completion mode', () => jsonResponse({ version: '0.5.0', admin_login_configured: true, admin_session: { ...ADMIN_SESSION, completion_mode: 'bearer' } })],
    ['unavailable discovery', () => jsonResponse({ error: 'unavailable' }, 503)],
  ])('fails closed without completing SSO for %s', async (_case, version) => {
    const fetch = sessionFetchMock({
      '/version': version,
      '/v1/admin/auth/config': () => jsonResponse({ error: 'unavailable' }, 503),
      '/v1/admin/auth/callback': () => jsonResponse({ access_token: 'unexpected-token' }),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');

    render(<MemoryRouter><AdminShell /></MemoryRouter>);

    await screen.findByText(UNAVAILABLE_COMPLETION);
    expect(fetch.mock.calls.some(([url]) => url === '/v1/admin/auth/callback')).toBe(false);
    expect(getMemoryToken()).toBeNull();
    // A session cookie may still exist, so the panel keeps Log out reachable.
    expect(await screen.findByRole('button', { name: 'Retry sign-in options' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Log out' })).toBeTruthy();
  });

  it.each([401, 403, 404])('refuses SSO completion when the split-listener route answers %s', async (status) => {
    const fetch = sessionFetchMock({
      '/version': () => jsonResponse({ error: 'not found' }, 404),
      '/v1/admin/auth/config': () => jsonResponse({ error: 'rejected' }, status),
      // A gateway that offers sessions still answers a bearer completion with a token.
      '/v1/admin/auth/callback': () => jsonResponse({ access_token: 'unexpected-token' }),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');

    render(<MemoryRouter><AdminShell /></MemoryRouter>);

    await screen.findByText(UNCONFIRMED_COMPLETION);
    expect(fetch.mock.calls.some(([url]) => url === '/v1/admin/auth/callback')).toBe(false);
    expect(getMemoryToken()).toBeNull();
    expect(window.location.hash).toBe('');
    // Such a gateway serves no session here, so the panel stays a plain bearer panel.
    expect(screen.getByRole('heading', { level: 2, name: 'Bearer token' })).toBeTruthy();
    expect(screen.getByLabelText('Token', { exact: true })).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Log in with SSO' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry sign-in options' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Log out' })).toBeNull();
  });

  it('keeps the completed cookie mode for the page load when later discovery would fail', async () => {
    let discoveryFails = false;
    const server = cookieSessionServer();
    const fetch = vi.fn((input: string, init?: RequestInit) => {
      const path = new URL(input, 'http://localhost').pathname;
      if (discoveryFails && (path === '/version' || path === '/v1/admin/auth/config')) {
        return Promise.resolve(jsonResponse({ error: 'unavailable' }, 503));
      }
      return server.fetch(input, init);
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await waitFor(() => expect(server.completions()).toHaveLength(1));
    await act(async () => { server.complete(); });
    await screen.findByText('Signed in with SSO. The session cookie lasts until logout or session expiry.');

    // A transient failure after the completion cannot turn the remounted
    // panel into a bearer panel without Log out.
    discoveryFails = true;
    fireEvent.click(screen.getByRole('link', { name: 'Status' }));
    fireEvent.click(screen.getByRole('link', { name: 'Token/Dashboard' }));

    expect(await screen.findByRole('heading', { level: 2, name: 'SSO session' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Log out' })).toBeTruthy();
    expect(screen.queryByLabelText('Token', { exact: true })).toBeNull();
    expect(fetch.mock.calls.filter(([url]) => url === '/version')).toHaveLength(1);
    expect(fetch.mock.calls.some(([url]) => url === '/v1/admin/auth/config')).toBe(false);
  });

  it('keeps one unavailable answer for the completion and the panel until the operator retries', async () => {
    const fetch = sessionFetchMock({
      '/version': () => jsonResponse({ error: 'unavailable' }, 503),
      '/v1/admin/auth/config': () => jsonResponse({ error: 'unavailable' }, 503),
    });
    vi.stubGlobal('fetch', fetch);
    window.history.replaceState(null, '', '/admin/#/auth/complete?code=code&state=state');
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    await screen.findByText(UNAVAILABLE_COMPLETION);
    await screen.findByRole('button', { name: 'Retry sign-in options' });
    const discoveries = () => fetch.mock.calls.filter(([url]) => url === '/version').length;
    expect(discoveries()).toBe(1);

    // A remounted panel reuses the answer rather than asking on its own.
    fireEvent.click(screen.getByRole('link', { name: 'Status' }));
    fireEvent.click(screen.getByRole('link', { name: 'Token/Dashboard' }));
    await screen.findByRole('button', { name: 'Retry sign-in options' });
    expect(discoveries()).toBe(1);

    fireEvent.click(screen.getByRole('button', { name: 'Retry sign-in options' }));
    await waitFor(() => expect(discoveries()).toBe(2));
  });

  it.each([
    { mode: 'cookie', version: offeredVersion, controls: ['Use bearer token'] },
    {
      mode: 'unavailable discovery',
      version: () => jsonResponse({ error: 'unavailable' }, 503),
      controls: ['Retry sign-in options', 'Save', 'Clear'],
    },
  ])('disables credential choices while logout is in flight ($mode)', async ({ version, controls }) => {
    let finish!: () => void;
    const logout = new Promise<Response>((resolve) => { finish = () => resolve(new Response(null, { status: 204 })); });
    vi.stubGlobal('fetch', sessionFetchMock({
      '/version': version,
      '/v1/admin/auth/config': () => jsonResponse({ error: 'unavailable' }, 503),
      '/v1/admin/auth/logout': () => logout,
    }));
    render(<MemoryRouter><AdminShell /></MemoryRouter>);
    fireEvent.click(await screen.findByRole('button', { name: 'Log out' }));

    expect((screen.getByRole('button', { name: 'Logging out' }) as HTMLButtonElement).disabled).toBe(true);
    for (const name of controls) {
      expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    await act(async () => { finish(); });

    await screen.findByText('Logged out. Sign in again to continue.');
    for (const name of controls) {
      expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(false);
    }
  });

  it('registers the traffic inventory route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoints: [],
            next_cursor: null,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter initialEntries={['/traffic']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Traffic' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Traffic inventory',
      }),
    ).toBeTruthy();
  });

  it('registers the traffic endpoint detail route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoint: {
              method: 'GET',
              endpoint_template: '/users/{id}',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T10:00:00Z',
              call_count: 10,
              distinct_principal_count: 1,
              is_new: false,
              reviewed: false,
              reviewed_at: null,
              reviewed_by: null,
              covered_by_rule: true,
              latency: {
                count: 10,
                p50_ms: 8,
                p95_ms: 15,
                p99_ms: 20,
                sample_count: 10,
              },
              status_counts: [{ status: 200, count: 10 }],
              updated_at: '2026-07-04T10:01:00Z',
            },
            principals: {
              principals: [],
              next_cursor: null,
            },
            audit: {
              available: false,
              match_strategy: 'stateless_path_template',
              match_limitations:
                'Matches literal paths and immediate well-known identifier templates; statefully learned slug templates are not reverse-mapped.',
              omitted_reason: 'AUDIT_SQLITE_PATH not configured',
            },
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter
        initialEntries={[
          '/traffic/detail?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D',
        ]}
      >
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'GET /users/{id}',
      }),
    ).toBeTruthy();
  });

  it('registers the principal detail route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            principal: {
              subject: 'alice',
              issuer: '',
              auth_method: 'bearer',
              email: 'alice@example.test',
              org_id: 'org-a',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T10:00:00Z',
              request_count: 10,
            },
            endpoints_touched: [],
            rules_hit: [],
            anomaly_history: [],
            tools_called: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter
        initialEntries={[
          '/identities/detail?subject=alice&issuer=&auth_method=bearer',
        ]}
      >
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'alice',
      }),
    ).toBeTruthy();
  });

  it('registers the policy rules route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/policy/rules/hits') {
          return Promise.resolve(
            new Response(JSON.stringify({ rules: [] }), {
              status: 200,
              headers: {
                'Content-Type': 'application/json',
              },
            }),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/rules']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Rules' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Rulebase',
      }),
    ).toBeTruthy();
  });

  it('registers the token management route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/tokens') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                tokens: [],
                next_cursor: null,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/tokens']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Tokens' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Service tokens',
      }),
    ).toBeTruthy();
  });

  it('registers the OpenAPI tools route, navigation entry, and dashboard link', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/tools/openapi']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'OpenAPI tools' })).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'OpenAPI tools',
      }),
    ).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 2,
        name: 'OpenAPI tools',
      }),
    ).toBeTruthy();

    cleanup();
    vi.stubGlobal('fetch', versionFetchMock(false));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByText('Review OpenAPI tools before registration')).toBeTruthy();
  });

  it('links to connections and tool inventory from navigation and the dashboard', () => {
    vi.stubGlobal('fetch', versionFetchMock(false));

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    const navigation = within(
      screen.getByRole('navigation', { name: 'Admin sections' }),
    );
    expect(
      navigation.getByRole('link', { name: 'Connections' }).getAttribute('href'),
    ).toBe('/connections');
    expect(
      navigation
        .getByRole('link', { name: 'Tool inventory' })
        .getAttribute('href'),
    ).toBe('/tools');
    expect(
      screen.getByText('Configure, test, and refresh upstream connections'),
    ).toBeTruthy();
    expect(
      screen.getByText('Review registered tools and connection health'),
    ).toBeTruthy();
  });

  it('registers connection and tool inventory routes with specific page titles', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)));

    const routes = [
      ['/connections', 'Connections'],
      ['/connections/new', 'New connection'],
      ['/connections/connection-a', 'Connection details'],
      ['/connections/connection-a/edit', 'Edit connection'],
      ['/tools', 'Tool inventory'],
      ['/tools/tool-a', 'Tool details'],
      ['/tools/tool-a/playground', 'Tool playground'],
    ] as const;

    for (const [path, title] of routes) {
      render(
        <MemoryRouter initialEntries={[path]}>
          <AdminShell />
        </MemoryRouter>,
      );

      expect(
        screen.getByRole('heading', { level: 1, name: title }),
      ).toBeTruthy();
      expect(
        screen.queryByRole('heading', {
          level: 2,
          name: 'Admin route not found',
        }),
      ).toBeNull();
      cleanup();
    }
  });

  it('registers the identity directory route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/principals') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                principals: [],
                next_cursor: null,
                anonymous_request_count: 0,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/identities']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Identities' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Identity directory',
      }),
    ).toBeTruthy();
  });

  it('registers the policy history route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(String(input), 'http://localhost');
        if (url.pathname === '/v1/admin/policy') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                schema_version: '0.1.0',
                id: 'test-policy',
                default_action: 'deny',
                enforcement_mode: 'enforce',
                roles: {},
                routes: [],
                rules: [],
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                  ETag: '"etag-initial"',
                },
              },
            ),
          );
        }
        if (url.pathname === '/v1/admin/policy/history') {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                versions: [],
                next_cursor: null,
              }),
              {
                status: 200,
                headers: {
                  'Content-Type': 'application/json',
                },
              },
            ),
          );
        }

        return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
      }),
    );

    render(
      <MemoryRouter initialEntries={['/policy/history']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      within(screen.getByRole('navigation', { name: 'Admin sections' })).getByRole(
        'link',
        { name: 'History' },
      ),
    ).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Policy version history',
      }),
    ).toBeTruthy();
  });

  it('registers the shadow review route, title, navigation entry, and dashboard link', async () => {
    vi.stubGlobal('fetch', policyShadowReviewFetchMock());

    render(
      <MemoryRouter initialEntries={['/policy/shadow-review']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      within(screen.getByRole('navigation', { name: 'Admin sections' })).getByRole(
        'link',
        { name: 'Shadow review' },
      ),
    ).toBeTruthy();
    expect(
      screen.getByRole('heading', {
        level: 1,
        name: 'Shadow review',
      }),
    ).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Shadow review queue',
      }),
    ).toBeTruthy();

    cleanup();
    vi.stubGlobal('fetch', policyShadowReviewFetchMock());

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      screen.getByText('Review would-deny events from shadow rules'),
    ).toBeTruthy();
  });
});

describe('Policy Studio route', () => {
  it('registers the Policy Studio route, title, navigation entries, and dashboard link', async () => {
    vi.stubGlobal('fetch', policyStudioFetchMock());

    render(
      <MemoryRouter initialEntries={['/policy/studio']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      within(screen.getByRole('navigation', { name: 'Admin sections' })).getByRole(
        'link',
        { name: 'Policy Studio' },
      ),
    ).toBeTruthy();
    expect(
      within(screen.getByRole('navigation', { name: 'Rules workspace' })).getByRole(
        'link',
        { name: 'Studio' },
      ),
    ).toBeTruthy();
    expect(screen.getByRole('heading', { level: 1, name: 'Policy Studio' })).toBeTruthy();
    expect(
      await screen.findByText(
        'You have no policy drafts. Create one from the live policy to start editing.',
      ),
    ).toBeTruthy();

    cleanup();
    vi.stubGlobal('fetch', policyStudioFetchMock());

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByText('Edit the whole policy in a validated draft')).toBeTruthy();
  });
});

function policyStudioFetchMock() {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    const json = (body: unknown, headers: Record<string, string> = {}) =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...headers },
        }),
      );
    if (url.pathname === '/v1/admin/capabilities') {
      return json({ permissions: ['admin:policy:read', 'admin:policy:write'] });
    }
    if (url.pathname === '/v1/admin/policy') {
      return json(
        {
          schema_version: '1.0.0',
          default_action: 'deny',
          enforcement_mode: 'enforce',
          roles: {},
          routes: [],
          rules: [],
        },
        { ETag: '"etag-initial"' },
      );
    }
    if (url.pathname === '/v1/admin/policy/drafts') {
      return json({
        drafts: [],
        limits: {
          ttl_seconds: 86400,
          max_drafts_per_owner: 8,
          max_drafts: 128,
          max_candidate_bytes: 1048576,
        },
      });
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}

function policyShadowReviewFetchMock() {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname === '/v1/admin/policy') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            schema_version: '0.1.0',
            id: 'test-policy',
            default_action: 'deny',
            enforcement_mode: 'enforce',
            roles: {},
            routes: [],
            rules: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ETag: '"etag-initial"',
            },
          },
        ),
      );
    }
    if (url.pathname === '/v1/admin/policy/rules/shadow-review') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            scanned_event_count: 0,
            scan_truncated: false,
            rules: [],
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}

function versionFetchMock(adminLoginConfigured: boolean) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname === '/version') {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            version: '0.5.0',
            admin_login_configured: adminLoginConfigured,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      );
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}

function sessionFetchMock(
  responses: Record<string, (init?: RequestInit) => Response | Promise<Response>>,
) {
  return vi.fn((input: string, init?: RequestInit) => {
    const url = new URL(input, 'http://localhost');
    const respond = responses[url.pathname];
    return respond
      ? Promise.resolve(respond(init))
      : Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });
}

/**
 * A gateway that issues the HttpOnly session only when the held completion is
 * released, and rejects cookie-mode admin requests until then.
 */
function cookieSessionServer({
  body = { authenticated: true, expires_in: 3600 } as unknown,
  logoutStatus = 204,
} = {}) {
  let active = false;
  let cookieGrants = 0;
  let release!: () => void;
  const completion = new Promise<Response>((resolve) => {
    release = () => {
      active = true;
      resolve(jsonResponse(body));
    };
  });
  const fetch = sessionFetchMock({
    '/version': offeredVersion,
    '/v1/admin/capabilities': (init) => {
      if (new Headers(init?.headers).has('Authorization')) {
        return jsonResponse({ permissions: ['admin:traffic:read'] });
      }
      if (active && init?.credentials === 'same-origin') {
        cookieGrants += 1;
        return jsonResponse({ permissions: ['admin:traffic:read'] });
      }
      return jsonResponse({ error: 'unauthenticated' }, 401);
    },
    '/v1/admin/traffic/endpoints': () => jsonResponse({ endpoints: [], next_cursor: null }),
    '/v1/admin/auth/callback': () => completion,
    '/v1/admin/auth/logout': (init) => {
      if (logoutStatus !== 204) {
        return jsonResponse({ error: 'unavailable' }, logoutStatus);
      }
      if (init?.credentials === 'same-origin') active = false;
      return new Response(null, { status: 204 });
    },
  });
  const calls = (path: string) => fetch.mock.calls
    .filter(([url]) => url === path)
    .map(([, init]) => init);
  return {
    fetch,
    complete: () => release(),
    active: () => active,
    cookieGrants: () => cookieGrants,
    completions: () => calls('/v1/admin/auth/callback'),
    logouts: () => calls('/v1/admin/auth/logout'),
  };
}

/**
 * A gateway without sessions whose held completion answers with a bearer
 * token, and which rejects admin requests that do not carry that token.
 */
function bearerCompletionServer() {
  const token = `test-${crypto.randomUUID()}`;
  let release!: () => void;
  const completion = new Promise<Response>((resolve) => {
    release = () => resolve(jsonResponse({ access_token: token }));
  });
  const fetch = sessionFetchMock({
    '/version': () => jsonResponse({ version: '0.5.0', admin_login_configured: true }),
    '/v1/admin/capabilities': (init) => new Headers(init?.headers).get('Authorization') === `Bearer ${token}`
      ? jsonResponse({ permissions: ['admin:traffic:read'] })
      : jsonResponse({ error: 'unauthenticated' }, 401),
    '/v1/admin/traffic/endpoints': () => jsonResponse({ endpoints: [], next_cursor: null }),
    '/v1/admin/auth/callback': () => completion,
  });
  return {
    fetch,
    token,
    complete: () => release(),
    completions: () => fetch.mock.calls.filter(([url]) => url === '/v1/admin/auth/callback'),
  };
}

function offeredVersion() {
  return jsonResponse({
    version: '0.5.0',
    admin_login_configured: true,
    admin_session: ADMIN_SESSION,
  });
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}
