import { useAdminIdentityVersion, useAdminUnauthenticated } from './lib/adminCapabilities';
import { adminIdentityChanged, adminNavigationChanged, getAdminIdentityVersion, subscribeAdminSession } from './lib/adminSession';
import { FormEvent, useEffect, useRef, useState } from 'react';
import {
  BrowserRouter,
  Link,
  NavLink,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom';

import {
  assertAdminRequestOrigin,
  clearMemoryToken,
  getCredentialSelection,
  getMemoryToken,
  isBearerSelected,
  selectBearerMode,
  setMemoryToken,
} from './lib/auth';
import { adminApiUrl, adminBasePath } from './lib/config';
import { addCsrfHeader, adminFetchJson, AdminApiError, fetchAdminCapabilities } from './lib/api';
import {
  AdminAuthDiscovery,
  AdminAuthDiscoverySource,
  AdminSessionOffer,
  createAdminAuthDiscovery,
  isJsonRecord,
} from './lib/adminAuthDiscovery';
import {
  CapabilityDetail,
  CapabilityInventoryView,
} from './views/CapabilityInventoryView';
import { ClusterView } from './views/ClusterView';
import { ConnectionDetail } from './views/ConnectionDetail';
import { ConnectionEditor } from './views/ConnectionEditor';
import { ConnectionsView } from './views/ConnectionsView';
import { IdentitiesView } from './views/IdentitiesView';
import { LiveTail } from './views/LiveTail';
import { LogExplorer } from './views/LogExplorer';
import { OpenApiToolsView } from './views/OpenApiToolsView';
import { PolicyHistoryView } from './views/PolicyHistoryView';
import { PrincipalDetail } from './views/PrincipalDetail';
import { RuleEditor } from './views/RuleEditor';
import { RuleTable } from './views/RuleTable';
import { ShadowReviewView } from './views/ShadowReviewView';
import { SignalsView } from './views/SignalsView';
import { StatusPage } from './views/StatusPage';
import { TrafficEndpointDetail } from './views/TrafficEndpointDetail';
import { TrafficInventory } from './views/TrafficInventory';
import { TrafficOverview } from './views/TrafficOverview';
import { TokensView } from './views/TokensView';
import { ToolPlayground } from './views/ToolPlayground';

const THEME_STORAGE_KEY = 'greengateway_admin_theme';

type ThemeName = 'light' | 'dark';

export function App() {
  return (
    <BrowserRouter basename={adminBasePath()}>
      <AdminShell />
    </BrowserRouter>
  );
}

function AdminSessionExpired() {
  const alertRef = useRef<HTMLDivElement>(null);
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState('Sign in again to continue. Previous session data has been cleared.');
  useEffect(() => { alertRef.current?.focus(); }, []);

  async function checkSession() {
    setChecking(true);
    try {
      // The transport signals successful authentication, remounting the route.
      await fetchAdminCapabilities(AbortSignal.timeout(10_000));
    } catch (error) {
      setMessage(error instanceof AdminApiError && error.status === 401
        ? 'Sign in again to continue.'
        : error instanceof AdminApiError && error.status === 403
          ? 'Your session cannot read admin permissions.'
          : 'Admin permissions are temporarily unavailable. Try checking your session again.');
    } finally {
      setChecking(false);
    }
  }

  return <main className="panel">
    <div className="error-panel alert warning" role="alert" tabIndex={-1} ref={alertRef}>
      <h2>Admin session expired</h2>
      <p>{message}</p>
    </div>
    <Link to="/">Sign in</Link>
    <button type="button" disabled={checking} onClick={() => { void checkSession(); }}>
      {checking ? 'Checking session' : 'Check session'}
    </button>
  </main>;
}

export function AdminShell() {
  const location = useLocation();
  const identityVersion = useAdminIdentityVersion();
  const unauthenticated = useAdminUnauthenticated();
  useEffect(() => { adminNavigationChanged(); }, [location.pathname]);
  const [theme, setTheme] = useState<ThemeName>(() => readStoredTheme());
  const [authRefreshKey, setAuthRefreshKey] = useState(0);
  const [authCompletionStatus, setAuthCompletionStatus] = useState<string | null>(
    null,
  );
  // One discovery answer for this page load, shared by the completion and the panel.
  const [authDiscovery] = useState(() => createAdminAuthDiscovery());
  const pageTitle = pageTitleForPath(location.pathname);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorageOrNull()?.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  useEffect(() => {
    void completeAuthFromFragment(authDiscovery).then((result) => {
      if (result) {
        setAuthCompletionStatus(result.status);
        setAuthRefreshKey((current) => current + 1);
      }
    });
  }, [authDiscovery]);

  function toggleTheme() {
    setTheme((current) => (current === 'dark' ? 'light' : 'dark'));
  }

  return (
    <div className="admin-shell">
      <aside className="sidebar" aria-label="Admin navigation">
        <div className="logo" aria-label="GreenGateway admin">
          <span className="logo-mark" aria-hidden="true">
            GG
          </span>
          <span className="logo-word">GreenGateway</span>
          <span className="logo-badge">GG</span>
        </div>

        <nav className="nav-section" aria-label="Admin sections">
          <p className="nav-label">Admin</p>
          <NavLink to="/" end className={navItemClassName}>
            Token/Dashboard
          </NavLink>
          <NavLink to="/logs" className={navItemClassName}>
            Logs
          </NavLink>
          <NavLink to="/traffic" className={navItemClassName}>
            Traffic
          </NavLink>
          <NavLink to="/rules" className={navItemClassName}>
            Rules
          </NavLink>
          <NavLink to="/tokens" className={navItemClassName}>
            Tokens
          </NavLink>
          <NavLink to="/connections" className={navItemClassName}>
            Connections
          </NavLink>
          <NavLink to="/tools" end className={navItemClassName}>
            Tool inventory
          </NavLink>
          <NavLink to="/tools/openapi" className={navItemClassName}>
            OpenAPI tools
          </NavLink>
          <NavLink to="/identities" className={navItemClassName}>
            Identities
          </NavLink>
          <NavLink to="/policy/history" className={navItemClassName}>
            History
          </NavLink>
          <NavLink to="/policy/shadow-review" className={navItemClassName}>
            Shadow review
          </NavLink>
          <NavLink to="/signals" className={navItemClassName}>
            Signals
          </NavLink>
          <NavLink to="/policy/rules/editor" className={navItemClassName}>
            Rule editor
          </NavLink>
          <NavLink to="/live" className={navItemClassName}>
            Live
          </NavLink>
          <NavLink to="/cluster" className={navItemClassName}>
            Cluster
          </NavLink>
          <NavLink to="/status" className={navItemClassName}>
            Status
          </NavLink>
        </nav>

        <div className="sidebar-foot">
          <button
            type="button"
            className="theme-toggle"
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            aria-pressed={theme === 'dark'}
            onClick={toggleTheme}
          >
            <span>Theme</span>
            <span className="theme-toggle-pill">
              {theme === 'dark' ? 'Dark' : 'Light'}
            </span>
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <p className="eyebrow">Admin</p>
          <h1>{pageTitle}</h1>
        </header>

        {unauthenticated && location.pathname !== '/' ? <AdminSessionExpired /> : (
        <Routes key={location.pathname === '/' ? 'dashboard' : identityVersion}>
          <Route
            path="/"
            element={
              <Dashboard
                authRefreshKey={authRefreshKey}
                authCompletionStatus={authCompletionStatus}
                authDiscovery={authDiscovery}
              />
            }
          />
          <Route path="/logs" element={<LogExplorer />} />
          <Route path="/traffic" element={<TrafficInventory />} />
          <Route path="/traffic/detail" element={<TrafficEndpointDetail />} />
          <Route path="/rules" element={<RuleTable />} />
          <Route path="/tokens" element={<TokensView />} />
          <Route path="/connections" element={<ConnectionsView />} />
          <Route path="/connections/new" element={<ConnectionEditor />} />
          <Route path="/connections/:id/edit" element={<ConnectionEditor />} />
          <Route path="/connections/:id" element={<ConnectionDetail />} />
          <Route path="/tools/openapi" element={<OpenApiToolsView />} />
          <Route path="/tools" element={<CapabilityInventoryView />} />
          <Route path="/tools/:id/playground" element={<ToolPlayground />} />
          <Route path="/tools/:id" element={<CapabilityDetail />} />
          <Route path="/identities" element={<IdentitiesView />} />
          <Route path="/identities/detail" element={<PrincipalDetail />} />
          <Route path="/policy/history" element={<PolicyHistoryView />} />
          <Route path="/policy/shadow-review" element={<ShadowReviewView />} />
          <Route path="/signals" element={<SignalsView />} />
          <Route path="/policy/rules/editor" element={<RuleEditor />} />
          <Route path="/live" element={<LiveTail />} />
          <Route path="/cluster" element={<ClusterView />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
        )}
      </div>
    </div>
  );
}

function Dashboard({
  authRefreshKey,
  authCompletionStatus,
  authDiscovery,
}: {
  authRefreshKey: number;
  authCompletionStatus: string | null;
  authDiscovery: AdminAuthDiscoverySource;
}) {
  return (
    <main className="content-grid page-content">
      <TrafficOverview />
      <TokenPanel
        authRefreshKey={authRefreshKey}
        authCompletionStatus={authCompletionStatus}
        authDiscovery={authDiscovery}
      />

      <section className="panel" aria-labelledby="views-heading">
        <div className="section-heading">
          <p className="eyebrow">Workspace</p>
          <h2 id="views-heading">Admin views</h2>
        </div>
        <div className="view-links">
          <Link to="/logs">
            <span>Log explorer</span>
            <small>Audit history and filters</small>
          </Link>
          <Link to="/traffic">
            <span>Traffic inventory</span>
            <small>Discovered endpoints and rule coverage</small>
          </Link>
          <Link to="/rules">
            <span>Rulebase</span>
            <small>Ordered zero trust rules, modes, and evidence</small>
          </Link>
          <Link to="/tokens">
            <span>Tokens</span>
            <small>Create, rotate, and revoke service tokens</small>
          </Link>
          <Link to="/connections">
            <span>Connections</span>
            <small>Configure, test, and refresh upstream connections</small>
          </Link>
          <Link to="/tools">
            <span>Tool inventory</span>
            <small>Review registered tools and connection health</small>
          </Link>
          <Link to="/tools/openapi">
            <span>OpenAPI tools</span>
            <small>Review OpenAPI tools before registration</small>
          </Link>
          <Link to="/identities">
            <span>Identities</span>
            <small>Users, bots, issuers, and auth methods</small>
          </Link>
          <Link to="/policy/history">
            <span>Policy history</span>
            <small>Version timeline and rollback</small>
          </Link>
          <Link to="/policy/shadow-review">
            <span>Shadow review</span>
            <small>Review would-deny events from shadow rules</small>
          </Link>
          <Link to="/signals">
            <span>Signals</span>
            <small>Discovery findings and review actions</small>
          </Link>
          <Link to="/policy/rules/editor">
            <span>Rule editor</span>
            <small>Create or edit one policy rule</small>
          </Link>
          <Link to="/live">
            <span>Live tail</span>
            <small>Streaming audit events</small>
          </Link>
          <Link to="/cluster">
            <span>Cluster</span>
            <small>Readiness, replicas, and background task health</small>
          </Link>
          <Link to="/status">
            <span>Status</span>
            <small>Gateway runtime and config</small>
          </Link>
        </div>
      </section>
    </main>
  );
}

function TokenPanel({
  authRefreshKey,
  authCompletionStatus,
  authDiscovery,
}: {
  authRefreshKey: number;
  authCompletionStatus: string | null;
  authDiscovery: AdminAuthDiscoverySource;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [hasToken, setHasToken] = useState(() => getMemoryToken() !== null);
  const [bearerSelected, setBearerSelected] = useState(() => isBearerSelected());
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [discovery, setDiscovery] = useState<AdminAuthDiscovery | null>(null);
  const [discoveryAttempt, setDiscoveryAttempt] = useState(0);
  const [loggingOut, setLoggingOut] = useState(false);
  const session = discovery?.kind === 'cookie' ? discovery.session : null;
  const ssoConfigured = discovery?.kind === 'bearer' && discovery.loginConfigured;
  // Without an answer, a session cookie may still authenticate this tab, so
  // the panel must not present it as signed out. An unconfirmed answer comes
  // from a gateway that serves no session here, or from a proxy that hides
  // the route; the panel offers neither SSO nor a session to log out of.
  const discoveryUnavailable = discovery?.kind === 'unavailable';
  // An offered cookie session is the default; bearer mode is entered only by
  // an explicit switch or by saving a token.
  const cookieMode = session !== null && !bearerSelected;

  useEffect(() => subscribeAdminSession((event) => {
    if (event.kind !== 'identity' && event.kind !== 'unauthenticated') return;
    if (inputRef.current) inputRef.current.value = '';
    setVisible(false);
    setHasToken(getMemoryToken() !== null);
    setBearerSelected(isBearerSelected());
    setStatus(event.kind === 'unauthenticated' ? 'Session ended. Sign in again.' : null);
  }), []);

  useEffect(() => {
    let cancelled = false;

    async function loadAuthOptions() {
      const result = await (discoveryAttempt === 0 ? authDiscovery.current() : authDiscovery.retry());
      if (!cancelled) {
        setDiscovery(result);
      }
    }

    void loadAuthOptions();

    return () => {
      cancelled = true;
    };
  }, [authDiscovery, discoveryAttempt]);

  useEffect(() => {
    if (authRefreshKey === 0) {
      return;
    }

    setHasToken(getMemoryToken() !== null);
    setBearerSelected(isBearerSelected());
    setStatus(authCompletionStatus);
  }, [authRefreshKey, authCompletionStatus]);

  function saveToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = inputRef.current?.value.trim() ?? '';
    // Keep the input uncontrolled: a credential must never become a value
    // attribute or be repopulated from the active in-memory credential.
    if (inputRef.current) inputRef.current.value = '';
    // An empty save in explicit bearer mode must not resume the cookie session.
    if (value || session === null) {
      setMemoryToken(value);
    } else {
      selectBearerMode();
    }
    setVisible(false);
    setHasToken(value.length > 0);
    setStatus(value ? 'Token active in this tab until reload or session expiry.' : 'Token cleared.');
  }

  function clearToken() {
    if (session === null) {
      clearMemoryToken();
    } else {
      selectBearerMode();
    }
    if (inputRef.current) inputRef.current.value = '';
    setHasToken(false);
    setVisible(false);
    setStatus('Token cleared.');
  }

  function switchCredentialMode() {
    // Both directions discard the memory credential, and the identity change
    // drops cached grants and drafts before the next request.
    if (cookieMode) {
      selectBearerMode();
      setStatus('Bearer token mode. Admin requests no longer send the session cookie.');
    } else {
      clearMemoryToken();
      setStatus('SSO session mode. Admin requests use the session cookie.');
    }
  }

  async function logOut() {
    setLoggingOut(true);
    try {
      // The shared client adds the configured CSRF header and, on success,
      // clears memory credentials and changes the admin identity. Without a
      // discovery answer, this UI's own prefix is the only route it accepts.
      await adminFetchJson<unknown>(session?.logoutUrl ?? adminApiUrl('/auth/logout'), {
        method: 'POST',
        cache: 'no-store',
      });
      setStatus('Logged out. Sign in again to continue.');
    } catch {
      setStatus('Log out did not complete. The session may still be active; try again.');
    } finally {
      setLoggingOut(false);
    }
  }

  function retryDiscovery() {
    setStatus(null);
    setDiscoveryAttempt((attempt) => attempt + 1);
  }

  // Choosing credentials while logout is pending would change the identity,
  // and the shared client would then discard the logout's answer.
  const logOutButton = (
    <button
      type="button"
      className="secondary-button"
      disabled={loggingOut}
      onClick={() => { void logOut(); }}
    >
      {loggingOut ? 'Logging out' : 'Log out'}
    </button>
  );

  return (
    <section className="panel token-panel" aria-labelledby="token-heading">
      <div className="section-heading">
        <p className="eyebrow">Authentication</p>
        <h2 id="token-heading">{cookieMode ? 'SSO session' : 'Bearer token'}</h2>
      </div>
      {cookieMode ? (
        <p className="body-copy">
          Sign in with SSO to use an HttpOnly session cookie that page scripts
          cannot read. It lasts across reloads until logout or session expiry.
        </p>
      ) : (
        <p className="body-copy">
          Paste a bearer token for this tab. It stays in memory and is lost on
          reload, navigation away, or session expiry. Admin requests send it as an Authorization header.
        </p>
      )}

      {session ? (
        <div className="sso-login-row">
          {cookieMode ? (
            <a className="secondary-button" href={session.loginUrl}>
              Log in with SSO
            </a>
          ) : null}
          {cookieMode ? logOutButton : null}
          <button
            type="button"
            className="secondary-button"
            disabled={loggingOut}
            onClick={switchCredentialMode}
          >
            {cookieMode ? 'Use bearer token' : 'Use SSO session'}
          </button>
        </div>
      ) : discoveryUnavailable ? (
        <div className="sso-login-row">
          <button type="button" className="secondary-button" disabled={loggingOut} onClick={retryDiscovery}>
            Retry sign-in options
          </button>
          {bearerSelected ? null : logOutButton}
        </div>
      ) : ssoConfigured ? (
        <div className="sso-login-row">
          <a className="secondary-button" href={adminApiUrl('/auth/login')} onClick={clearToken}>
            Log in with SSO
          </a>
        </div>
      ) : null}

      {cookieMode ? null : (
        <form className="token-form" onSubmit={saveToken}>
          <label htmlFor="admin-token" className="field-label">
            Token
          </label>
          <div className="token-row">
            <input
              id="admin-token"
              name="admin-token"
              ref={inputRef}
              type={visible ? 'text' : 'password'}
              autoComplete="off"
              spellCheck={false}
              placeholder="Paste bearer token"
            />
            <button type="button" className="secondary-button" aria-pressed={visible}
              aria-controls="admin-token" onClick={() => setVisible(!visible)}>
              {visible ? 'Hide token' : 'Show token'}
            </button>
            <button type="submit" className="primary-button" disabled={loggingOut}>
              Save
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={loggingOut}
              onClick={clearToken}
            >
              Clear
            </button>
          </div>
        </form>
      )}

      <div className="token-state" role="status" aria-live="polite">
        <span className={hasToken ? 'state-dot saved' : 'state-dot'} />
        <span>
          {status ??
            (cookieMode
              ? 'Admin requests use the SSO session cookie when signed in.'
              : hasToken
                ? 'A token is active in this tab until reload.'
                : discoveryUnavailable && !bearerSelected
                  ? 'Sign-in options are unavailable. An SSO session may still be active; retry or log out.'
                  : 'No bearer token is active in this tab.')}
        </span>
      </div>
    </section>
  );
}

type AuthCompletionResult = {
  status: string;
};

const UNCONFIRMED_COMPLETION_STATUS =
  'SSO sign-in was not completed: the gateway did not confirm whether it issues a session cookie, so no token was requested. ' +
  'Use a bearer token, or ask an operator to check that the admin auth/config route reaches the gateway.';
const UNAVAILABLE_COMPLETION_STATUS =
  'SSO sign-in was not completed: sign-in options are unavailable, so no token was requested. Start sign-in again.';

async function completeAuthFromFragment(
  authDiscovery: AdminAuthDiscoverySource,
): Promise<AuthCompletionResult | null> {
  if (typeof window === 'undefined') {
    return null;
  }

  const hash = window.location.hash;
  if (hash.startsWith('#/auth/complete?')) {
    const params = new URLSearchParams(hash.slice('#/auth/complete?'.length));
    // Remove the code before any asynchronous work, including React's
    // development effect replay. Legacy bearer-token fragments are rejected.
    clearLocationHash();
    const code = params.get('code')?.trim();
    const state = params.get('state')?.trim();
    if (
      !code || !state || params.has('token') ||
      params.getAll('code').length !== 1 ||
      params.getAll('state').length !== 1
    ) {
      return { status: 'SSO sign-in did not complete. Start sign-in again.' };
    }
    const identity = getAdminIdentityVersion();
    const selection = getCredentialSelection();
    try {
      // Only an explicit answer lets the code be posted. Anything else would
      // risk a bearer token reaching this page from a gateway that offers a
      // session, so the completion stops before the code is exchanged.
      const discovery = await authDiscovery.current();
      if (discovery.kind === 'unconfirmed') {
        return { status: UNCONFIRMED_COMPLETION_STATUS };
      }
      if (discovery.kind === 'unavailable') {
        return { status: UNAVAILABLE_COMPLETION_STATUS };
      }
      const session = discovery.kind === 'cookie' ? discovery.session : null;
      const headers = new Headers({
        'Content-Type': 'application/json',
        Accept: 'application/json',
      });
      addCsrfHeader(headers, 'POST');
      const url = session?.completionUrl ?? adminApiUrl('/auth/callback');
      assertAdminRequestOrigin(url);
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers,
        body: JSON.stringify(session ? { code, state, mode: 'cookie' } : { code, state }),
      });
      if (!response.ok) {
        throw new Error('SSO completion failed');
      }
      if (session) {
        return await applyCookieCompletion(response, session, selection);
      }
      const body: unknown = await response.json();
      if (
        !body || typeof body !== 'object' || !('access_token' in body) ||
        typeof body.access_token !== 'string' || !body.access_token.trim()
      ) {
        throw new Error('SSO completion failed');
      }
      if (identity !== getAdminIdentityVersion()) {
        return { status: 'SSO completion discarded because the session changed. Start sign-in again.' };
      }
      setMemoryToken(body.access_token);
      return { status: 'Signed in with SSO in this tab until reload or session expiry.' };
    } catch {
      return { status: 'SSO sign-in did not complete. Start sign-in again.' };
    }
  }

  if (hash.startsWith('#/auth/error?')) {
    clearLocationHash();
    return {
      status: 'SSO sign-in did not complete.',
    };
  }

  return null;
}

function clearLocationHash() {
  window.history.replaceState(
    null,
    document.title,
    `${window.location.pathname}${window.location.search}`,
  );
}

/**
 * The response set the HttpOnly session cookie before this body is read. A
 * 401 for a request sent before that cookie existed changes only the identity
 * version, so it does not discard the completion. Choosing other credentials
 * while it was pending does, and an unexpected body is not trusted either:
 * both end the issued session rather than leave one the UI did not apply.
 */
async function applyCookieCompletion(
  response: Response,
  session: AdminSessionOffer,
  selection: number,
): Promise<AuthCompletionResult> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // An unreadable success may still have set the cookie.
  }
  // This body carries no credential, and no token field is read from it.
  const completed = isCookieCompletionResponse(body);
  if (completed && selection === getCredentialSelection()) {
    adminIdentityChanged();
    return { status: 'Signed in with SSO. The session cookie lasts until logout or session expiry.' };
  }
  const revoked = await revokeAdminSession(session.logoutUrl);
  if (!isBearerSelected()) {
    // Cookie-mode requests could have used the issued session meanwhile.
    adminIdentityChanged();
  }
  if (!revoked) {
    return {
      status: 'The SSO session could not be ended and may still be active. Log out from SSO session mode to end it.',
    };
  }
  return completed
    ? { status: 'SSO completion discarded because the session changed. Start sign-in again.' }
    : { status: 'SSO sign-in did not complete. Start sign-in again.' };
}

/**
 * Ends the gateway session this browser holds whatever the tab's credential
 * mode: same-origin cookies and the CSRF header, never an Authorization
 * header, and no change to the tab's memory credentials.
 */
async function revokeAdminSession(logoutUrl: string): Promise<boolean> {
  try {
    assertAdminRequestOrigin(logoutUrl);
    const headers = new Headers({ Accept: 'application/json' });
    addCsrfHeader(headers, 'POST');
    const response = await fetch(logoutUrl, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers,
    });
    return response.ok;
  } catch {
    return false;
  }
}

function isCookieCompletionResponse(value: unknown): boolean {
  return (
    isJsonRecord(value) &&
    value.authenticated === true &&
    typeof value.expires_in === 'number' &&
    Number.isSafeInteger(value.expires_in) &&
    value.expires_in > 0
  );
}

function NotFoundPage() {
  return (
    <main className="single-page page-content">
      <section className="panel narrow-panel" aria-labelledby="missing-heading">
        <div className="section-heading">
          <p className="eyebrow">Not found</p>
          <h2 id="missing-heading">Admin route not found</h2>
        </div>
        <p className="body-copy">Choose an admin view from the sidebar.</p>
      </section>
    </main>
  );
}

function navItemClassName({ isActive }: { isActive: boolean }): string {
  return isActive ? 'nav-item active' : 'nav-item';
}

function pageTitleForPath(pathname: string): string {
  if (pathname === '/logs') {
    return 'Log explorer';
  }
  if (pathname === '/traffic') {
    return 'Traffic inventory';
  }
  if (pathname === '/traffic/detail') {
    return 'Traffic detail';
  }
  if (pathname === '/rules') {
    return 'Rulebase';
  }
  if (pathname === '/tokens') {
    return 'Tokens';
  }
  if (pathname === '/connections') {
    return 'Connections';
  }
  if (pathname === '/connections/new') {
    return 'New connection';
  }
  if (/^\/connections\/[^/]+\/edit$/.test(pathname)) {
    return 'Edit connection';
  }
  if (/^\/connections\/[^/]+$/.test(pathname)) {
    return 'Connection details';
  }
  if (pathname === '/tools/openapi') {
    return 'OpenAPI tools';
  }
  if (pathname === '/tools') {
    return 'Tool inventory';
  }
  if (/^\/tools\/[^/]+\/playground$/.test(pathname)) {
    return 'Tool playground';
  }
  if (/^\/tools\/[^/]+$/.test(pathname)) {
    return 'Tool details';
  }
  if (pathname === '/identities') {
    return 'Identity directory';
  }
  if (pathname === '/identities/detail') {
    return 'Identity detail';
  }
  if (pathname === '/policy/history') {
    return 'Policy history';
  }
  if (pathname === '/policy/shadow-review') {
    return 'Shadow review';
  }
  if (pathname === '/signals') {
    return 'Signals';
  }
  if (pathname === '/policy/rules/editor') {
    return 'Rule editor';
  }
  if (pathname === '/live') {
    return 'Live tail';
  }
  if (pathname === '/cluster') {
    return 'Cluster';
  }
  if (pathname === '/status') {
    return 'Status';
  }
  if (pathname === '/') {
    return 'Token dashboard';
  }

  return 'Not found';
}

function readStoredTheme(): ThemeName {
  const storedTheme = localStorageOrNull()?.getItem(THEME_STORAGE_KEY);
  return storedTheme === 'dark' ? 'dark' : 'light';
}

function localStorageOrNull(): Storage | null {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return window.localStorage;
  } catch {
    return null;
  }
}
