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
  getMemoryToken,
  isBearerSelected,
  selectBearerMode,
  setMemoryToken,
} from './lib/auth';
import { adminApiUrl, adminBasePath } from './lib/config';
import { addCsrfHeader, adminFetchJson, AdminApiError, fetchAdminCapabilities } from './lib/api';
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
  const pageTitle = pageTitleForPath(location.pathname);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorageOrNull()?.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  useEffect(() => {
    void completeAuthFromFragment().then((result) => {
      if (result) {
        setAuthCompletionStatus(result.status);
        setAuthRefreshKey((current) => current + 1);
      }
    });
  }, []);

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
}: {
  authRefreshKey: number;
  authCompletionStatus: string | null;
}) {
  return (
    <main className="content-grid page-content">
      <TrafficOverview />
      <TokenPanel
        authRefreshKey={authRefreshKey}
        authCompletionStatus={authCompletionStatus}
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
}: {
  authRefreshKey: number;
  authCompletionStatus: string | null;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [hasToken, setHasToken] = useState(() => getMemoryToken() !== null);
  const [bearerSelected, setBearerSelected] = useState(() => isBearerSelected());
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [ssoConfigured, setSsoConfigured] = useState(false);
  const [session, setSession] = useState<AdminSessionOffer | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
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
      const discovery = await discoverAdminAuth();
      if (!cancelled) {
        setSsoConfigured(discovery.loginConfigured);
        setSession(discovery.session);
      }
    }

    void loadAuthOptions();

    return () => {
      cancelled = true;
    };
  }, []);

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
    if (session === null) {
      return;
    }
    setLoggingOut(true);
    try {
      // The shared client adds the configured CSRF header and, on success,
      // clears memory credentials and changes the admin identity.
      await adminFetchJson<unknown>(session.logoutUrl, { method: 'POST', cache: 'no-store' });
      setStatus('Logged out. Sign in again to continue.');
    } catch {
      setStatus('Log out did not complete. The session may still be active; try again.');
    } finally {
      setLoggingOut(false);
    }
  }

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
          {cookieMode ? (
            <button
              type="button"
              className="secondary-button"
              disabled={loggingOut}
              onClick={() => { void logOut(); }}
            >
              {loggingOut ? 'Logging out' : 'Log out'}
            </button>
          ) : null}
          <button
            type="button"
            className="secondary-button"
            onClick={switchCredentialMode}
          >
            {cookieMode ? 'Use bearer token' : 'Use SSO session'}
          </button>
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
            <button type="submit" className="primary-button">
              Save
            </button>
            <button
              type="button"
              className="secondary-button"
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
                : 'No bearer token is active in this tab.')}
        </span>
      </div>
    </section>
  );
}

type AuthCompletionResult = {
  status: string;
};

async function completeAuthFromFragment(): Promise<AuthCompletionResult | null> {
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
    try {
      // An unconfirmed server contract must not silently fall back to
      // returning a bearer token to this page.
      const discovery = await discoverAdminAuth();
      if (!discovery.available) {
        throw new Error('SSO completion failed');
      }
      const session = discovery.session;
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
      const body: unknown = await response.json();
      if (session) {
        // The server sets an HttpOnly cookie. This body carries no credential,
        // and no token field is read from it.
        if (!isCookieCompletionResponse(body)) {
          throw new Error('SSO completion failed');
        }
        if (identity !== getAdminIdentityVersion()) {
          return { status: 'SSO completion discarded because the session changed. Start sign-in again.' };
        }
        adminIdentityChanged();
        return { status: 'Signed in with SSO. The session cookie lasts until logout or session expiry.' };
      }
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

type AdminSessionOffer = Readonly<{
  loginUrl: string;
  completionUrl: string;
  logoutUrl: string;
}>;

type AdminAuthDiscovery = Readonly<{
  available: boolean;
  loginConfigured: boolean;
  session: AdminSessionOffer | null;
}>;

const ADMIN_AUTH_UNAVAILABLE: AdminAuthDiscovery = {
  available: false,
  loginConfigured: false,
  session: null,
};

/**
 * `/version` answers on a unified listener. A split management listener only
 * serves the prefix-aware `auth/config` route, which exists only while admin
 * sessions are enabled. Discovery bypasses the shared admin client, so it
 * never attaches a bearer token and a rejection cannot end the current session.
 */
async function discoverAdminAuth(): Promise<AdminAuthDiscovery> {
  try {
    const response = await fetch('/version');
    if (response.ok) {
      const body: unknown = await response.json();
      if (isVersionResponse(body)) {
        return adminAuthDiscovery(body.admin_login_configured, body.admin_session);
      }
    }
  } catch {
    // Fall back to the management-origin discovery route.
  }

  try {
    const response = await fetch(adminApiUrl('/auth/config'), {
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    });
    if (response.status === 401 || response.status === 403 || response.status === 404) {
      return { available: true, loginConfigured: false, session: null };
    }
    if (!response.ok) {
      return ADMIN_AUTH_UNAVAILABLE;
    }
    const body: unknown = await response.json();
    return isJsonRecord(body)
      ? adminAuthDiscovery(true, body.admin_session)
      : ADMIN_AUTH_UNAVAILABLE;
  } catch {
    return ADMIN_AUTH_UNAVAILABLE;
  }
}

function adminAuthDiscovery(loginConfigured: boolean, advertised: unknown): AdminAuthDiscovery {
  if (advertised === undefined || advertised === null) {
    return { available: true, loginConfigured, session: null };
  }
  const session = adminSessionOffer(advertised);
  // A malformed advertisement is not an absent one: fail closed rather than
  // completing SSO as a bearer token.
  return session === null
    ? ADMIN_AUTH_UNAVAILABLE
    : { available: true, loginConfigured: true, session };
}

/** Accept only the cookie contract for this UI's own admin API prefix. */
function adminSessionOffer(value: unknown): AdminSessionOffer | null {
  const offer = {
    loginUrl: adminApiUrl('/auth/login'),
    completionUrl: adminApiUrl('/auth/callback'),
    logoutUrl: adminApiUrl('/auth/logout'),
  };
  if (
    !isJsonRecord(value) ||
    value.completion_mode !== 'cookie' ||
    value.login_url !== offer.loginUrl ||
    value.completion_url !== offer.completionUrl ||
    value.logout_url !== offer.logoutUrl
  ) {
    return null;
  }
  return offer;
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

type VersionResponse = {
  admin_login_configured: boolean;
  admin_session?: unknown;
};

function isVersionResponse(value: unknown): value is VersionResponse {
  return (
    value !== null &&
    typeof value === 'object' &&
    'admin_login_configured' in value &&
    typeof value.admin_login_configured === 'boolean'
  );
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
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
