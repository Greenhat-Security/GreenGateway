import { useAdminIdentityVersion, useAdminUnauthenticated } from './lib/adminCapabilities';
import { adminNavigationChanged, getAdminIdentityVersion, subscribeAdminSession } from './lib/adminSession';
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
  setMemoryToken,
} from './lib/auth';
import { adminApiUrl, adminBasePath } from './lib/config';
import { addCsrfHeader, AdminApiError, fetchAdminCapabilities } from './lib/api';
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
  const [visible, setVisible] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [ssoConfigured, setSsoConfigured] = useState(false);

  useEffect(() => subscribeAdminSession((event) => {
    if (event.kind !== 'identity' && event.kind !== 'unauthenticated') return;
    if (inputRef.current) inputRef.current.value = '';
    setVisible(false);
    setHasToken(getMemoryToken() !== null);
    setStatus(event.kind === 'unauthenticated' ? 'Session ended. Sign in again.' : null);
  }), []);

  useEffect(() => {
    let cancelled = false;

    async function loadVersion() {
      try {
        const response = await fetch('/version');
        if (!response.ok) {
          return;
        }
        const body: unknown = await response.json();
        if (!cancelled && isVersionResponse(body)) {
          setSsoConfigured(body.admin_login_configured);
        }
      } catch {
        if (!cancelled) {
          setSsoConfigured(false);
        }
      }
    }

    void loadVersion();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (authRefreshKey === 0) {
      return;
    }

    setHasToken(getMemoryToken() !== null);
    setStatus(authCompletionStatus);
  }, [authRefreshKey, authCompletionStatus]);

  function saveToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = inputRef.current?.value.trim() ?? '';
    // Keep the input uncontrolled: a credential must never become a value
    // attribute or be repopulated from the active in-memory credential.
    if (inputRef.current) inputRef.current.value = '';
    setMemoryToken(value);
    setVisible(false);
    setHasToken(value.length > 0);
    setStatus(value ? 'Token active in this tab until reload or session expiry.' : 'Token cleared.');
  }

  function clearToken() {
    clearMemoryToken();
    if (inputRef.current) inputRef.current.value = '';
    setHasToken(false);
    setVisible(false);
    setStatus('Token cleared.');
  }

  return (
    <section className="panel token-panel" aria-labelledby="token-heading">
      <div className="section-heading">
        <p className="eyebrow">Authentication</p>
        <h2 id="token-heading">Bearer token</h2>
      </div>
      <p className="body-copy">
        Paste a bearer token for this tab. It stays in memory and is lost on
        reload, navigation away, or session expiry. Admin requests send it as an Authorization header.
      </p>

      {ssoConfigured ? (
        <div className="sso-login-row">
          <a className="secondary-button" href={adminApiUrl('/auth/login')} onClick={clearToken}>
            Log in with SSO
          </a>
        </div>
      ) : null}

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

      <div className="token-state" role="status" aria-live="polite">
        <span className={hasToken ? 'state-dot saved' : 'state-dot'} />
        <span>
          {status ??
            (hasToken
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
      const headers = new Headers({
        'Content-Type': 'application/json',
        Accept: 'application/json',
      });
      addCsrfHeader(headers, 'POST');
      const url = adminApiUrl('/auth/callback');
      assertAdminRequestOrigin(url);
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers,
        body: JSON.stringify({ code, state }),
      });
      if (!response.ok) {
        throw new Error('SSO completion failed');
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

type VersionResponse = {
  admin_login_configured: boolean;
};

function isVersionResponse(value: unknown): value is VersionResponse {
  return (
    value !== null &&
    typeof value === 'object' &&
    'admin_login_configured' in value &&
    typeof value.admin_login_configured === 'boolean'
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
