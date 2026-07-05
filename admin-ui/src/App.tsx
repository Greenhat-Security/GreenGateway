import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  BrowserRouter,
  Link,
  NavLink,
  Route,
  Routes,
  useLocation,
} from 'react-router-dom';

import {
  clearStoredToken,
  getStoredToken,
  setStoredToken,
} from './lib/auth';
import { adminApiUrl, adminBasePath } from './lib/config';
import { IdentitiesView } from './views/IdentitiesView';
import { LiveTail } from './views/LiveTail';
import { LogExplorer } from './views/LogExplorer';
import { PolicyHistoryView } from './views/PolicyHistoryView';
import { RuleEditor } from './views/RuleEditor';
import { RuleTable } from './views/RuleTable';
import { ShadowReviewView } from './views/ShadowReviewView';
import { SignalsView } from './views/SignalsView';
import { StatusPage } from './views/StatusPage';
import { TrafficEndpointDetail } from './views/TrafficEndpointDetail';
import { TrafficInventory } from './views/TrafficInventory';
import { TokensView } from './views/TokensView';

const THEME_STORAGE_KEY = 'greengateway_admin_theme';

type ThemeName = 'light' | 'dark';

export function App() {
  return (
    <BrowserRouter basename={adminBasePath()}>
      <AdminShell />
    </BrowserRouter>
  );
}

export function AdminShell() {
  const location = useLocation();
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
    const result = completeAuthFromFragment();
    if (!result) {
      return;
    }

    setAuthCompletionStatus(result.status);
    setAuthRefreshKey((current) => current + 1);
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

        <Routes>
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
          <Route path="/identities" element={<IdentitiesView />} />
          <Route path="/policy/history" element={<PolicyHistoryView />} />
          <Route path="/policy/shadow-review" element={<ShadowReviewView />} />
          <Route path="/signals" element={<SignalsView />} />
          <Route path="/policy/rules/editor" element={<RuleEditor />} />
          <Route path="/live" element={<LiveTail />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
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
          <p className="eyebrow">Phase 2</p>
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
            <span>Rule table</span>
            <small>Ordered firewall policy and hit counts</small>
          </Link>
          <Link to="/tokens">
            <span>Tokens</span>
            <small>Create, rotate, and revoke service tokens</small>
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
  const initialToken = useMemo(() => getStoredToken() ?? '', []);
  const [token, setToken] = useState(initialToken);
  const [hasStoredToken, setHasStoredToken] = useState(initialToken.length > 0);
  const [status, setStatus] = useState<string | null>(null);
  const [ssoConfigured, setSsoConfigured] = useState(false);

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

    const storedToken = getStoredToken() ?? '';
    setToken(storedToken);
    setHasStoredToken(storedToken.length > 0);
    setStatus(authCompletionStatus);
  }, [authRefreshKey, authCompletionStatus]);

  function saveToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const saved = setStoredToken(token);
    const trimmed = token.trim();
    setHasStoredToken(saved && trimmed.length > 0);
    setToken(trimmed);
    setStatus(
      saved
        ? trimmed.length > 0
          ? 'Token saved for this browser session.'
          : 'Token cleared.'
        : 'Session storage is unavailable in this browser context.',
    );
  }

  function clearToken() {
    const cleared = clearStoredToken();
    setToken('');
    setHasStoredToken(false);
    setStatus(
      cleared
        ? 'Token cleared.'
        : 'Session storage is unavailable in this browser context.',
    );
  }

  return (
    <section className="panel token-panel" aria-labelledby="token-heading">
      <div className="section-heading">
        <p className="eyebrow">Authentication</p>
        <h2 id="token-heading">Bearer token</h2>
      </div>
      <p className="body-copy">
        Paste a bearer token for this browser session. Admin API requests send
        it as an Authorization header.
      </p>

      {ssoConfigured ? (
        <div className="sso-login-row">
          <a className="secondary-button" href={adminApiUrl('/auth/login')}>
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
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={token}
            placeholder="Paste bearer token"
            onChange={(event) => setToken(event.target.value)}
          />
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
        <span className={hasStoredToken ? 'state-dot saved' : 'state-dot'} />
        <span>
          {status ??
            (hasStoredToken
              ? 'A token is saved for this browser session.'
              : 'No token is saved for this browser session.')}
        </span>
      </div>
    </section>
  );
}

type AuthCompletionResult = {
  status: string;
};

function completeAuthFromFragment(): AuthCompletionResult | null {
  if (typeof window === 'undefined') {
    return null;
  }

  const hash = window.location.hash;
  if (hash.startsWith('#/auth/complete?')) {
    const token = new URLSearchParams(hash.slice('#/auth/complete?'.length))
      .get('token')
      ?.trim();
    if (!token) {
      clearLocationHash();
      return {
        status: 'SSO sign-in did not return a token.',
      };
    }

    const saved = setStoredToken(token);
    clearLocationHash();
    return {
      status: saved
        ? 'Signed in with SSO for this browser session.'
        : 'Session storage is unavailable in this browser context.',
    };
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
    return 'Rule table';
  }
  if (pathname === '/tokens') {
    return 'Tokens';
  }
  if (pathname === '/identities') {
    return 'Identity directory';
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
