import { FormEvent, useMemo, useState } from 'react';
import {
  BrowserRouter,
  Link,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom';

import {
  clearStoredToken,
  getStoredToken,
  setStoredToken,
} from './lib/auth';
import { LogExplorer } from './views/LogExplorer';

export function App() {
  return (
    <BrowserRouter basename="/admin">
      <AdminShell />
    </BrowserRouter>
  );
}

function AdminShell() {
  return (
    <div className="admin-shell">
      <header className="app-header">
        <div className="brand-block">
          <p className="eyebrow">GreenGateway</p>
          <h1>Admin</h1>
        </div>
        <nav className="top-nav" aria-label="Admin sections">
          <NavLink to="/" end>
            Token
          </NavLink>
          <NavLink to="/logs">Logs</NavLink>
          <NavLink to="/live">Live</NavLink>
          <NavLink to="/status">Status</NavLink>
        </nav>
      </header>

      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/logs" element={<LogExplorer />} />
        <Route
          path="/live"
          element={
            <ComingSoonPage
              eyebrow="Phase 2"
              title="Live tail"
              body="Streaming audit events will land in the next PR."
            />
          }
        />
        <Route
          path="/status"
          element={
            <ComingSoonPage
              eyebrow="Phase 2"
              title="Status"
              body="Gateway health and version details will land in a follow-up PR."
            />
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </div>
  );
}

function Dashboard() {
  return (
    <main className="content-grid">
      <TokenPanel />

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
          <Link to="/live">
            <span>Live tail</span>
            <small>Coming soon</small>
          </Link>
          <Link to="/status">
            <span>Status</span>
            <small>Coming soon</small>
          </Link>
        </div>
      </section>
    </main>
  );
}

function TokenPanel() {
  const initialToken = useMemo(() => getStoredToken() ?? '', []);
  const [token, setToken] = useState(initialToken);
  const [hasStoredToken, setHasStoredToken] = useState(initialToken.length > 0);
  const [status, setStatus] = useState<string | null>(null);

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
    <section className="panel" aria-labelledby="token-heading">
      <div className="section-heading">
        <p className="eyebrow">Authentication</p>
        <h2 id="token-heading">Bearer token</h2>
      </div>
      <p className="body-copy">
        Paste a bearer token for this browser session. Admin API requests send
        it as an Authorization header.
      </p>

      <form className="token-form" onSubmit={saveToken}>
        <label htmlFor="admin-token">Token</label>
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

function ComingSoonPage({
  eyebrow,
  title,
  body,
}: {
  eyebrow: string;
  title: string;
  body: string;
}) {
  return (
    <main className="single-page">
      <section className="panel narrow-panel" aria-labelledby="coming-heading">
        <div className="section-heading">
          <p className="eyebrow">{eyebrow}</p>
          <h2 id="coming-heading">{title}</h2>
        </div>
        <p className="body-copy">{body}</p>
      </section>
    </main>
  );
}

function NotFoundPage() {
  return (
    <main className="single-page">
      <section className="panel narrow-panel" aria-labelledby="missing-heading">
        <div className="section-heading">
          <p className="eyebrow">Not found</p>
          <h2 id="missing-heading">Admin route not found</h2>
        </div>
        <p className="body-copy">Choose an admin view from the header.</p>
      </section>
    </main>
  );
}
