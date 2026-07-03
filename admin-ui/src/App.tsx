import { FormEvent, useMemo, useState } from 'react';

import {
  clearStoredToken,
  getStoredToken,
  setStoredToken,
} from './lib/auth';

export function App() {
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
    <div className="admin-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">GreenGateway</p>
          <h1>Admin</h1>
        </div>
        <div className="version-pill">Gateway version pending status API</div>
      </header>

      <main className="content-grid">
        <section className="token-panel" aria-labelledby="token-heading">
          <div className="section-heading">
            <p className="eyebrow">Authentication</p>
            <h2 id="token-heading">Bearer token</h2>
          </div>
          <p className="body-copy">
            Until admin SSO lands in Phase 7, paste a bearer token here. It is
            stored in session storage and sent as an Authorization header on
            admin API requests.
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
              <button type="submit">Save</button>
              <button type="button" className="secondary" onClick={clearToken}>
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

        <section className="placeholder-panel" aria-labelledby="coming-heading">
          <div className="section-heading">
            <p className="eyebrow">Phase 2 scaffold</p>
            <h2 id="coming-heading">Views landing next</h2>
          </div>
          <div className="placeholder-list">
            <div>
              <h3>Log explorer</h3>
              <p>Queryable audit history over the admin audit API.</p>
            </div>
            <div>
              <h3>Live tail</h3>
              <p>Streaming admin events from the existing SSE endpoint.</p>
            </div>
            <div>
              <h3>Status page</h3>
              <p>Gateway health and version details for operators.</p>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
