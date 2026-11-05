import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { hasAdminPermission, useAdminCapabilities } from '../lib/adminCapabilities';
import { AdminCapabilitiesNotice } from '../lib/AdminCapabilitiesNotice';
import {
  fetchMcpClientConfigs,
  MCP_CLIENTS,
  type McpClient,
  type McpClientAuth,
  type McpClientConfigs,
} from '../lib/mcpClients';

const MCP_CLIENTS_READ_PERMISSION = 'admin:mcp:clients:read';

const CLIENT_LABELS: Record<McpClient, string> = {
  generic: 'Generic Streamable HTTP',
  'claude-desktop': 'Claude Desktop',
  cursor: 'Cursor',
  vscode: 'VS Code',
};

const CLIENT_GUIDANCE: Record<McpClient, string> = {
  generic:
    'A description of the connection for any Streamable HTTP client: translate it into that client’s own configuration.',
  'claude-desktop':
    'Claude Desktop adds a remote server as a custom connector by its URL and authorizes it with OAuth. Paste this URL there.',
  cursor: 'Save as mcp.json in one of the locations below, or merge the server entry into an existing file.',
  vscode: 'Save as mcp.json in the location below, or merge the server entry into an existing file.',
};

type LoadError = {
  kind: 'unauthorized' | 'forbidden' | 'public-url' | 'unreadable' | 'network' | 'generic';
  message: string;
};

/**
 * Credential-free MCP client configuration templates (issue #242). The
 * templates are server-rendered text: the URL comes from the gateway's
 * GATEWAY_PUBLIC_URL, never from this page's location. Copying is manual:
 * "Select all" selects the template and the operator copies it with the
 * keyboard or context menu. Nothing here reads or writes the clipboard, and
 * the admin UI's Permissions-Policy denies the asynchronous clipboard API.
 */
export function McpClientsView() {
  const capabilities = useAdminCapabilities();
  const canRead = hasAdminPermission(capabilities, MCP_CLIENTS_READ_PERMISSION);
  const [readRequested, setReadRequested] = useState(false);
  useEffect(() => {
    if (canRead) setReadRequested(true);
  }, [canRead]);
  const [configs, setConfigs] = useState<McpClientConfigs | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<LoadError | null>(null);
  const [client, setClient] = useState<McpClient>('generic');
  const [auth, setAuth] = useState<McpClientAuth>('oauth');
  const [selectionStatus, setSelectionStatus] = useState<string | null>(null);
  const templateRef = useRef<HTMLTextAreaElement | null>(null);

  useEffect(() => {
    let isCurrent = true;
    async function load() {
      setIsLoading(true);
      setLoadError(null);
      setConfigs(null);
      try {
        const loaded = await fetchMcpClientConfigs();
        if (!isCurrent) return;
        setConfigs(loaded);
        setAuth(loaded.oauth ? 'oauth' : 'token');
      } catch (error) {
        if (!isCurrent) return;
        setLoadError(toLoadError(error));
      } finally {
        if (isCurrent) setIsLoading(false);
      }
    }
    if (readRequested) void load();
    return () => {
      isCurrent = false;
    };
  }, [readRequested]);

  const permissionRequired =
    (capabilities.status === 'ready' && !canRead) || loadError?.kind === 'forbidden';
  const visible = canRead ? configs : null;
  const template =
    visible?.templates.find((candidate) => candidate.client === client && candidate.auth === auth) ??
    null;
  const clientAuths = visible
    ? visible.templates.filter((candidate) => candidate.client === client).map((candidate) => candidate.auth)
    : [];

  function chooseClient(next: McpClient) {
    setClient(next);
    setSelectionStatus(null);
    if (!visible) return;
    const auths = visible.templates
      .filter((candidate) => candidate.client === next)
      .map((candidate) => candidate.auth);
    if (!auths.includes(auth) && auths.length > 0) setAuth(auths[0]);
  }

  function chooseAuth(next: McpClientAuth) {
    setAuth(next);
    setSelectionStatus(null);
  }

  function selectTemplate() {
    const area = templateRef.current;
    if (!area) return;
    area.focus();
    area.select();
    setSelectionStatus('Template selected. Press Ctrl+C (or Cmd+C) to copy it.');
  }

  return (
    <main className="logs-page mcp-clients-page">
      <section className="panel logs-panel mcp-clients-panel" aria-labelledby="mcp-clients-heading">
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">MCP</p>
            <h2 id="mcp-clients-heading">MCP client configuration</h2>
          </div>
        </div>

        <AdminCapabilitiesNotice state={capabilities} />
        {permissionRequired ? (
          <div className="error-panel alert warning" role="alert">
            <h3>MCP client template permission required</h3>
            <p>Your session does not include {MCP_CLIENTS_READ_PERMISSION}.</p>
          </div>
        ) : null}
        {loadError && loadError.kind !== 'forbidden' ? <LoadErrorMessage error={loadError} /> : null}

        {canRead && isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading MCP client templates…
          </div>
        ) : null}

        {visible ? (
          <div className="mcp-clients-body">
            <dl className="mcp-clients-facts">
              <div>
                <dt>MCP endpoint</dt>
                <dd className="endpoint-template" data-testid="mcp-url">
                  {visible.mcpUrl}
                </dd>
              </div>
              <div>
                <dt>OAuth</dt>
                <dd data-testid="mcp-oauth">
                  {visible.oauth
                    ? 'Available: the protected-resource metadata advertises an authorization server.'
                    : 'Not available: no authorization server is advertised, so only token templates are offered.'}
                </dd>
              </div>
            </dl>

            <fieldset className="rule-fieldset">
              <legend>Client</legend>
              <div className="rule-check-grid">
                {MCP_CLIENTS.map((candidate) => (
                  <label className="rule-check-row" key={candidate}>
                    <input
                      type="radio"
                      className="rule-radio"
                      name="mcp-client"
                      value={candidate}
                      checked={client === candidate}
                      onChange={() => chooseClient(candidate)}
                    />
                    {CLIENT_LABELS[candidate]}
                  </label>
                ))}
              </div>
            </fieldset>

            {clientAuths.length > 1 ? (
              <fieldset className="rule-fieldset">
                <legend>Authentication</legend>
                <div className="rule-check-grid two-column">
                  {clientAuths.map((candidate) => (
                    <label className="rule-check-row" key={candidate}>
                      <input
                        type="radio"
                        className="rule-radio"
                        name="mcp-client-auth"
                        value={candidate}
                        checked={auth === candidate}
                        onChange={() => chooseAuth(candidate)}
                      />
                      {candidate === 'oauth' ? 'OAuth (URL only)' : 'Service token from the environment'}
                    </label>
                  ))}
                </div>
              </fieldset>
            ) : null}

            {template ? (
              <div className="mcp-template">
                <p>{CLIENT_GUIDANCE[client]}</p>
                {template.locations.length > 0 ? (
                  <ul className="mcp-template-locations" aria-label="File locations">
                    {template.locations.map((location) => (
                      <li key={location} className="endpoint-template">
                        {location}
                      </li>
                    ))}
                  </ul>
                ) : null}
                <label htmlFor="mcp-template-text" className="mcp-template-label">
                  {CLIENT_LABELS[client]} template ({template.auth === 'oauth' ? 'OAuth' : 'token'})
                </label>
                <textarea
                  id="mcp-template-text"
                  ref={templateRef}
                  className="mcp-template-text endpoint-template"
                  readOnly
                  spellCheck={false}
                  rows={Math.min(16, template.content.split('\n').length + 1)}
                  value={template.content}
                />
                <div className="token-row">
                  <button type="button" className="secondary-button" onClick={selectTemplate}>
                    Select all
                  </button>
                </div>
                <p role="status" aria-live="polite" className="mcp-template-status">
                  {selectionStatus ?? 'Select the template and copy it with the keyboard or the context menu.'}
                </p>
                {template.auth === 'token' ? (
                  <p className="mcp-template-note">
                    The template never holds a token. Set {visible.tokenVariable} in the client’s
                    environment to a service token whose scopes include mcp:tools and a role allowed to
                    use the gateway’s MCP route and tools. Minting one is a separate step on{' '}
                    <Link to="/tokens">Service tokens</Link> (admin:tokens:write).
                  </p>
                ) : (
                  <p className="mcp-template-note">
                    The client discovers the authorization server from the gateway’s protected-resource
                    metadata and obtains its own token.
                  </p>
                )}
              </div>
            ) : (
              <div className="error-panel alert warning" role="status">
                <p>
                  {CLIENT_LABELS[client]} has no template here:{' '}
                  {client === 'claude-desktop'
                    ? 'it connects with OAuth, and this gateway advertises no authorization server.'
                    : 'this gateway offers none for it.'}
                </p>
              </div>
            )}
          </div>
        ) : null}
      </section>
    </main>
  );
}

function LoadErrorMessage({ error }: { error: LoadError }) {
  const title =
    error.kind === 'unauthorized'
      ? 'Sign-in required'
      : error.kind === 'public-url'
        ? 'GATEWAY_PUBLIC_URL is needed'
        : error.kind === 'unreadable'
          ? 'Unreadable templates'
          : 'MCP client templates are unavailable';
  return (
    <div className="error-panel alert warning" role="alert">
      <h3>{title}</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toLoadError(error: unknown): LoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) return { kind: 'unauthorized', message: error.message };
    if (error.status === 403) return { kind: 'forbidden', message: error.message };
    if (error.status === 409 && error.code === 'public_url_not_configured') {
      return {
        kind: 'public-url',
        message:
          'The gateway has no GATEWAY_PUBLIC_URL, so it has no public MCP endpoint to put in a template. Set it and restart the gateway.',
      };
    }
    if (error.status === 409 && error.code === 'public_url_not_templatable') {
      return {
        kind: 'public-url',
        message:
          'The MCP endpoint derived from GATEWAY_PUBLIC_URL holds characters a client configuration file would interpolate ($, {, } or \\), or is too long.',
      };
    }
    return { kind: 'generic', message: error.message };
  }
  if (error instanceof Error && error.name === 'McpClientConfigsUnreadable') {
    return { kind: 'unreadable', message: error.message };
  }
  if (error instanceof Error) {
    return { kind: 'network', message: `Network request failed: ${error.message}` };
  }
  return { kind: 'network', message: 'Network request failed.' };
}
