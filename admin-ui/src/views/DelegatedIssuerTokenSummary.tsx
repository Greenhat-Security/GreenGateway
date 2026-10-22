import type { SafeDelegatedIssuerToken } from '../lib/connections';

/**
 * A Connection's delegated issuer token as the detail page shows it. The
 * editor changes these settings; the caller assertion that signs the subject
 * token is shown separately and changed through the admin API.
 */
export function DelegatedIssuerTokenSummary({
  authentication,
}: {
  authentication: SafeDelegatedIssuerToken;
}) {
  return (
    <>
      <div className="alert warning" role="status">
        <p>
          <strong>Each caller reaches the upstream as themselves.</strong> For
          every calling principal, the gateway exchanges a caller assertion
          for that principal&apos;s own access token at the issuer below
          (RFC 8693 token exchange), caches it for that principal only, and
          sends it as the bearer token. Only manual HTTP tool calls are
          served. A call without a principal, such as a service token, is
          refused with <code>delegated_token_no_principal</code>; an issuer
          that refuses the caller, with <code>delegated_token_denied</code>;
          and any other failed exchange, with{' '}
          <code>delegated_token_exchange_failed</code>. Nothing is sent
          upstream for a refused call.
        </p>
        <p>
          The issuer can hand out any user&apos;s token to whoever holds this
          connection&apos;s client secret, so keep that secret in an external
          provider and grant read-only scopes where the upstream allows it.
        </p>
        <p>
          <strong>Test connection runs as you.</strong> It exchanges a token
          for your own account, sends the saved test request with it, and
          drops it: the token is not cached and serves no other call. It is
          refused for a service token or a sign-in without an identity
          provider issuer (<code>delegated_token_no_principal</code>), and
          while the connection is disabled, because the issuer verifies the
          subject token against published keys that include only enabled
          connections (<code>caller_assertion_key_not_published</code>). A
          passing test shows that your own grant works, not anyone
          else&apos;s.
        </p>
      </div>
      <dl className="traffic-metadata-grid">
        <Row
          label="Token exchange URL"
          value={authentication.token_exchange_url}
          code
        />
        <Row label="Client ID" value={authentication.client_id} code />
        <Row
          label="Client secret"
          value={
            authentication.client_secret_configured
              ? 'Configured'
              : 'Not configured'
          }
        />
        <Row
          label="Requested scopes"
          value={
            authentication.requested_scopes.length > 0
              ? authentication.requested_scopes.join(' ')
              : 'None'
          }
          code={authentication.requested_scopes.length > 0}
        />
        <Row
          label="Audience"
          value={authentication.audience ?? 'Not set'}
          code={authentication.audience !== undefined}
        />
        <Row
          label="Resource"
          value={authentication.resource ?? 'Not set'}
          code={authentication.resource !== undefined}
        />
        <Row
          label="Revocation URL"
          value={
            authentication.revocation_url ??
            'Not set: a purged token is only dropped'
          }
          code={authentication.revocation_url !== undefined}
        />
        <Row
          label="Subject token"
          value="Caller assertion signed by the gateway"
        />
      </dl>
    </>
  );
}

function Row({
  label,
  value,
  code = false,
}: {
  label: string;
  value: string;
  code?: boolean;
}) {
  return (
    <div className="spec-row">
      <dt className="k">{label}</dt>
      <dd className="v">{code ? <code>{value}</code> : value}</dd>
    </div>
  );
}
