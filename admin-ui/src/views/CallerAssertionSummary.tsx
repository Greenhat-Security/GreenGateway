import type { SafeCallerAssertion } from '../lib/connections';

/**
 * A Connection's caller assertion, read only. Shared by the detail page and
 * the editor; nothing in the admin UI edits the block, and saving a
 * Connection keeps it exactly as stored.
 */
export function CallerAssertionSummary({
  assertion,
}: {
  assertion: SafeCallerAssertion;
}) {
  return (
    <>
      <div className="alert warning" role="status">
        <p>
          <strong>Accepted, not yet enforced.</strong> GreenGateway does not
          sign or send caller assertions yet, so it refuses every call, test,
          and discovery on a connection that carries one, with the reason{' '}
          <code>caller_assertion_not_enforced</code>.
        </p>
        <p>
          The admin UI shows this block read only, and saving the connection
          here keeps it unchanged. To use the connection before enforcement
          ships, remove the block through the admin API by sending{' '}
          <code>&quot;caller_assertion&quot;: null</code>.
        </p>
        {assertion.bind_approval ? (
          <p>
            This block asks for approval binding, which the gateway no longer
            accepts on a save. Remove it through the admin API before saving
            this connection.
          </p>
        ) : null}
      </div>
      <dl className="traffic-metadata-grid">
        <Row
          label="Signing key"
          value={
            assertion.signing_key_configured ? 'Configured' : 'Not configured'
          }
        />
        <Row label="Key ID" value={assertion.kid} code />
        <Row label="Algorithm" value={assertion.algorithm.toUpperCase()} />
        <Row label="Issuer" value={assertion.issuer} code />
        <Row label="Audience" value={assertion.audience} code />
        <Row label="Token type" value={assertion.token_type} code />
        <Row label="Assertion header" value={assertion.header_name} code />
        <Row
          label="Lifetime"
          value={`${assertion.lifetime_seconds.toLocaleString()} seconds`}
        />
        <Row
          label="Claims"
          value={['sub', ...(assertion.claims ?? [])].join(', ')}
        />
        <Row
          label="Request binding"
          value={
            assertion.bind_request
              ? 'Method, path, and body digest'
              : 'Not bound'
          }
        />
        <Row
          label="Approval binding"
          value={
            assertion.bind_approval ? 'Requested, not supported' : 'Not bound'
          }
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
