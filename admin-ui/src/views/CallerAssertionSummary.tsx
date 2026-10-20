import type {
  CallerAssertionKeyProblem,
  CallerAssertionKeyProblemCode,
  SafeCallerAssertion,
} from '../lib/connections';

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
          <code>&quot;caller_assertion&quot;: null</code>, which needs the
          secrets-write permission.
        </p>
        {assertion.bind_approval ? (
          <p>
            This block asks for approval binding, which the gateway no longer
            accepts on a save. Remove it through the admin API before saving
            this connection.
          </p>
        ) : null}
      </div>
      {assertion.key_problem ? (
        <KeyProblemAlert problem={assertion.key_problem} />
      ) : null}
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
        {(assertion.published_keys ?? []).map((key) => (
          <Row
            key={key.kid}
            label="Also published"
            value={`${key.kid} (${key.algorithm.toUpperCase()}, ${
              key.signing_key_configured ? 'configured' : 'not configured'
            })`}
          />
        ))}
      </dl>
    </>
  );
}

const KEY_PROBLEM_REASONS: Record<CallerAssertionKeyProblemCode, string> = {
  unresolvable_binding:
    'its secret alias is not configured, or does not hold a key',
  binding_unavailable:
    'its secret source could not be read; the key returns once it can be',
  invalid_signing_key:
    'its secret is not exactly one PKCS#8 private key (BEGIN PRIVATE KEY)',
  algorithm_mismatch: 'its key is for the other algorithm',
  unusable_signing_key:
    'its key is not a P-256 key for ES256 or an RSA key of at least 2048 bits for RS256',
  duplicate_kid:
    'another enabled connection publishes a different key under the same key ID',
};

function KeyProblemAlert({ problem }: { problem: CallerAssertionKeyProblem }) {
  return (
    <div className="alert error" role="alert">
      <p>
        <strong>Keys not published.</strong> GreenGateway leaves this
        connection&apos;s keys out of its published key set because the key
        configured in <code>{problem.field}</code> cannot be used:{' '}
        {KEY_PROBLEM_REASONS[problem.code]} (<code>{problem.code}</code>).
      </p>
      <p>
        Every other connection&apos;s keys are still published. A save that
        keeps this connection enabled checks its keys again and is refused
        until the key is fixed; disabling the connection needs no key.
      </p>
    </div>
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
