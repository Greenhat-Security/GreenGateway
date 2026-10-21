import type {
  CallerAssertionKeyProblem,
  CallerAssertionKeyProblemCode,
  SafeCallerAssertion,
} from '../lib/connections';

/**
 * A Connection's caller assertion, read only. Shared by the detail page and
 * the editor; nothing in the admin UI edits the block, and saving a
 * Connection keeps it exactly as stored.
 *
 * `subjectTokenOnly` is set for a delegated issuer token Connection, whose
 * assertion is signed as the subject token of its token exchange and sent to
 * the issuer alone, never upstream.
 */
export function CallerAssertionSummary({
  assertion,
  subjectTokenOnly = false,
}: {
  assertion: SafeCallerAssertion;
  subjectTokenOnly?: boolean;
}) {
  return (
    <>
      <div className="alert warning" role="status">
        {subjectTokenOnly ? (
          <p>
            <strong>Caller assertion configured as the subject token.</strong>{' '}
            This connection signs the assertion only to name the calling
            principal to its token-exchange issuer, which verifies it against
            the gateway&apos;s published keys. It is never sent to the
            upstream, and its assertion header is only cleared from what a
            caller sends.
          </p>
        ) : (
          <p>
            <strong>Caller assertion configured.</strong> Once the gateway
            accepts this block, every manual HTTP, OpenAPI, and MCP tool call
            and every proxied request on this connection carries an assertion
            signed for the calling principal, and a call without one, such as
            a service token, is refused with{' '}
            <code>caller_assertion_no_principal</code>. Uses with no caller to
            name, such as discovery, enum and label sources, and tests, and
            the steps of composite tools are refused with{' '}
            <code>caller_assertion_not_enforced</code>, and so is every call
            when the block is one only an earlier release accepted: approval
            binding, an assertion header that matches another header on this
            connection, or a plain HTTP endpoint.
          </p>
        )}
        {subjectTokenOnly ? (
          <p>
            The admin UI shows this block read only. It cannot be removed
            while this connection authenticates with a delegated issuer token:
            the gateway signs the subject token with it, and refuses a change
            that removes it. To stop this connection, disable the connection
            through the admin API. After an incident, also revoke the grants at
            the issuer and rotate the client secret before enabling it again.
          </p>
        ) : (
          <p>
            The admin UI shows this block read only, and saving the connection
            here keeps it unchanged. To stop attesting callers, remove the
            block through the admin API by sending{' '}
            <code>&quot;caller_assertion&quot;: null</code>, which needs the
            secrets-write permission.
          </p>
        )}
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
        Tool calls on this connection are refused with{' '}
        <code>caller_assertion_key_not_published</code> while its keys are
        left out, even if the signing key still loads, because no upstream
        could verify what it signs. They are served again once every key
        loads. Every other connection&apos;s keys are still published. A save
        that keeps this connection enabled checks its keys again and is
        refused until the key is fixed; disabling the connection needs no key.
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
