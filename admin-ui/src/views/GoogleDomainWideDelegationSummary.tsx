import type { SafeGoogleDomainWideDelegation } from '../lib/connections';

/**
 * A Connection's Google domain-wide delegation as the detail page shows it.
 * Every field is shown: none is a secret, and the profile is only the ID of
 * the gateway's own startup configuration. The editor changes them.
 */
export function GoogleDomainWideDelegationSummary({
  authentication,
}: {
  authentication: SafeGoogleDomainWideDelegation;
}) {
  return (
    <>
      <div className="alert warning" role="status">
        <p>
          <strong>Each caller reaches Google as themselves.</strong> For every
          calling principal, Google signs an assertion naming that
          principal&apos;s email as the service account below, through IAM
          Credentials <code>signJwt</code> authenticated as the workload
          identity profile, and the gateway exchanges it for the user&apos;s
          own token, caches it for that principal only, and sends it as the
          bearer token. The gateway holds no service account key. Only manual
          HTTP tool calls are served. A call without a principal, such as a
          service token, is refused with{' '}
          <code>delegated_token_no_principal</code>; a caller from an unlisted
          identity provider, with{' '}
          <code>google_delegation_issuer_not_trusted</code>; and a caller
          without a plain email address, with{' '}
          <code>google_delegation_no_email</code>. Nothing is sent upstream for
          a refused call, and every token Google mints is audited as{' '}
          <code>connection.google_delegation_token</code> with the caller as
          actor.
        </p>
        <p>
          The service account can act as every user of the Workspace domain
          for the scopes its administrator authorised, so keep it dedicated to
          this connection and its scopes read-only and few.
        </p>
        <p>
          <strong>Test connection runs as you.</strong> Google mints a token
          for your own Workspace account, the saved test request is sent with
          it, and it is dropped: the token is not cached and serves no other
          call. A passing test shows that the service account may act as you,
          not as anyone else.
        </p>
      </div>
      <dl className="traffic-metadata-grid">
        <Row
          label="Service account"
          value={authentication.service_account_email}
          code
        />
        <Row
          label="Workload identity profile"
          value={authentication.workload_identity_profile}
          code
        />
        <Row label="Scopes" value={authentication.scopes.join(' ')} code />
        <Row label="Subject claim" value={authentication.subject_claim} code />
        <Row
          label="Subject issuers"
          value={authentication.subject_issuers.join(' ')}
          code
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
