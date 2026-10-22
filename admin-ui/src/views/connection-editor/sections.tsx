import {
  useEffect,
  useRef,
  useState
} from 'react';

import {
  MAX_PUBLISHED_ASSERTION_KEYS,
  type CallerAssertionAlgorithm,
  type CallerAssertionClaim,
  type ConnectionKind
} from '../../lib/connections';
import {
  createConnectionSecret,
  deleteConnectionSecret,
  listConnectionSecrets,
  rotateConnectionSecret,
  type ConnectionSecretMetadata,
  type ConnectionSecretPurpose
} from '../../lib/secrets';
import { CallerAssertionSummary } from '../CallerAssertionSummary';

import {
  AdditionalHeaderDraft,
  additionalHeaderFieldError,
  ALL_SECRET_PURPOSES,
  AssertionKeyDraft,
  assertionKeyWithPatch,
  authenticationPurpose,
  AuthenticationType,
  authenticationTypeLocked,
  BindingDraft,
  BindingIntent,
  CALLER_ASSERTION_PROBLEMS_ID,
  CallerAssertionDraft,
  callerAssertionDraftFromStored,
  callerAssertionDraftWithPromotedKey,
  CallerAssertionMode,
  callerAssertionSectionProblems,
  ConnectionFormState,
  describedBy,
  DiscoveryType,
  effectiveCallerAssertionMode,
  emptyAssertionKey,
  FieldErrors,
  formatSecretProvider,
  formatSecretPurpose,
  isTlsSecretPurpose,
  MAX_ADDITIONAL_HEADERS,
  MAX_CALLER_ASSERTION_LIFETIME_SECONDS,
  newCallerAssertionDraft,
  secretErrorRequiresReload,
  SecretInventoryState,
  secretMaxLength,
  secretMutationError,
  secretMutationReloadRequired,
  SubjectTokenDraft,
  subjectTokenDraftApplies,
} from './model';
export function ConnectionIdentitySection({
  form,
  errors,
  disabled,
  sensitiveDisabled,
  onUpdate,
  onKindChange,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  disabled: boolean;
  sensitiveDisabled: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
  onKindChange: (kind: ConnectionKind) => void;
}) {
  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-basics-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Identity</p>
        <h3 id="connection-basics-heading">Connection basics</h3>
      </div>
      <div className="filter-grid connection-form-grid">
        <FormField
          id="connection-display-name"
          label="Display name"
          error={errors.display_name}
        >
          <input
            id="connection-display-name"
            value={form.displayName}
            disabled={disabled}
            maxLength={128}
            aria-invalid={Boolean(errors.display_name)}
            aria-describedby={describedBy('connection-display-name', errors.display_name)}
            onChange={(event) => onUpdate({ displayName: event.target.value })}
          />
        </FormField>
        <label htmlFor="connection-kind">
          Connection kind
          <select
            id="connection-kind"
            value={form.kind}
            disabled={sensitiveDisabled}
            onChange={(event) =>
              onKindChange(event.target.value as ConnectionKind)
            }
          >
            <option value="http_api">HTTP API</option>
            <option value="mcp_streamable_http">MCP streamable HTTP</option>
          </select>
        </label>
        <FormField
          id="connection-base-url"
          label="Base URL"
          error={errors['endpoint.base_url']}
        >
          <input
            id="connection-base-url"
            type="url"
            placeholder="https://api.example.com"
            value={form.baseUrl}
            disabled={sensitiveDisabled}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={Boolean(errors['endpoint.base_url'])}
            aria-describedby={describedBy(
              'connection-base-url',
              errors['endpoint.base_url'],
            )}
            onChange={(event) => onUpdate({ baseUrl: event.target.value })}
          />
        </FormField>
        <FormField
          id="connection-base-path"
          label="Base path"
          error={errors['endpoint.base_path']}
        >
          <input
            id="connection-base-path"
            value={form.basePath}
            disabled={sensitiveDisabled}
            spellCheck={false}
            aria-invalid={Boolean(errors['endpoint.base_path'])}
            aria-describedby={describedBy(
              'connection-base-path',
              errors['endpoint.base_path'],
            )}
            onChange={(event) => onUpdate({ basePath: event.target.value })}
          />
        </FormField>
      </div>
      <label htmlFor="connection-description">
        Description
        <textarea
          id="connection-description"
          value={form.description}
          disabled={disabled}
          maxLength={1024}
          onChange={(event) => onUpdate({ description: event.target.value })}
        />
      </label>
      <label className="rule-check-row">
        <input
          type="checkbox"
          checked={form.enabled}
          disabled={disabled}
          onChange={(event) =>
            onUpdate({
              enabled: event.target.checked,
              enableConfirmed: false,
            })
          }
        />
        Enabled
      </label>
    </section>
  );
}

export function AuthenticationSection({
  form,
  errors,
  canBindSecret,
  secrets,
  disabled,
  delegatedOffered,
  onUpdate,
  onAuthenticationTypeChange,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  canBindSecret: boolean;
  secrets: ConnectionSecretMetadata[];
  disabled: boolean;
  delegatedOffered: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
  onAuthenticationTypeChange: (type: AuthenticationType) => void;
}) {
  const hasSecret = authenticationPurpose(form.authenticationType) !== null;
  const typeLocked = authenticationTypeLocked(form);
  const delegated = form.authenticationType === 'delegated_issuer_token';
  const google = form.authenticationType === 'google_domain_wide_delegation';
  const requestsToken =
    form.authenticationType === 'oauth2_client_credentials' || delegated;
  const scopesField = delegated
    ? 'authentication.requested_scopes'
    : 'authentication.scopes';
  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-auth-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Credentials</p>
        <h3 id="connection-auth-heading">Authentication</h3>
      </div>
      <div className="filter-grid connection-form-grid">
        <FormField
          id="connection-authentication-type"
          label="Authentication type"
          error={errors['authentication.type']}
        >
          <select
            id="connection-authentication-type"
            value={form.authenticationType}
            disabled={disabled || typeLocked}
            aria-invalid={Boolean(errors['authentication.type'])}
            aria-describedby={
              describedBy(
                'connection-authentication-type',
                errors['authentication.type'],
              ) ??
              (typeLocked ? 'connection-authentication-type-locked' : undefined)
            }
            onChange={(event) =>
              onAuthenticationTypeChange(
                event.target.value as AuthenticationType,
              )
            }
          >
            {typeLocked ? null : (
              <>
                <option value="none">None</option>
                <option value="header_api_key">Header API key</option>
                <option value="static_bearer">Static bearer</option>
                <option value="oauth2_client_credentials">
                  OAuth 2 client credentials
                </option>
                <option value="google_domain_wide_delegation">
                  Google domain-wide delegation (each caller&apos;s own)
                </option>
              </>
            )}
            {delegatedOffered ? (
              <option value="delegated_issuer_token">
                Delegated issuer token (each caller&apos;s own)
              </option>
            ) : null}
          </select>
        </FormField>
        {form.authenticationType === 'header_api_key' ? (
          <FormField
            id="connection-header-name"
            label="Header name"
            error={errors['authentication.header_name']}
          >
            <input
              id="connection-header-name"
              value={form.headerName}
              disabled={disabled}
              autoComplete="off"
              spellCheck={false}
              aria-invalid={Boolean(errors['authentication.header_name'])}
              aria-describedby={describedBy(
                'connection-header-name',
                errors['authentication.header_name'],
              )}
              onChange={(event) => onUpdate({ headerName: event.target.value })}
            />
          </FormField>
        ) : null}
        {requestsToken ? (
          <>
            <FormField
              id="connection-client-id"
              label={delegated ? 'Issuer client ID' : 'OAuth client ID'}
              error={errors['authentication.client_id']}
            >
              <input
                id="connection-client-id"
                value={form.clientId}
                disabled={disabled}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={Boolean(errors['authentication.client_id'])}
                aria-describedby={describedBy(
                  'connection-client-id',
                  errors['authentication.client_id'],
                )}
                onChange={(event) => onUpdate({ clientId: event.target.value })}
              />
            </FormField>
            {delegated ? (
              <FormField
                id="connection-token-exchange-url"
                label="Token exchange URL"
                error={errors['authentication.token_exchange_url']}
              >
                <input
                  id="connection-token-exchange-url"
                  type="url"
                  value={form.tokenExchangeUrl}
                  disabled={disabled}
                  placeholder="https://issuer.example/oauth2/token-exchange"
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={Boolean(
                    errors['authentication.token_exchange_url'],
                  )}
                  aria-describedby={describedBy(
                    'connection-token-exchange-url',
                    errors['authentication.token_exchange_url'],
                  )}
                  onChange={(event) =>
                    onUpdate({ tokenExchangeUrl: event.target.value })
                  }
                />
              </FormField>
            ) : (
              <FormField
                id="connection-token-url"
                label="OAuth token URL"
                error={errors['authentication.token_url']}
              >
                <input
                  id="connection-token-url"
                  type="url"
                  value={form.tokenUrl}
                  disabled={disabled}
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={Boolean(errors['authentication.token_url'])}
                  aria-describedby={describedBy(
                    'connection-token-url',
                    errors['authentication.token_url'],
                  )}
                  onChange={(event) => onUpdate({ tokenUrl: event.target.value })}
                />
              </FormField>
            )}
            <FormField
              id="connection-oauth-scopes"
              label={delegated ? 'Requested scopes' : 'OAuth scopes'}
              error={errors[scopesField]}
            >
              <input
                id="connection-oauth-scopes"
                value={form.scopes}
                disabled={disabled}
                placeholder={delegated ? 'mail.read' : 'read write'}
                autoComplete="off"
                aria-invalid={Boolean(errors[scopesField])}
                aria-describedby={describedBy(
                  'connection-oauth-scopes',
                  errors[scopesField],
                )}
                onChange={(event) => onUpdate({ scopes: event.target.value })}
              />
            </FormField>
            <FormField
              id="connection-oauth-audience"
              label={delegated ? 'Requested audience' : 'OAuth audience'}
              error={errors['authentication.audience']}
            >
              <input
                id="connection-oauth-audience"
                value={form.audience}
                disabled={disabled}
                autoComplete="off"
                aria-invalid={Boolean(errors['authentication.audience'])}
                aria-describedby={describedBy(
                  'connection-oauth-audience',
                  errors['authentication.audience'],
                )}
                onChange={(event) => onUpdate({ audience: event.target.value })}
              />
            </FormField>
            <FormField
              id="connection-oauth-resource"
              label={delegated ? 'Requested resource' : 'OAuth resource'}
              error={errors['authentication.resource']}
            >
              <input
                id="connection-oauth-resource"
                value={form.resource}
                disabled={disabled}
                autoComplete="off"
                aria-invalid={Boolean(errors['authentication.resource'])}
                aria-describedby={describedBy(
                  'connection-oauth-resource',
                  errors['authentication.resource'],
                )}
                onChange={(event) => onUpdate({ resource: event.target.value })}
              />
            </FormField>
            {delegated ? (
              <FormField
                id="connection-revocation-url"
                label="Revocation URL (optional)"
                error={errors['authentication.revocation_url']}
              >
                <input
                  id="connection-revocation-url"
                  type="url"
                  value={form.revocationUrl}
                  disabled={disabled}
                  placeholder="https://issuer.example/oauth2/revoke"
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={Boolean(errors['authentication.revocation_url'])}
                  aria-describedby={
                    describedBy(
                      'connection-revocation-url',
                      errors['authentication.revocation_url'],
                    ) ?? 'connection-revocation-url-help'
                  }
                  onChange={(event) =>
                    onUpdate({ revocationUrl: event.target.value })
                  }
                />
              </FormField>
            ) : null}
          </>
        ) : null}
        {google ? (
          <GoogleDomainWideDelegationFields
            form={form}
            errors={errors}
            disabled={disabled}
            onUpdate={onUpdate}
          />
        ) : null}
      </div>
      {google ? (
        <p id="connection-google-profile-help" className="capability-description">
          The workload identity profile is the <code>id</code> of a{' '}
          <code>CONNECTION_GCP_PROVIDER</code> profile in the gateway&apos;s
          startup configuration: the federated identity that has Google sign
          as the service account. It holds no key, and an enabled connection
          can be saved only once the profile is configured.
        </p>
      ) : null}
      {google ? (
        <FormField
          id="connection-google-subject-issuers"
          label="Subject issuers (one per line)"
          error={errors['authentication.subject_issuers']}
        >
          <textarea
            id="connection-google-subject-issuers"
            value={form.subjectIssuers}
            disabled={disabled}
            rows={2}
            placeholder="https://idp.example.com"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={Boolean(errors['authentication.subject_issuers'])}
            aria-describedby={
              describedBy(
                'connection-google-subject-issuers',
                errors['authentication.subject_issuers'],
              ) ?? 'connection-google-subject-issuers-help'
            }
            onChange={(event) =>
              onUpdate({ subjectIssuers: event.target.value })
            }
          />
        </FormField>
      ) : null}
      {google ? (
        <p
          id="connection-google-subject-issuers-help"
          className="capability-description"
        >
          Each call acts as the Workspace user whose email the caller&apos;s
          identity provider put in its token, so list only the provider
          authoritative for the domain: any other could name any user. A
          caller from an unlisted provider is refused. The subject claim is
          always <code>email</code>.
        </p>
      ) : null}
      {google ? <GoogleDomainWideDelegationNote /> : null}
      {typeLocked ? (
        <p
          id="connection-authentication-type-locked"
          className="capability-description"
        >
          A delegated issuer token connection keeps its credential type. Its
          caller assertion stays through every save, and under any other type
          the gateway would start sending it upstream. Create a new connection
          to use another credential.
        </p>
      ) : null}
      {delegated ? (
        <p
          id="connection-revocation-url-help"
          className="capability-description"
        >
          When a principal&apos;s tokens are purged, the gateway revokes each
          one at the revocation URL (RFC 7009), once and best effort, with the
          exchange&apos;s client credentials. Without it a purged token is only
          dropped and stays valid at the issuer until it expires.
        </p>
      ) : null}
      {delegated ? <DelegatedIssuerTokenNote /> : null}
      {hasSecret ? (
        <BindingControl
          id="connection-auth-secret"
          label={
            form.authenticationType === 'oauth2_client_credentials'
              ? 'OAuth client secret'
              : delegated
                ? 'Token exchange client secret'
                : 'Authentication secret'
          }
          binding={form.authenticationBinding}
          purpose={authenticationPurpose(form.authenticationType)}
          secrets={secrets}
          canBindSecret={canBindSecret}
          disabled={disabled}
          error={
            errors[
            requestsToken
              ? 'authentication.client_secret_id'
              : 'authentication.secret_id'
            ]
          }
          onChange={(authenticationBinding) =>
            onUpdate({ authenticationBinding })
          }
        />
      ) : null}
      {delegated ? (
        <p className="capability-description">
          The client secret resolves only from an operator alias or an
          external secret provider; the encrypted local store cannot hold it.
          Give it an alias of its own: the gateway refuses a save that binds
          it under any other field of any connection.
        </p>
      ) : null}
    </section>
  );
}

/**
 * What a delegated issuer token does and where its trust sits, beside the
 * fields that configure it.
 */
function DelegatedIssuerTokenNote() {
  return (
    <div className="alert warning" role="status">
      <p>
        <strong>Each caller reaches the upstream as themselves.</strong> For
        every calling principal the gateway exchanges a caller assertion it
        signs for that principal&apos;s own access token at the issuer (RFC
        8693 token exchange), caches it for that principal only, and sends it
        as the bearer token. Only manual HTTP tool calls are served, and a call
        without a principal, such as a service token, is refused.
      </p>
      <p>
        Whoever holds the client secret can ask the issuer for any
        user&apos;s token. Keep it in an external provider, and request
        read-only scopes where the upstream allows it.
      </p>
    </div>
  );
}

/**
 * The fields of a Google domain-wide delegation, in the authentication grid.
 * None is a secret: the account and the profile are names, and the profile
 * resolves only from the gateway's own startup configuration.
 */
function GoogleDomainWideDelegationFields({
  form,
  errors,
  disabled,
  onUpdate,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  disabled: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
}) {
  return (
    <>
      <FormField
        id="connection-google-service-account"
        label="Delegated service account"
        error={errors['authentication.service_account_email']}
      >
        <input
          id="connection-google-service-account"
          type="email"
          value={form.serviceAccountEmail}
          disabled={disabled}
          placeholder="gateway-delegate@project-id.iam.gserviceaccount.com"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(errors['authentication.service_account_email'])}
          aria-describedby={describedBy(
            'connection-google-service-account',
            errors['authentication.service_account_email'],
          )}
          onChange={(event) =>
            onUpdate({ serviceAccountEmail: event.target.value })
          }
        />
      </FormField>
      <FormField
        id="connection-google-profile"
        label="Workload identity profile"
        error={errors['authentication.workload_identity_profile']}
      >
        <input
          id="connection-google-profile"
          value={form.workloadIdentityProfile}
          disabled={disabled}
          placeholder="gateway-wif"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(
            errors['authentication.workload_identity_profile'],
          )}
          aria-describedby={
            describedBy(
              'connection-google-profile',
              errors['authentication.workload_identity_profile'],
            ) ?? 'connection-google-profile-help'
          }
          onChange={(event) =>
            onUpdate({ workloadIdentityProfile: event.target.value })
          }
        />
      </FormField>
      <FormField
        id="connection-oauth-scopes"
        label="Google scopes"
        error={errors['authentication.scopes']}
      >
        <input
          id="connection-oauth-scopes"
          value={form.scopes}
          disabled={disabled}
          placeholder="https://www.googleapis.com/auth/gmail.readonly"
          autoComplete="off"
          spellCheck={false}
          aria-invalid={Boolean(errors['authentication.scopes'])}
          aria-describedby={describedBy(
            'connection-oauth-scopes',
            errors['authentication.scopes'],
          )}
          onChange={(event) => onUpdate({ scopes: event.target.value })}
        />
      </FormField>
    </>
  );
}

/**
 * What a Google domain-wide delegation does and where its trust sits, beside
 * the fields that configure it.
 */
function GoogleDomainWideDelegationNote() {
  return (
    <div className="alert warning" role="status">
      <p>
        <strong>Each caller reaches Google as themselves.</strong> For every
        calling principal named by email by a listed subject issuer, Google
        signs an assertion as the service account through IAM Credentials{' '}
        <code>signJwt</code>, and the gateway exchanges it for that
        user&apos;s own token, caches it for that principal only, and sends it
        as the bearer token. No service account key is held anywhere in the
        gateway. Only manual HTTP tool calls and stored tests are served, and a
        call without a principal, such as a service token, is refused.
      </p>
      <p>
        The service account can act as every user of the Workspace domain for
        the scopes the Workspace administrator authorised for it. Use an
        account dedicated to this connection, authorise read-only scopes only
        and as few as the tools need, and keep these scopes within that list.
        The egress allowlist must include <code>sts.googleapis.com</code>,{' '}
        <code>iamcredentials.googleapis.com</code> and{' '}
        <code>oauth2.googleapis.com</code>.
      </p>
    </div>
  );
}

export function AdditionalHeadersSection({
  headers,
  errors,
  canBindSecret,
  secrets,
  disabled,
  onAdd,
  onUpdate,
  onRemove,
}: {
  headers: AdditionalHeaderDraft[];
  errors: FieldErrors;
  canBindSecret: boolean;
  secrets: ConnectionSecretMetadata[];
  disabled: boolean;
  onAdd: () => void;
  onUpdate: (
    index: number,
    patch: Partial<Pick<AdditionalHeaderDraft, 'headerName' | 'binding'>>,
  ) => void;
  onRemove: (index: number) => void;
}) {
  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-additional-headers-heading"
    >
      <div className="section-heading connection-additional-headers-heading">
        <div>
          <p className="eyebrow">Proxy identity</p>
          <h3 id="connection-additional-headers-heading">
            Additional secret headers
          </h3>
        </div>
        <button
          type="button"
          className="secondary-button"
          disabled={disabled || headers.length >= MAX_ADDITIONAL_HEADERS}
          onClick={onAdd}
        >
          Add secret header
        </button>
      </div>
      <p className="capability-description">
        Add up to four secret-backed headers for an identity-aware proxy or
        another upstream credential layer. The gateway strips caller values
        before injecting these headers on every connection lane.
      </p>
      {headers.length === 0 ? (
        <p className="capability-description">No additional headers.</p>
      ) : (
        <div className="connection-additional-header-list">
          {headers.map((header, index) => {
            const headerNameError = additionalHeaderFieldError(
              errors,
              index,
              'header_name',
            );
            const secretError = additionalHeaderFieldError(
              errors,
              index,
              'secret_id',
            );
            const number = index + 1;
            return (
              <div
                className="connection-additional-header-row"
                key={header.draftId}
              >
                <div className="filter-grid connection-form-grid">
                  <FormField
                    id={`connection-additional-header-${index}-name`}
                    label={`Additional header ${number} name`}
                    error={headerNameError}
                  >
                    <input
                      id={`connection-additional-header-${index}-name`}
                      value={header.headerName}
                      disabled={disabled}
                      maxLength={64}
                      autoComplete="off"
                      spellCheck={false}
                      aria-invalid={Boolean(headerNameError)}
                      aria-describedby={describedBy(
                        `connection-additional-header-${index}-name`,
                        headerNameError,
                      )}
                      onChange={(event) =>
                        onUpdate(index, { headerName: event.target.value })
                      }
                    />
                  </FormField>
                  <BindingControl
                    id={`connection-additional-header-${index}-secret`}
                    label={`Additional header ${number} secret`}
                    binding={header.binding}
                    purpose="header_api_key"
                    secrets={secrets}
                    canBindSecret={canBindSecret}
                    disabled={disabled}
                    error={secretError}
                    onChange={(binding) => onUpdate(index, { binding })}
                  />
                </div>
                <button
                  type="button"
                  className="secondary-button connection-additional-header-remove"
                  disabled={disabled}
                  onClick={() => onRemove(index)}
                >
                  Remove additional header {number}
                </button>
              </div>
            );
          })}
        </div>
      )}
      <p className="capability-description">
        {headers.length} of {MAX_ADDITIONAL_HEADERS} configured.
      </p>
    </section>
  );
}

/**
 * The caller assertion: the stored block read only until the operator chooses
 * to edit or remove it, or a new block. A save that does neither leaves the
 * stored block out of the write, so the gateway keeps it exactly as stored.
 * A delegated issuer token Connection's block is its subject token instead:
 * read only once it exists, and drafted by `SubjectTokenSection` before.
 *
 * `disabled` is set without the secrets-write permission: binding, changing
 * or removing the block is secret authority.
 */
export function CallerAssertionSection({
  form,
  errors,
  secrets,
  canBindSecret,
  secretsWriteAllowed,
  disabled,
  onUpdate,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  secrets: ConnectionSecretMetadata[];
  // Whether the alias pickers can bind: the permission and a loaded inventory.
  canBindSecret: boolean;
  secretsWriteAllowed: boolean;
  disabled: boolean;
  onUpdate: (
    update: (current: ConnectionFormState) => ConnectionFormState,
  ) => void;
}) {
  const stored = form.callerAssertion;
  const mode = effectiveCallerAssertionMode(form);
  // A delegated issuer token Connection's block is its subject token: drafted
  // by the subject-token section while the Connection is new, and read only
  // once it exists.
  const subjectToken = form.authenticationType === 'delegated_issuer_token';
  const problems = callerAssertionSectionProblems(
    errors,
    mode === 'edit' || subjectTokenDraftApplies(form),
  );

  function setMode(next: CallerAssertionMode) {
    onUpdate((current) => ({
      ...current,
      callerAssertionMode: next,
      ...(next === 'edit'
        ? {
          callerAssertionDraft:
            current.callerAssertion === null
              ? newCallerAssertionDraft()
              : callerAssertionDraftFromStored(current.callerAssertion),
        }
        : {}),
    }));
  }

  function updateDraft(
    update: (draft: CallerAssertionDraft) => CallerAssertionDraft,
  ) {
    onUpdate((current) => ({
      ...current,
      callerAssertionDraft: update(current.callerAssertionDraft),
    }));
  }

  const problemAlert =
    problems.length > 0 ? (
      <div
        className="error-panel alert warning"
        role="alert"
        id={CALLER_ASSERTION_PROBLEMS_ID}
        tabIndex={-1}
      >
        <h3>Review the caller assertion</h3>
        {problems.map((problem) => (
          <p key={problem}>{problem}</p>
        ))}
      </div>
    ) : null;

  if (subjectToken) {
    if (stored === null) {
      return problemAlert;
    }
    return (
      <section
        className="connection-form-section"
        aria-labelledby="connection-caller-assertion-heading"
      >
        <div className="section-heading">
          <p className="eyebrow">Caller attestation</p>
          <h3 id="connection-caller-assertion-heading">Subject token</h3>
        </div>
        {problemAlert}
        <CallerAssertionSummary assertion={stored} subjectTokenOnly />
      </section>
    );
  }

  // A domain-wide delegation carries no block, so a stored one is removed by
  // the save; see `effectiveCallerAssertionMode`. Another type keeps it.
  if (form.authenticationType === 'google_domain_wide_delegation') {
    return (
      <section
        className="connection-form-section"
        aria-labelledby="connection-caller-assertion-heading"
      >
        <div className="section-heading">
          <p className="eyebrow">Caller attestation</p>
          <h3 id="connection-caller-assertion-heading">Caller assertion</h3>
        </div>
        {problemAlert}
        {stored !== null ? (
          <>
            <div className="alert warning" role="status">
              <p>
                <strong>Removed when you save.</strong> A Google domain-wide
                delegation sends the caller&apos;s own Google token, and Google
                verifies no caller assertion of the gateway&apos;s, so the
                gateway refuses the block on this credential. Its keys are
                withdrawn from the published key set. Choose another
                authentication type to keep it.
              </p>
            </div>
            <CallerAssertionSummary assertion={stored} />
          </>
        ) : (
          <p className="capability-description">
            A Google domain-wide delegation carries no caller assertion: the
            caller&apos;s own Google token already names them, and Google
            verifies no assertion of the gateway&apos;s.
          </p>
        )}
      </section>
    );
  }

  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-caller-assertion-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Caller attestation</p>
        <h3 id="connection-caller-assertion-heading">Caller assertion</h3>
      </div>
      {problemAlert}
      {mode === 'edit' ? (
        <CallerAssertionEditor
          draft={form.callerAssertionDraft}
          errors={errors}
          secrets={secrets}
          canBindSecret={canBindSecret}
          disabled={disabled}
          onUpdate={updateDraft}
        />
      ) : null}
      {mode === 'remove' && stored !== null ? (
        <div className="alert warning" role="status">
          <p>
            <strong>Removed when you save.</strong> Requests on this
            connection then reach the upstream without an assertion of the
            caller, and its keys are withdrawn from the published key set.
          </p>
        </div>
      ) : null}
      {mode !== 'edit' && stored !== null ? (
        <CallerAssertionSummary assertion={stored} />
      ) : null}
      {mode !== 'edit' && stored === null ? (
        <p className="capability-description">
          No caller assertion. Add one to send the upstream a short-lived JWT,
          signed by the gateway, that names the calling principal on the
          requests this connection makes for a caller.
        </p>
      ) : null}
      <div className="form-actions">
        {mode === 'keep' ? (
          <button
            type="button"
            className="secondary-button"
            disabled={disabled}
            onClick={() => setMode('edit')}
          >
            {stored === null ? 'Add caller assertion' : 'Edit caller assertion'}
          </button>
        ) : null}
        {mode === 'keep' && stored !== null ? (
          <button
            type="button"
            className="secondary-button"
            disabled={disabled}
            onClick={() => setMode('remove')}
          >
            Remove caller assertion
          </button>
        ) : null}
        {mode !== 'keep' ? (
          <button
            type="button"
            className="secondary-button"
            disabled={disabled}
            onClick={() => setMode('keep')}
          >
            {stored === null
              ? 'Discard new caller assertion'
              : mode === 'remove'
                ? 'Keep caller assertion'
                : 'Discard caller assertion changes'}
          </button>
        ) : null}
        {!secretsWriteAllowed ? (
          <span className="badge neutral">
            Changing the caller assertion needs secrets-write permission
          </span>
        ) : null}
      </div>
    </section>
  );
}

function CallerAssertionEditor({
  draft,
  errors,
  secrets,
  canBindSecret,
  disabled,
  onUpdate,
}: {
  draft: CallerAssertionDraft;
  errors: FieldErrors;
  secrets: ConnectionSecretMetadata[];
  canBindSecret: boolean;
  disabled: boolean;
  onUpdate: (
    update: (draft: CallerAssertionDraft) => CallerAssertionDraft,
  ) => void;
}) {
  const hasKeyAlias = secrets.some(
    (secret) =>
      secret.configured &&
      secret.compatible_purposes.includes('assertion_signing_key'),
  );

  function patchDraft(patch: Partial<CallerAssertionDraft>) {
    onUpdate((current) => ({ ...current, ...patch }));
  }

  function patchSigningKey(
    patch: Partial<Pick<AssertionKeyDraft, 'kid' | 'algorithm' | 'binding'>>,
  ) {
    onUpdate((current) => ({
      ...current,
      signingKey: assertionKeyWithPatch(current.signingKey, patch),
    }));
  }

  function patchPublishedKey(
    index: number,
    patch: Partial<Pick<AssertionKeyDraft, 'kid' | 'algorithm' | 'binding'>>,
  ) {
    onUpdate((current) => ({
      ...current,
      publishedKeys: current.publishedKeys.map((key, position) =>
        position === index ? assertionKeyWithPatch(key, patch) : key,
      ),
    }));
  }

  function toggleClaim(claim: CallerAssertionClaim, included: boolean) {
    onUpdate((current) => ({
      ...current,
      // Appended or removed in place, so the stored order survives.
      claims: included
        ? current.claims.includes(claim)
          ? current.claims
          : [...current.claims, claim]
        : current.claims.filter((existing) => existing !== claim),
    }));
  }

  return (
    <>
      <p className="capability-description">
        Requests this connection makes for a caller carry a JWT naming that
        caller in the assertion header, signed with the signing key. The
        upstream verifies it against{' '}
        <code>/.well-known/caller-assertion-jwks.json</code> and pins the
        issuer, audience, token type and algorithm. A call with no principal
        to name, such as a service token, is refused. Saving an enabled
        connection loads every key, and a key that cannot be used refuses
        the save.
      </p>
      {canBindSecret && !hasKeyAlias ? (
        <div className="alert info" role="status">
          No configured secret alias can hold a signing key. A key must sit
          behind an operator alias or an external secret provider; the
          encrypted local store cannot hold one.
        </div>
      ) : null}
      <div className="filter-grid connection-form-grid">
        <AssertionKeyFields
          idPrefix="connection-caller-assertion"
          secretFieldId="connection-caller-assertion-signing-key"
          keyDraft={draft.signingKey}
          label="Signing key"
          kidError={errors['caller_assertion.kid']}
          secretError={errors['caller_assertion.signing_key_id']}
          secrets={secrets}
          canBindSecret={canBindSecret}
          disabled={disabled}
          onChange={patchSigningKey}
        />
        <AssertionTextField
          id="connection-caller-assertion-issuer"
          label="Issuer (iss)"
          value={draft.issuer}
          placeholder="https://gateway.example"
          error={errors['caller_assertion.issuer']}
          disabled={disabled}
          onChange={(issuer) => patchDraft({ issuer })}
        />
        <AssertionTextField
          id="connection-caller-assertion-audience"
          label="Audience (aud)"
          value={draft.audience}
          placeholder="https://internal.example/api"
          error={errors['caller_assertion.audience']}
          disabled={disabled}
          onChange={(audience) => patchDraft({ audience })}
        />
        <AssertionTextField
          id="connection-caller-assertion-token-type"
          label="Token type (typ)"
          value={draft.tokenType}
          placeholder="caller-assertion+jwt"
          error={errors['caller_assertion.token_type']}
          disabled={disabled}
          onChange={(tokenType) => patchDraft({ tokenType })}
        />
        <AssertionTextField
          id="connection-caller-assertion-header-name"
          label="Assertion header"
          value={draft.headerName}
          maxLength={64}
          error={errors['caller_assertion.header_name']}
          disabled={disabled}
          onChange={(headerName) => patchDraft({ headerName })}
        />
        <FormField
          id="connection-caller-assertion-lifetime"
          label="Lifetime (seconds)"
          error={errors['caller_assertion.lifetime_seconds']}
        >
          <input
            id="connection-caller-assertion-lifetime"
            type="number"
            min={1}
            max={MAX_CALLER_ASSERTION_LIFETIME_SECONDS}
            value={draft.lifetimeSeconds}
            disabled={disabled}
            aria-invalid={Boolean(errors['caller_assertion.lifetime_seconds'])}
            aria-describedby={describedBy(
              'connection-caller-assertion-lifetime',
              errors['caller_assertion.lifetime_seconds'],
            )}
            onChange={(event) =>
              patchDraft({ lifetimeSeconds: event.target.value })
            }
          />
        </FormField>
      </div>
      <fieldset className="connection-caller-assertion-options">
        <legend>Claims beyond sub</legend>
        {(['email', 'roles'] as const).map((claim) => (
          <label className="rule-check-row" key={claim}>
            <input
              type="checkbox"
              id={`connection-caller-assertion-claim-${claim}`}
              checked={draft.claims.includes(claim)}
              disabled={disabled}
              onChange={(event) => toggleClaim(claim, event.target.checked)}
            />
            {claim === 'email'
              ? 'Email (email), advisory: the identity provider may not have verified it'
              : 'Roles (roles)'}
          </label>
        ))}
        <label className="rule-check-row">
          <input
            type="checkbox"
            id="connection-caller-assertion-bind-request"
            checked={draft.bindRequest}
            disabled={disabled}
            onChange={(event) =>
              patchDraft({ bindRequest: event.target.checked })
            }
          />
          Bind the request: method, request target and SHA-256 of the exact
          body sent (bind_request)
        </label>
      </fieldset>
      <div className="section-heading connection-additional-headers-heading">
        <div>
          <h4>Published keys</h4>
          <p className="capability-description">
            Keys the JWKS publishes beside the signing key that never sign:
            the next key, published before it signs, and the previous one,
            kept until what it signed has expired. Make a published key the
            signing key to rotate.
          </p>
        </div>
        <button
          type="button"
          className="secondary-button"
          disabled={
            disabled ||
            draft.publishedKeys.length >= MAX_PUBLISHED_ASSERTION_KEYS
          }
          onClick={() =>
            onUpdate((current) =>
              current.publishedKeys.length >= MAX_PUBLISHED_ASSERTION_KEYS
                ? current
                : {
                  ...current,
                  publishedKeys: [
                    ...current.publishedKeys,
                    emptyAssertionKey(),
                  ],
                },
            )
          }
        >
          Add published key
        </button>
      </div>
      {draft.publishedKeys.length > 0 ? (
        <div className="connection-additional-header-list">
          {draft.publishedKeys.map((key, index) => {
            const number = index + 1;
            return (
              <div
                className="connection-additional-header-row"
                key={key.draftId}
              >
                <div className="filter-grid connection-form-grid">
                  <AssertionKeyFields
                    idPrefix={`connection-caller-assertion-published-key-${index}`}
                    secretFieldId={`connection-caller-assertion-published-key-${index}-secret`}
                    keyDraft={key}
                    label={`Published key ${number}`}
                    kidError={
                      errors[`caller_assertion.published_keys.${index}.kid`]
                    }
                    secretError={
                      errors[
                      `caller_assertion.published_keys.${index}.signing_key_id`
                      ]
                    }
                    secrets={secrets}
                    canBindSecret={canBindSecret}
                    disabled={disabled}
                    onChange={(patch) => patchPublishedKey(index, patch)}
                  />
                </div>
                <div className="form-actions">
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={disabled}
                    onClick={() =>
                      onUpdate((current) =>
                        callerAssertionDraftWithPromotedKey(current, index),
                      )
                    }
                  >
                    Make published key {number} the signing key
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={disabled}
                    onClick={() =>
                      onUpdate((current) => ({
                        ...current,
                        publishedKeys: current.publishedKeys.filter(
                          (_key, position) => position !== index,
                        ),
                      }))
                    }
                  >
                    Remove published key {number}
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="capability-description">No published keys.</p>
      )}
    </>
  );
}

/**
 * One key's `kid`, algorithm and secret alias. The alias picker lists only
 * aliases that can hold an assertion signing key, which leaves out the
 * encrypted local store.
 */
function AssertionKeyFields({
  idPrefix,
  secretFieldId,
  keyDraft,
  label,
  kidError,
  secretError,
  secrets,
  canBindSecret,
  disabled,
  onChange,
}: {
  idPrefix: string;
  secretFieldId: string;
  keyDraft: AssertionKeyDraft;
  label: string;
  kidError?: string;
  secretError?: string;
  secrets: ConnectionSecretMetadata[];
  canBindSecret: boolean;
  disabled: boolean;
  onChange: (
    patch: Partial<Pick<AssertionKeyDraft, 'kid' | 'algorithm' | 'binding'>>,
  ) => void;
}) {
  return (
    <>
      <BindingControl
        id={secretFieldId}
        label={`${label} secret alias`}
        binding={keyDraft.binding}
        purpose="assertion_signing_key"
        secrets={secrets}
        canBindSecret={canBindSecret}
        disabled={disabled}
        error={secretError}
        allowClear={false}
        onChange={(binding) => onChange({ binding })}
      />
      <AssertionTextField
        id={`${idPrefix}-kid`}
        label={`${label} ID (kid)`}
        value={keyDraft.kid}
        error={kidError}
        disabled={disabled}
        onChange={(kid) => onChange({ kid })}
      />
      <label htmlFor={`${idPrefix}-algorithm`}>
        {label} algorithm
        <select
          id={`${idPrefix}-algorithm`}
          value={keyDraft.algorithm}
          disabled={disabled}
          onChange={(event) =>
            onChange({
              algorithm: event.target.value as CallerAssertionAlgorithm,
            })
          }
        >
          <option value="es256">ES256 (P-256 key)</option>
          <option value="rs256">RS256 (RSA key, 2048 bits or more)</option>
        </select>
      </label>
    </>
  );
}

function AssertionTextField({
  id,
  label,
  value,
  placeholder,
  maxLength,
  error,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  placeholder?: string;
  maxLength?: number;
  error?: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <FormField id={id} label={label} error={error}>
      <input
        id={id}
        value={value}
        disabled={disabled}
        placeholder={placeholder}
        maxLength={maxLength}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={Boolean(error)}
        aria-describedby={describedBy(id, error)}
        onChange={(event) => onChange(event.target.value)}
      />
    </FormField>
  );
}

const SUBJECT_TOKEN_CLAIMS: { claim: CallerAssertionClaim; label: string }[] = [
  { claim: 'email', label: 'Email' },
  { claim: 'roles', label: 'Roles' },
];

/**
 * The caller assertion a new delegated issuer token Connection signs its
 * subject tokens with. Shown only while creating one: once the Connection
 * exists the block is read only here (see `CallerAssertionSection`).
 */
export function SubjectTokenSection({
  draft,
  errors,
  canBindSecret,
  secrets,
  disabled,
  onChange,
}: {
  draft: SubjectTokenDraft;
  errors: FieldErrors;
  canBindSecret: boolean;
  secrets: ConnectionSecretMetadata[];
  disabled: boolean;
  onChange: (draft: SubjectTokenDraft) => void;
}) {
  const update = (patch: Partial<SubjectTokenDraft>) =>
    onChange({ ...draft, ...patch });
  const textField = (
    id: string,
    field: string,
    label: string,
    key: 'kid' | 'issuer' | 'audience' | 'tokenType' | 'headerName',
    placeholder: string,
  ) => (
    <FormField id={id} label={label} error={errors[field]}>
      <input
        id={id}
        value={draft[key]}
        disabled={disabled}
        placeholder={placeholder}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={Boolean(errors[field])}
        aria-describedby={describedBy(id, errors[field])}
        onChange={(event) => update({ [key]: event.target.value })}
      />
    </FormField>
  );

  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-subject-token-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Caller attestation</p>
        <h3 id="connection-subject-token-heading">Subject token</h3>
      </div>
      <p className="capability-description">
        The gateway names each caller to the issuer with a short-lived JWT it
        signs with this key: <code>sub</code> is the caller&apos;s identity
        provider issuer, <code>#</code> and subject, with{' '}
        <code>caller_iss</code> and <code>caller_sub</code> beside it. The
        issuer verifies it against{' '}
        <code>/.well-known/caller-assertion-jwks.json</code>, which carries
        the keys of enabled connections only, and pins its issuer, audience
        and token type. Set the audience to the value the issuer expects,
        never an upstream&apos;s, and use one no other connection&apos;s
        caller assertion uses. The token is never sent upstream.
      </p>
      <BindingControl
        id="connection-subject-token-key"
        label="Signing key"
        binding={draft.signingKeyBinding}
        purpose="assertion_signing_key"
        secrets={secrets}
        canBindSecret={canBindSecret}
        disabled={disabled}
        error={errors['caller_assertion.signing_key_id']}
        onChange={(signingKeyBinding) => update({ signingKeyBinding })}
      />
      <p className="capability-description">
        A PKCS#8 private key behind an operator alias or an external secret
        provider: P-256 for ES256, RSA of at least 2048 bits for RS256. An
        enabled save loads it and is refused if it cannot be used. After the
        connection is created, change this block or rotate its key through
        the admin API.
      </p>
      <div className="filter-grid connection-form-grid">
        {textField(
          'connection-subject-token-kid',
          'caller_assertion.kid',
          'Key ID (kid)',
          'kid',
          'gw-2026-10',
        )}
        <label htmlFor="connection-subject-token-algorithm">
          Algorithm
          <select
            id="connection-subject-token-algorithm"
            value={draft.algorithm}
            disabled={disabled}
            onChange={(event) =>
              update({
                algorithm: event.target.value as CallerAssertionAlgorithm,
              })
            }
          >
            <option value="es256">ES256</option>
            <option value="rs256">RS256</option>
          </select>
        </label>
        {textField(
          'connection-subject-token-issuer',
          'caller_assertion.issuer',
          'Issuer (iss)',
          'issuer',
          'https://gateway.example',
        )}
        {textField(
          'connection-subject-token-audience',
          'caller_assertion.audience',
          'Audience (aud)',
          'audience',
          'https://issuer.example',
        )}
        {textField(
          'connection-subject-token-type',
          'caller_assertion.token_type',
          'Token type (typ)',
          'tokenType',
          'caller-assertion+jwt',
        )}
        <FormField
          id="connection-subject-token-lifetime"
          label="Lifetime (seconds)"
          error={errors['caller_assertion.lifetime_seconds']}
        >
          <input
            id="connection-subject-token-lifetime"
            type="number"
            min={1}
            max={MAX_CALLER_ASSERTION_LIFETIME_SECONDS}
            value={draft.lifetimeSeconds}
            disabled={disabled}
            aria-invalid={Boolean(errors['caller_assertion.lifetime_seconds'])}
            aria-describedby={describedBy(
              'connection-subject-token-lifetime',
              errors['caller_assertion.lifetime_seconds'],
            )}
            onChange={(event) =>
              update({ lifetimeSeconds: event.target.value })
            }
          />
        </FormField>
        {textField(
          'connection-subject-token-header',
          'caller_assertion.header_name',
          'Reserved header name',
          'headerName',
          'x-caller-assertion',
        )}
      </div>
      <p className="capability-description">
        The reserved header carries nothing on a delegated connection; the
        gateway only clears it from what a caller sends, so it must differ
        from every other header this connection owns. Lifetime is at most{' '}
        {MAX_CALLER_ASSERTION_LIFETIME_SECONDS} seconds.
      </p>
      <fieldset className="connection-subject-token-claims">
        <legend>Claims beside sub</legend>
        {SUBJECT_TOKEN_CLAIMS.map(({ claim, label }) => (
          <label key={claim}>
            <input
              type="checkbox"
              checked={draft.claims.includes(claim)}
              disabled={disabled}
              onChange={(event) =>
                update({
                  claims: event.target.checked
                    ? SUBJECT_TOKEN_CLAIMS.map((entry) => entry.claim).filter(
                      (entry) => entry === claim || draft.claims.includes(entry),
                    )
                    : draft.claims.filter((entry) => entry !== claim),
                })
              }
            />
            {label}
          </label>
        ))}
      </fieldset>
    </section>
  );
}

export function TlsSection({
  form,
  errors,
  canBindSecret,
  secrets,
  disabled,
  authorityLocked,
  onUpdate,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  canBindSecret: boolean;
  secrets: ConnectionSecretMetadata[];
  disabled: boolean;
  authorityLocked: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
}) {
  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-tls-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Transport</p>
        <h3 id="connection-tls-heading">TLS identity</h3>
      </div>
      <BindingControl
        id="connection-ca-bundle"
        label="Custom CA bundle"
        binding={form.caBundleBinding}
        purpose="tls_ca_bundle"
        secrets={secrets}
        canBindSecret={canBindSecret}
        disabled={disabled || authorityLocked}
        error={errors['tls.ca_bundle_alias']}
        onChange={(caBundleBinding) => onUpdate({ caBundleBinding })}
      />
      <BindingControl
        id="connection-client-certificate"
        label="Client certificate"
        binding={form.clientCertificateBinding}
        purpose="tls_certificate"
        secrets={secrets}
        canBindSecret={canBindSecret}
        disabled={disabled || authorityLocked}
        error={errors['tls.client_certificate_id']}
        onChange={(clientCertificateBinding) =>
          onUpdate({ clientCertificateBinding })
        }
      />
      <BindingControl
        id="connection-client-private-key"
        label="Client private key"
        binding={form.clientPrivateKeyBinding}
        purpose="tls_private_key"
        secrets={secrets}
        canBindSecret={canBindSecret}
        disabled={disabled || authorityLocked}
        error={errors['tls.client_private_key_id']}
        onChange={(clientPrivateKeyBinding) =>
          onUpdate({ clientPrivateKeyBinding })
        }
      />
    </section>
  );
}

export function BindingControl({
  id,
  label,
  binding,
  purpose,
  secrets,
  canBindSecret,
  disabled,
  error,
  allowClear = true,
  onChange,
}: {
  id: string;
  label: string;
  binding: BindingDraft;
  purpose: ConnectionSecretPurpose | null;
  secrets: ConnectionSecretMetadata[];
  canBindSecret: boolean;
  disabled: boolean;
  error?: string;
  // A caller-assertion key cannot be unbound, only replaced or left out.
  allowClear?: boolean;
  onChange: (binding: BindingDraft) => void;
}) {
  const compatibleSecrets =
    purpose === null
      ? []
      : secrets.filter(
        (secret) =>
          secret.configured &&
          secret.compatible_purposes.includes(purpose),
      );
  const selection =
    binding.intent === 'replace'
      ? `secret:${binding.secretId}`
      : `intent:${binding.intent}`;

  return (
    <div className="connection-secret-control">
      <FormField id={id} label={label} error={error}>
        <select
          id={id}
          value={selection}
          disabled={disabled || !canBindSecret}
          aria-invalid={Boolean(error)}
          aria-describedby={describedBy(id, error)}
          onChange={(event) => {
            const value = event.target.value;
            if (value.startsWith('secret:')) {
              onChange({
                configured: binding.configured,
                intent: 'replace',
                secretId: value.slice('secret:'.length),
              });
              return;
            }
            onChange({
              ...binding,
              intent: value.slice('intent:'.length) as BindingIntent,
              secretId: '',
            });
          }}
        >
          {!binding.configured ? (
            <option value="intent:none">Not configured</option>
          ) : null}
          {binding.configured ? (
            <option value="intent:preserve">Keep configured value</option>
          ) : null}
          {compatibleSecrets.map((secret) => (
            <option value={`secret:${secret.id}`} key={secret.id}>
              {secret.label} ({formatSecretProvider(secret.provider)})
            </option>
          ))}
          {binding.configured && allowClear ? (
            <option value="intent:clear">Clear binding</option>
          ) : null}
        </select>
      </FormField>
      {!canBindSecret ? (
        <span className="badge neutral">Secret binding is read only</span>
      ) : null}
    </div>
  );
}

export function LocalSecretManager({
  inventory,
  canBindSecret,
  resetKey,
  contextKey,
  onInventoryChange,
  onBind,
  onDelete,
  onMutatingChange,
  onDraftChange,
  clearDraftRef,
}: {
  inventory: Extract<SecretInventoryState, { kind: 'ready' }>;
  canBindSecret: boolean;
  resetKey: string;
  contextKey: string;
  onInventoryChange: (next: SecretInventoryState) => void;
  onBind: (purpose: ConnectionSecretPurpose, secretId: string) => boolean;
  onDelete: (secretId: string) => void;
  onMutatingChange: (isMutating: boolean) => void;
  onDraftChange: (hasDraft: boolean) => void;
  clearDraftRef: { current: (() => void) | null };
}) {
  const localSecrets = inventory.value.secrets.filter(
    (secret) => secret.provider === 'local_encrypted',
  );
  const canCreate =
    inventory.value.actions.can_create &&
    inventory.value.providers.local_encrypted;
  const [mode, setMode] = useState<'create' | 'manage'>(
    canCreate ? 'create' : 'manage',
  );
  const [purpose, setPurpose] =
    useState<ConnectionSecretPurpose>('static_bearer');
  const [label, setLabel] = useState('');
  const [selectedSecretId, setSelectedSecretId] = useState(
    localSecrets[0]?.id ?? '',
  );
  const [plaintext, setPlaintext] = useState('');
  const plaintextRef = useRef('');
  const operationController = useRef<AbortController | null>(null);
  const [isMutating, setIsMutating] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const deleteButton = useRef<HTMLButtonElement | null>(null);
  const confirmDeleteButton = useRef<HTMLButtonElement | null>(null);
  const restoreDeleteFocus = useRef(false);
  const focusNoticeAfterDelete = useRef(false);
  const [notice, setNotice] = useState<{
    tone: 'success' | 'warning' | 'error';
    title: string;
    message: string;
    conflict?: boolean;
  } | null>(null);
  const noticePanel = useRef<HTMLDivElement | null>(null);

  const selectedSecret =
    inventory.value.secrets.find(
      (secret) => secret.id === selectedSecretId,
    ) ?? null;

  function clearPlaintext() {
    plaintextRef.current = '';
    setPlaintext('');
    onDraftChange(false);
  }

  useEffect(() => {
    clearDraftRef.current = clearPlaintext;
    return () => {
      if (clearDraftRef.current === clearPlaintext) {
        clearDraftRef.current = null;
      }
    };
  });

  useEffect(() => {
    operationController.current?.abort();
    operationController.current = null;
    clearPlaintext();
    setIsMutating(false);
    onMutatingChange(false);
    setConfirmingDelete(false);
    return () => {
      operationController.current?.abort();
      operationController.current = null;
      plaintextRef.current = '';
      onMutatingChange(false);
      onDraftChange(false);
    };
  }, [resetKey]);

  useEffect(() => {
    setNotice(null);
  }, [contextKey]);

  useEffect(() => {
    if (
      notice &&
      (notice.tone !== 'success' || focusNoticeAfterDelete.current)
    ) {
      focusNoticeAfterDelete.current = false;
      queueMicrotask(() => noticePanel.current?.focus());
    }
  }, [notice]);

  useEffect(() => {
    if (confirmingDelete) {
      confirmDeleteButton.current?.focus();
      return;
    }
    if (restoreDeleteFocus.current) {
      restoreDeleteFocus.current = false;
      deleteButton.current?.focus();
    }
  }, [confirmingDelete]);

  useEffect(() => {
    const nextSelectedId = localSecrets[0]?.id ?? '';
    if (
      !inventory.value.secrets.some(
        (secret) => secret.id === selectedSecretId,
      ) &&
      selectedSecretId !== nextSelectedId
    ) {
      setSelectedSecretId(nextSelectedId);
      // Entered material belongs to the selection it was typed against, so a
      // selection that disappears must take the draft with it. On the first
      // load there is no prior selection -- the id moves from empty to the
      // first secret simply because the inventory arrived -- and clearing
      // there discards what the operator typed while the list was still
      // loading, with no stale binding to protect against.
      if (selectedSecretId !== '') {
        clearPlaintext();
      }
    }
  }, [inventory.value.secrets, localSecrets, selectedSecretId]);

  function updatePlaintext(value: string) {
    plaintextRef.current = value;
    setPlaintext(value);
    onDraftChange(value.length > 0);
    setNotice(null);
  }

  function chooseMode(nextMode: 'create' | 'manage') {
    clearPlaintext();
    setMode(nextMode);
    setConfirmingDelete(false);
    setNotice(null);
  }

  function choosePurpose(nextPurpose: ConnectionSecretPurpose) {
    clearPlaintext();
    setPurpose(nextPurpose);
    setNotice(null);
  }

  function chooseSecret(secretId: string) {
    clearPlaintext();
    setSelectedSecretId(secretId);
    setConfirmingDelete(false);
    setNotice(null);
  }

  function cancelDelete() {
    restoreDeleteFocus.current = true;
    setConfirmingDelete(false);
  }

  function beginOperation(): AbortController {
    operationController.current?.abort();
    const controller = new AbortController();
    operationController.current = controller;
    setIsMutating(true);
    onMutatingChange(true);
    return controller;
  }

  function finishOperation(controller: AbortController) {
    if (operationController.current === controller) {
      operationController.current = null;
    }
    if (!controller.signal.aborted) {
      setIsMutating(false);
      onMutatingChange(false);
      clearPlaintext();
    } else {
      plaintextRef.current = '';
    }
  }

  async function createLocalSecret() {
    const normalizedLabel = label.trim();
    if (
      !canCreate ||
      isMutating ||
      normalizedLabel.length === 0 ||
      plaintextRef.current.length === 0
    ) {
      setNotice({
        tone: 'warning',
        title: 'Secret details required',
        message: 'Enter a safe label and secret value before creating it.',
      });
      return;
    }

    let submittedPlaintext = plaintextRef.current;
    clearPlaintext();
    const controller = beginOperation();
    setNotice(null);
    try {
      const resource = await createConnectionSecret(
        {
          label: normalizedLabel,
          purpose,
          value: submittedPlaintext,
        },
        inventory.collectionEtag,
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }
      const created = resource.value;
      if (resource.collectionEtag === null) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      onInventoryChange({
        kind: 'ready',
        value: {
          ...inventory.value,
          secrets: [
            created,
            ...inventory.value.secrets.filter(
              (secret) => secret.id !== created.id,
            ),
          ],
        },
        collectionEtag: resource.collectionEtag,
      });
      // `canBindSecret` only says the operator may bind; whether this secret's
      // purpose matches a field on the draft is a separate question, and the
      // notice has to answer the one that actually happened. The purpose
      // selector defaults to `static_bearer` regardless of the connection's
      // authentication type, so a mismatch is the default state for a
      // header-API-key or OAuth connection rather than an edge case.
      const bound = canBindSecret && onBind(purpose, created.id);
      setSelectedSecretId(created.id);
      setLabel('');
      setMode('manage');
      setNotice({
        tone: bound || !canBindSecret ? 'success' : 'warning',
        title: 'Local secret created',
        message: bound
          ? 'The value was accepted, selected for this draft, and cleared from this page. It cannot be revealed again.'
          : canBindSecret
            ? `The value was accepted and cleared from this page, but nothing on this form takes a ${formatSecretPurpose(purpose)} secret, so it was not selected. Choose a matching purpose, or bind it from the field that needs it.`
            : 'The value was accepted and cleared from this page. It cannot be revealed again.',
      });
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (
        secretErrorRequiresReload(error)
      ) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      setNotice(secretMutationError(error, 'create'));
    } finally {
      submittedPlaintext = '';
      finishOperation(controller);
    }
  }

  async function rotateLocalSecret() {
    if (
      selectedSecret === null ||
      !selectedSecret.actions.can_rotate ||
      isMutating ||
      plaintextRef.current.length === 0
    ) {
      setNotice({
        tone: 'warning',
        title: 'New secret value required',
        message: 'Enter a new value for a rotatable local secret.',
      });
      return;
    }
    const rotationPurpose = selectedSecret.compatible_purposes[0];
    const previousVersion = selectedSecret.version;
    if (
      rotationPurpose === undefined ||
      previousVersion === undefined
    ) {
      clearPlaintext();
      onInventoryChange(secretMutationReloadRequired());
      return;
    }

    let submittedPlaintext = plaintextRef.current;
    clearPlaintext();
    const controller = beginOperation();
    setNotice(null);
    try {
      const resource = await rotateConnectionSecret(
        selectedSecret.id,
        {
          purpose: rotationPurpose,
          value: submittedPlaintext,
        },
        selectedSecret.etag,
        inventory.collectionEtag,
        previousVersion,
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }
      const rotated = resource.value;
      if (resource.collectionEtag === null) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      onInventoryChange({
        kind: 'ready',
        value: {
          ...inventory.value,
          secrets: inventory.value.secrets.map((secret) =>
            secret.id === rotated.id ? rotated : secret,
          ),
        },
        collectionEtag: resource.collectionEtag,
      });
      setNotice({
        tone: 'success',
        title: 'Local secret rotated',
        message:
          'The replacement value was accepted and cleared from this page.',
      });
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (
        secretErrorRequiresReload(error)
      ) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      setNotice(secretMutationError(error, 'rotate'));
    } finally {
      submittedPlaintext = '';
      finishOperation(controller);
    }
  }

  async function deleteLocalSecret() {
    if (
      selectedSecret === null ||
      !selectedSecret.actions.can_delete ||
      !confirmingDelete ||
      isMutating
    ) {
      return;
    }

    clearPlaintext();
    const controller = beginOperation();
    setNotice(null);
    try {
      const resource = await deleteConnectionSecret(
        selectedSecret.id,
        selectedSecret.etag,
        inventory.collectionEtag,
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }
      if (resource.collectionEtag === null) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      onInventoryChange({
        kind: 'ready',
        value: {
          ...inventory.value,
          secrets: inventory.value.secrets.filter(
            (secret) => secret.id !== selectedSecret.id,
          ),
        },
        collectionEtag: resource.collectionEtag,
      });
      onDelete(selectedSecret.id);
      const remainingLocalSecrets = inventory.value.secrets.filter(
        (secret) =>
          secret.id !== selectedSecret.id &&
          secret.provider === 'local_encrypted',
      );
      setSelectedSecretId(remainingLocalSecrets[0]?.id ?? '');
      setConfirmingDelete(false);
      focusNoticeAfterDelete.current = true;
      setNotice({
        tone: 'success',
        title: 'Local secret deleted',
        message: 'The encrypted local secret was removed.',
      });
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (
        secretErrorRequiresReload(error)
      ) {
        onInventoryChange(secretMutationReloadRequired());
        return;
      }
      setNotice(secretMutationError(error, 'delete'));
    } finally {
      finishOperation(controller);
    }
  }

  async function reloadSecrets() {
    clearPlaintext();
    const controller = beginOperation();
    try {
      const resource = await listConnectionSecrets(controller.signal);
      if (controller.signal.aborted) {
        return;
      }
      const nextEtag = resource.collectionEtag;
      if (nextEtag === null) {
        throw new Error('Secret collection ETag missing.');
      }
      onInventoryChange({
        kind: 'ready',
        value: resource.value,
        collectionEtag: nextEtag,
      });
      setNotice(null);
    } catch {
      if (controller.signal.aborted) {
        return;
      }
      setNotice({
        tone: 'error',
        title: 'Secret inventory reload failed',
        message: 'Reload the connection editor before retrying.',
      });
    } finally {
      finishOperation(controller);
    }
  }

  if (!inventory.value.providers.local_encrypted && localSecrets.length === 0) {
    return (
      <section
        className="connection-form-section"
        aria-labelledby="local-secret-heading"
      >
        <div className="section-heading">
          <p className="eyebrow">Secret lifecycle</p>
          <h3 id="local-secret-heading">Local encrypted secrets</h3>
        </div>
        <div className="alert info" role="status">
          Local encrypted secret mutations are unavailable. Configured operator
          aliases can still be selected above when compatible.
        </div>
      </section>
    );
  }

  return (
    <section
      className="connection-form-section"
      aria-labelledby="local-secret-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Secret lifecycle</p>
        <h3 id="local-secret-heading">Local encrypted secrets</h3>
      </div>
      <p>
        Values are sent once to encrypted local storage. They are never returned
        by the gateway, saved in the browser, or added to the URL.
      </p>
      <label htmlFor="local-secret-mode">
        Operation
        <select
          id="local-secret-mode"
          value={mode}
          disabled={isMutating}
          onChange={(event) =>
            chooseMode(event.target.value as 'create' | 'manage')
          }
        >
          {canCreate ? <option value="create">Create local secret</option> : null}
          <option value="manage">Rotate or delete local secret</option>
        </select>
      </label>

      {mode === 'create' && canCreate ? (
        <div className="filter-grid connection-form-grid">
          <label htmlFor="local-secret-label">
            Safe label
            <input
              id="local-secret-label"
              value={label}
              maxLength={128}
              disabled={isMutating}
              autoComplete="off"
              onChange={(event) => setLabel(event.target.value)}
            />
          </label>
          <label htmlFor="local-secret-purpose">
            Purpose
            <select
              id="local-secret-purpose"
              value={purpose}
              disabled={isMutating}
              onChange={(event) =>
                choosePurpose(
                  event.target.value as ConnectionSecretPurpose,
                )
              }
            >
              {ALL_SECRET_PURPOSES.map((candidate) => (
                <option value={candidate} key={candidate}>
                  {formatSecretPurpose(candidate)}
                </option>
              ))}
            </select>
          </label>
          <SecretPlaintextInput
            id="local-secret-create-value"
            label="Secret value"
            value={plaintext}
            maxLength={secretMaxLength(purpose)}
            multiline={isTlsSecretPurpose(purpose)}
            disabled={isMutating}
            onChange={updatePlaintext}
          />
          <div className="form-actions">
            <button
              type="button"
              className="primary-button"
              disabled={
                isMutating ||
                label.trim().length === 0 ||
                plaintext.length === 0
              }
              onClick={() => {
                void createLocalSecret();
              }}
            >
              {isMutating
                ? 'Creating'
                : canBindSecret
                  ? 'Create and select'
                  : 'Create local secret'}
            </button>
          </div>
        </div>
      ) : null}

      {mode === 'manage' ? (
        <div className="filter-grid connection-form-grid">
          <label htmlFor="local-secret-selection">
            Local secret
            <select
              id="local-secret-selection"
              value={selectedSecretId}
              disabled={isMutating || localSecrets.length === 0}
              onChange={(event) => chooseSecret(event.target.value)}
            >
              {localSecrets.length === 0 ? (
                <option value="">No local secrets</option>
              ) : null}
              {localSecrets.map((secret) => (
                <option value={secret.id} key={secret.id}>
                  {secret.label} ({formatSecretPurpose(
                    secret.compatible_purposes[0],
                  )})
                </option>
              ))}
            </select>
          </label>
          {selectedSecret?.actions.can_rotate ? (
            <SecretPlaintextInput
              id="local-secret-rotate-value"
              label="New secret value"
              value={plaintext}
              maxLength={secretMaxLength(
                selectedSecret.compatible_purposes[0],
              )}
              multiline={isTlsSecretPurpose(
                selectedSecret.compatible_purposes[0],
              )}
              disabled={isMutating}
              onChange={updatePlaintext}
            />
          ) : null}
          <div
            className="form-actions"
            onKeyDown={(event) => {
              if (confirmingDelete && event.key === 'Escape') {
                event.preventDefault();
                event.stopPropagation();
                cancelDelete();
              }
            }}
          >
            {selectedSecret?.actions.can_rotate ? (
              <button
                type="button"
                className="primary-button"
                disabled={isMutating || plaintext.length === 0}
                onClick={() => {
                  void rotateLocalSecret();
                }}
              >
                {isMutating ? 'Rotating' : 'Rotate'}
              </button>
            ) : null}
            {selectedSecret?.actions.can_delete ? (
              confirmingDelete ? (
                <>
                  <button
                    type="button"
                    className="rule-danger-button"
                    ref={confirmDeleteButton}
                    aria-label={`Confirm delete ${selectedSecret.label} (${selectedSecret.id})`}
                    disabled={isMutating}
                    onClick={() => {
                      void deleteLocalSecret();
                    }}
                  >
                    Confirm delete
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    aria-label={`Cancel delete ${selectedSecret.label} (${selectedSecret.id})`}
                    disabled={isMutating}
                    onClick={cancelDelete}
                  >
                    Cancel delete
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="secondary-button"
                  ref={deleteButton}
                  disabled={isMutating}
                  onClick={() => {
                    clearPlaintext();
                    setConfirmingDelete(true);
                  }}
                >
                  Delete
                </button>
              )
            ) : null}
          </div>
          {selectedSecret && !selectedSecret.actions.can_delete ? (
            <span className="badge neutral">
              {selectedSecret.dependency_count > 0
                ? `In use by ${selectedSecret.dependency_count} connection dependencies`
                : 'Delete not authorized'}
            </span>
          ) : null}
        </div>
      ) : null}

      {notice ? (
        <div
          className={`error-panel alert ${notice.tone}`}
          role={notice.tone === 'success' ? 'status' : 'alert'}
          tabIndex={-1}
          ref={noticePanel}
        >
          <h3>{notice.title}</h3>
          <p>{notice.message}</p>
          {notice.conflict ? (
            <button
              type="button"
              className="secondary-button"
              disabled={isMutating}
              onClick={() => {
                void reloadSecrets();
              }}
            >
              Reload secret inventory
            </button>
          ) : null}
        </div>
      ) : null}
      <div className="connection-live-region" aria-live="polite">
        {isMutating ? 'Updating encrypted local secret' : ''}
      </div>
    </section>
  );
}

export function SecretPlaintextInput({
  id,
  label,
  value,
  maxLength,
  multiline,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  maxLength: number;
  multiline: boolean;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label htmlFor={id}>
      {label}
      {multiline ? (
        <textarea
          id={id}
          value={value}
          maxLength={maxLength}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          id={id}
          type="password"
          value={value}
          maxLength={maxLength}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              event.stopPropagation();
            }
          }}
        />
      )}
    </label>
  );
}

export function TimeoutsAndDiscoverySection({
  form,
  errors,
  disabled,
  discoveryTargetDisabled,
  discoveryAuthenticationDisabled,
  onUpdate,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  disabled: boolean;
  discoveryTargetDisabled: boolean;
  discoveryAuthenticationDisabled: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
}) {
  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-discovery-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Behavior</p>
        <h3 id="connection-discovery-heading">Timeouts and discovery</h3>
      </div>
      <label className="rule-check-row">
        <input
          type="checkbox"
          checked={form.customTimeouts}
          disabled={disabled}
          onChange={(event) =>
            onUpdate({ customTimeouts: event.target.checked })
          }
        />
        Override default timeouts
      </label>
      {form.customTimeouts ? (
        <div className="filter-grid connection-form-grid">
          <NumberField
            id="connection-connect-timeout"
            label="Connect timeout (ms)"
            value={form.connectTimeoutMs}
            error={errors['timeouts.connect_timeout_ms']}
            disabled={disabled}
            onChange={(connectTimeoutMs) => onUpdate({ connectTimeoutMs })}
          />
          <NumberField
            id="connection-request-timeout"
            label="Request timeout (ms)"
            value={form.requestTimeoutMs}
            error={errors['timeouts.request_timeout_ms']}
            disabled={disabled}
            onChange={(requestTimeoutMs) => onUpdate({ requestTimeoutMs })}
          />
          <NumberField
            id="connection-idle-timeout"
            label="Response idle timeout (ms)"
            value={form.responseIdleTimeoutMs}
            error={errors['timeouts.response_idle_timeout_ms']}
            disabled={disabled}
            onChange={(responseIdleTimeoutMs) =>
              onUpdate({ responseIdleTimeoutMs })
            }
          />
        </div>
      ) : null}
      <div className="filter-grid connection-form-grid">
        <label htmlFor="connection-discovery-type">
          Discovery profile
          <select
            id="connection-discovery-type"
            value={form.discoveryType}
            disabled={discoveryTargetDisabled}
            onChange={(event) =>
              onUpdate({
                discoveryType: event.target.value as DiscoveryType,
              })
            }
          >
            {form.kind === 'http_api' ? (
              <>
                <option value="none">None</option>
                <option value="managed_openapi">Managed OpenAPI</option>
              </>
            ) : (
              <>
                <option value="none">None</option>
                <option value="managed_mcp">Managed MCP</option>
              </>
            )}
          </select>
        </label>
        {form.discoveryType === 'managed_openapi' ? (
          <FormField
            id="connection-discovery-path"
            label="OpenAPI document path"
            error={errors['discovery.path']}
          >
            <input
              id="connection-discovery-path"
              value={form.discoveryPath}
              disabled={discoveryTargetDisabled}
              placeholder="/openapi.json"
              spellCheck={false}
              aria-invalid={Boolean(errors['discovery.path'])}
              aria-describedby={describedBy(
                'connection-discovery-path',
                errors['discovery.path'],
              )}
              onChange={(event) =>
                onUpdate({ discoveryPath: event.target.value })
              }
            />
          </FormField>
        ) : null}
      </div>
      {form.discoveryType !== 'none' ? (
        <label className="rule-check-row">
          <input
            type="checkbox"
            checked={form.discoveryUsesAuthentication}
            disabled={discoveryAuthenticationDisabled}
            onChange={(event) =>
              onUpdate({
                discoveryUsesAuthentication: event.target.checked,
              })
            }
          />
          Use this connection&apos;s authentication for discovery
        </label>
      ) : null}
    </section>
  );
}

export function TestProfileSection({
  form,
  errors,
  disabled,
  targetDisabled,
  onUpdate,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  disabled: boolean;
  targetDisabled: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
}) {
  if (form.kind !== 'http_api') {
    return null;
  }

  return (
    <section
      className="connection-form-section"
      aria-labelledby="connection-test-profile-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Verification</p>
        <h3 id="connection-test-profile-heading">Test profile</h3>
      </div>
      <label className="rule-check-row">
        <input
          type="checkbox"
          checked={form.testProfileEnabled}
          disabled={targetDisabled}
          onChange={(event) =>
            onUpdate({ testProfileEnabled: event.target.checked })
          }
        />
        Configure a safe HTTP test request
      </label>
      {form.testProfileEnabled ? (
        <div className="filter-grid connection-form-grid">
          <label htmlFor="connection-test-method">
            Method
            <select
              id="connection-test-method"
              value={form.testMethod}
              disabled={targetDisabled}
              onChange={(event) =>
                onUpdate({ testMethod: event.target.value as 'GET' | 'HEAD' })
              }
            >
              <option value="GET">GET</option>
              <option value="HEAD">HEAD</option>
            </select>
          </label>
          <FormField
            id="connection-test-path"
            label="Path"
            error={errors['test_profile.path']}
          >
            <input
              id="connection-test-path"
              value={form.testPath}
              disabled={targetDisabled}
              spellCheck={false}
              aria-invalid={Boolean(errors['test_profile.path'])}
              aria-describedby={describedBy(
                'connection-test-path',
                errors['test_profile.path'],
              )}
              onChange={(event) => onUpdate({ testPath: event.target.value })}
            />
          </FormField>
          <FormField
            id="connection-expected-statuses"
            label="Expected statuses"
            error={errors['test_profile.expected_statuses']}
          >
            <input
              id="connection-expected-statuses"
              value={form.expectedStatuses}
              disabled={disabled}
              placeholder="200, 204"
              inputMode="numeric"
              aria-invalid={Boolean(errors['test_profile.expected_statuses'])}
              aria-describedby={describedBy(
                'connection-expected-statuses',
                errors['test_profile.expected_statuses'],
              )}
              onChange={(event) =>
                onUpdate({ expectedStatuses: event.target.value })
              }
            />
          </FormField>
        </div>
      ) : null}
    </section>
  );
}

export function NumberField({
  id,
  label,
  value,
  error,
  disabled,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  error?: string;
  disabled: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <FormField id={id} label={label} error={error}>
      <input
        id={id}
        type="number"
        min={1}
        max={120000}
        value={value}
        disabled={disabled}
        aria-invalid={Boolean(error)}
        aria-describedby={describedBy(id, error)}
        onChange={(event) => onChange(event.target.value)}
      />
    </FormField>
  );
}

export function FormField({
  id,
  label,
  error,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  children: React.ReactNode;
}) {
  return (
    <label htmlFor={id}>
      {label}
      {children}
      {error ? (
        <span className="field-error" id={`${id}-error`}>
          {error}
        </span>
      ) : null}
    </label>
  );
}

export function EditorAlert({
  title,
  message,
  tone,
}: {
  title: string;
  message: string;
  tone: 'warning' | 'error' | 'info';
}) {
  return (
    <div className={`error-panel alert ${tone}`} role="alert">
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}
