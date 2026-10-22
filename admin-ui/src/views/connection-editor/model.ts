
import { AdminApiError } from '../../lib/api';
import {
  MAX_PUBLISHED_ASSERTION_KEYS,
  type CallerAssertionAlgorithm,
  type CallerAssertionClaim,
  type CallerAssertionKeyBinding,
  type CallerAssertionWrite,
  type ConnectionAuthentication,
  type ConnectionCreateWrite,
  type ConnectionDetail,
  type ConnectionKind,
  type ConnectionWrite,
  type SafeCallerAssertion,
  type TlsProfile
} from '../../lib/connections';
import {
  ConnectionSecretContractError,
  type ConnectionSecretListResponse,
  type ConnectionSecretMetadata,
  type ConnectionSecretPurpose
} from '../../lib/secrets';

export type AuthenticationType = ConnectionAuthentication['type'];
export type DiscoveryType = 'none' | 'managed_openapi' | 'managed_mcp';
export type BindingIntent = 'none' | 'preserve' | 'clear' | 'replace';

export type BindingDraft = {
  configured: boolean;
  intent: BindingIntent;
  secretId: string;
};

export type AdditionalHeaderDraft = {
  draftId: number;
  headerName: string;
  initialHeaderName?: string;
  initiallyConfigured: boolean;
  binding: BindingDraft;
};

/**
 * The caller assertion a new delegated issuer token Connection signs its
 * subject tokens with. Written only when the editor creates the Connection;
 * see `createWriteFromForm`.
 */
export type SubjectTokenDraft = {
  signingKeyBinding: BindingDraft;
  kid: string;
  algorithm: CallerAssertionAlgorithm;
  issuer: string;
  audience: string;
  tokenType: string;
  headerName: string;
  lifetimeSeconds: string;
  claims: CallerAssertionClaim[];
};

/**
 * What a save does with the caller assertion. `keep` leaves the block out of
 * the write, so the gateway keeps the stored block exactly as it is (or, with
 * none stored, adds none); `edit` writes `callerAssertionDraft` in full; and
 * `remove` writes `null`, which removes the stored block.
 */
export type CallerAssertionMode = 'keep' | 'edit' | 'remove';

/** The signing key or one published key of a caller assertion being edited. */
export type AssertionKeyDraft = {
  draftId: number;
  kid: string;
  algorithm: CallerAssertionAlgorithm;
  /**
   * The stored key this draft was loaded as. A kept binding is sent as a
   * marker, and the gateway keeps the alias of the stored key with the same
   * `kid` and algorithm, so changing either drops the kept binding and
   * changing both back restores it.
   */
  stored?: {
    kid: string;
    algorithm: CallerAssertionAlgorithm;
    configured: boolean;
  };
  binding: BindingDraft;
};

export type CallerAssertionDraft = {
  signingKey: AssertionKeyDraft;
  issuer: string;
  audience: string;
  tokenType: string;
  headerName: string;
  lifetimeSeconds: string;
  // In the stored order, so an unchanged block writes back identical.
  claims: CallerAssertionClaim[];
  bindRequest: boolean;
  publishedKeys: AssertionKeyDraft[];
};

export type ConnectionFormState = {
  displayName: string;
  description: string;
  enabled: boolean;
  enableConfirmed: boolean;
  initiallyEnabled: boolean;
  kind: ConnectionKind;
  baseUrl: string;
  basePath: string;
  authenticationType: AuthenticationType;
  initialAuthenticationType: AuthenticationType;
  headerName: string;
  // Shared by OAuth client credentials and the delegated issuer token, whose
  // token requests take the same client ID, scope, audience and resource.
  clientId: string;
  tokenUrl: string;
  tokenExchangeUrl: string;
  // A delegated issuer token's optional RFC 7009 endpoint.
  revocationUrl: string;
  scopes: string;
  audience: string;
  resource: string;
  authenticationBinding: BindingDraft;
  additionalHeaders: AdditionalHeaderDraft[];
  // The block as stored, shown read only unless `callerAssertionMode` is
  // `edit`.
  callerAssertion: SafeCallerAssertion | null;
  callerAssertionMode: CallerAssertionMode;
  // Written only in `edit` mode; see `writeFromForm`.
  callerAssertionDraft: CallerAssertionDraft;
  // A new delegated Connection's block, used only while `callerAssertion` is
  // null; see `subjectTokenDraftApplies`.
  subjectToken: SubjectTokenDraft;
  caBundleBinding: BindingDraft;
  clientCertificateBinding: BindingDraft;
  clientPrivateKeyBinding: BindingDraft;
  customTimeouts: boolean;
  connectTimeoutMs: string;
  requestTimeoutMs: string;
  responseIdleTimeoutMs: string;
  discoveryType: DiscoveryType;
  discoveryPath: string;
  discoveryUsesAuthentication: boolean;
  testProfileEnabled: boolean;
  testMethod: 'GET' | 'HEAD';
  testPath: string;
  expectedStatuses: string;
};

export type EditorLoadState =
  | { kind: 'loading' }
  | {
    kind: 'ready';
    detail: ConnectionDetail | null;
    canCreate: boolean;
    canBindSecret: boolean;
    canManageSecrets: boolean;
  }
  | {
    kind: 'error';
    title: string;
    message: string;
    tone: 'warning' | 'error';
  };

export type SaveState =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'saved'; message: string }
  | {
    kind: 'error';
    title: string;
    message: string;
    tone: 'warning' | 'error';
    conflict: boolean;
    recovery?: 'reload' | 'connections';
  };

export type FieldErrors = Record<string, string>;

export type SecretInventoryState =
  | { kind: 'idle' | 'loading' }
  | {
    kind: 'ready';
    value: ConnectionSecretListResponse;
    collectionEtag: string;
  }
  | {
    kind: 'error';
    title: string;
    message: string;
    tone: 'warning' | 'error';
  };

// Declared before `DEFAULT_FORM`, whose draft takes the first ID.
let nextAssertionKeyDraftId = 1;

export const DEFAULT_FORM: ConnectionFormState = {
  displayName: '',
  description: '',
  enabled: false,
  enableConfirmed: false,
  initiallyEnabled: false,
  kind: 'http_api',
  baseUrl: '',
  basePath: '/',
  authenticationType: 'none',
  initialAuthenticationType: 'none',
  headerName: 'X-API-Key',
  clientId: '',
  tokenUrl: '',
  tokenExchangeUrl: '',
  revocationUrl: '',
  scopes: '',
  audience: '',
  resource: '',
  authenticationBinding: emptyBinding(),
  additionalHeaders: [],
  callerAssertion: null,
  callerAssertionMode: 'keep',
  callerAssertionDraft: newCallerAssertionDraft(),
  subjectToken: {
    signingKeyBinding: emptyBinding(),
    kid: '',
    algorithm: 'es256',
    issuer: '',
    audience: '',
    tokenType: '',
    // Never sent upstream by a delegated Connection; the gateway still needs
    // a valid name, which it clears from anything a caller sends.
    headerName: 'x-caller-assertion',
    lifetimeSeconds: '60',
    claims: [],
  },
  caBundleBinding: emptyBinding(),
  clientCertificateBinding: emptyBinding(),
  clientPrivateKeyBinding: emptyBinding(),
  customTimeouts: false,
  connectTimeoutMs: '10000',
  requestTimeoutMs: '30000',
  responseIdleTimeoutMs: '30000',
  discoveryType: 'none',
  discoveryPath: '',
  discoveryUsesAuthentication: false,
  testProfileEnabled: false,
  testMethod: 'GET',
  testPath: '/',
  expectedStatuses: '200',
};

export const MAX_ADDITIONAL_HEADERS = 4;
export let nextAdditionalHeaderDraftId = 1;

export const ALL_SECRET_PURPOSES: ConnectionSecretPurpose[] = [
  'header_api_key',
  'static_bearer',
  'oauth_client_secret',
  'tls_ca_bundle',
  'tls_certificate',
  'tls_private_key',
];

// The gateway's bounds on a caller assertion's fields.
export const MAX_CALLER_ASSERTION_LIFETIME_SECONDS = 300;
const MAX_ASSERTION_KID_BYTES = 128;
const MAX_ASSERTION_ISSUER_AUDIENCE_BYTES = 512;
const MAX_ASSERTION_TOKEN_TYPE_BYTES = 128;

/**
 * Whether the authentication type of this form is fixed. A stored delegated
 * issuer token Connection keeps its type: its caller assertion stays through
 * every save, and under any other type the gateway would start sending that
 * subject-token assertion upstream on every call.
 */
export function authenticationTypeLocked(form: ConnectionFormState): boolean {
  return form.initialAuthenticationType === 'delegated_issuer_token';
}

/**
 * Whether the delegated issuer token is offered: when creating a Connection,
 * and on a stored one that already uses it. The editor drafts the subject
 * token only on a create, so an existing Connection cannot turn a caller
 * assertion it already has, whose audience names its upstream, into a
 * subject token, nor gain one through this credential.
 */
export function delegatedIssuerTokenOffered(
  form: ConnectionFormState,
  creating: boolean,
): boolean {
  return creating || authenticationTypeLocked(form);
}

/**
 * Whether a save writes `form.subjectToken`: a delegated issuer token with no
 * stored caller assertion, which only a create can be.
 */
export function subjectTokenDraftApplies(form: ConnectionFormState): boolean {
  return (
    form.authenticationType === 'delegated_issuer_token' &&
    form.callerAssertion === null
  );
}

/**
 * Why the editor cannot open `detail`, or `null` when it can.
 *
 * A Google domain-wide delegation is shown read only: the editor has no form
 * for it, and saving through a form that cannot represent it would replace
 * the credential with whichever type the form defaulted to.
 */
export function editorUnsupportedReason(
  detail: ConnectionDetail,
): string | null {
  if (
    detail.configuration?.authentication.type ===
    'google_domain_wide_delegation'
  ) {
    return 'This connection uses Google domain-wide delegation, which the editor cannot change yet. Change it through the admin API.';
  }
  return null;
}

export function formFromDetail(detail: ConnectionDetail): ConnectionFormState {
  const configuration = detail.configuration;
  if (configuration === undefined) {
    return {
      ...DEFAULT_FORM,
      displayName: detail.display_name,
      enabled: detail.enabled,
      initiallyEnabled: detail.enabled,
      kind: detail.kind,
    };
  }

  const authentication = configuration.authentication;
  if (authentication.type === 'google_domain_wide_delegation') {
    // The editor refuses such a connection before it builds a form; see
    // `editorUnsupportedReason`.
    throw new Error(editorUnsupportedReason(detail) ?? 'Unsupported connection');
  }
  const authenticationConfigured =
    authentication.type === 'header_api_key' ||
      authentication.type === 'static_bearer'
      ? authentication.secret_configured
      : authentication.type === 'oauth2_client_credentials' ||
        authentication.type === 'delegated_issuer_token'
        ? authentication.client_secret_configured
        : false;
  const tokenRequest =
    authentication.type === 'oauth2_client_credentials'
      ? {
        clientId: authentication.client_id,
        scopes: authentication.scopes,
        audience: authentication.audience,
        resource: authentication.resource,
      }
      : authentication.type === 'delegated_issuer_token'
        ? {
          clientId: authentication.client_id,
          scopes: authentication.requested_scopes,
          audience: authentication.audience,
          resource: authentication.resource,
        }
        : null;
  const timeouts = configuration.timeouts;
  const discovery = configuration.discovery;
  const testProfile = configuration.test_profile;

  return {
    displayName: detail.display_name,
    description: configuration.description ?? '',
    enabled: detail.enabled,
    enableConfirmed: false,
    initiallyEnabled: detail.enabled,
    kind: detail.kind,
    baseUrl: configuration.endpoint.base_url,
    basePath: configuration.endpoint.base_path,
    authenticationType: authentication.type,
    initialAuthenticationType: authentication.type,
    headerName:
      authentication.type === 'header_api_key'
        ? authentication.header_name
        : 'X-API-Key',
    clientId: tokenRequest?.clientId ?? '',
    tokenUrl:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.token_url
        : '',
    tokenExchangeUrl:
      authentication.type === 'delegated_issuer_token'
        ? authentication.token_exchange_url
        : '',
    revocationUrl:
      authentication.type === 'delegated_issuer_token'
        ? authentication.revocation_url ?? ''
        : '',
    scopes: tokenRequest?.scopes.join(' ') ?? '',
    audience: tokenRequest?.audience ?? '',
    resource: tokenRequest?.resource ?? '',
    authenticationBinding: authenticationConfigured
      ? configuredBinding()
      : emptyBinding(),
    additionalHeaders: (configuration.additional_headers ?? []).map(
      (header) => ({
        draftId: nextAdditionalHeaderDraftId++,
        headerName: header.header_name,
        initialHeaderName: header.header_name,
        initiallyConfigured: header.secret_configured,
        binding: bindingFromMarker(header.secret_configured),
      }),
    ),
    callerAssertion: configuration.caller_assertion ?? null,
    callerAssertionMode: 'keep',
    callerAssertionDraft: newCallerAssertionDraft(),
    subjectToken: DEFAULT_FORM.subjectToken,
    caBundleBinding: bindingFromMarker(
      configuration.tls.ca_bundle_configured,
    ),
    clientCertificateBinding: bindingFromMarker(
      configuration.tls.client_certificate_configured,
    ),
    clientPrivateKeyBinding: bindingFromMarker(
      configuration.tls.client_private_key_configured,
    ),
    customTimeouts: timeouts !== undefined,
    connectTimeoutMs: String(timeouts?.connect_timeout_ms ?? 10000),
    requestTimeoutMs: String(timeouts?.request_timeout_ms ?? 30000),
    responseIdleTimeoutMs: String(
      timeouts?.response_idle_timeout_ms ?? 30000,
    ),
    discoveryType: discovery?.type ?? 'none',
    discoveryPath:
      discovery?.type === 'managed_openapi' ? discovery.path ?? '' : '',
    discoveryUsesAuthentication:
      discovery?.use_connection_authentication ?? false,
    testProfileEnabled: testProfile !== undefined,
    testMethod: testProfile?.method === 'HEAD' ? 'HEAD' : 'GET',
    testPath: testProfile?.path ?? '/',
    expectedStatuses: (testProfile?.expected_statuses ?? [200]).join(', '),
  };
}

export function detailConfiguresCredentialAuthority(
  detail: ConnectionDetail | null,
): boolean {
  const configuration = detail?.configuration;
  if (configuration === undefined) {
    return false;
  }
  const authenticationConfigured =
    configuration.authentication.type !== 'none';
  // A caller assertion binds private keys, so the gateway treats it as
  // credential authority too: changing the endpoint or test target of a
  // Connection that carries one needs the secrets-write permission.
  return (
    authenticationConfigured ||
    (configuration.additional_headers?.length ?? 0) > 0 ||
    configuration.caller_assertion !== undefined ||
    configuration.tls.ca_bundle_configured ||
    configuration.tls.client_certificate_configured ||
    configuration.tls.client_private_key_configured
  );
}

export function writeFromForm(form: ConnectionFormState): ConnectionWrite {
  const authentication = authenticationFromForm(form);
  const tls: TlsProfile = {
    ...bindingPayload(
      form.caBundleBinding,
      'ca_bundle_alias',
      'ca_bundle_configured',
    ),
    ...bindingPayload(
      form.clientCertificateBinding,
      'client_certificate_id',
      'client_certificate_configured',
    ),
    ...bindingPayload(
      form.clientPrivateKeyBinding,
      'client_private_key_id',
      'client_private_key_configured',
    ),
  };
  const description = form.description.trim();
  const discovery =
    form.discoveryType === 'managed_openapi'
      ? {
        type: 'managed_openapi' as const,
        ...(form.discoveryPath.trim()
          ? { path: form.discoveryPath.trim() }
          : {}),
        use_connection_authentication:
          form.discoveryUsesAuthentication,
      }
      : form.discoveryType === 'managed_mcp'
        ? {
          type: 'managed_mcp' as const,
          use_connection_authentication:
            form.discoveryUsesAuthentication,
        }
        : undefined;

  // The stored block is written only when the operator edits or removes it.
  // The replace contract keeps an omitted block exactly as stored, so every
  // other save, a rename or a credential rotation, cannot change it. A new
  // delegated Connection's block is added by `createWriteFromForm`.
  const mode = effectiveCallerAssertionMode(form);
  const callerAssertion =
    mode === 'edit'
      ? { caller_assertion: callerAssertionWrite(form.callerAssertionDraft) }
      : mode === 'remove' && form.callerAssertion !== null
        ? { caller_assertion: null }
        : {};
  return {
    display_name: form.displayName.trim(),
    ...(description ? { description } : {}),
    enabled: form.enabled,
    kind: form.kind,
    endpoint: {
      base_url: form.baseUrl.trim(),
      base_path: form.basePath.trim(),
    },
    authentication,
    ...(form.additionalHeaders.length > 0
      ? {
        additional_headers: form.additionalHeaders.map((header) => ({
          header_name: header.headerName.trim(),
          ...bindingPayload(
            header.binding,
            'secret_id',
            'secret_configured',
          ),
        })),
      }
      : {}),
    ...callerAssertion,
    tls,
    ...(form.customTimeouts
      ? {
        timeouts: {
          connect_timeout_ms: Number(form.connectTimeoutMs),
          request_timeout_ms: Number(form.requestTimeoutMs),
          response_idle_timeout_ms: Number(form.responseIdleTimeoutMs),
        },
      }
      : {}),
    ...(discovery ? { discovery } : {}),
    // Not gated on the kind. Switching to MCP already clears
    // `testProfileEnabled`, so this only keeps a profile an MCP Connection was
    // loaded with. It is inert there and its section is hidden, but dropping it
    // on an unrelated save deleted a stored field, and on a credentialed
    // Connection the changed test target made that save need secrets
    // permission.
    ...(form.testProfileEnabled
      ? {
        test_profile: {
          method: form.testMethod,
          path: form.testPath.trim(),
          expected_statuses: parseStatuses(form.expectedStatuses),
        },
      }
      : {}),
  };
}

/**
 * The body of a create: `writeFromForm`, with the caller assertion a new
 * delegated issuer token Connection signs its subject tokens with in place of
 * the general block, which that credential never edits. A create has nothing
 * stored to remove.
 */
export function createWriteFromForm(
  form: ConnectionFormState,
): ConnectionCreateWrite {
  const { caller_assertion: callerAssertion, ...write } = writeFromForm(form);
  if (subjectTokenDraftApplies(form)) {
    return {
      ...write,
      caller_assertion: subjectTokenFromForm(form.subjectToken),
    };
  }
  return callerAssertion ? { ...write, caller_assertion: callerAssertion } : write;
}

export function subjectTokenFromForm(
  draft: SubjectTokenDraft,
): CallerAssertionWrite {
  return {
    signing_key_id: draft.signingKeyBinding.secretId.trim(),
    kid: draft.kid.trim(),
    algorithm: draft.algorithm,
    issuer: draft.issuer.trim(),
    audience: draft.audience.trim(),
    token_type: draft.tokenType.trim(),
    header_name: draft.headerName.trim(),
    lifetime_seconds: Number(draft.lifetimeSeconds),
    ...(draft.claims.length > 0 ? { claims: [...draft.claims] } : {}),
  };
}

export function authenticationFromForm(
  form: ConnectionFormState,
): ConnectionAuthentication {
  const binding =
    form.authenticationType === 'oauth2_client_credentials' ||
      form.authenticationType === 'delegated_issuer_token'
      ? bindingPayload(
        form.authenticationBinding,
        'client_secret_id',
        'client_secret_configured',
      )
      : bindingPayload(
        form.authenticationBinding,
        'secret_id',
        'secret_configured',
      );
  switch (form.authenticationType) {
    case 'none':
      return { type: 'none' };
    case 'header_api_key':
      return {
        type: 'header_api_key',
        header_name: form.headerName.trim(),
        ...binding,
      };
    case 'static_bearer':
      return { type: 'static_bearer', ...binding };
    case 'oauth2_client_credentials':
      return {
        type: 'oauth2_client_credentials',
        client_id: form.clientId.trim(),
        token_url: form.tokenUrl.trim(),
        scopes: normalizeList(form.scopes),
        ...(form.audience.trim()
          ? { audience: form.audience.trim() }
          : {}),
        ...(form.resource.trim()
          ? { resource: form.resource.trim() }
          : {}),
        client_auth_method: 'client_secret_basic',
        ...binding,
      };
    case 'delegated_issuer_token':
      return {
        type: 'delegated_issuer_token',
        token_exchange_url: form.tokenExchangeUrl.trim(),
        client_id: form.clientId.trim(),
        requested_scopes: normalizeList(form.scopes),
        ...(form.audience.trim()
          ? { audience: form.audience.trim() }
          : {}),
        ...(form.resource.trim()
          ? { resource: form.resource.trim() }
          : {}),
        ...(form.revocationUrl.trim()
          ? { revocation_url: form.revocationUrl.trim() }
          : {}),
        // The only value: the gateway signs a caller assertion naming the
        // caller. The caller's own inbound token is never forwarded.
        subject_token_source: 'caller_assertion',
        ...binding,
      };
  }
}

export function bindingPayload<
  IdField extends string,
  MarkerField extends string,
>(
  binding: BindingDraft,
  idField: IdField,
  markerField: MarkerField,
): Partial<Record<IdField, string> & Record<MarkerField, boolean>> {
  if (binding.intent === 'replace') {
    return {
      [idField]: binding.secretId.trim(),
    } as Partial<Record<IdField, string> & Record<MarkerField, boolean>>;
  }
  if (binding.intent === 'preserve') {
    return {
      [markerField]: true,
    } as Partial<Record<IdField, string> & Record<MarkerField, boolean>>;
  }
  if (binding.intent === 'clear') {
    return {
      [markerField]: false,
    } as Partial<Record<IdField, string> & Record<MarkerField, boolean>>;
  }
  return {};
}

export function validateForm(
  form: ConnectionFormState,
  secrets: ConnectionSecretMetadata[] = [],
): FieldErrors {
  const errors: FieldErrors = {};
  if (!form.displayName.trim()) {
    errors.display_name = 'Enter a display name.';
  }
  if (!validBaseUrl(form.baseUrl)) {
    errors['endpoint.base_url'] =
      'Enter an HTTP or HTTPS origin with no path, query, fragment, or credentials.';
  }
  if (!validOriginRelativePath(form.basePath)) {
    errors['endpoint.base_path'] =
      'Enter a safe origin-relative path with no query, fragment, or traversal.';
  }
  if (
    form.authenticationType === 'header_api_key' &&
    !form.headerName.trim()
  ) {
    errors['authentication.header_name'] = 'Enter the API key header name.';
  }
  // A save that keeps the stored caller assertion has the gateway revalidate
  // it against the headers being saved, so these would be refused anyway;
  // saying so here names the field to change instead of a form-wide error. A
  // new delegated Connection's block is checked the same way. An edited block
  // reports a clash on its own header field instead; see
  // `validateCallerAssertion`.
  const draftsSubjectToken = subjectTokenDraftApplies(form);
  const callerAssertionMode = effectiveCallerAssertionMode(form);
  const callerAssertionHeaderName = draftsSubjectToken
    ? form.subjectToken.headerName.trim().toLowerCase() || null
    : callerAssertionMode === 'keep'
      ? form.callerAssertion?.header_name.toLowerCase() ?? null
      : null;
  if (
    callerAssertionHeaderName !== null &&
    form.authenticationType === 'header_api_key' &&
    form.headerName.trim().toLowerCase() === callerAssertionHeaderName
  ) {
    errors['authentication.header_name'] =
      'The API key header cannot use the caller assertion header name.';
  }
  if (
    callerAssertionMode === 'keep' &&
    form.callerAssertion?.bind_approval === true
  ) {
    errors.form =
      'This connection was saved with a caller assertion that asks for approval binding, which the gateway no longer accepts. Edit the caller assertion, which turns approval binding off, or remove it before saving this connection.';
  }
  if (callerAssertionMode === 'edit') {
    validateCallerAssertion(form, secrets, errors);
  }
  if (form.additionalHeaders.length > MAX_ADDITIONAL_HEADERS) {
    errors.form = `Configure no more than ${MAX_ADDITIONAL_HEADERS} additional headers.`;
  }
  const additionalHeaderNames = new Map<string, number>();
  for (const [index, header] of form.additionalHeaders.entries()) {
    const nameField = `additional_headers.${index}.header_name`;
    const secretField = `additional_headers.${index}.secret_id`;
    const headerName = header.headerName.trim();
    if (!validCredentialHeaderName(headerName)) {
      errors[nameField] =
        'Enter a valid, non-reserved HTTP header name of at most 64 bytes.';
    } else {
      const normalized = headerName.toLowerCase();
      if (
        form.authenticationType === 'header_api_key' &&
        normalized === form.headerName.trim().toLowerCase()
      ) {
        errors[nameField] =
          'An additional header cannot use the primary credential header name.';
      } else if (normalized === callerAssertionHeaderName) {
        errors[nameField] =
          'An additional header cannot use the caller assertion header name.';
      } else if (additionalHeaderNames.has(normalized)) {
        errors[nameField] =
          'Additional header names must be unique, ignoring case.';
      } else {
        additionalHeaderNames.set(normalized, index);
      }
    }
    if (
      header.binding.intent === 'replace' &&
      !bindingHasCompatibleSecret(
        header.binding,
        'header_api_key',
        secrets,
      )
    ) {
      errors[secretField] =
        'Select a configured header API key secret alias.';
    }
    if (
      form.enabled &&
      !bindingIsEffectivelyConfigured(
        header.binding,
        'header_api_key',
        secrets,
      )
    ) {
      errors[secretField] =
        'Enabled connections require a configured secret for every additional header.';
    }
  }
  if (form.authenticationType === 'oauth2_client_credentials') {
    if (!form.clientId.trim()) {
      errors['authentication.client_id'] = 'Enter the OAuth client ID.';
    }
    if (!validTokenUrl(form.tokenUrl)) {
      errors['authentication.token_url'] =
        'Enter an HTTPS token URL with no credentials, query, or fragment.';
    }
    const scopes = normalizeList(form.scopes);
    if (new Set(scopes).size !== scopes.length) {
      errors['authentication.scopes'] = 'OAuth scopes must be unique.';
    }
  }
  if (form.authenticationType === 'delegated_issuer_token') {
    if (form.kind !== 'http_api') {
      errors['authentication.type'] =
        'A delegated issuer token works only on an HTTP API connection.';
    }
    if (!form.clientId.trim()) {
      errors['authentication.client_id'] =
        'Enter the client ID the gateway uses at the issuer.';
    }
    if (!validTokenUrl(form.tokenExchangeUrl)) {
      errors['authentication.token_exchange_url'] =
        'Enter an HTTPS token exchange URL with no credentials, query, or fragment.';
    }
    if (form.revocationUrl.trim() && !validTokenUrl(form.revocationUrl)) {
      errors['authentication.revocation_url'] =
        'Enter an HTTPS revocation URL with no credentials, query, or fragment, or leave it empty.';
    }
    const scopes = normalizeList(form.scopes);
    if (new Set(scopes).size !== scopes.length) {
      errors['authentication.requested_scopes'] =
        'Requested scopes must be unique.';
    }
  }
  if (draftsSubjectToken) {
    validateSubjectToken(form, secrets, errors);
  }
  const authenticationSecretField =
    form.authenticationType === 'oauth2_client_credentials' ||
      form.authenticationType === 'delegated_issuer_token'
      ? 'authentication.client_secret_id'
      : 'authentication.secret_id';
  const requiredAuthenticationPurpose = authenticationPurpose(
    form.authenticationType,
  );
  if (
    form.authenticationBinding.intent === 'replace' &&
    !bindingHasCompatibleSecret(
      form.authenticationBinding,
      requiredAuthenticationPurpose,
      secrets,
    )
  ) {
    errors[authenticationSecretField] =
      'Select a configured secret alias compatible with this authentication type.';
  }
  if (
    form.enabled &&
    requiredAuthenticationPurpose !== null &&
    !bindingIsEffectivelyConfigured(
      form.authenticationBinding,
      requiredAuthenticationPurpose,
      secrets,
    )
  ) {
    errors[authenticationSecretField] =
      'Enabled authenticated connections require a configured compatible secret alias.';
  }
  for (const [binding, field, purpose, label] of [
    [
      form.caBundleBinding,
      'tls.ca_bundle_alias',
      'tls_ca_bundle',
      'custom CA bundle',
    ],
    [
      form.clientCertificateBinding,
      'tls.client_certificate_id',
      'tls_certificate',
      'client certificate',
    ],
    [
      form.clientPrivateKeyBinding,
      'tls.client_private_key_id',
      'tls_private_key',
      'client private key',
    ],
  ] as const) {
    if (
      binding.intent === 'replace' &&
      !bindingHasCompatibleSecret(binding, purpose, secrets)
    ) {
      errors[field] =
        `Select a configured ${label} alias with the required purpose.`;
    }
  }
  const effectiveClientCertificate = bindingIsEffectivelyConfigured(
    form.clientCertificateBinding,
    'tls_certificate',
    secrets,
  );
  const effectiveClientPrivateKey = bindingIsEffectivelyConfigured(
    form.clientPrivateKeyBinding,
    'tls_private_key',
    secrets,
  );
  if (
    form.enabled &&
    effectiveClientCertificate !== effectiveClientPrivateKey
  ) {
    const missingField = effectiveClientCertificate
      ? 'tls.client_private_key_id'
      : 'tls.client_certificate_id';
    errors[missingField] =
      'Enabled mutual TLS requires both a client certificate and private key.';
  }
  const requestsTls =
    bindingRequestsSecret(form.caBundleBinding) ||
    bindingRequestsSecret(form.clientCertificateBinding) ||
    bindingRequestsSecret(form.clientPrivateKeyBinding);
  const requestsAdditionalHeaders = form.additionalHeaders.length > 0;
  if (
    (form.authenticationType !== 'none' ||
      requestsTls ||
      requestsAdditionalHeaders) &&
    !isHttpsOrigin(form.baseUrl)
  ) {
    errors['endpoint.base_url'] =
      'Credentialed connections and TLS profiles must use an HTTPS origin.';
  }
  // The gateway refuses `https_required` for a kept block too: an assertion
  // read off the wire can be presented as the caller until it expires.
  if (
    savesCallerAssertion(form) &&
    errors['endpoint.base_url'] === undefined &&
    !isHttpsOrigin(form.baseUrl)
  ) {
    errors['endpoint.base_url'] =
      'Connections with a caller assertion must use an HTTPS origin.';
  }
  if (form.customTimeouts) {
    validateTimeout(
      form.connectTimeoutMs,
      'timeouts.connect_timeout_ms',
      errors,
    );
    validateTimeout(
      form.requestTimeoutMs,
      'timeouts.request_timeout_ms',
      errors,
    );
    validateTimeout(
      form.responseIdleTimeoutMs,
      'timeouts.response_idle_timeout_ms',
      errors,
    );
  }
  if (
    form.discoveryType === 'managed_openapi' &&
    form.discoveryPath.trim() &&
    !validOriginRelativePath(form.discoveryPath.trim())
  ) {
    errors['discovery.path'] =
      'Enter a safe origin-relative discovery path with no query, fragment, encoded separators, or traversal.';
  }
  if (form.testProfileEnabled) {
    if (!validOriginRelativePath(form.testPath)) {
      errors['test_profile.path'] =
        'Enter a safe origin-relative path with no query, fragment, or traversal.';
    }
    const statusTokens = splitList(form.expectedStatuses);
    const statuses = statusTokens.map((status) => Number(status));
    if (statusTokens.length === 0) {
      errors['test_profile.expected_statuses'] =
        'Enter one or more HTTP status codes from 100 to 599.';
    } else if (statusTokens.length > 16) {
      errors['test_profile.expected_statuses'] =
        'Enter no more than 16 expected HTTP statuses.';
    } else if (
      statusTokens.some((status) => !/^\d+$/.test(status)) ||
      statuses.some(
        (status) =>
          !Number.isInteger(status) || status < 100 || status > 599,
      )
    ) {
      errors['test_profile.expected_statuses'] =
        'Enter whole-number HTTP status codes from 100 to 599.';
    } else if (new Set(statuses).size !== statuses.length) {
      errors['test_profile.expected_statuses'] =
        'Expected HTTP statuses must be unique.';
    }
  }
  if (form.enabled && !form.initiallyEnabled && !form.enableConfirmed) {
    errors.form = 'Confirm activation before enabling this connection.';
  }
  return errors;
}

/**
 * The gateway's rules for the caller assertion a new delegated Connection
 * signs its subject tokens with, so a refusal names the field to change. An
 * enabled save also loads the key, which only the gateway can do.
 */
function validateSubjectToken(
  form: ConnectionFormState,
  secrets: ConnectionSecretMetadata[],
  errors: FieldErrors,
) {
  const draft = form.subjectToken;
  if (
    !bindingHasCompatibleSecret(
      draft.signingKeyBinding,
      'assertion_signing_key',
      secrets,
    )
  ) {
    errors['caller_assertion.signing_key_id'] =
      'Select a configured assertion signing key alias.';
  }
  for (const [field, value, maxBytes, label] of [
    ['caller_assertion.kid', draft.kid, MAX_ASSERTION_KID_BYTES, 'a key ID'],
    [
      'caller_assertion.issuer',
      draft.issuer,
      MAX_ASSERTION_ISSUER_AUDIENCE_BYTES,
      'the issuer the subject token names',
    ],
    [
      'caller_assertion.audience',
      draft.audience,
      MAX_ASSERTION_ISSUER_AUDIENCE_BYTES,
      'the audience the token issuer expects',
    ],
    [
      'caller_assertion.token_type',
      draft.tokenType,
      MAX_ASSERTION_TOKEN_TYPE_BYTES,
      'a token type',
    ],
  ] as const) {
    const trimmed = value.trim();
    if (
      trimmed.length === 0 ||
      new TextEncoder().encode(trimmed).length > maxBytes ||
      /[\u0000-\u001f\u007f-\u009f]/.test(trimmed)
    ) {
      errors[field] =
        `Enter ${label} of 1 to ${maxBytes} bytes with no control characters.`;
    }
  }
  const headerName = draft.headerName.trim();
  if (!validCredentialHeaderName(headerName)) {
    errors['caller_assertion.header_name'] =
      'Enter a valid, non-reserved HTTP header name of at most 64 bytes.';
  }
  const lifetime = Number(draft.lifetimeSeconds);
  if (
    !/^\d+$/.test(draft.lifetimeSeconds.trim()) ||
    !Number.isInteger(lifetime) ||
    lifetime < 1 ||
    lifetime > MAX_CALLER_ASSERTION_LIFETIME_SECONDS
  ) {
    errors['caller_assertion.lifetime_seconds'] =
      `Enter a whole number of seconds from 1 to ${MAX_CALLER_ASSERTION_LIFETIME_SECONDS}.`;
  }
}

export function newCallerAssertionDraft(): CallerAssertionDraft {
  return {
    signingKey: emptyAssertionKey(),
    issuer: '',
    audience: '',
    tokenType: '',
    headerName: 'X-Caller-Assertion',
    lifetimeSeconds: '60',
    claims: [],
    bindRequest: false,
    publishedKeys: [],
  };
}

export function emptyAssertionKey(): AssertionKeyDraft {
  return {
    draftId: nextAssertionKeyDraftId++,
    kid: '',
    algorithm: 'es256',
    binding: emptyBinding(),
  };
}

function storedAssertionKey(
  kid: string,
  algorithm: CallerAssertionAlgorithm,
  configured: boolean,
): AssertionKeyDraft {
  return {
    draftId: nextAssertionKeyDraftId++,
    kid,
    algorithm,
    stored: { kid, algorithm, configured },
    binding: bindingFromMarker(configured),
  };
}

/**
 * The stored block as a draft that writes it back unchanged: every key kept
 * by marker, approval binding off. A block an earlier release stored with
 * approval binding cannot be saved as it is, and editing it is how the
 * operator turns that off.
 */
export function callerAssertionDraftFromStored(
  stored: SafeCallerAssertion,
): CallerAssertionDraft {
  return {
    signingKey: storedAssertionKey(
      stored.kid,
      stored.algorithm,
      stored.signing_key_configured,
    ),
    issuer: stored.issuer,
    audience: stored.audience,
    tokenType: stored.token_type,
    headerName: stored.header_name,
    lifetimeSeconds: String(stored.lifetime_seconds),
    claims: [...(stored.claims ?? [])],
    bindRequest: stored.bind_request,
    publishedKeys: (stored.published_keys ?? []).map((key) =>
      storedAssertionKey(key.kid, key.algorithm, key.signing_key_configured),
    ),
  };
}

/**
 * Applies an edit to one key. Like an additional header renamed away from its
 * stored binding, a key whose `kid` or algorithm no longer names the stored
 * key it was loaded as loses its kept binding, because the gateway would
 * refuse the marker; changing both back restores it.
 */
export function assertionKeyWithPatch(
  key: AssertionKeyDraft,
  patch: Partial<Pick<AssertionKeyDraft, 'kid' | 'algorithm' | 'binding'>>,
): AssertionKeyDraft {
  const next = { ...key, ...patch };
  if (
    key.stored === undefined ||
    !key.stored.configured ||
    patch.binding !== undefined
  ) {
    return next;
  }
  const namesStoredKey =
    next.kid === key.stored.kid && next.algorithm === key.stored.algorithm;
  if (!namesStoredKey && next.binding.intent === 'preserve') {
    return { ...next, binding: emptyBinding() };
  }
  if (namesStoredKey && next.binding.intent === 'none') {
    return { ...next, binding: configuredBinding() };
  }
  return next;
}

/**
 * Rotation step 3 in one action: the published key at `index` becomes the
 * signing key and the signing key takes its place in `published_keys`. Each
 * key keeps its `kid`, algorithm and binding, so a kept alias moves with it.
 */
export function callerAssertionDraftWithPromotedKey(
  draft: CallerAssertionDraft,
  index: number,
): CallerAssertionDraft {
  const promoted = draft.publishedKeys[index];
  if (promoted === undefined) {
    return draft;
  }
  return {
    ...draft,
    signingKey: promoted,
    publishedKeys: draft.publishedKeys.map((key, position) =>
      position === index ? draft.signingKey : key,
    ),
  };
}

export function callerAssertionWrite(
  draft: CallerAssertionDraft,
): CallerAssertionWrite {
  return {
    ...assertionKeyBindingPayload(draft.signingKey.binding),
    kid: draft.signingKey.kid,
    algorithm: draft.signingKey.algorithm,
    issuer: draft.issuer,
    audience: draft.audience,
    token_type: draft.tokenType,
    header_name: draft.headerName.trim(),
    lifetime_seconds: Number(draft.lifetimeSeconds),
    ...(draft.claims.length > 0 ? { claims: [...draft.claims] } : {}),
    bind_request: draft.bindRequest,
    bind_approval: false,
    ...(draft.publishedKeys.length > 0
      ? {
        published_keys: draft.publishedKeys.map((key) => ({
          ...assertionKeyBindingPayload(key.binding),
          kid: key.kid,
          algorithm: key.algorithm,
        })),
      }
      : {}),
  };
}

/**
 * A replaced binding names its alias; a kept one is the marker the gateway
 * resolves by `kid`. An unbound key writes neither, which `validateForm`
 * refuses before any save.
 */
function assertionKeyBindingPayload(
  binding: BindingDraft,
): CallerAssertionKeyBinding {
  if (binding.intent === 'replace') {
    return { signing_key_id: binding.secretId.trim() };
  }
  if (binding.intent === 'preserve' && binding.configured) {
    return { signing_key_configured: true };
  }
  return {};
}

/**
 * What a save does with the caller assertion. A delegated issuer token
 * Connection's block is its subject token: a new one is drafted in
 * `subjectToken` and a stored one stays read only, so for that credential the
 * general block is always kept.
 */
export function effectiveCallerAssertionMode(
  form: ConnectionFormState,
): CallerAssertionMode {
  return form.authenticationType === 'delegated_issuer_token'
    ? 'keep'
    : form.callerAssertionMode;
}

/** Whether a save leaves the Connection carrying a caller assertion. */
export function savesCallerAssertion(form: ConnectionFormState): boolean {
  const mode = effectiveCallerAssertionMode(form);
  return (
    subjectTokenDraftApplies(form) ||
    mode === 'edit' ||
    (mode === 'keep' && form.callerAssertion !== null)
  );
}

function validateCallerAssertion(
  form: ConnectionFormState,
  secrets: ConnectionSecretMetadata[],
  errors: FieldErrors,
) {
  const draft = form.callerAssertionDraft;
  validateAssertionKeyBinding(
    draft.signingKey.binding,
    'caller_assertion.signing_key_id',
    secrets,
    errors,
  );
  for (const [value, field, maxBytes, label] of [
    [
      draft.signingKey.kid,
      'caller_assertion.kid',
      MAX_ASSERTION_KID_BYTES,
      'a key ID',
    ],
    [
      draft.issuer,
      'caller_assertion.issuer',
      MAX_ASSERTION_ISSUER_AUDIENCE_BYTES,
      'an issuer',
    ],
    [
      draft.audience,
      'caller_assertion.audience',
      MAX_ASSERTION_ISSUER_AUDIENCE_BYTES,
      'an audience',
    ],
    [
      draft.tokenType,
      'caller_assertion.token_type',
      MAX_ASSERTION_TOKEN_TYPE_BYTES,
      'a token type',
    ],
  ] as const) {
    if (!validAssertionText(value, maxBytes)) {
      errors[field] =
        `Enter ${label} of 1 to ${maxBytes} bytes with no control characters.`;
    }
  }

  const headerName = draft.headerName.trim();
  const normalizedHeaderName = headerName.toLowerCase();
  if (!validCredentialHeaderName(headerName)) {
    errors['caller_assertion.header_name'] =
      'Enter a valid, non-reserved HTTP header name of at most 64 bytes.';
  } else if (
    form.authenticationType === 'header_api_key' &&
    form.headerName.trim().toLowerCase() === normalizedHeaderName
  ) {
    errors['caller_assertion.header_name'] =
      'The assertion header must differ from the API key header.';
  } else if (
    form.additionalHeaders.some(
      (header) =>
        header.headerName.trim().toLowerCase() === normalizedHeaderName,
    )
  ) {
    errors['caller_assertion.header_name'] =
      'The assertion header must differ from every additional header.';
  }

  const lifetime = Number(draft.lifetimeSeconds);
  if (
    !/^\d+$/.test(draft.lifetimeSeconds.trim()) ||
    lifetime < 1 ||
    lifetime > MAX_CALLER_ASSERTION_LIFETIME_SECONDS
  ) {
    errors['caller_assertion.lifetime_seconds'] =
      `Enter a whole number of seconds from 1 to ${MAX_CALLER_ASSERTION_LIFETIME_SECONDS}.`;
  }

  if (draft.publishedKeys.length > MAX_PUBLISHED_ASSERTION_KEYS) {
    errors['caller_assertion.published_keys'] =
      `Publish no more than ${MAX_PUBLISHED_ASSERTION_KEYS} keys beside the signing key.`;
  }
  // A verifier selects a key by `kid`, so each names one key, and one alias
  // is never published under two names.
  const kids = new Set([draft.signingKey.kid]);
  const aliases = new Set(
    draft.signingKey.binding.intent === 'replace'
      ? [draft.signingKey.binding.secretId.trim()]
      : [],
  );
  for (const [index, key] of draft.publishedKeys.entries()) {
    const kidField = `caller_assertion.published_keys.${index}.kid`;
    const secretField = `caller_assertion.published_keys.${index}.signing_key_id`;
    if (!validAssertionText(key.kid, MAX_ASSERTION_KID_BYTES)) {
      errors[kidField] =
        'Enter a key ID of 1 to 128 bytes with no control characters.';
    } else if (kids.has(key.kid)) {
      errors[kidField] =
        'Every published key needs its own key ID, distinct from the signing key and every other published key.';
    }
    kids.add(key.kid);
    validateAssertionKeyBinding(key.binding, secretField, secrets, errors);
    if (key.binding.intent === 'replace') {
      const alias = key.binding.secretId.trim();
      if (errors[secretField] === undefined && aliases.has(alias)) {
        errors[secretField] = 'Each secret alias may be published once.';
      }
      aliases.add(alias);
    }
  }
}

function validateAssertionKeyBinding(
  binding: BindingDraft,
  field: string,
  secrets: ConnectionSecretMetadata[],
  errors: FieldErrors,
) {
  if (binding.intent === 'preserve' && binding.configured) {
    return;
  }
  if (
    binding.intent === 'replace' &&
    bindingHasCompatibleSecret(binding, 'assertion_signing_key', secrets)
  ) {
    return;
  }
  errors[field] =
    binding.intent === 'replace'
      ? 'Select a configured secret alias that can hold an assertion signing key.'
      : 'Select the secret alias that holds this key.';
}

function validAssertionText(value: string, maxBytes: number): boolean {
  return (
    value.length > 0 &&
    new TextEncoder().encode(value).length <= maxBytes &&
    // Rust's `char::is_control`, which the gateway applies.
    !/[\u0000-\u001f\u007f-\u009f]/.test(value)
  );
}

// What the gateway's caller-assertion problem codes mean, for the fields of
// this block. The code is shown beside the sentence so an operator can find it
// in the operator guide.
const CALLER_ASSERTION_PROBLEMS: Record<string, string> = {
  required: 'This connection needs a caller assertion.',
  invalid_value: 'Enter a value with no control characters, within the length limit.',
  invalid_header_name:
    'Enter a valid, non-reserved HTTP header name of at most 64 bytes.',
  duplicate_header_name:
    'The assertion header must differ from the API key header and every additional header.',
  invalid_lifetime: `Enter 1 to ${MAX_CALLER_ASSERTION_LIFETIME_SECONDS} seconds.`,
  duplicate_claim: 'List each claim once.',
  unsupported_binding: 'This binding is not supported here.',
  too_many_keys: `Publish no more than ${MAX_PUBLISHED_ASSERTION_KEYS} keys beside the signing key.`,
  duplicate_kid:
    'Another key, on this connection or on another enabled one, is published under this key ID.',
  duplicate_signing_key: 'Each secret alias may be published once.',
  unresolvable_binding:
    'The alias is not configured, is unknown to its source, or does not hold a key.',
  binding_unavailable:
    'The secret source could not be read. Retry once it is available.',
  invalid_signing_key:
    'The alias does not hold exactly one PKCS#8 private key (BEGIN PRIVATE KEY).',
  algorithm_mismatch: 'The key is for the other algorithm.',
  unusable_signing_key:
    'The key cannot sign with this algorithm: ES256 needs a P-256 key and RS256 an RSA key of at least 2048 bits.',
  secret_purpose_conflict:
    'This alias is bound as a delegated token-exchange client secret and cannot also hold an assertion key.',
};

export function callerAssertionProblemMessage(code: string): string {
  const sentence = CALLER_ASSERTION_PROBLEMS[code];
  return sentence === undefined
    ? humanizeCode(code)
    : `${sentence} (${code})`;
}

export function bindingHasCompatibleSecret(
  binding: BindingDraft,
  purpose: ConnectionSecretPurpose | null,
  secrets: ConnectionSecretMetadata[],
): boolean {
  if (binding.intent !== 'replace' || purpose === null) {
    return false;
  }
  const secretId = binding.secretId.trim();
  return (
    secretId.length > 0 &&
    secrets.some(
      (secret) =>
        secret.id === secretId &&
        secret.configured &&
        secret.compatible_purposes.includes(purpose),
    )
  );
}

export function bindingIsEffectivelyConfigured(
  binding: BindingDraft,
  purpose: ConnectionSecretPurpose,
  secrets: ConnectionSecretMetadata[],
): boolean {
  if (binding.intent === 'preserve') {
    return binding.configured;
  }
  return bindingHasCompatibleSecret(binding, purpose, secrets);
}

export function bindingRequestsSecret(binding: BindingDraft): boolean {
  return (
    (binding.intent === 'preserve' && binding.configured) ||
    (binding.intent === 'replace' && binding.secretId.trim().length > 0)
  );
}

export function isHttpsOrigin(value: string): boolean {
  try {
    return new URL(value.trim()).protocol === 'https:';
  } catch {
    return false;
  }
}

export function validateTimeout(
  value: string,
  field: string,
  errors: FieldErrors,
) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 120000) {
    errors[field] = 'Enter a whole number from 1 to 120000.';
  }
}

export function validCredentialHeaderName(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    value.length > 0 &&
    new TextEncoder().encode(value).length <= 64 &&
    /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(value) &&
    ![
      'authorization',
      'cookie',
      'host',
      'content-length',
      'content-type',
      'connection',
      'expect',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade',
      'x-request-id',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-forwarded-port',
      'x-forwarded-proto',
      'x-real-ip',
      'x-csrf-token',
      'forwarded',
      'via',
    ].includes(normalized) &&
    !normalized.startsWith('x-forwarded-') &&
    !normalized.startsWith('x-greengateway-') &&
    !normalized.startsWith('sec-')
  );
}

export function validBaseUrl(value: string): boolean {
  const trimmed = value.trim();
  if (
    new TextEncoder().encode(trimmed).length > 2048 ||
    !/^https?:\/\/[^/?#]+\/?$/i.test(trimmed)
  ) {
    return false;
  }
  try {
    const url = new URL(trimmed);
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      url.username === '' &&
      url.password === '' &&
      (url.pathname === '' || url.pathname === '/') &&
      url.search === '' &&
      url.hash === ''
    );
  } catch {
    return false;
  }
}

export function validTokenUrl(value: string): boolean {
  const trimmed = value.trim();
  if (new TextEncoder().encode(trimmed).length > 2048) {
    return false;
  }
  const authorityStart = trimmed.indexOf('://');
  if (authorityStart < 0) {
    return false;
  }
  const pathStart = trimmed.indexOf('/', authorityStart + 3);
  const rawPath = pathStart < 0 ? '/' : trimmed.slice(pathStart);
  if (!validOriginRelativePath(rawPath)) {
    return false;
  }
  try {
    const url = new URL(trimmed);
    return (
      url.protocol === 'https:' &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === '' &&
      validOriginRelativePath(url.pathname)
    );
  } catch {
    return false;
  }
}

export function validOriginRelativePath(value: string): boolean {
  if (
    value.length === 0 ||
    new TextEncoder().encode(value).length > 1024 ||
    !value.startsWith('/') ||
    value.includes('//') ||
    value.includes('?') ||
    value.includes('#') ||
    value.includes('\\') ||
    /[\u0000-\u0020\u007f]/.test(value)
  ) {
    return false;
  }
  let decoded = value;
  for (let pass = 0; pass < 4; pass += 1) {
    if (
      /%(?:2f|5c)/i.test(decoded) ||
      decoded
        .split('/')
        .some((segment) => segment === '..' || segment === '.')
    ) {
      return false;
    }
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) {
        return !/[\u0000-\u001f\u007f]/.test(decoded);
      }
      decoded = next;
    } catch {
      return false;
    }
  }
  return false;
}

export function parseStatuses(value: string): number[] {
  return splitList(value).map((status) => Number(status));
}

export function normalizeList(value: string): string[] {
  return splitList(value);
}

export function splitList(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function emptyBinding(): BindingDraft {
  return { configured: false, intent: 'none', secretId: '' };
}

export function emptyAdditionalHeader(): AdditionalHeaderDraft {
  return {
    draftId: nextAdditionalHeaderDraftId++,
    headerName: '',
    initiallyConfigured: false,
    binding: emptyBinding(),
  };
}

export function additionalHeaderWithPatch(
  header: AdditionalHeaderDraft,
  patch: Partial<Pick<AdditionalHeaderDraft, 'headerName' | 'binding'>>,
): AdditionalHeaderDraft {
  const next = { ...header, ...patch };
  if (
    patch.headerName === undefined ||
    header.initialHeaderName === undefined ||
    !header.initiallyConfigured
  ) {
    return next;
  }
  const stillNamesCurrentBinding =
    patch.headerName.trim().toLowerCase() ===
    header.initialHeaderName.trim().toLowerCase();
  if (!stillNamesCurrentBinding && header.binding.intent === 'preserve') {
    return { ...next, binding: emptyBinding() };
  }
  if (
    stillNamesCurrentBinding &&
    header.binding.intent === 'none' &&
    patch.binding === undefined
  ) {
    return { ...next, binding: configuredBinding() };
  }
  return next;
}

export function configuredBinding(): BindingDraft {
  return { configured: true, intent: 'preserve', secretId: '' };
}

export function bindingFromMarker(configured: boolean): BindingDraft {
  return configured ? configuredBinding() : emptyBinding();
}

export function authenticationPurpose(
  authenticationType: AuthenticationType,
): ConnectionSecretPurpose | null {
  switch (authenticationType) {
    case 'header_api_key':
      return 'header_api_key';
    case 'static_bearer':
      return 'static_bearer';
    case 'oauth2_client_credentials':
      return 'oauth_client_secret';
    case 'delegated_issuer_token':
      return 'token_exchange_client_secret';
    case 'none':
      return null;
  }
}

export function withoutDeletedBinding(
  binding: BindingDraft,
  secretId: string,
): BindingDraft {
  return binding.intent === 'replace' && binding.secretId === secretId
    ? emptyBinding()
    : binding;
}

export function secretDraftResetKey(
  connectionId: string | undefined,
  form: ConnectionFormState,
): string {
  return [
    connectionId ?? 'new',
    form.kind,
    form.authenticationType,
    bindingKey(form.authenticationBinding),
    ...form.additionalHeaders.flatMap((header) => [
      header.headerName,
      bindingKey(header.binding),
    ]),
    bindingKey(form.caBundleBinding),
    bindingKey(form.clientCertificateBinding),
    bindingKey(form.clientPrivateKeyBinding),
  ].join('|');
}

export function bindingKey(binding: BindingDraft): string {
  return `${binding.intent}:${binding.secretId}`;
}

export function formatSecretProvider(
  provider: ConnectionSecretMetadata['provider'],
): string {
  switch (provider) {
    case 'operator_environment':
      return 'operator environment';
    case 'operator_file':
      return 'operator file';
    case 'local_encrypted':
      return 'local encrypted';
    case 'vault_kv_v2':
      return 'Vault KV v2';
    case 'gcp_secret_manager':
      return 'GCP Secret Manager';
    case 'azure_key_vault':
      return 'Azure Key Vault';
    case 'aws_secrets_manager':
      return 'AWS Secrets Manager';
    case 'kubernetes_secrets':
      return 'Kubernetes Secrets';
    default:
      // A kind added to the gateway ahead of this build. Naming it from the
      // wire value keeps the option readable instead of rendering `undefined`.
      return provider.replaceAll('_', ' ');
  }
}

export function formatSecretPurpose(
  purpose: ConnectionSecretPurpose | undefined,
): string {
  if (purpose === undefined) {
    return 'unknown purpose';
  }
  return purpose.replaceAll('_', ' ');
}

export function secretMaxLength(
  purpose: ConnectionSecretPurpose | undefined,
): number {
  switch (purpose) {
    case 'tls_ca_bundle':
    case 'tls_certificate':
      return 1024 * 1024;
    case 'tls_private_key':
      return 256 * 1024;
    case 'assertion_signing_key':
      return 16 * 1024;
    default:
      return 8 * 1024;
  }
}

export function isTlsSecretPurpose(
  purpose: ConnectionSecretPurpose | undefined,
): boolean {
  return (
    purpose === 'tls_ca_bundle' ||
    purpose === 'tls_certificate' ||
    purpose === 'tls_private_key'
  );
}

export function secretMutationError(
  error: unknown,
  operation: 'create' | 'rotate' | 'delete',
): {
  tone: 'warning' | 'error';
  title: string;
  message: string;
  conflict?: boolean;
} {
  if (error instanceof AdminApiError && error.status === 401) {
    return {
      tone: 'warning',
      title: 'Authentication required',
      message:
        'Authenticate again before changing secrets. The entered value was cleared.',
    };
  }
  if (error instanceof AdminApiError && error.status === 503) {
    return {
      tone: 'error',
      title: 'Secret service unavailable',
      message:
        'Encrypted local secret storage is unavailable. The entered value was cleared and was not retried.',
    };
  }
  if (error instanceof AdminApiError && error.status === 409) {
    const dependencyCount =
      typeof error.details.dependency_count === 'number'
        ? error.details.dependency_count
        : null;
    return {
      tone: 'warning',
      title: 'Secret operation blocked',
      message:
        dependencyCount !== null
          ? `The secret is still used by ${dependencyCount} dependencies. The entered value was cleared.`
          : `${error.message} The entered value was cleared.`,
    };
  }
  if (error instanceof AdminApiError && error.status === 412) {
    return {
      tone: 'warning',
      title: 'Secret changed',
      message:
        'The secret changed before this request completed. Reload the latest metadata before retrying. The entered value was cleared and was not retried.',
      conflict: true,
    };
  }
  if (error instanceof AdminApiError && error.status === 428) {
    return {
      tone: 'warning',
      title: 'Secret precondition unavailable',
      message:
        'The exact secret version was unavailable. Reload the inventory before retrying. The entered value was cleared and was not retried.',
      conflict: true,
    };
  }
  if (error instanceof AdminApiError && error.status === 403) {
    return {
      tone: 'warning',
      title: 'Secret permission required',
      message: `The gateway did not authorize this secret ${operation}. The entered value was cleared.`,
    };
  }
  if (
    error instanceof AdminApiError &&
    (error.status === 400 || error.status === 422)
  ) {
    return {
      tone: 'warning',
      title: 'Invalid secret request',
      message: `${error.message} The entered value was cleared.`,
    };
  }
  return {
    tone: 'error',
    title: `Secret ${operation} failed`,
    message:
      'The request failed without exposing stored secret material. The entered value was cleared.',
  };
}

export function secretInventoryLoadError(error: unknown): SecretInventoryState {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        kind: 'error',
        title: 'Authentication required',
        message: 'Authenticate again before loading safe secret aliases.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        kind: 'error',
        title: 'Secret permission required',
        message:
          'The gateway did not authorize this principal to view or bind secret aliases.',
        tone: 'warning',
      };
    }
    if (error.status === 503) {
      return {
        kind: 'error',
        title: 'Secret service unavailable',
        message: 'The encrypted secret control plane is unavailable.',
        tone: 'error',
      };
    }
    return {
      kind: 'error',
      title: 'Secret inventory unavailable',
      message: error.message,
      tone: 'error',
    };
  }
  return {
    kind: 'error',
    title: 'Secret inventory unavailable',
    message: 'Secret inventory request failed.',
    tone: 'error',
  };
}

export function secretMutationReloadRequired(): SecretInventoryState {
  return {
    kind: 'error',
    title: 'Secret inventory reload required',
    message:
      'The mutation completed without a fresh collection precondition token. Reload the editor before another secret operation.',
    tone: 'warning',
  };
}

export function secretErrorRequiresReload(error: unknown): boolean {
  return (
    (error instanceof ConnectionSecretContractError &&
      error.requiresReload) ||
    (error instanceof AdminApiError &&
      (error.status === 412 || error.status === 428))
  );
}

export function requiredEtag(value: string | null, message: string): string {
  if (value === null) {
    throw new Error(message);
  }
  return value;
}

export function describedBy(id: string, error?: string): string | undefined {
  return error ? `${id}-error` : undefined;
}

export function additionalHeaderFieldError(
  errors: FieldErrors,
  index: number,
  field: 'header_name' | 'secret_id',
): string | undefined {
  return (
    errors[`additional_headers.${index}.${field}`] ??
    (index === 0 ? errors[`additional_headers.${field}`] : undefined)
  );
}

export function focusFirstProblem(errors: FieldErrors) {
  const fieldToId: Record<string, string> = {
    display_name: 'connection-display-name',
    'endpoint.base_url': 'connection-base-url',
    'endpoint.base_path': 'connection-base-path',
    'authentication.type': 'connection-authentication-type',
    'authentication.header_name': 'connection-header-name',
    'authentication.client_id': 'connection-client-id',
    'authentication.token_url': 'connection-token-url',
    'authentication.token_exchange_url': 'connection-token-exchange-url',
    'authentication.revocation_url': 'connection-revocation-url',
    'authentication.scopes': 'connection-oauth-scopes',
    'authentication.requested_scopes': 'connection-oauth-scopes',
    'authentication.audience': 'connection-oauth-audience',
    'authentication.resource': 'connection-oauth-resource',
    'authentication.secret_id': 'connection-auth-secret',
    'authentication.client_secret_id': 'connection-auth-secret',
    'caller_assertion.signing_key_id': 'connection-subject-token-key',
    'caller_assertion.kid': 'connection-subject-token-kid',
    'caller_assertion.issuer': 'connection-subject-token-issuer',
    'caller_assertion.audience': 'connection-subject-token-audience',
    'caller_assertion.token_type': 'connection-subject-token-type',
    'caller_assertion.header_name': 'connection-subject-token-header',
    'caller_assertion.lifetime_seconds': 'connection-subject-token-lifetime',
    'additional_headers.header_name': 'connection-additional-header-0-name',
    'additional_headers.secret_id': 'connection-additional-header-0-secret',
    'tls.ca_bundle_alias': 'connection-ca-bundle',
    'tls.client_certificate_id': 'connection-client-certificate',
    'tls.client_private_key_id': 'connection-client-private-key',
    'timeouts.connect_timeout_ms': 'connection-connect-timeout',
    'timeouts.request_timeout_ms': 'connection-request-timeout',
    'timeouts.response_idle_timeout_ms': 'connection-idle-timeout',
    'discovery.path': 'connection-discovery-path',
    'test_profile.path': 'connection-test-path',
    'test_profile.expected_statuses': 'connection-expected-statuses',
  };
  // The same caller-assertion field is drafted by the subject-token section
  // of a new delegated Connection or by the caller-assertion editor; when
  // neither shows it, its problem is listed in the caller-assertion section.
  const callerAssertionEditorIds: Record<string, string> = {
    'caller_assertion.signing_key_id': 'connection-caller-assertion-signing-key',
    'caller_assertion.kid': 'connection-caller-assertion-kid',
    'caller_assertion.issuer': 'connection-caller-assertion-issuer',
    'caller_assertion.audience': 'connection-caller-assertion-audience',
    'caller_assertion.token_type': 'connection-caller-assertion-token-type',
    'caller_assertion.header_name': 'connection-caller-assertion-header-name',
    'caller_assertion.lifetime_seconds': 'connection-caller-assertion-lifetime',
  };
  const candidates = Object.keys(errors)
    .map((field): string[] | undefined => {
      if (field === 'caller_assertion' || field.startsWith('caller_assertion.')) {
        const indexedPublishedKey =
          /^caller_assertion\.published_keys\.(\d+)\.(kid|signing_key_id)$/.exec(
            field,
          );
        return [
          fieldToId[field],
          callerAssertionEditorIds[field],
          indexedPublishedKey
            ? `connection-caller-assertion-published-key-${indexedPublishedKey[1]}-${indexedPublishedKey[2] === 'kid' ? 'kid' : 'secret'
            }`
            : undefined,
          CALLER_ASSERTION_PROBLEMS_ID,
        ].filter((id): id is string => id !== undefined);
      }
      if (fieldToId[field]) {
        return [fieldToId[field]];
      }
      const indexedAdditionalHeader =
        /^additional_headers\.(\d+)\.(header_name|secret_id)$/.exec(field);
      return indexedAdditionalHeader
        ? [
          `connection-additional-header-${indexedAdditionalHeader[1]}-${indexedAdditionalHeader[2] === 'header_name' ? 'name' : 'secret'
          }`,
        ]
        : undefined;
    })
    .find((ids) => ids !== undefined);
  if (candidates) {
    queueMicrotask(() =>
      candidates
        .map((id) => document.getElementById(id))
        .find((element) => element !== null)
        ?.focus(),
    );
  }
}

export const CALLER_ASSERTION_PROBLEMS_ID = 'connection-caller-assertion-problems';

/**
 * The caller-assertion problems that have no field of their own on screen:
 * the block's own, and those of fields no section shows. While a stored block
 * is kept or removed it is shown read only, so all of them; while it is
 * edited, or a new delegated Connection drafts it as its subject token, those
 * of the block's own fields are shown on the fields.
 */
export function callerAssertionSectionProblems(
  errors: FieldErrors,
  fieldsShown: boolean,
): string[] {
  return Object.entries(errors)
    .filter(
      ([field]) =>
        field === 'caller_assertion' ||
        (field.startsWith('caller_assertion.') &&
          !(fieldsShown && CALLER_ASSERTION_DRAFT_FIELDS.has(field)) &&
          !(
            fieldsShown &&
            /^caller_assertion\.published_keys\.\d+\./.test(field)
          )),
    )
    .map(([, message]) => message);
}

const CALLER_ASSERTION_DRAFT_FIELDS = new Set([
  'caller_assertion.signing_key_id',
  'caller_assertion.kid',
  'caller_assertion.issuer',
  'caller_assertion.audience',
  'caller_assertion.token_type',
  'caller_assertion.header_name',
  'caller_assertion.lifetime_seconds',
]);

/**
 * The gateway's field problems as editor field errors. A caller-assertion
 * problem keeps its field and shows its code beside what it means; the
 * section shows it wherever no field does (see
 * `callerAssertionSectionProblems`).
 */
export function fieldErrorsFromProblems(
  problems: readonly { field: string; code: string }[],
): FieldErrors {
  const knownFields = new Set([
    'display_name',
    'endpoint.base_url',
    'endpoint.base_path',
    'authentication.type',
    'authentication.header_name',
    'authentication.client_id',
    'authentication.token_url',
    'authentication.token_exchange_url',
    'authentication.revocation_url',
    'authentication.scopes',
    'authentication.requested_scopes',
    'authentication.audience',
    'authentication.resource',
    'authentication.secret_id',
    'authentication.client_secret_id',
    'additional_headers.header_name',
    'additional_headers.secret_id',
    'tls.ca_bundle_alias',
    'tls.client_certificate_id',
    'tls.client_private_key_id',
    'timeouts.connect_timeout_ms',
    'timeouts.request_timeout_ms',
    'timeouts.response_idle_timeout_ms',
    'discovery.path',
    'test_profile.path',
    'test_profile.expected_statuses',
  ]);
  const errors: FieldErrors = {};
  for (const problem of problems) {
    if (
      problem.field === 'caller_assertion' ||
      problem.field.startsWith('caller_assertion.')
    ) {
      // The gateway names a published key's field without its index, so its
      // problem is shown beside the list rather than on one row.
      appendFieldError(
        errors,
        problem.field.startsWith('caller_assertion.published_keys')
          ? 'caller_assertion.published_keys'
          : problem.field,
        callerAssertionProblemMessage(problem.code),
      );
      continue;
    }
    const message = humanizeCode(problem.code);
    if (problem.field === 'tls') {
      appendFieldError(errors, 'tls.client_certificate_id', message);
      appendFieldError(errors, 'tls.client_private_key_id', message);
    } else if (knownFields.has(problem.field)) {
      appendFieldError(errors, problem.field, message);
    } else {
      appendFieldError(errors, 'form', message);
    }
  }
  return errors;
}

export function appendFieldError(
  errors: FieldErrors,
  field: string,
  message: string,
) {
  const existing = errors[field];
  errors[field] =
    existing === undefined || existing === message
      ? message
      : `${existing} ${message}`;
}

export function humanizeCode(code: string): string {
  const text = code.replaceAll('_', ' ');
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}.`;
}

export function toLoadError(error: unknown): EditorLoadState {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        kind: 'error',
        title: 'Bearer token required',
        message: 'Authenticate before opening the connection editor.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        kind: 'error',
        title: 'Connection permission required',
        message:
          'This principal cannot read the connection editor resource.',
        tone: 'error',
      };
    }
    if (error.status === 404) {
      return {
        kind: 'error',
        title: 'Connection not found',
        message: 'The requested connection does not exist.',
        tone: 'warning',
      };
    }
    if (error.status === 503) {
      return {
        kind: 'error',
        title: 'Connection service unavailable',
        message:
          'The managed connection control plane is not available on this gateway.',
        tone: 'error',
      };
    }
    return {
      kind: 'error',
      title: 'Connection request failed',
      message: error.message,
      tone: 'error',
    };
  }

  return {
    kind: 'error',
    title: 'Connection request failed',
    message:
      error instanceof Error
        ? `Network request failed: ${error.message}`
        : 'Network request failed.',
    tone: 'error',
  };
}

export function toSaveError(error: unknown): SaveState {
  if (error instanceof AdminApiError) {
    if (error.status === 409) {
      return {
        kind: 'error',
        title: 'Connection update blocked',
        message: error.message,
        tone: 'warning',
        conflict: false,
      };
    }
    if (error.status === 412) {
      return {
        kind: 'error',
        title: 'Connection changed',
        message:
          'The connection state changed while you were editing. Reload the latest state before retrying.',
        tone: 'warning',
        conflict: true,
      };
    }
    if (error.status === 428) {
      return {
        kind: 'error',
        title: 'Connection precondition unavailable',
        message:
          'The editor no longer has the exact connection version required to save safely. Reload before retrying.',
        tone: 'warning',
        conflict: true,
      };
    }
    if (error.status === 401) {
      return {
        kind: 'error',
        title: 'Authentication required',
        message: 'Authenticate again before saving this connection.',
        tone: 'warning',
        conflict: false,
      };
    }
    if (error.status === 403) {
      return {
        kind: 'error',
        title: 'Connection permission required',
        message:
          'The gateway did not authorize this connection or secret-binding change.',
        tone: 'warning',
        conflict: false,
      };
    }
    if (error.status === 503) {
      return {
        kind: 'error',
        title: 'Connection service unavailable',
        message:
          'The managed connection control plane is unavailable. No retry was attempted.',
        tone: 'error',
        conflict: false,
      };
    }
    if (error.status === 400 || error.status === 422) {
      return {
        kind: 'error',
        title: 'Invalid connection',
        message: error.message,
        tone: 'warning',
        conflict: false,
      };
    }
    return {
      kind: 'error',
      title: 'Connection save failed',
      message: error.message,
      tone: 'error',
      conflict: false,
    };
  }

  return {
    kind: 'error',
    title: 'Connection save failed',
    message:
      error instanceof Error
        ? `Network request failed: ${error.message}`
        : 'Network request failed.',
    tone: 'error',
    conflict: false,
  };
}
