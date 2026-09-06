
import { AdminApiError } from '../../lib/api';
import {
  type ConnectionAuthentication,
  type ConnectionDetail,
  type ConnectionKind,
  type ConnectionWrite,
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
  clientId: string;
  tokenUrl: string;
  scopes: string;
  audience: string;
  resource: string;
  authenticationBinding: BindingDraft;
  additionalHeaders: AdditionalHeaderDraft[];
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
  scopes: '',
  audience: '',
  resource: '',
  authenticationBinding: emptyBinding(),
  additionalHeaders: [],
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
  const authenticationConfigured =
    authentication.type === 'header_api_key' ||
      authentication.type === 'static_bearer'
      ? authentication.secret_configured
      : authentication.type === 'oauth2_client_credentials'
        ? authentication.client_secret_configured
        : false;
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
    clientId:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.client_id
        : '',
    tokenUrl:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.token_url
        : '',
    scopes:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.scopes.join(' ')
        : '',
    audience:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.audience ?? ''
        : '',
    resource:
      authentication.type === 'oauth2_client_credentials'
        ? authentication.resource ?? ''
        : '',
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
  return (
    authenticationConfigured ||
    (configuration.additional_headers?.length ?? 0) > 0 ||
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
    ...(form.kind === 'http_api' && form.testProfileEnabled
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

export function authenticationFromForm(
  form: ConnectionFormState,
): ConnectionAuthentication {
  const binding =
    form.authenticationType === 'oauth2_client_credentials'
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
  const authenticationSecretField =
    form.authenticationType === 'oauth2_client_credentials'
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
    'authentication.header_name': 'connection-header-name',
    'authentication.client_id': 'connection-client-id',
    'authentication.token_url': 'connection-token-url',
    'authentication.scopes': 'connection-oauth-scopes',
    'authentication.audience': 'connection-oauth-audience',
    'authentication.resource': 'connection-oauth-resource',
    'authentication.secret_id': 'connection-auth-secret',
    'authentication.client_secret_id': 'connection-auth-secret',
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
  const target = Object.keys(errors)
    .map((field) => {
      if (fieldToId[field]) {
        return fieldToId[field];
      }
      const indexedAdditionalHeader =
        /^additional_headers\.(\d+)\.(header_name|secret_id)$/.exec(field);
      return indexedAdditionalHeader
        ? `connection-additional-header-${indexedAdditionalHeader[1]}-${indexedAdditionalHeader[2] === 'header_name' ? 'name' : 'secret'
        }`
        : undefined;
    })
    .find((id) => id !== undefined);
  if (target) {
    queueMicrotask(() => document.getElementById(target)?.focus());
  }
}

export function fieldErrorsFromProblems(
  problems: readonly { field: string; code: string }[],
): FieldErrors {
  const knownFields = new Set([
    'display_name',
    'endpoint.base_url',
    'endpoint.base_path',
    'authentication.header_name',
    'authentication.client_id',
    'authentication.token_url',
    'authentication.scopes',
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
