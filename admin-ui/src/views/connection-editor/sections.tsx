import {
  useEffect,
  useRef,
  useState
} from 'react';

import {
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

import {
  AdditionalHeaderDraft,
  additionalHeaderFieldError,
  ALL_SECRET_PURPOSES,
  authenticationPurpose,
  AuthenticationType,
  BindingDraft,
  BindingIntent,
  ConnectionFormState,
  describedBy,
  DiscoveryType,
  FieldErrors,
  formatSecretProvider,
  formatSecretPurpose,
  isTlsSecretPurpose,
  MAX_ADDITIONAL_HEADERS,
  secretErrorRequiresReload,
  SecretInventoryState,
  secretMaxLength,
  secretMutationError,
  secretMutationReloadRequired,
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
  onUpdate,
  onAuthenticationTypeChange,
}: {
  form: ConnectionFormState;
  errors: FieldErrors;
  canBindSecret: boolean;
  secrets: ConnectionSecretMetadata[];
  disabled: boolean;
  onUpdate: (patch: Partial<ConnectionFormState>) => void;
  onAuthenticationTypeChange: (type: AuthenticationType) => void;
}) {
  const hasSecret = form.authenticationType !== 'none';
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
        <label htmlFor="connection-authentication-type">
          Authentication type
          <select
            id="connection-authentication-type"
            value={form.authenticationType}
            disabled={disabled}
            onChange={(event) =>
              onAuthenticationTypeChange(
                event.target.value as AuthenticationType,
              )
            }
          >
            <option value="none">None</option>
            <option value="header_api_key">Header API key</option>
            <option value="static_bearer">Static bearer</option>
            <option value="oauth2_client_credentials">
              OAuth 2 client credentials
            </option>
          </select>
        </label>
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
        {form.authenticationType === 'oauth2_client_credentials' ? (
          <>
            <FormField
              id="connection-client-id"
              label="OAuth client ID"
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
            <FormField
              id="connection-oauth-scopes"
              label="OAuth scopes"
              error={errors['authentication.scopes']}
            >
              <input
                id="connection-oauth-scopes"
                value={form.scopes}
                disabled={disabled}
                placeholder="read write"
                autoComplete="off"
                aria-invalid={Boolean(errors['authentication.scopes'])}
                aria-describedby={describedBy(
                  'connection-oauth-scopes',
                  errors['authentication.scopes'],
                )}
                onChange={(event) => onUpdate({ scopes: event.target.value })}
              />
            </FormField>
            <FormField
              id="connection-oauth-audience"
              label="OAuth audience"
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
              label="OAuth resource"
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
          </>
        ) : null}
      </div>
      {hasSecret ? (
        <BindingControl
          id="connection-auth-secret"
          label={
            form.authenticationType === 'oauth2_client_credentials'
              ? 'OAuth client secret'
              : 'Authentication secret'
          }
          binding={form.authenticationBinding}
          purpose={authenticationPurpose(form.authenticationType)}
          secrets={secrets}
          canBindSecret={canBindSecret}
          disabled={disabled}
          error={
            errors[
            form.authenticationType === 'oauth2_client_credentials'
              ? 'authentication.client_secret_id'
              : 'authentication.secret_id'
            ]
          }
          onChange={(authenticationBinding) =>
            onUpdate({ authenticationBinding })
          }
        />
      ) : null}
    </section>
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
          {binding.configured ? (
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
