import {
  FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  ConnectionContractError,
  createConnection,
  getConnection,
  listConnections,
  type ConnectionAuthentication,
  type ConnectionDetail,
  type ConnectionKind,
  type ConnectionWrite,
  type TlsProfile,
  updateConnection,
} from '../lib/connections';
import {
  createConnectionSecret,
  ConnectionSecretContractError,
  deleteConnectionSecret,
  listConnectionSecrets,
  rotateConnectionSecret,
  type ConnectionSecretListResponse,
  type ConnectionSecretMetadata,
  type ConnectionSecretPurpose,
} from '../lib/secrets';

type AuthenticationType = ConnectionAuthentication['type'];
type DiscoveryType = 'none' | 'managed_openapi' | 'managed_mcp';
type BindingIntent = 'none' | 'preserve' | 'clear' | 'replace';

type BindingDraft = {
  configured: boolean;
  intent: BindingIntent;
  secretId: string;
};

type ConnectionFormState = {
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

type EditorLoadState =
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

type SaveState =
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

type FieldErrors = Record<string, string>;

type SecretInventoryState =
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

const DEFAULT_FORM: ConnectionFormState = {
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

const ALL_SECRET_PURPOSES: ConnectionSecretPurpose[] = [
  'header_api_key',
  'static_bearer',
  'oauth_client_secret',
  'tls_ca_bundle',
  'tls_certificate',
  'tls_private_key',
];

export function ConnectionEditor() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isEditing = id !== undefined;
  const [loadState, setLoadState] = useState<EditorLoadState>({
    kind: 'loading',
  });
  const [form, setForm] = useState<ConnectionFormState>(DEFAULT_FORM);
  const [etag, setEtag] = useState<string | null>(null);
  const [collectionEtag, setCollectionEtag] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [saveState, setSaveState] = useState<SaveState>({ kind: 'idle' });
  const [requiresReload, setRequiresReload] = useState(false);
  const [secretMutationInFlight, setSecretMutationInFlight] =
    useState(false);
  const [secretDraftPresent, setSecretDraftPresent] = useState(false);
  const [secretInventory, setSecretInventory] =
    useState<SecretInventoryState>({ kind: 'idle' });
  const loadGeneration = useRef(0);
  const saveController = useRef<AbortController | null>(null);
  const saveAlert = useRef<HTMLDivElement | null>(null);
  const conflictAction = useRef<HTMLButtonElement | null>(null);
  const clearSecretDraft = useRef<(() => void) | null>(null);
  const secretInventoryAlert = useRef<HTMLDivElement | null>(null);

  const loadEditor = useCallback(
    async (signal?: AbortSignal, preserveCreateDraft = false) => {
      const generation = ++loadGeneration.current;
      setLoadState({ kind: 'loading' });
      setRequiresReload(false);
      setSaveState({ kind: 'idle' });
      setFieldErrors({});

      try {
        if (id === undefined) {
          const resource = await listConnections({ limit: 1 }, signal);
          if (signal?.aborted || generation !== loadGeneration.current) {
            return;
          }

          const nextCollectionEtag = resource.collectionEtag;
          if (nextCollectionEtag === null) {
            throw new Error(
              'The gateway did not return the connection collection ETag.',
            );
          }

          setCollectionEtag(nextCollectionEtag);
          setEtag(null);
          if (!preserveCreateDraft) {
            setForm(DEFAULT_FORM);
          }
          setLoadState({
            kind: 'ready',
            detail: null,
            canCreate: resource.value.actions.can_create,
            canBindSecret: resource.value.actions.can_bind_secret,
            canManageSecrets:
              resource.value.actions.can_manage_secrets,
          });
          return;
        }

        const resource = await getConnection(id, signal);
        if (signal?.aborted || generation !== loadGeneration.current) {
          return;
        }
        if (resource.etag === null) {
          throw new Error('The gateway did not return the connection ETag.');
        }

        setEtag(resource.etag);
        setCollectionEtag(resource.collectionEtag);
        setForm(formFromDetail(resource.value));
        setLoadState({
          kind: 'ready',
          detail: resource.value,
          canCreate: false,
          canBindSecret: resource.value.actions.can_bind_secret,
          canManageSecrets:
            resource.value.actions.can_manage_secrets,
        });
      } catch (error) {
        if (signal?.aborted || generation !== loadGeneration.current) {
          return;
        }
        setLoadState(toLoadError(error));
      }
    },
    [id],
  );

  useEffect(() => {
    const controller = new AbortController();
    void loadEditor(controller.signal);
    return () => {
      controller.abort();
      saveController.current?.abort();
      saveController.current = null;
      loadGeneration.current += 1;
    };
  }, [loadEditor]);

  const shouldLoadSecrets =
    loadState.kind === 'ready' &&
    (loadState.canBindSecret || loadState.canManageSecrets);

  useEffect(() => {
    const controller = new AbortController();
    if (!shouldLoadSecrets) {
      setSecretInventory({ kind: 'idle' });
      return () => controller.abort();
    }

    setSecretInventory({ kind: 'loading' });
    void listConnectionSecrets(controller.signal)
      .then((resource) => {
        if (controller.signal.aborted) {
          return;
        }
        const nextEtag = resource.collectionEtag;
        if (nextEtag === null) {
          setSecretInventory({
            kind: 'error',
            title: 'Secret inventory unavailable',
            message:
              'The gateway did not return the secret collection ETag.',
            tone: 'error',
          });
          return;
        }
        setSecretInventory({
          kind: 'ready',
          value: resource.value,
          collectionEtag: nextEtag,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setSecretInventory(secretInventoryLoadError(error));
      });

    return () => controller.abort();
  }, [id, shouldLoadSecrets]);

  useEffect(() => {
    if (saveState.kind === 'error') {
      if (
        !saveState.conflict &&
        Object.keys(fieldErrors).some((field) => field !== 'form')
      ) {
        focusFirstProblem(fieldErrors);
        return;
      }
      queueMicrotask(() => {
        if (saveState.conflict || saveState.recovery) {
          conflictAction.current?.focus();
        } else {
          saveAlert.current?.focus();
        }
      });
    }
  }, [fieldErrors, saveState]);

  useEffect(() => {
    if (secretInventory.kind === 'error') {
      queueMicrotask(() => secretInventoryAlert.current?.focus());
    }
  }, [secretInventory]);

  function updateForm(
    patch:
      | Partial<ConnectionFormState>
      | ((current: ConnectionFormState) => ConnectionFormState),
  ) {
    setForm((current) =>
      typeof patch === 'function' ? patch(current) : { ...current, ...patch },
    );
    setFieldErrors({});
    setSaveState((current) =>
      requiresReload ? current : { kind: 'idle' },
    );
  }

  function updateAuthenticationType(next: AuthenticationType) {
    updateForm((current) => {
      const configured =
        next === current.initialAuthenticationType &&
        current.authenticationBinding.configured;
      return {
        ...current,
        authenticationType: next,
        authenticationBinding: configured
          ? configuredBinding()
          : emptyBinding(),
      };
    });
  }

  function updateKind(next: ConnectionKind) {
    updateForm((current) => ({
      ...current,
      kind: next,
      discoveryType:
        next === 'mcp_streamable_http'
          ? 'managed_mcp'
          : current.discoveryType === 'managed_mcp'
            ? 'none'
            : current.discoveryType,
      testProfileEnabled:
        next === 'mcp_streamable_http'
          ? false
          : current.testProfileEnabled,
    }));
  }

  async function saveConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearSecretDraft.current?.();
    setSecretDraftPresent(false);
    if (secretDraftPresent) {
      setSaveState({
        kind: 'error',
        title: 'One-time secret value cleared',
        message:
          'Finish or dismiss the secret operation before saving the connection. Entered secret material was cleared.',
        tone: 'warning',
        conflict: false,
      });
      return;
    }
    const errors = validateForm(form, availableSecrets);
    setFieldErrors(errors);
    setSaveState({ kind: 'idle' });
    if (Object.keys(errors).length > 0) {
      focusFirstProblem(errors);
      return;
    }

    if (loadState.kind !== 'ready') {
      return;
    }
    if (requiresReload || secretMutationInFlight || secretDraftPresent) {
      return;
    }
    if (isEditing && !loadState.detail?.actions.can_update) {
      setSaveState({
        kind: 'error',
        title: 'Connection is read only',
        message:
          'The gateway did not authorize this principal to update the connection.',
        tone: 'warning',
        conflict: false,
      });
      return;
    }
    if (!isEditing && !loadState.canCreate) {
      setSaveState({
        kind: 'error',
        title: 'Create permission required',
        message:
          'The gateway did not authorize this principal to create connections.',
        tone: 'warning',
        conflict: false,
      });
      return;
    }

    const write = writeFromForm(form);
    saveController.current?.abort();
    const controller = new AbortController();
    saveController.current = controller;
    setSaveState({ kind: 'saving' });
    try {
      const resource =
        id === undefined
          ? await createConnection(
              write,
              requiredEtag(
                collectionEtag,
                'Connection collection ETag is unavailable. Reload and retry.',
              ),
              controller.signal,
            )
          : await updateConnection(
              id,
              write,
              requiredEtag(
                etag,
                'Connection ETag is unavailable. Reload and retry.',
              ),
              controller.signal,
            );
      if (controller.signal.aborted) {
        return;
      }

      setEtag(resource.etag);
      setCollectionEtag(resource.collectionEtag);
      setSaveState({
        kind: 'saved',
        message: id === undefined ? 'Connection created.' : 'Connection saved.',
      });
      navigate(
        `/connections/${encodeURIComponent(resource.value.id)}`,
        { replace: id === undefined },
      );
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (
        error instanceof ConnectionContractError &&
        error.requiresReload
      ) {
        const ambiguousCreate = id === undefined;
        setRequiresReload(true);
        setEtag(null);
        setCollectionEtag(null);
        if (ambiguousCreate) {
          setForm(DEFAULT_FORM);
        }
        setSaveState({
          kind: 'error',
          title: ambiguousCreate
            ? 'Connection creation outcome unknown'
            : 'Connection save outcome unknown',
          message: ambiguousCreate
            ? 'The gateway may have created this connection, so the draft was reset to prevent a duplicate. Return to Connections and reload the inventory before continuing.'
            : 'The gateway may have saved this update without returning matching version metadata. Reload the known connection before editing again.',
          tone: 'warning',
          conflict: false,
          recovery: ambiguousCreate ? 'connections' : 'reload',
        });
        return;
      }
      const nextState = toSaveError(error);
      if (nextState.kind === 'error' && nextState.conflict) {
        setRequiresReload(true);
      }
      if (error instanceof AdminApiError && error.problems.length > 0) {
        const serverErrors = fieldErrorsFromProblems(error.problems);
        setFieldErrors(serverErrors);
        focusFirstProblem(serverErrors);
      }
      setSaveState(nextState);
    } finally {
      if (saveController.current === controller) {
        saveController.current = null;
      }
    }
  }

  async function reloadAfterConflict() {
    const controller = new AbortController();
    await loadEditor(controller.signal, id === undefined);
  }

  async function reloadSecretInventory() {
    setSecretInventory({ kind: 'loading' });
    try {
      const resource = await listConnectionSecrets();
      if (resource.collectionEtag === null) {
        setSecretInventory(secretMutationReloadRequired());
        return;
      }
      setSecretInventory({
        kind: 'ready',
        value: resource.value,
        collectionEtag: resource.collectionEtag,
      });
    } catch (error) {
      setSecretInventory(secretInventoryLoadError(error));
    }
  }

  const detail =
    loadState.kind === 'ready' ? loadState.detail : null;
  const canEdit =
    loadState.kind === 'ready' &&
    (id === undefined
      ? loadState.canCreate
      : Boolean(loadState.detail?.actions.can_update));
  const readOnlyLegacy =
    detail?.read_only === true || (isEditing && detail?.configuration === undefined);
  const canBindSecret =
    loadState.kind === 'ready' && loadState.canBindSecret;
  const canManageSecrets =
    loadState.kind === 'ready' && loadState.canManageSecrets;
  const canAccessSecretInventory =
    canBindSecret || canManageSecrets;
  const secretsOnlyMode =
    loadState.kind === 'ready' &&
    id === undefined &&
    !loadState.canCreate &&
    loadState.canManageSecrets;
  const secretInventoryReady =
    secretInventory.kind === 'ready' ? secretInventory : null;
  const canUseSecretBindings =
    canBindSecret && secretInventoryReady !== null;
  const availableSecrets = secretInventoryReady?.value.secrets ?? [];
  const credentialAuthorityLocked =
    !canBindSecret && detailConfiguresCredentialAuthority(detail);
  const enablingNow = form.enabled && !form.initiallyEnabled;
  const editorBusy =
    saveState.kind === 'saving' || secretMutationInFlight;

  function bindSecret(purpose: ConnectionSecretPurpose, secretId: string) {
    const replacement: BindingDraft = {
      configured: false,
      intent: 'replace',
      secretId,
    };
    if (purpose === authenticationPurpose(form.authenticationType)) {
      updateForm({ authenticationBinding: replacement });
      return;
    }
    if (purpose === 'tls_ca_bundle') {
      updateForm({ caBundleBinding: replacement });
    } else if (purpose === 'tls_certificate') {
      updateForm({ clientCertificateBinding: replacement });
    } else if (purpose === 'tls_private_key') {
      updateForm({ clientPrivateKeyBinding: replacement });
    }
  }

  function removeDeletedSecret(secretId: string) {
    updateForm((current) => ({
      ...current,
      authenticationBinding: withoutDeletedBinding(
        current.authenticationBinding,
        secretId,
      ),
      caBundleBinding: withoutDeletedBinding(
        current.caBundleBinding,
        secretId,
      ),
      clientCertificateBinding: withoutDeletedBinding(
        current.clientCertificateBinding,
        secretId,
      ),
      clientPrivateKeyBinding: withoutDeletedBinding(
        current.clientPrivateKeyBinding,
        secretId,
      ),
    }));
  }

  return (
    <main className="logs-page connection-editor-page">
      <section
        className="panel logs-panel connection-editor-panel"
        aria-labelledby="connection-editor-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Connections</p>
            <h2 id="connection-editor-heading">
              {isEditing
                ? 'Edit connection'
                : secretsOnlyMode
                  ? 'Manage secrets'
                  : 'New connection'}
            </h2>
          </div>
          <span className="result-count">
            {id ?? (secretsOnlyMode ? 'Safe aliases' : 'Disabled draft')}
          </span>
        </div>

        {secretsOnlyMode ? (
          <p>
            Create, rotate, or delete local secret aliases. Plaintext is sent
            only for the requested operation and is never displayed again.
          </p>
        ) : (
          <>
            <p>
              Configure a saved upstream. New connections stay disabled unless
              you explicitly confirm activation.
            </p>
            <div className="alert info" role="status">
              Saved targets always use the gateway&apos;s production DNS,
              egress, TLS, credential, and policy checks. This editor cannot
              create a network exception.
            </div>
          </>
        )}

        {loadState.kind === 'loading' ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading connection editor
          </div>
        ) : null}

        {loadState.kind === 'error' ? (
          <EditorAlert
            title={loadState.title}
            message={loadState.message}
            tone={loadState.tone}
          />
        ) : null}

        {loadState.kind === 'ready' &&
        id === undefined &&
        !loadState.canCreate &&
        !loadState.canManageSecrets ? (
          <EditorAlert
            title="Create permission required"
            message="The gateway has disabled connection creation for this principal or managed connection storage is unavailable."
            tone="warning"
          />
        ) : null}

        {readOnlyLegacy ? (
          <div className="error-panel alert info" role="status">
            <h3>Read-only legacy connection</h3>
            <p>
              This item is projected from legacy gateway configuration. Migrate
              it to a managed connection before editing it.
            </p>
          </div>
        ) : null}

        {loadState.kind === 'ready' &&
        !readOnlyLegacy &&
        (id === undefined ? loadState.canCreate : detail !== null) ? (
          <form
            className="connection-form"
            onSubmit={(event) => {
              void saveConnection(event);
            }}
            noValidate
          >
            <ConnectionIdentitySection
              form={form}
              errors={fieldErrors}
              disabled={!canEdit || editorBusy}
              sensitiveDisabled={
                !canEdit ||
                editorBusy ||
                credentialAuthorityLocked
              }
              onUpdate={updateForm}
              onKindChange={updateKind}
            />
            <AuthenticationSection
              form={form}
              errors={fieldErrors}
              canBindSecret={canUseSecretBindings}
              secrets={availableSecrets}
              disabled={
                !canEdit ||
                editorBusy ||
                credentialAuthorityLocked ||
                !canBindSecret
              }
              onUpdate={updateForm}
              onAuthenticationTypeChange={updateAuthenticationType}
            />
            <TlsSection
              form={form}
              errors={fieldErrors}
              canBindSecret={canUseSecretBindings}
              secrets={availableSecrets}
              disabled={!canEdit || editorBusy}
              authorityLocked={credentialAuthorityLocked}
              onUpdate={updateForm}
            />
            <TimeoutsAndDiscoverySection
              form={form}
              errors={fieldErrors}
              disabled={!canEdit || editorBusy}
              discoveryTargetDisabled={
                !canEdit ||
                editorBusy ||
                (!canBindSecret &&
                  detail?.configuration?.discovery
                    ?.use_connection_authentication === true)
              }
              discoveryAuthenticationDisabled={
                !canEdit || editorBusy || !canBindSecret
              }
              onUpdate={updateForm}
            />
            <TestProfileSection
              form={form}
              errors={fieldErrors}
              disabled={!canEdit || editorBusy}
              targetDisabled={
                !canEdit ||
                editorBusy ||
                credentialAuthorityLocked
              }
              onUpdate={updateForm}
            />

            {enablingNow ? (
              <label className="connection-enable-confirmation">
                <input
                  type="checkbox"
                  checked={form.enableConfirmed}
                  disabled={!canEdit || editorBusy}
                  onChange={(event) =>
                    updateForm({ enableConfirmed: event.target.checked })
                  }
                />
                I understand that enabling this connection makes it eligible
                for production traffic under the gateway&apos;s normal policy.
              </label>
            ) : null}

            {fieldErrors.form ? (
              <EditorAlert
                title="Review the connection"
                message={fieldErrors.form}
                tone="warning"
              />
            ) : null}
            {saveState.kind === 'error' ? (
              <div
                className={`error-panel alert ${saveState.tone}`}
                role="alert"
                tabIndex={-1}
                ref={saveAlert}
              >
                <h3>{saveState.title}</h3>
                <p>{saveState.message}</p>
                {saveState.conflict || saveState.recovery ? (
                  <button
                    type="button"
                    className="secondary-button"
                    ref={conflictAction}
                    onClick={() => {
                      if (saveState.recovery === 'connections') {
                        navigate('/connections', { replace: true });
                      } else {
                        void reloadAfterConflict();
                      }
                    }}
                  >
                    {saveState.recovery === 'connections'
                      ? 'Return to connections'
                      : id === undefined
                        ? 'Refresh create permission'
                        : 'Reload latest connection'}
                  </button>
                ) : null}
              </div>
            ) : null}
            {saveState.kind === 'saved' ? (
              <div className="error-panel alert success" role="status">
                <h3>Saved</h3>
                <p>{saveState.message}</p>
              </div>
            ) : null}

            <div className="connection-live-region" aria-live="polite">
              {saveState.kind === 'saving' ? 'Saving connection' : ''}
            </div>
            <div className="form-actions">
              <button
                type="submit"
                className="primary-button"
                disabled={
                  !canEdit ||
                  editorBusy ||
                  requiresReload ||
                  secretDraftPresent ||
                  (enablingNow && !form.enableConfirmed)
                }
              >
                {saveState.kind === 'saving'
                  ? 'Saving'
                  : id === undefined
                    ? form.enabled
                      ? 'Create and enable'
                      : 'Save disabled draft'
                    : 'Save connection'}
              </button>
              <Link
                className="secondary-button"
                to="/connections"
                aria-disabled={editorBusy}
                tabIndex={editorBusy ? -1 : undefined}
                onClick={(event) => {
                  if (editorBusy) {
                    event.preventDefault();
                  }
                }}
              >
                Cancel
              </Link>
            </div>
          </form>
        ) : null}

        {canAccessSecretInventory && secretInventory.kind === 'loading' ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading safe secret aliases
          </div>
        ) : null}
        {canAccessSecretInventory && secretInventory.kind === 'error' ? (
          <>
            <div tabIndex={-1} ref={secretInventoryAlert}>
              <EditorAlert
                title={secretInventory.title}
                message={secretInventory.message}
                tone={secretInventory.tone}
              />
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => {
                  void reloadSecretInventory();
                }}
              >
                Reload secret inventory
              </button>
            </div>
          </>
        ) : null}
        {canManageSecrets && secretInventoryReady ? (
          <LocalSecretManager
            inventory={secretInventoryReady}
            canBindSecret={canBindSecret}
            resetKey={secretDraftResetKey(id, form)}
            contextKey={`${id ?? 'new'}|${form.kind}|${form.authenticationType}`}
            onInventoryChange={setSecretInventory}
            onBind={bindSecret}
            onDelete={removeDeletedSecret}
            onMutatingChange={setSecretMutationInFlight}
            onDraftChange={setSecretDraftPresent}
            clearDraftRef={clearSecretDraft}
          />
        ) : null}
      </section>
    </main>
  );
}

function ConnectionIdentitySection({
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

function AuthenticationSection({
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

function TlsSection({
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

function BindingControl({
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

function LocalSecretManager({
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
  onBind: (purpose: ConnectionSecretPurpose, secretId: string) => void;
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
      if (canBindSecret) {
        onBind(purpose, created.id);
      }
      setSelectedSecretId(created.id);
      setLabel('');
      setMode('manage');
      setNotice({
        tone: 'success',
        title: 'Local secret created',
        message:
          canBindSecret
            ? 'The value was accepted, selected for this draft, and cleared from this page. It cannot be revealed again.'
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

function SecretPlaintextInput({
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

function TimeoutsAndDiscoverySection({
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

function TestProfileSection({
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

function NumberField({
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

function FormField({
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

function EditorAlert({
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

function formFromDetail(detail: ConnectionDetail): ConnectionFormState {
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

function detailConfiguresCredentialAuthority(
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
    configuration.tls.ca_bundle_configured ||
    configuration.tls.client_certificate_configured ||
    configuration.tls.client_private_key_configured
  );
}

function writeFromForm(form: ConnectionFormState): ConnectionWrite {
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

function authenticationFromForm(
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

function bindingPayload<
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

function validateForm(
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
  if (
    (form.authenticationType !== 'none' || requestsTls) &&
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

function bindingHasCompatibleSecret(
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

function bindingIsEffectivelyConfigured(
  binding: BindingDraft,
  purpose: ConnectionSecretPurpose,
  secrets: ConnectionSecretMetadata[],
): boolean {
  if (binding.intent === 'preserve') {
    return binding.configured;
  }
  return bindingHasCompatibleSecret(binding, purpose, secrets);
}

function bindingRequestsSecret(binding: BindingDraft): boolean {
  return (
    (binding.intent === 'preserve' && binding.configured) ||
    (binding.intent === 'replace' && binding.secretId.trim().length > 0)
  );
}

function isHttpsOrigin(value: string): boolean {
  try {
    return new URL(value.trim()).protocol === 'https:';
  } catch {
    return false;
  }
}

function validateTimeout(
  value: string,
  field: string,
  errors: FieldErrors,
) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 120000) {
    errors[field] = 'Enter a whole number from 1 to 120000.';
  }
}

function validBaseUrl(value: string): boolean {
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

function validTokenUrl(value: string): boolean {
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

function validOriginRelativePath(value: string): boolean {
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

function parseStatuses(value: string): number[] {
  return splitList(value).map((status) => Number(status));
}

function normalizeList(value: string): string[] {
  return splitList(value);
}

function splitList(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function emptyBinding(): BindingDraft {
  return { configured: false, intent: 'none', secretId: '' };
}

function configuredBinding(): BindingDraft {
  return { configured: true, intent: 'preserve', secretId: '' };
}

function bindingFromMarker(configured: boolean): BindingDraft {
  return configured ? configuredBinding() : emptyBinding();
}

function authenticationPurpose(
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

function withoutDeletedBinding(
  binding: BindingDraft,
  secretId: string,
): BindingDraft {
  return binding.intent === 'replace' && binding.secretId === secretId
    ? emptyBinding()
    : binding;
}

function secretDraftResetKey(
  connectionId: string | undefined,
  form: ConnectionFormState,
): string {
  return [
    connectionId ?? 'new',
    form.kind,
    form.authenticationType,
    bindingKey(form.authenticationBinding),
    bindingKey(form.caBundleBinding),
    bindingKey(form.clientCertificateBinding),
    bindingKey(form.clientPrivateKeyBinding),
  ].join('|');
}

function bindingKey(binding: BindingDraft): string {
  return `${binding.intent}:${binding.secretId}`;
}

function formatSecretProvider(
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

function formatSecretPurpose(
  purpose: ConnectionSecretPurpose | undefined,
): string {
  if (purpose === undefined) {
    return 'unknown purpose';
  }
  return purpose.replaceAll('_', ' ');
}

function secretMaxLength(
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

function isTlsSecretPurpose(
  purpose: ConnectionSecretPurpose | undefined,
): boolean {
  return (
    purpose === 'tls_ca_bundle' ||
    purpose === 'tls_certificate' ||
    purpose === 'tls_private_key'
  );
}

function secretMutationError(
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

function secretInventoryLoadError(error: unknown): SecretInventoryState {
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

function secretMutationReloadRequired(): SecretInventoryState {
  return {
    kind: 'error',
    title: 'Secret inventory reload required',
    message:
      'The mutation completed without a fresh collection precondition token. Reload the editor before another secret operation.',
    tone: 'warning',
  };
}

function secretErrorRequiresReload(error: unknown): boolean {
  return (
    (error instanceof ConnectionSecretContractError &&
      error.requiresReload) ||
    (error instanceof AdminApiError &&
      (error.status === 412 || error.status === 428))
  );
}

function requiredEtag(value: string | null, message: string): string {
  if (value === null) {
    throw new Error(message);
  }
  return value;
}

function describedBy(id: string, error?: string): string | undefined {
  return error ? `${id}-error` : undefined;
}

function focusFirstProblem(errors: FieldErrors) {
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
  const firstField = Object.keys(errors).find((field) => fieldToId[field]);
  if (firstField) {
    queueMicrotask(() => document.getElementById(fieldToId[firstField])?.focus());
  }
}

function fieldErrorsFromProblems(
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

function appendFieldError(
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

function humanizeCode(code: string): string {
  const text = code.replaceAll('_', ' ');
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}.`;
}

function toLoadError(error: unknown): EditorLoadState {
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

function toSaveError(error: unknown): SaveState {
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
