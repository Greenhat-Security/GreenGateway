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
  updateConnection,
  type ConnectionKind
} from '../lib/connections';
import {
  listConnectionSecrets,
  type ConnectionSecretPurpose
} from '../lib/secrets';

import {
  AdditionalHeaderDraft,
  additionalHeaderWithPatch,
  authenticationPurpose,
  AuthenticationType,
  BindingDraft,
  configuredBinding,
  ConnectionFormState,
  DEFAULT_FORM,
  detailConfiguresCredentialAuthority,
  EditorLoadState,
  emptyAdditionalHeader,
  emptyBinding,
  FieldErrors,
  fieldErrorsFromProblems,
  focusFirstProblem,
  formFromDetail,
  MAX_ADDITIONAL_HEADERS,
  requiredEtag,
  SaveState,
  secretDraftResetKey,
  secretInventoryLoadError,
  SecretInventoryState,
  secretMutationReloadRequired,
  toLoadError,
  toSaveError,
  validateForm,
  withoutDeletedBinding,
  writeFromForm,
} from './connection-editor/model';
import {
  AdditionalHeadersSection,
  AuthenticationSection,
  ConnectionIdentitySection,
  EditorAlert,
  LocalSecretManager,
  TestProfileSection,
  TimeoutsAndDiscoverySection,
  TlsSection,
} from './connection-editor/sections';
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

  function addAdditionalHeader() {
    updateForm((current) =>
      current.additionalHeaders.length >= MAX_ADDITIONAL_HEADERS
        ? current
        : {
          ...current,
          additionalHeaders: [
            ...current.additionalHeaders,
            emptyAdditionalHeader(),
          ],
        },
    );
  }

  function updateAdditionalHeader(
    index: number,
    patch: Partial<Pick<AdditionalHeaderDraft, 'headerName' | 'binding'>>,
  ) {
    updateForm((current) => ({
      ...current,
      additionalHeaders: current.additionalHeaders.map((header, position) =>
        position === index
          ? additionalHeaderWithPatch(header, patch)
          : header,
      ),
    }));
  }

  function removeAdditionalHeader(index: number) {
    updateForm((current) => ({
      ...current,
      additionalHeaders: current.additionalHeaders.filter(
        (_header, position) => position !== index,
      ),
    }));
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

  // Returns whether a field on this form actually took the secret. A secret
  // whose purpose is neither the current authentication purpose nor one of the
  // TLS purposes has nowhere to go, and the caller must not report it as
  // selected.
  function bindSecret(
    purpose: ConnectionSecretPurpose,
    secretId: string,
  ): boolean {
    const replacement: BindingDraft = {
      configured: false,
      intent: 'replace',
      secretId,
    };
    if (purpose === authenticationPurpose(form.authenticationType)) {
      updateForm({ authenticationBinding: replacement });
      return true;
    }
    if (purpose === 'tls_ca_bundle') {
      updateForm({ caBundleBinding: replacement });
      return true;
    }
    if (purpose === 'tls_certificate') {
      updateForm({ clientCertificateBinding: replacement });
      return true;
    }
    if (purpose === 'tls_private_key') {
      updateForm({ clientPrivateKeyBinding: replacement });
      return true;
    }
    return false;
  }

  function removeDeletedSecret(secretId: string) {
    updateForm((current) => ({
      ...current,
      authenticationBinding: withoutDeletedBinding(
        current.authenticationBinding,
        secretId,
      ),
      additionalHeaders: current.additionalHeaders.map((header) => ({
        ...header,
        binding: withoutDeletedBinding(header.binding, secretId),
      })),
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
            <AdditionalHeadersSection
              headers={form.additionalHeaders}
              errors={fieldErrors}
              canBindSecret={canUseSecretBindings}
              secrets={availableSecrets}
              disabled={
                !canEdit ||
                editorBusy ||
                credentialAuthorityLocked ||
                !canBindSecret
              }
              onAdd={addAdditionalHeader}
              onUpdate={updateAdditionalHeader}
              onRemove={removeAdditionalHeader}
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
