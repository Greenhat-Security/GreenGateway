import {
  FormEvent,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  AuthMethodName,
  PolicyDocument,
  PolicyRule,
  PolicyRuleAction,
  PolicyRulePreviewResponse,
  PolicyRulePreviewSample,
  PrincipalMatcher,
  createPolicyRule,
  fetchPolicy,
  isAuthMethodName,
  isPolicyRuleAction,
  patchPolicyRule,
  previewPolicyRule,
} from '../lib/policy';
import {
  TrafficEndpoint,
  emptyTrafficFilters,
  fetchTrafficEndpoints,
} from '../lib/traffic';
import { RuleWorkspaceNav } from './RuleWorkspaceNav';

export const RULE_PREVIEW_DEBOUNCE_MS = 450;

const RULE_PREVIEW_SAMPLE_LIMIT = 5;
const DEFAULT_PREVIEW_WINDOW_HOURS = 24;
const METHOD_OPTIONS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
];
const AUTH_METHOD_OPTIONS: Array<{
  value: AuthMethodName;
  label: string;
}> = [
  { value: 'bearer_token', label: 'Bearer token' },
  { value: 'session_cookie', label: 'Session cookie' },
  { value: 'service_token', label: 'Service token' },
];
const ACTION_OPTIONS: Array<{
  value: PolicyRuleAction;
  label: string;
  description: string;
}> = [
  {
    value: 'allow',
    label: 'Allow',
    description: 'Forward matching requests.',
  },
  {
    value: 'deny',
    label: 'Deny',
    description: 'Reject matching requests.',
  },
  {
    value: 'shadow',
    label: 'Shadow',
    description: 'Forward and record a would-deny decision.',
  },
];

type RuleFormState = {
  matcherType: 'path' | 'tool';
  methods: string[];
  path: string;
  toolName: string;
  roles: string[];
  roleDraft: string;
  issuers: string[];
  issuerDraft: string;
  authMethods: AuthMethodName[];
  principalIds: string[];
  principalIdDraft: string;
  action: PolicyRuleAction;
};

type FormErrors = {
  path?: string;
  toolName?: string;
};

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready' }
  | { kind: 'error'; title: string; message: string; tone: 'warning' | 'error' };

type SaveState =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'saved'; message: string }
  | { kind: 'error'; title: string; message: string; tone: 'warning' | 'error' };

type PreviewState =
  | { kind: 'idle'; message: string }
  | { kind: 'invalid'; message: string }
  | { kind: 'loading' }
  | { kind: 'ready'; response: PolicyRulePreviewResponse }
  | {
      kind: 'unavailable' | 'forbidden' | 'unauthorized' | 'error';
      title: string;
      message: string;
      tone: 'warning' | 'error';
    };

export function RuleEditor() {
  const [searchParams] = useSearchParams();
  const requestedRuleId = searchParams.get('rule_id')?.trim() || null;
  const [form, setForm] = useState<RuleFormState>(() => ({
    ...emptyRuleForm(),
    ...(requestedRuleId === null ? formFromPrefillParams(searchParams) : {}),
  }));
  const [policyEtag, setPolicyEtag] = useState<string | null>(null);
  const [roleOptions, setRoleOptions] = useState<string[]>([]);
  const [endpointTemplates, setEndpointTemplates] = useState<string[]>([]);
  const [loadState, setLoadState] = useState<LoadState>({ kind: 'loading' });
  const [saveState, setSaveState] = useState<SaveState>({ kind: 'idle' });
  const [previewState, setPreviewState] = useState<PreviewState>({
    kind: 'idle',
    message: 'Enter a path pattern to preview matched traffic.',
  });
  const [errors, setErrors] = useState<FormErrors>({});
  const [previewWindowHours, setPreviewWindowHours] = useState(
    DEFAULT_PREVIEW_WINDOW_HOURS,
  );
  const previewGenerationRef = useRef(0);

  useEffect(() => {
    let isCurrent = true;

    async function loadPolicy() {
      setLoadState({ kind: 'loading' });
      try {
        const response = await fetchPolicy();
        if (!isCurrent) {
          return;
        }

        setPolicyEtag(response.etag);
        setRoleOptions(policyRoleNames(response.policy));

        if (requestedRuleId !== null) {
          const existingRule = response.policy.rules.find(
            (rule) => rule.id === requestedRuleId,
          );
          if (!existingRule) {
            setLoadState({
              kind: 'error',
              title: 'Rule not found',
              message: `No active policy rule has id ${requestedRuleId}.`,
              tone: 'warning',
            });
            return;
          }
          setForm(formFromRule(existingRule));
        }

        setLoadState({ kind: 'ready' });
      } catch (error) {
        if (!isCurrent) {
          return;
        }
        setPolicyEtag(null);
        setLoadState(toPolicyLoadError(error));
      }
    }

    void loadPolicy();

    return () => {
      isCurrent = false;
    };
  }, [requestedRuleId]);

  useEffect(() => {
    let isCurrent = true;

    async function loadEndpointHints() {
      try {
        const response = await fetchTrafficEndpoints(emptyTrafficFilters());
        if (!isCurrent) {
          return;
        }
        setEndpointTemplates(uniqueEndpointTemplates(response.endpoints));
      } catch {
        if (isCurrent) {
          setEndpointTemplates([]);
        }
      }
    }

    void loadEndpointHints();

    return () => {
      isCurrent = false;
    };
  }, []);

  const candidateRule = useMemo(
    () => ruleFromForm(form),
    [
      form.action,
      form.authMethods,
      form.issuers,
      form.matcherType,
      form.methods,
      form.path,
      form.principalIds,
      form.roles,
      form.toolName,
    ],
  );
  const candidateKey = useMemo(
    () => JSON.stringify(candidateRule),
    [candidateRule],
  );
  const matcherError = validateMatcher(form);
  const matcherValue =
    form.matcherType === 'tool' ? form.toolName.trim() : form.path.trim();

  // Invalidate stale preview promises before passive effect cleanup runs.
  useLayoutEffect(() => {
    previewGenerationRef.current += 1;
    return () => {
      previewGenerationRef.current += 1;
    };
  }, [candidateKey, candidateRule, matcherError, matcherValue, previewWindowHours]);

  useEffect(() => {
    const previewGeneration = previewGenerationRef.current;
    const isCurrentPreview = () =>
      previewGenerationRef.current === previewGeneration;
    if (matcherValue.length === 0) {
      setPreviewState({
        kind: 'idle',
        message: 'Enter a matcher to preview matched traffic.',
      });
      return;
    }
    if (matcherError) {
      setPreviewState({
        kind: 'invalid',
        message: matcherError,
      });
      return;
    }

    const controller = new AbortController();
    setPreviewState({ kind: 'loading' });
    const timer = window.setTimeout(() => {
      void loadPreview(controller.signal);
    }, RULE_PREVIEW_DEBOUNCE_MS);

    async function loadPreview(signal: AbortSignal) {
      const windowEnd = new Date();
      const windowStart = new Date(
        windowEnd.valueOf() - previewWindowHours * 60 * 60 * 1000,
      );

      try {
        const response = await previewPolicyRule(
          {
            rule: candidateRule,
            from: windowStart.toISOString(),
            to: windowEnd.toISOString(),
            sample_limit: RULE_PREVIEW_SAMPLE_LIMIT,
          },
          signal,
        );
        if (!isCurrentPreview()) {
          return;
        }
        setPreviewState({ kind: 'ready', response });
      } catch (error) {
        if (signal.aborted || isAbortError(error)) {
          return;
        }
        if (!isCurrentPreview()) {
          return;
        }
        setPreviewState(toPreviewError(error));
      }
    }

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [candidateKey, candidateRule, matcherError, matcherValue, previewWindowHours]);

  function updatePath(value: string) {
    setForm((current) => ({ ...current, path: value }));
    setErrors((current) => ({ ...current, path: undefined }));
    setSaveState({ kind: 'idle' });
  }

  function updateToolName(value: string) {
    setForm((current) => ({ ...current, toolName: value }));
    setErrors((current) => ({ ...current, toolName: undefined }));
    setSaveState({ kind: 'idle' });
  }

  function updateMatcherType(matcherType: RuleFormState['matcherType']) {
    setForm((current) => ({ ...current, matcherType }));
    setErrors({});
    setSaveState({ kind: 'idle' });
  }

  function toggleMethod(method: string) {
    setForm((current) => {
      const hasMethod = current.methods.includes(method);
      const methods = hasMethod
        ? current.methods.filter((item) => item !== method)
        : [...current.methods, method];
      return { ...current, methods };
    });
    setSaveState({ kind: 'idle' });
  }

  function setAnyMethod() {
    setForm((current) => ({ ...current, methods: [] }));
    setSaveState({ kind: 'idle' });
  }

  function toggleAuthMethod(authMethod: AuthMethodName) {
    setForm((current) => {
      const hasAuthMethod = current.authMethods.includes(authMethod);
      const authMethods = hasAuthMethod
        ? current.authMethods.filter((item) => item !== authMethod)
        : [...current.authMethods, authMethod];
      return { ...current, authMethods };
    });
    setSaveState({ kind: 'idle' });
  }

  function updateAction(action: PolicyRuleAction) {
    setForm((current) => ({ ...current, action }));
    setSaveState({ kind: 'idle' });
  }

  function addRole() {
    const value = form.roleDraft.trim();
    if (value.length === 0) {
      return;
    }
    setForm((current) => ({
      ...current,
      roles: addUnique(current.roles, value),
      roleDraft: '',
    }));
    setSaveState({ kind: 'idle' });
  }

  function removeRole(role: string) {
    setForm((current) => ({
      ...current,
      roles: current.roles.filter((item) => item !== role),
    }));
    setSaveState({ kind: 'idle' });
  }

  function addIssuer() {
    const value = form.issuerDraft.trim();
    if (value.length === 0) {
      return;
    }
    setForm((current) => ({
      ...current,
      issuers: addUnique(current.issuers, value),
      issuerDraft: '',
    }));
    setSaveState({ kind: 'idle' });
  }

  function removeIssuer(issuer: string) {
    setForm((current) => ({
      ...current,
      issuers: current.issuers.filter((item) => item !== issuer),
    }));
    setSaveState({ kind: 'idle' });
  }

  function addPrincipalId() {
    const value = form.principalIdDraft.trim();
    if (value.length === 0) {
      return;
    }
    setForm((current) => ({
      ...current,
      principalIds: addUnique(current.principalIds, value),
      principalIdDraft: '',
    }));
    setSaveState({ kind: 'idle' });
  }

  function removePrincipalId(principalId: string) {
    setForm((current) => ({
      ...current,
      principalIds: current.principalIds.filter((item) => item !== principalId),
    }));
    setSaveState({ kind: 'idle' });
  }

  async function saveRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const nextErrors = validateForm(form);
    setErrors(nextErrors);
    setSaveState({ kind: 'idle' });
    if (Object.keys(nextErrors).length > 0) {
      return;
    }

    if (policyEtag === null) {
      setSaveState({
        kind: 'error',
        title: 'Policy ETag unavailable',
        message: 'Refresh the rule editor before saving this rule.',
        tone: 'warning',
      });
      return;
    }

    setSaveState({ kind: 'saving' });
    const rule = ruleFromForm(form);

    try {
      const response =
        requestedRuleId === null
          ? await createPolicyRule(rule, policyEtag)
          : await patchPolicyRule(requestedRuleId, policyEtag, rulePatchFromRule(rule));
      setPolicyEtag(response.etag ?? policyEtag);
      setSaveState({ kind: 'saved', message: 'Rule saved.' });
    } catch (error) {
      setSaveState(toSaveError(error));
    }
  }

  const isEditing = requestedRuleId !== null;
  const heading = isEditing ? 'Edit policy rule' : 'Create policy rule';
  const canRenderForm = loadState.kind === 'ready';

  return (
    <main className="logs-page rule-editor-page">
      <section
        className="panel logs-panel rule-editor-panel"
        aria-labelledby="rule-editor-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Policy</p>
            <h2 id="rule-editor-heading">{heading}</h2>
          </div>
          <span className="result-count">
            {isEditing ? requestedRuleId : 'New rule'}
          </span>
        </div>

        <RuleWorkspaceNav />

        {loadState.kind === 'loading' ? (
          <div className="loading-state" role="status">
            Loading policy
          </div>
        ) : null}

        {loadState.kind === 'error' ? (
          <EditorAlert
            title={loadState.title}
            message={loadState.message}
            tone={loadState.tone}
          />
        ) : null}

        {canRenderForm ? (
          <div className="rule-editor-layout">
            <form className="rule-form" onSubmit={saveRule} noValidate>
              <section
                className="rule-form-section"
                aria-labelledby="rule-match-heading"
              >
                <div className="section-heading">
                  <p className="eyebrow">Matcher</p>
                  <h3 id="rule-match-heading">Request shape</h3>
                </div>

                <fieldset className="rule-fieldset">
                  <legend>Rule target</legend>
                  <div className="rule-check-grid two-column">
                    <label className="rule-check-row">
                      <input
                        type="radio"
                        className="rule-radio"
                        name="rule-matcher-type"
                        checked={form.matcherType === 'path'}
                        onChange={() => updateMatcherType('path')}
                      />
                      HTTP path
                    </label>
                    <label className="rule-check-row">
                      <input
                        type="radio"
                        className="rule-radio"
                        name="rule-matcher-type"
                        checked={form.matcherType === 'tool'}
                        onChange={() => updateMatcherType('tool')}
                      />
                      MCP tool
                    </label>
                  </div>
                </fieldset>

                {form.matcherType === 'path' ? (
                  <>
                    <fieldset className="rule-fieldset">
                      <legend>HTTP methods</legend>
                      <div className="rule-check-grid">
                        <label className="rule-check-row">
                          <input
                            type="checkbox"
                            className="rule-checkbox"
                            checked={form.methods.length === 0}
                            onChange={setAnyMethod}
                          />
                          Any method
                        </label>
                        {METHOD_OPTIONS.map((method) => (
                          <label className="rule-check-row" key={method}>
                            <input
                              type="checkbox"
                              className="rule-checkbox"
                              checked={form.methods.includes(method)}
                              onChange={() => toggleMethod(method)}
                            />
                            {method}
                          </label>
                        ))}
                      </div>
                    </fieldset>

                    <label className="rule-field" htmlFor="rule-path">
                      <span className="field-label">Path pattern</span>
                      <input
                        id="rule-path"
                        className={`rule-input ${errors.path ? 'is-error' : ''}`}
                        type="text"
                        value={form.path}
                        list="rule-path-suggestions"
                        placeholder="/api/users/{id}"
                        spellCheck={false}
                        onChange={(event) => updatePath(event.target.value)}
                      />
                    </label>
                    <datalist id="rule-path-suggestions">
                      {endpointTemplates.map((template) => (
                        <option key={template} value={template} />
                      ))}
                    </datalist>
                    {errors.path ? (
                      <p className="rule-hint is-error">{errors.path}</p>
                    ) : (
                      <p className="rule-hint">
                        Use literal segments, <code>*</code> for one segment,{' '}
                        <code>**</code> for zero or more segments, and{' '}
                        <code>{'{name}'}</code> for a named segment.
                      </p>
                    )}
                  </>
                ) : (
                  <>
                    <label className="rule-field" htmlFor="rule-tool-name">
                      <span className="field-label">Tool name</span>
                      <input
                        id="rule-tool-name"
                        className={`rule-input ${errors.toolName ? 'is-error' : ''}`}
                        type="text"
                        value={form.toolName}
                        placeholder="reports.export"
                        spellCheck={false}
                        onChange={(event) => updateToolName(event.target.value)}
                      />
                    </label>
                    {errors.toolName ? (
                      <p className="rule-hint is-error">{errors.toolName}</p>
                    ) : (
                      <p className="rule-hint">
                        Match one exact MCP tool name.
                      </p>
                    )}
                  </>
                )}
              </section>

              <section
                className="rule-form-section"
                aria-labelledby="rule-principal-heading"
              >
                <div className="section-heading">
                  <p className="eyebrow">Principal</p>
                  <h3 id="rule-principal-heading">Caller constraints</h3>
                </div>

                <TokenListField
                  label="Role constraints"
                  inputId="rule-role"
                  value={form.roleDraft}
                  values={form.roles}
                  placeholder="support"
                  suggestions={roleOptions}
                  suggestionListId="rule-role-suggestions"
                  addButtonLabel="Add role"
                  emptyText="Any role"
                  onChange={(value) =>
                    setForm((current) => ({ ...current, roleDraft: value }))
                  }
                  onAdd={addRole}
                  onRemove={removeRole}
                />

                <TokenListField
                  label="Issuers"
                  inputId="rule-issuer"
                  value={form.issuerDraft}
                  values={form.issuers}
                  placeholder="https://idp.example/"
                  addButtonLabel="Add issuer"
                  emptyText="Any issuer"
                  onChange={(value) =>
                    setForm((current) => ({ ...current, issuerDraft: value }))
                  }
                  onAdd={addIssuer}
                  onRemove={removeIssuer}
                />

                <fieldset className="rule-fieldset">
                  <legend>Auth methods</legend>
                  <div className="rule-check-grid two-column">
                    {AUTH_METHOD_OPTIONS.map((option) => (
                      <label className="rule-check-row" key={option.value}>
                        <input
                          type="checkbox"
                          className="rule-checkbox"
                          checked={form.authMethods.includes(option.value)}
                          onChange={() => toggleAuthMethod(option.value)}
                        />
                        {option.label}
                      </label>
                    ))}
                  </div>
                  <p className="rule-hint">Leave both unchecked for any auth method.</p>
                </fieldset>

                <TokenListField
                  label="Principal IDs"
                  inputId="rule-principal-id"
                  value={form.principalIdDraft}
                  values={form.principalIds}
                  placeholder="user-123"
                  addButtonLabel="Add principal ID"
                  emptyText="Any principal ID"
                  onChange={(value) =>
                    setForm((current) => ({
                      ...current,
                      principalIdDraft: value,
                    }))
                  }
                  onAdd={addPrincipalId}
                  onRemove={removePrincipalId}
                />
              </section>

              <section
                className="rule-form-section"
                aria-labelledby="rule-action-heading"
              >
                <div className="section-heading">
                  <p className="eyebrow">Decision</p>
                  <h3 id="rule-action-heading">Action</h3>
                </div>
                <fieldset className="action-fieldset">
                  <legend className="sr-only">Rule action</legend>
                  <div className="action-choice-grid">
                    {ACTION_OPTIONS.map((option) => (
                      <label
                        className={`action-choice-card ${option.value} ${
                          form.action === option.value ? 'is-selected' : ''
                        }`}
                        key={option.value}
                      >
                        <input
                          type="radio"
                          className="rule-radio"
                          name="rule-action"
                          value={option.value}
                          checked={form.action === option.value}
                          onChange={() => updateAction(option.value)}
                        />
                        <span className={`badge ${actionBadgeClass(option.value)}`}>
                          {option.label}
                        </span>
                        <span>{option.description}</span>
                      </label>
                    ))}
                  </div>
                </fieldset>
              </section>

              <RuleLogicSummary rule={candidateRule} />

              {saveState.kind === 'error' ? (
                <EditorAlert
                  title={saveState.title}
                  message={saveState.message}
                  tone={saveState.tone}
                />
              ) : null}

              {saveState.kind === 'saved' ? (
                <div className="alert info" role="status">
                  {saveState.message}
                </div>
              ) : null}

              <div className="form-actions">
                <button
                  type="submit"
                  className="primary-button"
                  disabled={saveState.kind === 'saving'}
                >
                  {saveState.kind === 'saving' ? 'Saving rule' : 'Save rule'}
                </button>
                <Link className="secondary-button" to="/traffic">
                  View traffic inventory
                </Link>
              </div>
            </form>

            <RulePreviewPanel
              state={previewState}
              windowHours={previewWindowHours}
              onWindowHoursChange={setPreviewWindowHours}
            />
          </div>
        ) : null}
      </section>
    </main>
  );
}

function TokenListField({
  label,
  inputId,
  value,
  values,
  placeholder,
  suggestions = [],
  suggestionListId,
  addButtonLabel,
  emptyText,
  onChange,
  onAdd,
  onRemove,
}: {
  label: string;
  inputId: string;
  value: string;
  values: string[];
  placeholder: string;
  suggestions?: string[];
  suggestionListId?: string;
  addButtonLabel: string;
  emptyText: string;
  onChange: (value: string) => void;
  onAdd: () => void;
  onRemove: (value: string) => void;
}) {
  return (
    <div className="rule-field">
      <label className="field-label" htmlFor={inputId}>
        {label}
      </label>
      <div className="rule-token-row">
        <input
          id={inputId}
          className="rule-input"
          type="text"
          value={value}
          list={suggestionListId}
          placeholder={placeholder}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              onAdd();
            }
          }}
        />
        <button
          type="button"
          className="secondary-button"
          onClick={onAdd}
          disabled={value.trim().length === 0}
        >
          {addButtonLabel}
        </button>
      </div>
      {suggestionListId ? (
        <datalist id={suggestionListId}>
          {suggestions.map((suggestion) => (
            <option key={suggestion} value={suggestion} />
          ))}
        </datalist>
      ) : null}
      <div className="rule-chip-list" aria-label={`${label} selected values`}>
        {values.length === 0 ? (
          <span className="badge neutral">{emptyText}</span>
        ) : (
          values.map((item) => (
            <span className="rule-chip" key={item}>
              {item}
              <button
                type="button"
                aria-label={`Remove ${item}`}
                onClick={() => onRemove(item)}
              >
                x
              </button>
            </span>
          ))
        )}
      </div>
    </div>
  );
}

function RulePreviewPanel({
  state,
  windowHours,
  onWindowHoursChange,
}: {
  state: PreviewState;
  windowHours: number;
  onWindowHoursChange: (value: number) => void;
}) {
  return (
    <aside className="rule-preview-panel" aria-labelledby="rule-preview-heading">
      <div className="section-heading logs-heading">
        <div>
          <p className="eyebrow">Live preview</p>
          <h3 id="rule-preview-heading">Historical matches</h3>
        </div>
        <label className="rule-preview-window">
          Window
          <select
            value={String(windowHours)}
            onChange={(event) =>
              onWindowHoursChange(Number(event.target.value))
            }
          >
            <option value="1">1 hour</option>
            <option value="24">24 hours</option>
            <option value="168">7 days</option>
          </select>
        </label>
      </div>

      {state.kind === 'idle' || state.kind === 'invalid' ? (
        <div className="empty-state">{state.message}</div>
      ) : null}

      {state.kind === 'loading' ? (
        <div className="loading-state" role="status">
          Refreshing preview
        </div>
      ) : null}

      {state.kind === 'ready' ? (
        <PreviewResult response={state.response} windowHours={windowHours} />
      ) : null}

      {state.kind === 'unavailable' ||
      state.kind === 'forbidden' ||
      state.kind === 'unauthorized' ||
      state.kind === 'error' ? (
        <EditorAlert
          title={state.title}
          message={state.message}
          tone={state.tone}
        />
      ) : null}
    </aside>
  );
}

function PreviewResult({
  response,
  windowHours,
}: {
  response: PolicyRulePreviewResponse;
  windowHours: number;
}) {
  return (
    <div className="rule-preview-result">
      <div className="rule-preview-stat">
        <span className="stat-label">Matched requests</span>
        <span className="stat-value">{formatCount(response.match_count)}</span>
        <span className="body-copy">
          This rule would have matched {formatCount(response.match_count)}{' '}
          requests in the last {formatWindowHours(windowHours)}.
        </span>
      </div>
      <div className="rule-preview-meta">
        <span className="badge neutral">
          {formatCount(response.scanned_event_count)} scanned
        </span>
        <span className="badge neutral">{response.sample_strategy}</span>
      </div>
      {response.samples.length === 0 ? (
        <div className="empty-state">No matched request samples returned.</div>
      ) : (
        <div
          className="rule-preview-sample-list"
          role="list"
          aria-label="Matched request samples"
        >
          {response.samples.map((sample) => (
            <article
              className="rule-preview-sample"
              role="listitem"
              key={sample.event_id}
            >
              <div className="rule-preview-request">
                <span className="badge neutral">{sample.method}</span>
                <span className="endpoint-template">{sample.path}</span>
              </div>
              <dl className="rule-preview-sample-meta">
                <div>
                  <dt>Status</dt>
                  <dd>{sample.status ?? '-'}</dd>
                </div>
                <div>
                  <dt>Actor</dt>
                  <dd>{actorLabel(sample)}</dd>
                </div>
                <div>
                  <dt>Current rule</dt>
                  <dd>{activeRuleLabel(sample)}</dd>
                </div>
              </dl>
              <time className="timestamp-cell" dateTime={sample.timestamp}>
                {sample.timestamp}
              </time>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function EditorAlert({
  title,
  message,
  tone,
}: {
  title: string;
  message: string;
  tone: 'warning' | 'error';
}) {
  return (
    <div className={`error-panel alert ${tone}`} role="alert">
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}

function emptyRuleForm(): RuleFormState {
  return {
    matcherType: 'path',
    methods: [],
    path: '',
    toolName: '',
    roles: [],
    roleDraft: '',
    issuers: [],
    issuerDraft: '',
    authMethods: [],
    principalIds: [],
    principalIdDraft: '',
    action: 'deny',
  };
}

function formFromPrefillParams(
  searchParams: URLSearchParams,
): Partial<RuleFormState> {
  const form: Partial<RuleFormState> = {};

  const method = trimmedSearchParam(searchParams, 'prefill_method');
  if (method !== null && method !== '*') {
    form.methods = [method.toUpperCase()];
  }

  const path = trimmedSearchParam(searchParams, 'prefill_path');
  if (path !== null) {
    form.matcherType = 'path';
    form.path = path;
  }

  const toolName = trimmedSearchParam(searchParams, 'prefill_tool_name');
  if (toolName !== null) {
    form.matcherType = 'tool';
    form.methods = [];
    form.toolName = toolName;
  }

  const role = trimmedSearchParam(searchParams, 'prefill_role');
  if (role !== null) {
    form.roles = [role];
  }

  const issuer = trimmedSearchParam(searchParams, 'prefill_issuer');
  if (issuer !== null) {
    form.issuers = [issuer];
  }

  const authMethod = trimmedSearchParam(searchParams, 'prefill_auth_method');
  if (authMethod !== null && isAuthMethodName(authMethod)) {
    form.authMethods = [authMethod];
  }

  const principalId = trimmedSearchParam(searchParams, 'prefill_principal_id');
  if (principalId !== null) {
    form.principalIds = [principalId];
  }

  const action = trimmedSearchParam(searchParams, 'prefill_action');
  if (action !== null && isPolicyRuleAction(action)) {
    form.action = action;
  }

  return form;
}

function RuleLogicSummary({ rule }: { rule: PolicyRule }) {
  return (
    <section
      className="rule-form-section rule-logic-summary"
      aria-labelledby="rule-logic-summary-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Policy logic</p>
        <h3 id="rule-logic-summary-heading">Rule logic</h3>
      </div>
      <div className="rule-summary-box">
        <span className="stat-label">Rule summary</span>
        <p aria-label="Rule summary">
          {plainEnglishRuleSummary(rule)}
        </p>
      </div>
      <div className="rule-expression-box">
        <span className="stat-label">Policy expression</span>
        <pre aria-label="Policy expression">
          <code>{generatedExpression(rule)}</code>
        </pre>
      </div>
    </section>
  );
}

function plainEnglishRuleSummary(rule: PolicyRule): string {
  const target =
    rule.tool_name && rule.tool_name.trim().length > 0
      ? `MCP tool calls to ${rule.tool_name.trim()}`
      : `${formatMethodsForSummary(rule.methods ?? [])} requests to ${
          rule.path?.trim() || '(path not set)'
        }`;
  const principal = principalSummary(rule.principal);

  return `${actionSummaryVerb(rule.action)} ${target}${principal}.`;
}

function generatedExpression(rule: PolicyRule): string {
  const lines: string[] = [];

  if (rule.tool_name && rule.tool_name.trim().length > 0) {
    lines.push(`mcp.tool == ${JSON.stringify(rule.tool_name.trim())}`);
  } else {
    const methods = normalizeMethods(rule.methods ?? []);
    if (methods.length > 0) {
      lines.push(`request.method in ${JSON.stringify(methods)}`);
    } else {
      lines.push('request.method matches "*"');
    }
    lines.push(
      `request.path matches ${JSON.stringify(rule.path?.trim() || '(path not set)')}`,
    );
  }

  for (const role of normalizeStrings(rule.principal?.roles ?? [])) {
    lines.push(`principal.roles contains ${JSON.stringify(role)}`);
  }
  const issuers = normalizeStrings(rule.principal?.issuers ?? []);
  if (issuers.length > 0) {
    lines.push(`principal.issuer in ${JSON.stringify(issuers)}`);
  }
  const authMethods = normalizeAuthMethods(rule.principal?.auth_methods ?? []);
  if (authMethods.length > 0) {
    lines.push(`principal.auth_method in ${JSON.stringify(authMethods)}`);
  }
  const principalIds = normalizeStrings(rule.principal?.principal_ids ?? []);
  if (principalIds.length > 0) {
    lines.push(`principal.id in ${JSON.stringify(principalIds)}`);
  }
  lines.push(`decision = ${JSON.stringify(rule.action)}`);

  return lines.join('\nAND ');
}

function actionSummaryVerb(action: PolicyRuleAction): string {
  switch (action) {
    case 'allow':
      return 'Allow';
    case 'deny':
      return 'Deny';
    case 'shadow':
      return 'Log-only';
  }
}

function formatMethodsForSummary(methods: string[]): string {
  const normalized = normalizeMethods(methods);
  return normalized.length > 0 ? normalized.join(', ') : 'any method';
}

function principalSummary(principal: PrincipalMatcher | undefined): string {
  const parts: string[] = [];
  const roles = normalizeStrings(principal?.roles ?? []);
  const issuers = normalizeStrings(principal?.issuers ?? []);
  const authMethods = normalizeAuthMethods(principal?.auth_methods ?? []);
  const principalIds = normalizeStrings(principal?.principal_ids ?? []);

  if (roles.length > 0) {
    parts.push(`${roles.length === 1 ? 'role' : 'roles'} ${joinHumanList(roles)}`);
  }
  if (issuers.length > 0) {
    parts.push(
      `${issuers.length === 1 ? 'issuer' : 'issuers'} ${joinHumanList(issuers)}`,
    );
  }
  if (authMethods.length > 0) {
    parts.push(
      `${authMethods.length === 1 ? 'auth method' : 'auth methods'} ${joinHumanList(
        authMethods.map(formatAuthMethod),
      )}`,
    );
  }
  if (principalIds.length > 0) {
    parts.push(
      `${principalIds.length === 1 ? 'principal' : 'principals'} ${joinHumanList(
        principalIds,
      )}`,
    );
  }

  return parts.length > 0 ? ` for ${joinHumanList(parts)}` : ' for any principal';
}

function joinHumanList(values: string[]): string {
  if (values.length === 0) {
    return '';
  }
  if (values.length === 1) {
    return values[0];
  }
  if (values.length === 2) {
    return `${values[0]} and ${values[1]}`;
  }

  return `${values.slice(0, -1).join(', ')}, and ${values[values.length - 1]}`;
}

function formatAuthMethod(value: string): string {
  switch (value) {
    case 'bearer_token':
      return 'bearer token';
    case 'session_cookie':
      return 'session cookie';
    case 'service_token':
      return 'service token';
    default:
      return value;
  }
}

function formFromRule(rule: PolicyRule): RuleFormState {
  const toolName = rule.tool_name?.trim() ?? '';
  return {
    matcherType: toolName.length > 0 ? 'tool' : 'path',
    methods: normalizeMethods(rule.methods ?? []),
    path: rule.path ?? '',
    toolName,
    roles: normalizeStrings(rule.principal?.roles ?? []),
    roleDraft: '',
    issuers: normalizeStrings(rule.principal?.issuers ?? []),
    issuerDraft: '',
    authMethods: normalizeAuthMethods(rule.principal?.auth_methods ?? []),
    principalIds: normalizeStrings(rule.principal?.principal_ids ?? []),
    principalIdDraft: '',
    action: rule.action,
  };
}

function ruleFromForm(form: RuleFormState): PolicyRule {
  if (form.matcherType === 'tool') {
    return {
      methods: [],
      tool_name: form.toolName.trim(),
      principal: principalFromForm(form),
      action: form.action,
    };
  }

  return {
    methods: normalizeMethods(form.methods),
    path: form.path.trim(),
    principal: principalFromForm(form),
    action: form.action,
  };
}

function rulePatchFromRule(rule: PolicyRule) {
  const patch = {
    methods: rule.methods,
    principal: rule.principal,
    action: rule.action,
  };

  return rule.tool_name
    ? { ...patch, path: null, tool_name: rule.tool_name }
    : { ...patch, path: rule.path, tool_name: null };
}

function principalFromForm(form: RuleFormState): PrincipalMatcher {
  return {
    roles: normalizeStrings(form.roles),
    issuers: normalizeStrings(form.issuers),
    auth_methods: normalizeAuthMethods(form.authMethods),
    principal_ids: normalizeStrings(form.principalIds),
  };
}

function validateForm(form: RuleFormState): FormErrors {
  if (form.matcherType === 'tool') {
    const toolName = validateToolName(form.toolName);
    return toolName ? { toolName } : {};
  }

  const path = validatePathPattern(form.path);
  return path ? { path } : {};
}

function validateMatcher(form: RuleFormState): string | undefined {
  if (form.matcherType === 'tool') {
    return validateToolName(form.toolName);
  }

  return validatePathPattern(form.path);
}

function validatePathPattern(value: string): string | undefined {
  const path = value.trim();
  if (path.length === 0) {
    return 'Path pattern is required.';
  }
  if (!path.startsWith('/')) {
    return "Path pattern must start with '/'.";
  }
  if (path.includes('?') || path.includes('#')) {
    return 'Path pattern must not include a query string or fragment.';
  }

  const tail = path.slice(1);
  if (tail.length === 0) {
    return undefined;
  }

  for (const segment of tail.split('/')) {
    if (segment === '*' || segment === '**') {
      continue;
    }
    if (segment.includes('{') || segment.includes('}')) {
      if (!/^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(segment)) {
        return 'Capture names must start with a letter or underscore and contain only ASCII letters, digits, and underscores.';
      }
    }
  }

  return undefined;
}

function validateToolName(value: string): string | undefined {
  if (value.trim().length === 0) {
    return 'Tool name is required.';
  }

  return undefined;
}

function normalizeStrings(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => value.trim()).filter(Boolean)),
  );
}

function normalizeMethods(values: string[]): string[] {
  if (values.length === 0 || values.includes('*')) {
    return [];
  }
  return normalizeStrings(values).map((method) => method.toUpperCase());
}

function normalizeAuthMethods(values: string[]): AuthMethodName[] {
  return values.filter(isAuthMethodName);
}

function addUnique(values: string[], value: string): string[] {
  return normalizeStrings([...values, value]);
}

function trimmedSearchParam(
  searchParams: URLSearchParams,
  name: string,
): string | null {
  const value = searchParams.get(name)?.trim();
  return value && value.length > 0 ? value : null;
}

function policyRoleNames(policy: PolicyDocument): string[] {
  return Object.keys(policy.roles ?? {}).sort((left, right) =>
    left.localeCompare(right),
  );
}

function uniqueEndpointTemplates(endpoints: TrafficEndpoint[]): string[] {
  return Array.from(
    new Set(
      endpoints
        .filter((endpoint) => endpoint.method.trim().toUpperCase() !== 'MCP')
        .map((endpoint) => endpoint.endpoint_template.trim())
        .filter(Boolean),
    ),
  ).sort((left, right) => left.localeCompare(right));
}

function toPolicyLoadError(error: unknown): LoadState {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        kind: 'error',
        title: 'Bearer token required',
        message: 'Paste a bearer token before editing policy rules.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        kind: 'error',
        title: 'Policy read permission required',
        message: 'This token is valid but does not include admin:policy:read.',
        tone: 'error',
      };
    }
    return {
      kind: 'error',
      title: 'Policy load failed',
      message: error.message,
      tone: error.status === 400 ? 'warning' : 'error',
    };
  }

  if (error instanceof Error) {
    return {
      kind: 'error',
      title: 'Policy load failed',
      message: `Network request failed: ${error.message}`,
      tone: 'error',
    };
  }

  return {
    kind: 'error',
    title: 'Policy load failed',
    message: 'Network request failed.',
    tone: 'error',
  };
}

function toPreviewError(error: unknown): PreviewState {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        kind: 'unauthorized',
        title: 'Bearer token required',
        message: 'Paste a bearer token before previewing policy rules.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        kind: 'forbidden',
        title: 'Preview permission required',
        message: 'This token is valid but does not include admin:policy:read.',
        tone: 'error',
      };
    }
    if (error.status === 503) {
      return {
        kind: 'unavailable',
        title: 'Live preview unavailable',
        message:
          'Preview requires AUDIT_SQLITE_PATH to be configured. You can still save the rule.',
        tone: 'warning',
      };
    }
    return {
      kind: 'error',
      title: error.status === 400 ? 'Invalid preview rule' : 'Preview failed',
      message: error.message,
      tone: error.status === 400 ? 'warning' : 'error',
    };
  }

  if (error instanceof Error) {
    return {
      kind: 'error',
      title: 'Preview failed',
      message: `Network request failed: ${error.message}`,
      tone: 'error',
    };
  }

  return {
    kind: 'error',
    title: 'Preview failed',
    message: 'Network request failed.',
    tone: 'error',
  };
}

function toSaveError(error: unknown): SaveState {
  if (error instanceof AdminApiError) {
    if (error.status === 412) {
      return {
        kind: 'error',
        title: 'Policy changed',
        message:
          'Policy changed while you were editing. Refresh the rule editor and retry with the latest policy.',
        tone: 'warning',
      };
    }
    if (error.status === 428) {
      return {
        kind: 'error',
        title: 'Policy ETag required',
        message: 'Refresh the rule editor before saving this rule.',
        tone: 'warning',
      };
    }
    if (error.status === 403) {
      return {
        kind: 'error',
        title: 'Policy write permission required',
        message: 'This token is valid but does not include admin:policy:write.',
        tone: 'error',
      };
    }
    if (error.status === 401) {
      return {
        kind: 'error',
        title: 'Bearer token required',
        message: 'Paste a bearer token before saving policy rules.',
        tone: 'warning',
      };
    }
    return {
      kind: 'error',
      title: error.status === 400 ? 'Rule validation failed' : 'Rule save failed',
      message: error.message,
      tone: error.status === 400 ? 'warning' : 'error',
    };
  }

  if (error instanceof Error) {
    return {
      kind: 'error',
      title: 'Rule save failed',
      message: `Network request failed: ${error.message}`,
      tone: 'error',
    };
  }

  return {
    kind: 'error',
    title: 'Rule save failed',
    message: 'Network request failed.',
    tone: 'error',
  };
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

function actionBadgeClass(action: PolicyRuleAction): string {
  switch (action) {
    case 'allow':
      return 'success';
    case 'deny':
      return 'danger';
    case 'shadow':
      return 'warning';
  }
}

function actorLabel(sample: PolicyRulePreviewSample): string {
  return sample.actor?.user_id ?? '-';
}

function activeRuleLabel(sample: PolicyRulePreviewSample): string {
  return sample.matched_rule_id ?? sample.policy_decision ?? 'No active rule';
}

function formatWindowHours(hours: number): string {
  if (hours === 1) {
    return '1 hour';
  }
  if (hours === 24) {
    return '24 hours';
  }
  if (hours % 24 === 0) {
    return `${hours / 24} days`;
  }
  return `${hours} hours`;
}

function formatCount(value: number): string {
  return value.toLocaleString();
}
