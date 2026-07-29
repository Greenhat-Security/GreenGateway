import {
  FormEvent,
  useEffect,
  useRef,
  useState,
} from 'react';
import { Link, useParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  CapabilityContractError,
  type CapabilityDetail,
  getCapability,
} from '../lib/capabilityInventory';
import {
  ToolExecutionContractError,
  type ToolExecutionResult,
  executeCapability,
  isStrongExecutionEtag,
} from '../lib/toolPlayground';

// The backend's 64 KiB request limit includes the fixed
// `{"arguments":...}` envelope added by the API client.
const MAX_ARGUMENT_INPUT_BYTES = 65_536 - 14;
const EMPTY_ARGUMENTS = '{}';

type PlaygroundFeedback = {
  tone: 'success' | 'warning' | 'error';
  title: string;
  message: string;
};

export function ToolPlayground() {
  const { id = '' } = useParams<{ id: string }>();
  const [reloadKey, setReloadKey] = useState(0);
  const [detail, setDetail] = useState<CapabilityDetail | null>(null);
  const [etag, setEtag] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadFeedback, setLoadFeedback] =
    useState<PlaygroundFeedback | null>(null);
  const [argumentsText, setArgumentsText] = useState(EMPTY_ARGUMENTS);
  const argumentsRef = useRef(EMPTY_ARGUMENTS);
  const [result, setResult] = useState<ToolExecutionResult | null>(null);
  const [runFeedback, setRunFeedback] =
    useState<PlaygroundFeedback | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const runningRef = useRef(false);
  const requiresArgumentEditRef = useRef(false);
  const executionController = useRef<AbortController | null>(null);
  const feedbackRef = useRef<HTMLDivElement | null>(null);
  const resultRef = useRef<HTMLElement | null>(null);
  const [announcement, setAnnouncement] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    executionController.current?.abort();
    executionController.current = null;
    runningRef.current = false;
    requiresArgumentEditRef.current = false;
    argumentsRef.current = EMPTY_ARGUMENTS;
    setArgumentsText(EMPTY_ARGUMENTS);
    setResult(null);
    setRunFeedback(null);
    setLoadFeedback(null);
    setAnnouncement('');
    setIsRunning(false);
    setDetail(null);
    setEtag(null);
    setIsLoading(true);

    async function load() {
      if (id.trim().length === 0) {
        setLoadFeedback({
          tone: 'error',
          title: 'Tool playground unavailable',
          message: 'A valid opaque inventory ID is required.',
        });
        setIsLoading(false);
        return;
      }
      try {
        const resource = await getCapability(id, controller.signal);
        if (controller.signal.aborted) {
          return;
        }
        setDetail(resource.value);
        if (!isStrongExecutionEtag(resource.etag)) {
          setLoadFeedback({
            tone: 'warning',
            title: 'Execution validator unavailable',
            message:
              'Reload the tool before running it. No execution request was sent.',
          });
          setEtag(null);
        } else {
          setEtag(resource.etag);
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          setLoadFeedback(playgroundLoadError(error));
        }
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    }

    void load();
    return () => {
      controller.abort();
      executionController.current?.abort();
      executionController.current = null;
      runningRef.current = false;
      requiresArgumentEditRef.current = false;
      argumentsRef.current = EMPTY_ARGUMENTS;
    };
  }, [id, reloadKey]);

  useEffect(() => {
    if (loadFeedback !== null || runFeedback !== null) {
      feedbackRef.current?.focus();
    }
  }, [loadFeedback, runFeedback]);

  useEffect(() => {
    if (result !== null) {
      resultRef.current?.focus();
    }
  }, [result]);

  function updateArguments(value: string) {
    requiresArgumentEditRef.current = false;
    argumentsRef.current = value;
    setArgumentsText(value);
    setRunFeedback(null);
  }

  async function runTool(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (runningRef.current || requiresArgumentEditRef.current) {
      return;
    }
    runningRef.current = true;

    setResult(null);
    setRunFeedback(null);
    setAnnouncement('Previous result cleared.');

    let submittedText = argumentsRef.current;
    argumentsRef.current = EMPTY_ARGUMENTS;
    setArgumentsText(EMPTY_ARGUMENTS);

    try {
      if (utf8Length(submittedText) > MAX_ARGUMENT_INPUT_BYTES) {
        throw new Error('too large');
      }
      const parsed = JSON.parse(submittedText) as unknown;
      if (!isJsonObject(parsed)) {
        submittedText = '';
        runningRef.current = false;
        requiresArgumentEditRef.current = true;
        setRunFeedback({
          tone: 'error',
          title: 'JSON object required',
          message:
            'Arguments must be one JSON object. Arrays, scalars, and null are not accepted.',
        });
        return;
      }
    } catch {
      submittedText = '';
      runningRef.current = false;
      requiresArgumentEditRef.current = true;
      setRunFeedback({
        tone: 'error',
        title: 'Valid JSON object required',
        message:
          'Enter one valid JSON object. The submitted text was cleared.',
      });
      return;
    }

    if (
      detail === null ||
      !detail.actions.can_execute ||
      etag === null
    ) {
      submittedText = '';
      runningRef.current = false;
      setRunFeedback({
        tone: 'warning',
        title: 'Tool execution unavailable',
        message:
          'Reload the current tool and confirm that the server permits execution.',
      });
      return;
    }

    const controller = new AbortController();
    executionController.current?.abort();
    executionController.current = controller;
    setIsRunning(true);
    setAnnouncement('Tool execution started. Submitted arguments were cleared.');

    try {
      const execution = executeCapability(
        detail.id,
        submittedText,
        etag,
        controller.signal,
      );
      submittedText = '';
      const resource = await execution;
      if (controller.signal.aborted) {
        return;
      }
      setResult(resource.value);
      setRunFeedback(null);
      setAnnouncement('Tool execution completed.');
    } catch (error) {
      submittedText = '';
      if (controller.signal.aborted) {
        return;
      }
      if (
        error instanceof ToolExecutionContractError ||
        (error instanceof AdminApiError &&
          (error.status === 404 ||
            error.status === 412 ||
            error.status === 428))
      ) {
        setEtag(null);
      }
      setRunFeedback(playgroundRunError(error));
      setAnnouncement('Tool execution failed. No result was retained.');
    } finally {
      submittedText = '';
      if (executionController.current === controller) {
        executionController.current = null;
      }
      if (!controller.signal.aborted) {
        runningRef.current = false;
        setIsRunning(false);
      }
    }
  }

  function reloadTool() {
    executionController.current?.abort();
    executionController.current = null;
    runningRef.current = false;
    requiresArgumentEditRef.current = false;
    argumentsRef.current = EMPTY_ARGUMENTS;
    setArgumentsText(EMPTY_ARGUMENTS);
    setResult(null);
    setRunFeedback(null);
    setAnnouncement('Reloading current tool metadata.');
    setReloadKey((current) => current + 1);
  }

  function clearResult() {
    setResult(null);
    setRunFeedback(null);
    setAnnouncement('Tool result cleared.');
  }

  const executeReason =
    detail === null
      ? 'Tool metadata is not loaded'
      : !detail.actions.can_execute
        ? executeReasonMessage(detail.actions.reason)
        : etag === null
          ? 'Reload the current tool to obtain a strong execution validator'
          : null;
  const runDisabled =
    isLoading || isRunning || executeReason !== null || loadFeedback !== null;
  const heading = detail?.title?.trim() || detail?.name || 'Tool playground';

  return (
    <main className="logs-page capability-detail-page tool-playground-page">
      <section
        className="panel logs-panel capability-detail-panel tool-playground-panel"
        aria-labelledby="tool-playground-heading"
      >
        <div className="section-heading logs-heading traffic-detail-heading">
          <div>
            <p className="eyebrow">Constrained execution</p>
            <h2 id="tool-playground-heading">Tool playground</h2>
            {detail ? <p className="body-copy">{heading}</p> : null}
          </div>
          <div className="capability-actions">
            <Link
              className="secondary-button"
              to={`/tools/${encodeURIComponent(id)}`}
            >
              Back to tool details
            </Link>
            <Link className="secondary-button" to="/tools">
              Back to inventory
            </Link>
          </div>
        </div>

        <p className="body-copy">
          This page can invoke only this registered inventory tool through the
          gateway&apos;s normal authorization, policy, executor, and egress
          path. It cannot override URLs, methods, headers, TLS, or timeouts.
        </p>

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading tool playground
          </div>
        ) : null}

        {loadFeedback ? (
          <PlaygroundFeedbackPanel
            feedback={loadFeedback}
            feedbackRef={feedbackRef}
            onReload={reloadTool}
          />
        ) : null}

        {!isLoading && detail !== null ? (
          <div className="tool-playground-layout">
            <form
              className="connection-form tool-playground-form"
              onSubmit={(event) => {
                void runTool(event);
              }}
              noValidate
            >
              <section
                className="connection-form-section"
                aria-labelledby="tool-arguments-heading"
              >
                <div className="section-heading">
                  <p className="eyebrow">Input</p>
                  <h3 id="tool-arguments-heading">Arguments</h3>
                </div>
                <label htmlFor="tool-playground-arguments">
                  Arguments (JSON)
                  <textarea
                    id="tool-playground-arguments"
                    value={argumentsText}
                    maxLength={MAX_ARGUMENT_INPUT_BYTES}
                    disabled={runDisabled}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="{}"
                    aria-describedby="tool-playground-arguments-help"
                    onChange={(event) => updateArguments(event.target.value)}
                  />
                </label>
                <p id="tool-playground-arguments-help" className="body-copy">
                  Enter one JSON object. The gateway remains authoritative for
                  the registered input schema and policy decision. Submitted
                  text is cleared when a run begins.
                </p>
                <div className="form-actions">
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={runDisabled}
                    aria-describedby={
                      executeReason
                        ? 'tool-playground-disabled-reason'
                        : undefined
                    }
                  >
                    {isRunning ? 'Running tool' : 'Run tool'}
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    disabled={result === null}
                    onClick={clearResult}
                  >
                    Clear result
                  </button>
                </div>
                {executeReason ? (
                  <p
                    id="tool-playground-disabled-reason"
                    className="alert info"
                    role="status"
                  >
                    <strong>Run unavailable:</strong> {executeReason}.
                  </p>
                ) : null}
              </section>
            </form>

            <section
              className="capability-detail-section tool-playground-schema"
              aria-labelledby="tool-playground-schema-heading"
            >
              <div className="section-heading">
                <p className="eyebrow">Server contract</p>
                <h3 id="tool-playground-schema-heading">Input JSON schema</h3>
              </div>
              {detail.input_json_schema === undefined ? (
                <p>No input schema was advertised. The server still validates arguments.</p>
              ) : (
                <pre className="capability-schema">
                  {JSON.stringify(detail.input_json_schema, null, 2)}
                </pre>
              )}
            </section>
          </div>
        ) : null}

        {runFeedback ? (
          <PlaygroundFeedbackPanel
            feedback={runFeedback}
            feedbackRef={feedbackRef}
            onReload={
              etag === null
                ? reloadTool
                : undefined
            }
          />
        ) : null}

        {result ? (
          <ToolResult result={result} resultRef={resultRef} />
        ) : null}

        <p
          className="capability-live-region sr-only"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          {announcement}
        </p>
      </section>
    </main>
  );
}

function ToolResult({
  result,
  resultRef,
}: {
  result: ToolExecutionResult;
  resultRef: { current: HTMLElement | null };
}) {
  const output =
    result.kind === 'http' && result.body.type === 'text'
      ? result.body.value
      : JSON.stringify(
          result.kind === 'http' ? result.body.value : result,
          null,
          2,
        );
  return (
    <section
      className="capability-detail-section tool-playground-result"
      aria-labelledby="tool-playground-result-heading"
      tabIndex={-1}
      ref={resultRef}
    >
      <div className="section-heading">
        <p className="eyebrow">Latest bounded output</p>
        <h3 id="tool-playground-result-heading">Tool result</h3>
      </div>
      {result.kind === 'http' ? (
        <p>
          HTTP status <strong>{result.status}</strong>
        </p>
      ) : (
        <p>
          MCP result {result.is_error ? 'reported an error' : 'completed'}.
        </p>
      )}
      <pre className="signal-evidence tool-playground-output">{output}</pre>
    </section>
  );
}

function PlaygroundFeedbackPanel({
  feedback,
  feedbackRef,
  onReload,
}: {
  feedback: PlaygroundFeedback;
  feedbackRef: { current: HTMLDivElement | null };
  onReload?: () => void;
}) {
  return (
    <div
      className={`error-panel alert ${feedback.tone}`}
      role={feedback.tone === 'success' ? 'status' : 'alert'}
      aria-label={feedback.title}
      tabIndex={-1}
      ref={feedbackRef}
    >
      <h3>{feedback.title}</h3>
      <p>{feedback.message}</p>
      {onReload ? (
        <button
          type="button"
          className="secondary-button"
          onClick={onReload}
        >
          Reload current tool
        </button>
      ) : null}
    </div>
  );
}

function playgroundLoadError(error: unknown): PlaygroundFeedback {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return {
        tone: 'warning',
        title: 'Bearer token required',
        message: 'Authenticate before opening the tool playground.',
      };
    }
    if (error.status === 403) {
      return {
        tone: 'warning',
        title: 'Tool playground permission required',
        message: 'This principal cannot read the requested tool metadata.',
      };
    }
    if (error.status === 404) {
      return {
        tone: 'warning',
        title: 'Tool not found',
        message: 'The opaque inventory ID is no longer available.',
      };
    }
    if (error.status === 503) {
      return {
        tone: 'warning',
        title: 'Tool playground unavailable',
        message: 'The capability inventory is currently unavailable.',
      };
    }
  }
  if (error instanceof CapabilityContractError) {
    return {
      tone: 'error',
      title: 'Tool metadata rejected',
      message: 'The gateway returned invalid safe tool metadata.',
    };
  }
  return {
    tone: 'error',
    title: 'Tool playground unavailable',
    message: 'The tool metadata request failed.',
  };
}

function playgroundRunError(error: unknown): PlaygroundFeedback {
  if (error instanceof ToolExecutionContractError) {
    return {
      tone: 'error',
      title: 'Execution response rejected',
      message:
        'The response or validator was ambiguous. Reload before running this tool again.',
    };
  }
  if (error instanceof AdminApiError) {
    if (error.code === 'output_limit_exceeded') {
      return {
        tone: 'warning',
        title: 'Tool output limit exceeded',
        message:
          'The gateway rejected output larger than the safe 64 KiB limit (output_limit_exceeded).',
      };
    }
    if (error.status === 400 || error.status === 422) {
      return {
        tone: 'warning',
        title: 'Arguments rejected',
        message: 'The gateway rejected these arguments. No result was retained.',
      };
    }
    if (error.status === 401) {
      return {
        tone: 'warning',
        title: 'Authentication required',
        message: 'Authenticate again before running this tool.',
      };
    }
    if (error.status === 403) {
      return {
        tone: 'warning',
        title: 'Tool execution denied',
        message:
          'The gateway denied admin execution or the normal tool policy decision.',
      };
    }
    if (error.status === 404) {
      return {
        tone: 'warning',
        title: 'Tool no longer available',
        message: 'Reload the current inventory before running another tool.',
      };
    }
    if (error.status === 409) {
      return {
        tone: 'warning',
        title: 'Tool execution unavailable',
        message: 'The registered tool cannot be executed in its current state.',
      };
    }
    if (error.status === 412) {
      return {
        tone: 'warning',
        title: 'Tool changed before execution',
        message:
          'The submitted validator is stale. Reload the current tool; the request was not retried.',
      };
    }
    if (error.status === 428) {
      return {
        tone: 'warning',
        title: 'Execution validator required',
        message:
          'Reload the current tool to obtain a fresh validator. The request was not retried.',
      };
    }
    if (error.status === 429) {
      return {
        tone: 'warning',
        title: 'Tool execution busy',
        message: 'The bounded execution admission limit is currently full.',
      };
    }
    if (error.status === 503) {
      return {
        tone: 'warning',
        title: 'Tool executor unavailable',
        message: 'The registered executor is currently unavailable.',
      };
    }
  }
  return {
    tone: 'error',
    title: 'Tool execution failed',
    message: 'The request failed without retaining arguments or a result.',
  };
}

function executeReasonMessage(
  reason: CapabilityDetail['actions']['reason'],
): string {
  switch (reason) {
    case 'allowed':
      return 'Execution is allowed';
    case 'permission_denied':
      return 'This principal does not have admin tool execution permission';
    case 'metadata_only':
      return 'This capability is metadata-only and cannot be invoked';
    case 'disabled':
      return 'This registered tool or its connection is disabled';
    case 'unavailable':
      return 'This registered tool is unavailable';
    case 'stale':
      return 'This capability is stale and must be refreshed';
    case 'policy_denied':
      return 'The normal tool policy does not allow this invocation';
    case 'executor_unavailable':
      return 'The registered executor is unavailable';
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}
