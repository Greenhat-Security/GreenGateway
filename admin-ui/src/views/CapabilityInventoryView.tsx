import {
  FormEvent,
  type RefObject,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Link, useParams } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import {
  type CapabilityAvailabilityFilter,
  type CapabilityDetail as CapabilityDetailRecord,
  type CapabilityKind,
  type CapabilityListFilters,
  type CapabilitySourceFilter,
  type CapabilitySummary,
  getCapability,
  listCapabilityInventory,
} from '../lib/capabilityInventory';

type InventoryViewError = {
  kind:
    | 'unauthorized'
    | 'forbidden'
    | 'not-found'
    | 'bad-request'
    | 'unavailable'
    | 'network'
    | 'generic';
  message: string;
};

type InventoryFilterDraft = {
  kind: CapabilityKind | '';
  connectionId: string;
  source: CapabilitySourceFilter | '';
  available: '' | 'true' | 'false';
  availability: CapabilityAvailabilityFilter | '';
  text: string;
};

const CAPABILITY_PAGE_LIMIT = 50;
const EMPTY_FILTERS: InventoryFilterDraft = {
  kind: '',
  connectionId: '',
  source: '',
  available: '',
  availability: '',
  text: '',
};

export function CapabilityInventoryView() {
  const [filters, setFilters] = useState<InventoryFilterDraft>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<CapabilityListFilters>(
    () => ({ limit: CAPABILITY_PAGE_LIMIT }),
  );
  const [capabilities, setCapabilities] = useState<CapabilitySummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [loadError, setLoadError] = useState<InventoryViewError | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const errorRef = useRef<HTMLDivElement>(null);
  const focusedErrorRef = useRef<InventoryViewError | null>(null);
  const paginationControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = null;

    async function loadFirstPage() {
      setIsLoading(true);
      setIsLoadingMore(false);
      setLoadError(null);
      setAnnouncement('');

      try {
        const response = await listCapabilityInventory(
          appliedFilters,
          controller.signal,
        );
        if (controller.signal.aborted) {
          return;
        }
        setCapabilities(response.value.capabilities);
        setNextCursor(response.value.next_cursor ?? null);
        setTotalCount(response.value.total_count);
        setAnnouncement(
          inventoryResultAnnouncement(response.value.total_count),
        );
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }
        setCapabilities([]);
        setNextCursor(null);
        setTotalCount(0);
        setLoadError(toInventoryViewError(error));
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    }

    void loadFirstPage();
    return () => {
      controller.abort();
      paginationControllerRef.current?.abort();
    };
  }, [appliedFilters]);

  useEffect(() => {
    if (loadError === null) {
      focusedErrorRef.current = null;
      return;
    }

    if (focusedErrorRef.current === loadError) {
      return;
    }

    focusedErrorRef.current = loadError;
    errorRef.current?.focus();
  }, [loadError]);

  const resultCount = useMemo(
    () =>
      `${totalCount} ${totalCount === 1 ? 'capability' : 'capabilities'}`,
    [totalCount],
  );

  function updateFilter<K extends keyof InventoryFilterDraft>(
    name: K,
    value: InventoryFilterDraft[K],
  ) {
    setFilters((current) => ({ ...current, [name]: value }));
  }

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAppliedFilters(normalizeFilters(filters));
  }

  function clearFilters() {
    setFilters(EMPTY_FILTERS);
    setAppliedFilters({ limit: CAPABILITY_PAGE_LIMIT });
  }

  async function loadMore() {
    if (nextCursor === null || isLoadingMore || isLoading) {
      return;
    }

    setIsLoadingMore(true);
    setLoadError(null);
    setAnnouncement('');
    const controller = new AbortController();
    paginationControllerRef.current?.abort();
    paginationControllerRef.current = controller;

    try {
      const response = await listCapabilityInventory(
        { ...appliedFilters, cursor: nextCursor },
        controller.signal,
      );
      if (controller.signal.aborted) {
        return;
      }
      setCapabilities((current) => [
        ...current,
        ...response.value.capabilities,
      ]);
      setNextCursor(response.value.next_cursor ?? null);
      setTotalCount(response.value.total_count);
      setAnnouncement(
        `Loaded ${response.value.capabilities.length} more ${
          response.value.capabilities.length === 1
            ? 'capability'
            : 'capabilities'
        }.`,
      );
    } catch (error) {
      if (controller.signal.aborted) {
        return;
      }
      if (error instanceof AdminApiError && error.status === 412) {
        await recoverFromStaleCursor(controller.signal);
      } else {
        setLoadError(toInventoryViewError(error));
      }
    } finally {
      if (!controller.signal.aborted) {
        setIsLoadingMore(false);
      }
      if (paginationControllerRef.current === controller) {
        paginationControllerRef.current = null;
      }
    }
  }

  async function recoverFromStaleCursor(signal: AbortSignal) {
    try {
      const response = await listCapabilityInventory(appliedFilters, signal);
      if (signal.aborted) {
        return;
      }
      setCapabilities(response.value.capabilities);
      setNextCursor(response.value.next_cursor ?? null);
      setTotalCount(response.value.total_count);
      setAnnouncement(
        'The capability inventory changed. The list was refreshed from the first page.',
      );
    } catch (error) {
      if (signal.aborted) {
        return;
      }
      setCapabilities([]);
      setNextCursor(null);
      setTotalCount(0);
      setLoadError(toInventoryViewError(error));
    }
  }

  return (
    <main className="logs-page capability-inventory-page">
      <section
        className="panel logs-panel capability-inventory-panel"
        aria-labelledby="capability-inventory-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Tools</p>
            <h2 id="capability-inventory-heading">Capability inventory</h2>
          </div>
          <span className="result-count">{resultCount}</span>
        </div>

        <p className="section-description">
          Review registered tools and discovered MCP resources using the
          gateway&apos;s current connection, availability, and policy state.
        </p>

        <form className="filter-form" onSubmit={applyFilters}>
          <div className="filter-grid capability-filter-grid">
            <label>
              Search
              <input
                type="search"
                value={filters.text}
                placeholder="Name, title, URI, or description"
                onChange={(event) => updateFilter('text', event.target.value)}
              />
            </label>
            <label>
              Kind
              <select
                value={filters.kind}
                onChange={(event) =>
                  updateFilter(
                    'kind',
                    event.target.value as InventoryFilterDraft['kind'],
                  )
                }
              >
                <option value="">All kinds</option>
                <option value="tool">Tools</option>
                <option value="resource">Resources</option>
                <option value="resource_template">Resource templates</option>
              </select>
            </label>
            <label>
              Connection ID
              <input
                type="text"
                value={filters.connectionId}
                placeholder="billing-prod"
                onChange={(event) =>
                  updateFilter('connectionId', event.target.value)
                }
              />
            </label>
            <label>
              Source
              <select
                value={filters.source}
                onChange={(event) =>
                  updateFilter(
                    'source',
                    event.target.value as InventoryFilterDraft['source'],
                  )
                }
              >
                <option value="">All sources</option>
                <option value="manual_file">Manual file</option>
                <option value="openapi">OpenAPI</option>
                <option value="mcp_discovery">MCP discovery</option>
                <option value="projected_legacy_config">
                  Projected legacy config
                </option>
              </select>
            </label>
            <label>
              Available flag
              <select
                value={filters.available}
                onChange={(event) =>
                  updateFilter(
                    'available',
                    event.target.value as InventoryFilterDraft['available'],
                  )
                }
              >
                <option value="">Any value</option>
                <option value="true">Available</option>
                <option value="false">Not available</option>
              </select>
            </label>
            <label>
              Availability state
              <select
                value={filters.availability}
                onChange={(event) =>
                  updateFilter(
                    'availability',
                    event.target
                      .value as InventoryFilterDraft['availability'],
                  )
                }
              >
                <option value="">All states</option>
                <option value="available">Available</option>
                <option value="unavailable">Unavailable</option>
                <option value="stale">Stale</option>
              </select>
            </label>
          </div>

          <div className="form-actions">
            <button type="submit" className="primary-button" disabled={isLoading}>
              Apply filters
            </button>
            <button
              type="button"
              className="secondary-button"
              disabled={isLoading}
              onClick={clearFilters}
            >
              Clear
            </button>
          </div>
        </form>

        <div
          className="sr-only capability-live-region"
          role="status"
          aria-live="polite"
        >
          {announcement}
        </div>

        {loadError ? (
          <InventoryErrorMessage
            error={loadError}
            context="list"
            errorRef={errorRef}
            idPrefix="capability-inventory"
          />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading capability inventory
          </div>
        ) : null}

        {!isLoading && capabilities.length === 0 && loadError === null ? (
          <div className="empty-state">
            No capabilities matched these filters.
          </div>
        ) : null}

        {capabilities.length > 0 ? (
          <>
            <div className="table-scroll">
              <table className="logs-table capability-table">
                <thead>
                  <tr>
                    <th>Capability</th>
                    <th>Kind</th>
                    <th>Source</th>
                    <th>Connection</th>
                    <th>Runtime</th>
                    <th>Policy</th>
                  </tr>
                </thead>
                <tbody>
                  {capabilities.map((capability, index) => (
                    <CapabilityRow
                      capability={capability}
                      key={capability.id}
                      rowIndex={index}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination-row">
              {nextCursor !== null ? (
                <button
                  type="button"
                  className="secondary-button"
                  disabled={isLoadingMore}
                  onClick={() => {
                    void loadMore();
                  }}
                >
                  {isLoadingMore ? 'Loading more' : 'Load more'}
                </button>
              ) : (
                <span>No more capabilities</span>
              )}
            </div>
          </>
        ) : null}
      </section>
    </main>
  );
}

function CapabilityRow({
  capability,
  rowIndex,
}: {
  capability: CapabilitySummary;
  rowIndex: number;
}) {
  const displayName = capability.title?.trim() || capability.name;

  return (
    <tr className={`event-row ${rowIndex % 2 === 1 ? 'is-even' : ''}`}>
      <td data-label="Capability">
        <div className="traffic-endpoint-cell capability-primary-cell">
          <Link
            className="endpoint-template endpoint-detail-link capability-detail-link"
            to={capabilityDetailPath(capability.id)}
            aria-label={`View detail for ${displayName}`}
          >
            {displayName}
          </Link>
          {capability.title ? (
            <code className="timestamp-cell">{capability.name}</code>
          ) : null}
          {capability.description ? (
            <span className="capability-description">
              {capability.description}
              {capability.description_truncated ? '...' : ''}
            </span>
          ) : null}
        </div>
      </td>
      <td data-label="Kind">
        <span className="badge neutral">{kindLabel(capability.kind)}</span>
      </td>
      <td data-label="Source">
        <SourceSummary capability={capability} />
      </td>
      <td data-label="Connection">
        {capability.connection ? (
          <div className="traffic-endpoint-cell">
            <Link
              className="endpoint-detail-link"
              to={`/connections/${encodeURIComponent(capability.connection.id)}`}
            >
              {capability.connection.id}
            </Link>
            <span className="timestamp-cell">
              {humanizeIdentifier(capability.connection.kind)}
            </span>
          </div>
        ) : (
          <span>Local</span>
        )}
      </td>
      <td data-label="Runtime">
        <CapabilityStateBadges capability={capability} />
      </td>
      <td data-label="Policy">
        <PolicyEligibility capability={capability} />
      </td>
    </tr>
  );
}

function SourceSummary({ capability }: { capability: CapabilitySummary }) {
  const source = capability.source;

  return (
    <div className="traffic-endpoint-cell">
      <span className="badge neutral">{sourceLabel(source.type)}</span>
      {source.type === 'openapi' && source.operation_id ? (
        <code className="timestamp-cell">{source.operation_id}</code>
      ) : null}
      {(source.type === 'mcp_discovery' ||
        source.type === 'projected_legacy_config') &&
      source.remote_tool_name ? (
        <code className="timestamp-cell">{source.remote_tool_name}</code>
      ) : null}
    </div>
  );
}

function CapabilityStateBadges({
  capability,
}: {
  capability: CapabilitySummary;
}) {
  const state = capability.state;
  return (
    <div className="endpoint-badges">
      <span className={`badge ${state.enabled ? 'success' : 'neutral'}`}>
        {state.enabled ? 'Enabled' : 'Disabled'}
      </span>
      <span className={`badge ${state.available ? 'success' : 'warning'}`}>
        {state.available ? 'Available' : 'Unavailable'}
      </span>
      {state.stale ? <span className="badge warning">Stale</span> : null}
      <span className="timestamp-cell" title={state.reason}>
        {humanizeIdentifier(state.reason)}
      </span>
    </div>
  );
}

function PolicyEligibility({ capability }: { capability: CapabilitySummary }) {
  return (
    <div className="traffic-endpoint-cell">
      <span
        className={`badge ${capability.policy.eligible ? 'success' : 'warning'}`}
      >
        {capability.policy.eligible ? 'Eligible' : 'Not eligible'}
      </span>
      <span className="timestamp-cell" title={capability.policy.reason}>
        {humanizeIdentifier(capability.policy.reason)}
      </span>
    </div>
  );
}

export function CapabilityDetail() {
  const { id = '' } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<CapabilityDetailRecord | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<InventoryViewError | null>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const focusedErrorRef = useRef<InventoryViewError | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    async function loadDetail() {
      setIsLoading(true);
      setLoadError(null);

      if (id.trim().length === 0) {
        setDetail(null);
        setLoadError({
          kind: 'bad-request',
          message: 'Capability detail requires an opaque capability ID.',
        });
        setIsLoading(false);
        return;
      }

      try {
        const response = await getCapability(id, controller.signal);
        if (controller.signal.aborted) {
          return;
        }
        setDetail(response.value);
      } catch (error) {
        if (controller.signal.aborted) {
          return;
        }
        setDetail(null);
        setLoadError(toInventoryViewError(error));
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    }

    void loadDetail();
    return () => controller.abort();
  }, [id]);

  useEffect(() => {
    if (loadError === null) {
      focusedErrorRef.current = null;
      return;
    }

    if (focusedErrorRef.current === loadError) {
      return;
    }

    focusedErrorRef.current = loadError;
    errorRef.current?.focus();
  }, [loadError]);

  const heading =
    detail?.title?.trim() || detail?.name || 'Capability detail';

  return (
    <main className="logs-page capability-inventory-page capability-detail-page traffic-detail-page">
      <section
        className="panel logs-panel capability-inventory-panel capability-detail-panel traffic-detail-panel"
        aria-labelledby="capability-detail-heading"
      >
        <div className="section-heading logs-heading traffic-detail-heading">
          <div>
            <p className="eyebrow">Capability</p>
            <h2 id="capability-detail-heading">{heading}</h2>
          </div>
          <Link className="secondary-button" to="/tools">
            Back to inventory
          </Link>
        </div>

        {loadError ? (
          <InventoryErrorMessage
            error={loadError}
            context="detail"
            errorRef={errorRef}
            idPrefix="capability-detail"
          />
        ) : null}

        {isLoading ? (
          <div className="loading-state" role="status" aria-live="polite">
            Loading capability detail
          </div>
        ) : null}

        {!isLoading && detail !== null ? (
          <>
            <CapabilitySummarySection detail={detail} />
            <CapabilityProvenanceSection detail={detail} />
            <CapabilityMappingSection detail={detail} />
            <CapabilitySchemaSection detail={detail} />
          </>
        ) : null}
      </section>
    </main>
  );
}

function CapabilitySummarySection({
  detail,
}: {
  detail: CapabilityDetailRecord;
}) {
  return (
    <section
      className="traffic-detail-section capability-detail-section"
      aria-labelledby="capability-summary-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Runtime</p>
        <h3 id="capability-summary-heading">Summary</h3>
      </div>

      <div className="traffic-endpoint-summary">
        <div className="endpoint-title">
          <span className="badge neutral">{kindLabel(detail.kind)}</span>
          <code className="endpoint-template">{detail.name}</code>
        </div>
        {detail.description ? (
          <p>
            {detail.description}
            {detail.description_truncated ? '...' : ''}
          </p>
        ) : (
          <p>No description was provided.</p>
        )}
        <div className="capability-detail-state-grid">
          <div>
            <h4>Connection state</h4>
            <CapabilityStateBadges capability={detail} />
          </div>
          <div>
            <h4>Policy state</h4>
            <PolicyEligibility capability={detail} />
          </div>
        </div>
        <dl className="traffic-metadata-grid">
          <SpecRow label="Opaque ID" value={detail.id} code />
          <SpecRow label="Kind" value={kindLabel(detail.kind)} />
          <SpecRow label="URI" value={detail.uri ?? 'Not applicable'} code />
          <SpecRow
            label="URI template"
            value={detail.uri_template ?? 'Not applicable'}
            code
          />
          <SpecRow
            label="Schema digest"
            value={detail.schema_digest ?? 'Not provided'}
            code
          />
          <SpecRow
            label="Discovered"
            value={detail.discovered_at ?? 'Not recorded'}
          />
          <SpecRow
            label="Last successful refresh"
            value={detail.last_success_at ?? 'Not recorded'}
          />
        </dl>
      </div>
    </section>
  );
}

function CapabilityProvenanceSection({
  detail,
}: {
  detail: CapabilityDetailRecord;
}) {
  const source = detail.source;

  return (
    <section
      className="traffic-detail-section capability-detail-section"
      aria-labelledby="capability-provenance-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Origin</p>
        <h3 id="capability-provenance-heading">Provenance</h3>
      </div>
      <dl className="traffic-metadata-grid">
        <SpecRow label="Source" value={sourceLabel(source.type)} />
        {detail.connection ? (
          <>
            <SpecRow
              label="Connection"
              value={detail.connection.id}
              href={`/connections/${encodeURIComponent(detail.connection.id)}`}
            />
            <SpecRow
              label="Connection kind"
              value={humanizeIdentifier(detail.connection.kind)}
            />
            <SpecRow
              label="Managed by"
              value={humanizeIdentifier(detail.connection.management_source)}
            />
          </>
        ) : (
          <SpecRow label="Connection" value="Local gateway definition" />
        )}
        {source.type === 'openapi' ? (
          <>
            <SpecRow
              label="Operation ID"
              value={source.operation_id ?? 'Not provided'}
              code
            />
            <SpecRow
              label="Catalog revision"
              value={String(source.catalog_revision)}
            />
            <SpecRow
              label="Spec revision"
              value={String(source.spec_revision)}
            />
            <SpecRow label="Spec digest" value={source.spec_digest} code />
          </>
        ) : null}
        {source.type === 'mcp_discovery' ? (
          <SpecRow
            label="Remote tool"
            value={source.remote_tool_name ?? 'Not applicable'}
            code
          />
        ) : null}
        {source.type === 'projected_legacy_config' ? (
          <SpecRow
            label="Remote tool"
            value={source.remote_tool_name}
            code
          />
        ) : null}
      </dl>
    </section>
  );
}

function CapabilityMappingSection({
  detail,
}: {
  detail: CapabilityDetailRecord;
}) {
  const mapping = detail.mapping;
  if (!mapping) {
    return null;
  }

  return (
    <section
      className="traffic-detail-section capability-detail-section"
      aria-labelledby="capability-mapping-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Dispatch</p>
        <h3 id="capability-mapping-heading">Safe mapping</h3>
      </div>
      <dl className="traffic-metadata-grid">
        <SpecRow label="Mapping type" value={kindLabel(mapping.type)} />
        {mapping.type === 'http' ? (
          <>
            <SpecRow label="Method" value={mapping.method} />
            <SpecRow label="Path template" value={mapping.path_template} code />
            <SpecRow
              label="Query parameters"
              value={String(mapping.query_params.length)}
            />
            <SpecRow
              label="Body mapping"
              value={mapping.body ? humanizeIdentifier(mapping.body.mode) : 'None'}
            />
          </>
        ) : null}
        {mapping.type === 'mcp' ? (
          <SpecRow
            label="Remote tool"
            value={mapping.remote_tool_name}
            code
          />
        ) : null}
        {mapping.type === 'resource' ? (
          <>
            <SpecRow label="URI" value={mapping.uri} code />
            <SpecRow
              label="MIME type"
              value={mapping.mime_type ?? 'Not provided'}
            />
            <SpecRow
              label="Size"
              value={
                mapping.size === undefined
                  ? 'Not provided'
                  : `${mapping.size.toLocaleString()} bytes`
              }
            />
          </>
        ) : null}
        {mapping.type === 'resource_template' ? (
          <>
            <SpecRow
              label="URI template"
              value={mapping.uri_template}
              code
            />
            <SpecRow
              label="MIME type"
              value={mapping.mime_type ?? 'Not provided'}
            />
          </>
        ) : null}
      </dl>
      {mapping.type === 'http' && mapping.query_params.length > 0 ? (
        <div>
          <h4 id="capability-query-mapping-heading">
            Query parameter mappings
          </h4>
          <div className="table-scroll">
            <table
              className="logs-table traffic-detail-table"
              aria-labelledby="capability-query-mapping-heading"
            >
              <thead>
                <tr>
                  <th scope="col">Argument</th>
                  <th scope="col">Query parameter</th>
                  <th scope="col">Required</th>
                </tr>
              </thead>
              <tbody>
                {mapping.query_params.map((queryParam) => (
                  <tr
                    key={`${queryParam.arg_name}\n${queryParam.query_name}`}
                  >
                    <td>
                      <code>{queryParam.arg_name}</code>
                    </td>
                    <td>
                      <code>{queryParam.query_name}</code>
                    </td>
                    <td>{queryParam.required ? 'Yes' : 'No'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function CapabilitySchemaSection({
  detail,
}: {
  detail: CapabilityDetailRecord;
}) {
  if (detail.input_json_schema === undefined) {
    return null;
  }

  return (
    <section
      className="traffic-detail-section capability-detail-section"
      aria-labelledby="capability-schema-heading"
    >
      <div className="section-heading">
        <p className="eyebrow">Contract</p>
        <h3 id="capability-schema-heading">Input JSON schema</h3>
      </div>
      <pre className="signal-evidence capability-schema">
        {JSON.stringify(detail.input_json_schema, null, 2)}
      </pre>
    </section>
  );
}

function SpecRow({
  label,
  value,
  code = false,
  href,
}: {
  label: string;
  value: string;
  code?: boolean;
  href?: string;
}) {
  const content = href ? (
    <Link className="endpoint-detail-link" to={href}>
      {value}
    </Link>
  ) : code ? (
    <code>{value}</code>
  ) : (
    value
  );

  return (
    <div>
      <dt>{label}</dt>
      <dd>{content}</dd>
    </div>
  );
}

function InventoryErrorMessage({
  error,
  context,
  errorRef,
  idPrefix,
}: {
  error: InventoryViewError;
  context: 'list' | 'detail';
  errorRef: RefObject<HTMLDivElement | null>;
  idPrefix: string;
}) {
  const headingId = `${idPrefix}-error-heading`;
  const descriptionId = `${idPrefix}-error-description`;

  if (error.kind === 'unauthorized') {
    return (
      <div
        ref={errorRef}
        className="error-panel alert warning"
        role="alert"
        tabIndex={-1}
        aria-labelledby={headingId}
        aria-describedby={descriptionId}
      >
        <h3 id={headingId}>Bearer token required</h3>
        <p id={descriptionId}>
          Paste a bearer token before viewing capabilities. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div
        ref={errorRef}
        className="error-panel alert error"
        role="alert"
        tabIndex={-1}
        aria-labelledby={headingId}
        aria-describedby={descriptionId}
      >
        <h3 id={headingId}>Capability inventory permission required</h3>
        <p id={descriptionId}>
          This token is valid but does not include admin:tools:read.
        </p>
      </div>
    );
  }

  if (error.kind === 'not-found') {
    return (
      <div
        ref={errorRef}
        className="error-panel alert warning"
        role="alert"
        tabIndex={-1}
        aria-labelledby={headingId}
        aria-describedby={descriptionId}
      >
        <h3 id={headingId}>Capability not found</h3>
        <p id={descriptionId}>{error.message}</p>
      </div>
    );
  }

  if (error.kind === 'unavailable') {
    return (
      <div
        ref={errorRef}
        className="error-panel alert error"
        role="alert"
        tabIndex={-1}
        aria-labelledby={headingId}
        aria-describedby={descriptionId}
      >
        <h3 id={headingId}>Capability inventory unavailable</h3>
        <p id={descriptionId}>{error.message}</p>
      </div>
    );
  }

  return (
    <div
      ref={errorRef}
      className={`error-panel alert ${
        error.kind === 'bad-request' ? 'warning' : 'error'
      }`}
      role="alert"
      tabIndex={-1}
      aria-labelledby={headingId}
      aria-describedby={descriptionId}
    >
      <h3 id={headingId}>
        {error.kind === 'bad-request'
          ? `Invalid capability ${context === 'list' ? 'query' : 'request'}`
          : 'Request failed'}
      </h3>
      <p id={descriptionId}>{error.message}</p>
    </div>
  );
}

function inventoryResultAnnouncement(totalCount: number): string {
  if (totalCount === 0) {
    return 'Capability inventory loaded. No capabilities matched these filters.';
  }

  return `${totalCount} ${
    totalCount === 1 ? 'capability' : 'capabilities'
  } matched these filters.`;
}

function normalizeFilters(
  filters: InventoryFilterDraft,
): CapabilityListFilters {
  const normalized: CapabilityListFilters = {
    limit: CAPABILITY_PAGE_LIMIT,
  };
  const connectionId = filters.connectionId.trim();
  const text = filters.text.trim();

  if (filters.kind) {
    normalized.kind = filters.kind;
  }
  if (connectionId) {
    normalized.connectionId = connectionId;
  }
  if (filters.source) {
    normalized.source = filters.source;
  }
  if (filters.available) {
    normalized.available = filters.available === 'true';
  }
  if (filters.availability) {
    normalized.availability = filters.availability;
  }
  if (text) {
    normalized.text = text;
  }

  return normalized;
}

function capabilityDetailPath(id: string): string {
  return `/tools/${encodeURIComponent(id)}`;
}

function kindLabel(value: string): string {
  if (value === 'mcp') {
    return 'MCP';
  }
  return humanizeIdentifier(value);
}

function sourceLabel(source: CapabilitySourceFilter): string {
  if (source === 'openapi') {
    return 'OpenAPI';
  }
  if (source === 'mcp_discovery') {
    return 'MCP discovery';
  }
  return humanizeIdentifier(source);
}

function humanizeIdentifier(value: string): string {
  const words = value.replace(/_/g, ' ').trim();
  return words.length === 0
    ? 'Unknown'
    : `${words.charAt(0).toUpperCase()}${words.slice(1)}`;
}

function toInventoryViewError(error: unknown): InventoryViewError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
    }
    if (error.status === 404) {
      return { kind: 'not-found', message: error.message };
    }
    if (error.status === 400 || error.status === 412) {
      return { kind: 'bad-request', message: error.message };
    }
    if (error.status === 503) {
      return { kind: 'unavailable', message: error.message };
    }

    return { kind: 'generic', message: error.message };
  }

  if (error instanceof Error) {
    return {
      kind: 'network',
      message: `Network request failed: ${error.message}`,
    };
  }

  return { kind: 'network', message: 'Network request failed.' };
}
