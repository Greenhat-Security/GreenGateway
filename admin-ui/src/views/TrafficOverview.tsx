import { useEffect, useId, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AdminApiError } from '../lib/api';
import { hasAdminPermission, useAdminCapabilities, useAdminIdentityVersion } from '../lib/adminCapabilities';
import { emptyTrafficFilters, fetchTrafficEndpoints, type TrafficEndpoint } from '../lib/traffic';
import { endpointKey, flowDiagram, summarizeDestinations, trafficFlows, type Flow } from '../lib/trafficFlow';
import './TrafficOverview.css';

const number = (value: number) => value.toLocaleString();
const COLORS = ['#329d83', '#558de3', '#aa83d6', '#dc9860', '#d67198', '#56a5b2', '#869b4a', '#878ca9'];
const MAX_ENDPOINTS = 500;

export function TrafficOverview() {
  const capabilities = useAdminCapabilities();
  const identity = useAdminIdentityVersion();
  const granted = hasAdminPermission(capabilities, 'admin:traffic:read');
  const [grantedIdentity, setGrantedIdentity] = useState<number | null>(null);
  useEffect(() => {
    if (granted) setGrantedIdentity(identity);
    else if (capabilities.status !== 'loading') setGrantedIdentity(null);
  }, [granted, identity, capabilities.status]);
  // Preserve filters/pages during a background check, but conceal observations
  // until the grant is confirmed. Identity changes and denials drop the data.
  const retain = granted || (capabilities.status === 'loading' && grantedIdentity === identity);
  return <section className="panel traffic-overview" aria-label="Traffic overview">
    <div className="flow-heading"><div><p className="eyebrow">Observe your gateway</p><h2 id="traffic-overview-heading">Traffic overview</h2>
      <p className="body-copy">See where requests go and where rules match.</p></div><Link to="/traffic">Explore inventory →</Link></div>
    {retain && <div hidden={!granted}><TrafficOverviewData key={identity} /></div>}
    {!granted &&
      <p role="status" className="flow-notice">{capabilities.status === 'loading' ? 'Checking traffic permissions…' : capabilities.status === 'unavailable'
        ? 'Traffic permissions are temporarily unavailable.' : 'Sign in with traffic read permission to view gateway observations.'}</p>}
  </section>;
}

export function TrafficOverviewData() {
  const [endpoints, setEndpoints] = useState<TrafficEndpoint[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [request, setRequest] = useState<{ cursor?: string; revision: number }>({ revision: 0 });
  const [updated, setUpdated] = useState<Date | null>(null);
  const [method, setMethod] = useState('');
  const [destination, setDestination] = useState('');
  const [search, setSearch] = useState('');
  const [view, setView] = useState<'flow' | 'table'>('flow');
  const [selected, setSelected] = useState('');
  useEffect(() => {
    let current = true;
    setLoading(true); setError('');
    if (!request.cursor) { setEndpoints([]); setCursor(null); setUpdated(null); }
    void fetchTrafficEndpoints({ ...emptyTrafficFilters(), sort: 'call_count' }, request.cursor).then(response => {
      if (!current) return;
      setEndpoints(previous => [...new Map([...(request.cursor ? previous : []), ...response.endpoints].map(e => [endpointKey(e), e])).values()].slice(0, MAX_ENDPOINTS));
      setCursor(response.next_cursor); setUpdated(new Date());
    }).catch(cause => {
      if (!current) return;
      // A denied request must never leave a previous data set on screen.
      if (cause instanceof AdminApiError && [401, 403].includes(cause.status)) { setEndpoints([]); setCursor(null); setUpdated(null); }
      setError(cause instanceof AdminApiError && cause.status === 503 ? 'Traffic discovery is unavailable. Enable discovery storage to collect observations.'
        : cause instanceof AdminApiError && [401, 403].includes(cause.status) ? 'Traffic access is unavailable. Sign in with traffic read permission.'
          : 'Could not load traffic observations. Try again.');
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [request]);
  const allFlows = useMemo(() => trafficFlows(endpoints), [endpoints]);
  const destinations = useMemo(() => summarizeDestinations(allFlows), [allFlows]);
  const flows = useMemo(() => allFlows.filter(f => (!method || f.source === method) && (!destination || f.destination === destination)
    && (!search.trim() || endpointKey(f.endpoint).toLowerCase().includes(search.trim().toLowerCase()))), [allFlows, method, destination, search]);
  const groups = summarizeDestinations(flows);
  const total = flows.reduce((sum, f) => sum + f.count, 0);
  const unknown = flows.filter(f => f.coverage === 'unknown').reduce((sum, f) => sum + f.count, 0);
  const detail = groups.find(g => g.name === selected);
  return <>
    <div className="flow-controls">
      <label>Method<select value={method} onChange={e => { setMethod(e.target.value); setSelected(''); }}><option value="">All methods</option>
        {[...new Set(allFlows.map(f => f.source))].sort().map(m => <option key={m}>{m}</option>)}</select></label>
      <label>Destination<select value={destination} onChange={e => { setDestination(e.target.value); setSelected(''); }}><option value="">All destinations</option>
        {destinations.map(d => <option key={d.name}>{d.name}</option>)}</select></label>
      <label>Endpoint<input type="search" placeholder="Search an endpoint" value={search} onChange={e => { setSearch(e.target.value); setSelected(''); }} /></label>
      <button type="button" className="secondary-button" disabled={loading} onClick={() => setRequest({ revision: request.revision + 1 })}>Refresh</button>
    </div>
    {error && <div className="flow-notice alert error" role="alert">{error} <button type="button" disabled={loading} onClick={() => setRequest({ ...request, revision: request.revision + 1 })}>Retry</button></div>}
    {loading && <p role="status">Loading traffic observations…</p>}
    {!loading && !error && !endpoints.length && <div className="flow-empty"><h3>No traffic observed yet</h3><p>Once requests pass through a gateway with discovery enabled, their paths appear here.</p><Link to="/status">Check gateway status →</Link></div>}
    {endpoints.length > 0 && <>
      <div className="flow-stats" aria-label="Loaded traffic summary">
        <div><span>Observed requests</span><strong>{number(total)}</strong></div>
        <div><span>Endpoints in view</span><strong>{number(new Set(flows.map(f => endpointKey(f.endpoint))).size)}</strong></div>
        <div><span>Destination groups</span><strong>{number(groups.length)}</strong></div>
        <div><span>Partial / unknown coverage</span><strong>{number(unknown)}</strong></div>
      </div>
      <div className="flow-section-title"><div><h3>Request movement</h3><p>Request methods → observed upstream destinations</p></div>
        <div className="flow-view-toggle" aria-label="Traffic display"><button type="button" aria-pressed={view === 'flow'} onClick={() => setView('flow')}>Flow</button><button type="button" aria-pressed={view === 'table'} onClick={() => setView('table')}>Table</button></div></div>
      {flows.length ? view === 'flow' ? <Sankey flows={flows} /> : <div className="flow-table-wrap"><table className="flow-table"><caption>Request movement by method and destination</caption><thead><tr><th>Method</th><th>Destination</th><th>Requests</th></tr></thead><tbody>
        {flowDiagram(flows).ribbons.map(row => <tr key={JSON.stringify([row.source, row.target])}><td>{row.source}</td><td>{row.target}</td><td>{number(row.count)}</td></tr>)}
      </tbody></table></div> : <div className="flow-empty"><h3>No matching observations</h3><button type="button" onClick={() => { setMethod(''); setDestination(''); setSearch(''); }}>Clear filters</button></div>}
      <div className="flow-section-title"><div><h3>Destination breakdown</h3><p>Request counts grouped by current rule coverage, not historical allow/deny decisions.</p></div></div>
      <div className="flow-legend"><span><i className="covered" />Rule covered</span><span><i className="uncovered" />No matching rule</span><span><i className="unknown" />Partial / unknown</span></div>
      <div className="flow-destinations">{groups.map(group => <button type="button" key={group.name} className="flow-destination" aria-expanded={selected === group.name}
        onClick={() => setSelected(selected === group.name ? '' : group.name)}><span className="flow-destination-name">{group.name}<small>{group.endpoints.size} endpoint{group.endpoints.size === 1 ? '' : 's'}</small></span>
        <span className="flow-distribution"><strong>{number(group.total)} requests</strong><span className="flow-stacked" aria-hidden="true">{(['covered', 'uncovered', 'unknown'] as const).map(key => <span key={key} className={key} style={{ width: `${group[key] / group.total * 100}%` }} />)}</span>
          <small>{number(group.covered)} covered · {number(group.uncovered)} no rule · {number(group.unknown)} partial / unknown</small></span><span aria-hidden="true">{selected === group.name ? '−' : '+'}</span></button>)}</div>
      {detail && <section className="flow-detail" aria-label={`Endpoints for ${detail.name}`}><h4>Endpoints for {detail.name}</h4><ul>{[...detail.endpoints.values()].map(e => <li key={endpointKey(e)}><Link to={`/traffic/detail?${new URLSearchParams({ method: e.method, endpoint_template: e.endpoint_template })}`}>{endpointKey(e)}</Link></li>)}</ul></section>}
      <div className="flow-footer"><p>Lifetime observations for {endpoints.length} loaded endpoints{cursor ? ' · more endpoints available' : ''}. {updated && <>Updated {updated.toLocaleTimeString()}.</>}<br />Unknown destinations include observations without routing context. Counts describe requests, not bytes or unique users.</p>
        {cursor && endpoints.length < MAX_ENDPOINTS && <button type="button" disabled={loading} className="secondary-button" onClick={() => setRequest({ cursor, revision: request.revision + 1 })}>Load more endpoints</button>}
        {cursor && endpoints.length >= MAX_ENDPOINTS && <Link to="/traffic">Showing up to 500 endpoints. Explore inventory →</Link>}
      </div>
    </>}
  </>;
}

function Sankey({ flows }: { flows: Flow[] }) {
  const diagram = flowDiagram(flows);
  const id = useId();
  const color = (source: string) => COLORS[diagram.sources.findIndex(n => n.name === source) % COLORS.length];
  return <div className="flow-canvas"><svg viewBox={`0 0 960 ${diagram.height}`} role="img" aria-labelledby={`${id}-title`} aria-describedby={`${id}-description`}>
    <title id={`${id}-title`}>Request flow by method and destination</title><desc id={`${id}-description`}>Ribbon widths represent request counts. Use the Table display for exact counts and the destination breakdown for endpoint links. Smaller destinations are grouped into Other destinations.</desc>
    <text x="136" y="18" textAnchor="end" className="flow-column-label">METHOD</text><text x="710" y="18" className="flow-column-label">DESTINATION</text>
    {diagram.ribbons.map(r => <path key={JSON.stringify([r.source, r.target])} d={r.path} fill={color(r.source)} className="flow-ribbon"><title>{r.source} → {r.target}: {number(r.count)} requests</title></path>)}
    {diagram.sources.map(n => <g key={n.name}><rect x="140" y={n.y} width="12" height={Math.max(n.height, 1)} rx="3" fill={color(n.name)} /><text x="126" y={n.y + n.height / 2 - 2} textAnchor="end" className="flow-node-name">{n.name}</text><text x="126" y={n.y + n.height / 2 + 16} textAnchor="end" className="flow-node-count">{number(n.value)}</text></g>)}
    {diagram.targets.map(n => <g key={n.name}><rect x="688" y={n.y} width="12" height={Math.max(n.height, 1)} rx="3" fill="var(--gh-sys-primary)" /><text x="716" y={n.y + n.height / 2 - 2} className="flow-node-name"><title>{n.name}</title>{n.name.length > 29 ? `${n.name.slice(0, 26)}…` : n.name}</text><text x="716" y={n.y + n.height / 2 + 16} className="flow-node-count">{number(n.value)} requests</text></g>)}
  </svg></div>;
}
