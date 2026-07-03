import { type ReactNode, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { AdminApiError } from '../lib/api';
import { fetchGatewayStatus } from '../lib/status';
import type { GatewayStatus, RateLimitStatus } from '../lib/status';

type StatusLoadError = {
  kind: 'unauthorized' | 'forbidden' | 'network' | 'generic';
  message: string;
};

export function StatusPage() {
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<StatusLoadError | null>(null);

  useEffect(() => {
    let isCurrent = true;

    async function loadStatus() {
      setIsLoading(true);
      setError(null);

      try {
        const response = await fetchGatewayStatus();
        if (!isCurrent) {
          return;
        }

        setStatus(response);
      } catch (loadError) {
        if (!isCurrent) {
          return;
        }

        setStatus(null);
        setError(toStatusLoadError(loadError));
      } finally {
        if (isCurrent) {
          setIsLoading(false);
        }
      }
    }

    void loadStatus();

    return () => {
      isCurrent = false;
    };
  }, []);

  return (
    <main className="logs-page status-page">
      <section
        className="logs-panel status-panel"
        aria-labelledby="status-heading"
      >
        <div className="section-heading logs-heading">
          <div>
            <p className="eyebrow">Gateway</p>
            <h2 id="status-heading">Status</h2>
          </div>
          {status ? (
            <span className="result-count">v{status.version}</span>
          ) : null}
        </div>

        {error ? <StatusErrorMessage error={error} /> : null}

        {isLoading ? (
          <div className="loading-state" role="status">
            Loading gateway status
          </div>
        ) : null}

        {status ? <StatusSummary status={status} /> : null}
      </section>
    </main>
  );
}

function StatusSummary({ status }: { status: GatewayStatus }) {
  return (
    <div className="status-summary">
      <div className="status-stat-grid" aria-label="Runtime summary">
        <StatCard label="Version" value={status.version} />
        <StatCard label="Uptime" value={formatUptime(status.uptime_seconds)} />
        <StatCard label="Listen address" value={status.listen_addr} />
      </div>

      <div className="status-card-grid">
        <StatusSection title="Access control">
          <StatusItem
            label="Authentication"
            value={enabledLabel(status.auth_enabled)}
          />
          <StatusItem label="CSRF" value={enabledLabel(status.csrf_enabled)} />
          <StatusItem
            label="Trust proxy headers"
            value={enabledLabel(status.trust_proxy_headers)}
          />
          <StatusItem
            label="RBAC policy"
            value={status.rbac.policy_loaded ? 'Loaded' : 'Not loaded'}
          />
          <StatusItem
            label="Policy ID"
            value={status.rbac.policy_id ?? 'None'}
          />
        </StatusSection>

        <StatusSection title="Audit sinks">
          <StatusItem
            label="Stdout"
            value={enabledLabel(status.audit_sinks.stdout)}
          />
          <StatusItem
            label="File"
            value={enabledLabel(status.audit_sinks.file)}
          />
          <StatusItem
            label="SQLite"
            value={enabledLabel(status.audit_sinks.sqlite)}
          />
          <StatusItem
            label="Broadcast"
            value={enabledLabel(status.audit_sinks.broadcast)}
          />
        </StatusSection>

        <StatusSection title="Rate limits">
          <StatusItem
            label="Read"
            value={formatRateLimit(status.rate_limits.read)}
          />
          <StatusItem
            label="Write"
            value={formatRateLimit(status.rate_limits.write)}
          />
        </StatusSection>

        <StatusSection title="CORS">
          <StatusItem
            label="Allowed origins"
            value={
              status.cors_allow_origins.length > 0
                ? `${status.cors_allow_origins.length} configured`
                : 'None configured'
            }
          />
          {status.cors_allow_origins.length > 0 ? (
            <StatusListItem
              label="Origins"
              values={status.cors_allow_origins}
            />
          ) : null}
        </StatusSection>

        <StatusSection title="Egress">
          <StatusItem
            label="Allowed hosts"
            value={String(status.egress.allowed_hosts_count)}
          />
          <StatusItem
            label="Deny private IPs"
            value={enabledLabel(status.egress.deny_private_ips)}
          />
        </StatusSection>
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <article className="panel stat-card">
      <span className="stat-label">{label}</span>
      <span className="stat-value">{value}</span>
    </article>
  );
}

function StatusSection({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="panel status-section" aria-label={title}>
      <h3>{title}</h3>
      <dl className="status-grid">{children}</dl>
    </section>
  );
}

function StatusItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="status-item spec-row">
      <dt className="k">{label}</dt>
      <dd className="v">{value}</dd>
    </div>
  );
}

function StatusListItem({
  label,
  values,
}: {
  label: string;
  values: string[];
}) {
  return (
    <div className="status-item status-item-wide spec-row stacked">
      <dt className="k">{label}</dt>
      <dd>
        <div className="status-list" aria-label={label}>
          {values.map((value) => (
            <span key={value}>{value}</span>
          ))}
        </div>
      </dd>
    </div>
  );
}

function StatusErrorMessage({ error }: { error: StatusLoadError }) {
  if (error.kind === 'unauthorized') {
    return (
      <div className="error-panel alert warning" role="alert">
        <h3>Bearer token required</h3>
        <p>
          Paste a bearer token before viewing gateway status. Open the{' '}
          <Link to="/">token panel</Link>.
        </p>
      </div>
    );
  }

  if (error.kind === 'forbidden') {
    return (
      <div className="error-panel alert error" role="alert">
        <h3>Admin role required</h3>
        <p>This token is valid but does not include the admin role.</p>
      </div>
    );
  }

  return (
    <div className="error-panel alert error" role="alert">
      <h3>Status request failed</h3>
      <p>{error.message}</p>
    </div>
  );
}

function toStatusLoadError(error: unknown): StatusLoadError {
  if (error instanceof AdminApiError) {
    if (error.status === 401) {
      return { kind: 'unauthorized', message: error.message };
    }
    if (error.status === 403) {
      return { kind: 'forbidden', message: error.message };
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

export function formatUptime(seconds: number): string {
  const totalSeconds = Math.max(0, Math.floor(seconds));
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const remainingSeconds = totalSeconds % 60;
  const parts: string[] = [];

  if (days > 0) {
    parts.push(`${days}d`);
  }
  if (hours > 0) {
    parts.push(`${hours}h`);
  }
  if (minutes > 0 && parts.length < 2) {
    parts.push(`${minutes}m`);
  }
  if (parts.length === 0) {
    parts.push(`${remainingSeconds}s`);
  }

  return parts.join(' ');
}

function enabledLabel(value: boolean): string {
  return value ? 'Enabled' : 'Disabled';
}

function formatRateLimit(limit: RateLimitStatus): string {
  return `${limit.requests_per_second} req/s, burst ${limit.burst}`;
}
