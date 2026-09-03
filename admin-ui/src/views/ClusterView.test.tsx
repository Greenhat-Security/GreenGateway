import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ADMIN_TOKEN_STORAGE_KEY } from '../lib/auth';
import type { ClusterStatus } from '../lib/cluster';
import { ClusterView } from './ClusterView';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
});

describe('ClusterView', () => {
  it('reports a ready cluster with its replica, schema, revision, projector, and audit sections', async () => {
    const fetcher = clusterFetchMock({ status: clusterStatus() });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderClusterView();

    expect((await screen.findByTestId('cluster-mode-badge')).textContent).toBe(
      'Cluster mode',
    );
    expect(screen.getByTestId('cluster-state-badge').textContent).toBe('Ready');
    expect(screen.getByTestId('cluster-state-text').textContent).toBe(
      'State: Ready. This replica is serving traffic.',
    );

    expect(
      within(sectionByLabel('Replicas and versions')).getByText(
        '2 of 3 ready',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Replicas and versions')).getByText('3 replicas'),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Replicas and versions')).getByText(
        '1.0.1 (2), 1.0.2 (1)',
      ),
    ).toBeTruthy();

    expect(
      within(sectionByLabel('Schema compatibility')).getByText(
        'Compatible: the ledger is in this binary’s range',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Schema compatibility')).getByText('10 to 10'),
    ).toBeTruthy();

    expect(
      within(sectionByLabel('Security revisions')).getByText(
        'None: this replica is current',
      ),
    ).toBeTruthy();

    expect(
      within(sectionByLabel('Durable events and projector')).getByText(
        '8 events',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Durable events and projector')).getByText(
        'Present: a live replica holds the projector',
      ),
    ).toBeTruthy();

    expect(
      within(sectionByLabel('Audit queue')).getByText('3 of 8192 queued'),
    ).toBeTruthy();

    const taskRows = within(sectionByLabel('Leader tasks')).getAllByRole('row');
    expect(taskRows).toHaveLength(2);
    expect(within(taskRows[1]).getByText('audit_retention')).toBeTruthy();
    expect(within(taskRows[1]).getByText('Healthy')).toBeTruthy();

    // A healthy deployment has no reason, so it gets no remediation panel.
    expect(screen.queryByRole('region', { name: 'Remediation' })).toBeNull();
    expect(fetcher.clusterRequests).toBe(1);
  });

  it('renders a degraded reason from the fixed map with its remediation link', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          state: 'degraded',
          reason: 'maintenance_job_failing',
          leader_tasks: [
            {
              name: 'stale_member_sweep',
              held_by_this_instance: true,
              fence: 9,
              last_success_age_secs: 640,
              last_failure_code: 'timeout',
            },
          ],
        }),
      }).fetch,
    );

    renderClusterView();

    expect((await screen.findByTestId('cluster-state-badge')).textContent).toBe(
      'Degraded',
    );
    expect(screen.getByTestId('cluster-state-text').textContent).toBe(
      'State: Degraded. This replica is serving traffic. Reason: Maintenance job failing.',
    );
    expect(
      screen.getAllByText(
        'A background job owned by the maintenance singleton recorded a failure on its last run.',
      ).length,
    ).toBeGreaterThan(0);

    // The failing job is named as text, not by colour alone, and its raw
    // error code is rendered through the classifier's fixed vocabulary.
    expect(screen.getByText('Failing: Statement timed out')).toBeTruthy();
    expect(
      within(sectionByLabel('Leader tasks')).getByText('This replica'),
    ).toBeTruthy();

    const remediation = screen.getByRole('link', {
      name: 'Deployment guide: Membership and maintenance',
    });
    expect(remediation.getAttribute('href')).toBe(
      'https://github.com/Greenhat-Security/GreenGateway/blob/main/docs/deployment/postgres.md#membership-and-maintenance',
    );
  });

  it('reports a draining replica as not serving traffic', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          ready: false,
          state: 'draining',
          reason: 'draining',
          local: { ...clusterStatus().local, draining: true, instance_ready: false },
        }),
      }).fetch,
    );

    renderClusterView();

    expect((await screen.findByTestId('cluster-state-badge')).textContent).toBe(
      'Draining',
    );
    expect(screen.getByTestId('cluster-state-text').textContent).toBe(
      'State: Draining. This replica is not serving traffic. Reason: Draining.',
    );
    expect(
      screen.getByRole('link', {
        name: 'Deployment guide: Readiness and status',
      }).getAttribute('href'),
    ).toBe(
      'https://github.com/Greenhat-Security/GreenGateway/blob/main/docs/deployment/postgres.md#readiness-and-status',
    );
    expect(
      within(sectionByLabel('This replica')).getByText('Draining'),
    ).toBeTruthy();
  });

  it('reports a not-ready replica with the schema remediation anchor', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          ready: false,
          state: 'not_ready',
          reason: 'schema_incompatible',
          schema: {
            current_version: 11,
            binary_min: 10,
            binary_max: 10,
            compatible: false,
          },
        }),
      }).fetch,
    );

    renderClusterView();

    expect((await screen.findByTestId('cluster-state-badge')).textContent).toBe(
      'Not ready',
    );
    expect(screen.getByTestId('cluster-state-text').textContent).toBe(
      'State: Not ready. This replica is not serving traffic. Reason: Schema incompatible.',
    );
    expect(
      within(sectionByLabel('Schema compatibility')).getByText(
        'Incompatible: the ledger is outside this binary’s range',
      ),
    ).toBeTruthy();
    expect(
      screen.getByRole('link', {
        name: 'Deployment guide: Schema migrations',
      }).getAttribute('href'),
    ).toBe(
      'https://github.com/Greenhat-Security/GreenGateway/blob/main/docs/deployment/postgres.md#schema-migrations',
    );
  });

  it('renders standalone mode with the cluster-only sections reported as absent', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          mode: 'standalone',
          replicas: { ready: 1, total: 1 },
          binary_versions: [{ version: '1.0.1', count: 1 }],
          schema: {
            current_version: null,
            binary_min: 10,
            binary_max: 10,
            compatible: true,
          },
          projector: null,
          leader_tasks: null,
          pools: { database: null },
        }),
      }).fetch,
    );

    renderClusterView();

    expect((await screen.findByTestId('cluster-mode-badge')).textContent).toBe(
      'Standalone mode',
    );
    expect(
      within(sectionByLabel('Durable events and projector')).getByText(
        'Not reported: standalone deployments have no projector',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Leader tasks')).getByText(
        'Not reported: standalone deployments have no maintenance singleton',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Database pool')).getByText(
        'Not reported: standalone deployments have no shared pool',
      ),
    ).toBeTruthy();
    expect(
      within(sectionByLabel('Schema compatibility')).getByText('Not reported'),
    ).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('never renders a reason string the fixed map does not know', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          ready: false,
          state: 'not_ready',
          reason: 'postgres://gateway:hunter2@db.internal.example:5432/db',
        }),
      }).fetch,
    );

    renderClusterView();

    expect(
      (await screen.findByTestId('cluster-state-text')).textContent,
    ).toContain('Reason: Unrecognized reason.');
    expect(
      document.body.textContent?.includes('postgres://'),
    ).toBe(false);
  });

  it('gates the view on admin:cluster:read without calling the cluster API', async () => {
    const fetcher = clusterFetchMock({
      status: clusterStatus(),
      roles: { reader: { permissions: ['admin:policy:read'] } },
    });
    vi.stubGlobal('fetch', fetcher.fetch);

    renderClusterView({ token: jwtWithRoles(['reader']) });

    expect(
      await screen.findByText('Cluster permission required'),
    ).toBeTruthy();
    expect(
      screen.getByText('This token is valid but does not include admin:cluster:read.'),
    ).toBeTruthy();
    expect(fetcher.clusterRequests).toBe(0);
    expect(screen.queryByTestId('cluster-state-badge')).toBeNull();
  });

  it('renders the permission panel when the cluster API answers 403', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({ status: clusterStatus(), clusterStatusCode: 403 }).fetch,
    );

    renderClusterView();

    expect(
      await screen.findByText('Cluster permission required'),
    ).toBeTruthy();
    expect(screen.queryByText('Cluster status request failed')).toBeNull();
  });

  it('surfaces a failed cluster status request', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({ status: clusterStatus(), clusterStatusCode: 503 }).fetch,
    );

    renderClusterView();

    expect(
      await screen.findByText('Cluster status request failed'),
    ).toBeTruthy();
    expect(screen.getByText('cluster status is unavailable')).toBeTruthy();
    expect(screen.queryByTestId('cluster-state-badge')).toBeNull();
  });

  it('announces the state politely and keeps the task table and links keyboard reachable', async () => {
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          state: 'degraded',
          reason: 'security_revision_lagging',
          local: {
            ...clusterStatus().local,
            compiled_security_revision: 4,
            observed_security_revision: 9,
            revision_lag: 5,
          },
        }),
      }).fetch,
    );

    renderClusterView();

    const stateText = await screen.findByTestId('cluster-state-text');
    expect(stateText.getAttribute('aria-live')).toBe('polite');
    expect(stateText.getAttribute('role')).toBe('status');

    // The scrollable table is reachable and named for a keyboard user.
    const tableRegion = screen.getByRole('region', {
      name: 'Leader task health',
    });
    expect(tableRegion.getAttribute('tabindex')).toBe('0');
    expect(within(tableRegion).getByRole('table')).toBeTruthy();
    expect(
      within(tableRegion)
        .getAllByRole('columnheader')
        .map((header) => header.textContent),
    ).toEqual(['Job', 'Health', 'Held by', 'Last success', 'Fence']);

    // Every section is a landmark with an accessible name, and the state
    // is carried by words rather than by the badge colour alone.
    expect(screen.getByRole('region', { name: 'Deployment state' })).toBeTruthy();
    expect(screen.getByTestId('cluster-state-badge').textContent).toBe(
      'Degraded',
    );
    expect(
      within(sectionByLabel('Security revisions')).getByText('5 revisions'),
    ).toBeTruthy();

    // The remediation link is a real anchor with an href, so it is in the
    // tab order without any extra handling.
    const link = screen.getByRole('link', {
      name: 'Deployment guide: The policy control plane',
    });
    expect(link.tagName).toBe('A');
    expect(link.getAttribute('href')?.startsWith('https://')).toBe(true);
  });

  it('names the host only when the deployment opted into exposing it', async () => {
    vi.stubGlobal('fetch', clusterFetchMock({ status: clusterStatus() }).fetch);
    renderClusterView();

    // CLUSTER_STATUS_EXPOSE_HOSTNAMES is off, so the API sends null and
    // the row is absent rather than rendered as a missing value.
    const replica = await screen.findByRole('region', { name: 'This replica' });
    expect(within(replica).queryByText('Hostname')).toBeNull();

    cleanup();
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: clusterStatus({
          local: { ...clusterStatus().local, hostname: 'greengateway-7d9f6c' },
        }),
      }).fetch,
    );
    renderClusterView();

    const opted = await screen.findByRole('region', { name: 'This replica' });
    expect(within(opted).getByText('Hostname')).toBeTruthy();
    expect(within(opted).getByText('greengateway-7d9f6c')).toBeTruthy();
  });

  /**
   * `docs/deployment/postgres.md` calls its own headings part of that
   * file's contract, because this page links an operator straight into
   * them mid-incident. A heading renamed there and not here is a dead
   * link nobody notices until the night it is needed, so the link this
   * view actually renders is checked against the file itself.
   */
  it('links every reason to a heading that exists in the deployment guide', async () => {
    // Resolved from the vitest root (`admin-ui`) rather than from
    // `import.meta.url`, which the transform does not leave as a file URL.
    const guide = readFileSync(
      resolve(process.cwd(), '../docs/deployment/postgres.md'),
      'utf8',
    );
    const anchors = new Set(
      guide
        .split('\n')
        .filter((line) => /^#{2,3} /.test(line))
        .map((line) => githubAnchor(line.replace(/^#+ /, ''))),
    );
    expect(anchors.size).toBeGreaterThan(5);

    const reasons = [
      'starting',
      'draining',
      'config_fingerprint_mismatch',
      'storage_unavailable',
      'schema_incompatible',
      'instance_lease_invalid',
      'security_revision_not_compiled',
      'required_upstream_unavailable',
      'replicas_unavailable',
      'security_revision_lagging',
      'maintenance_job_failing',
      'member_error_reported',
      // And the fallback the view uses for a reason it does not know.
      'a_reason_from_a_newer_gateway',
    ];

    for (const reason of reasons) {
      cleanup();
      vi.stubGlobal(
        'fetch',
        clusterFetchMock({
          status: clusterStatus({ ready: false, state: 'not_ready', reason }),
        }).fetch,
      );
      renderClusterView();

      const remediation = await screen.findByRole('region', {
        name: 'Remediation',
      });
      const link = await within(remediation).findByRole('link');
      const href = link.getAttribute('href') ?? '';
      const anchor = href.slice(href.indexOf('#') + 1);
      expect(
        anchors.has(anchor),
        `${reason} links to #${anchor}, which is not a heading in docs/deployment/postgres.md`,
      ).toBe(true);

      // A reason the gateway can send must be in the view's map, not
      // swept into the unrecognized fallback. Only the last entry, which
      // is not a reason the gateway has, is allowed to land there.
      const known = reason !== 'a_reason_from_a_newer_gateway';
      expect(
        screen.getByTestId('cluster-state-text').textContent?.includes(
          'Reason: Unrecognized reason.',
        ),
        `${reason} is a reason the gateway sends; the view must have a label for it`,
      ).toBe(!known);
    }
  });

  it('shows a loading status region before the first response settles', async () => {
    vi.stubGlobal('fetch', clusterFetchMock({ status: clusterStatus() }).fetch);

    renderClusterView();

    expect(screen.getByText('Loading cluster status')).toBeTruthy();
    await waitFor(() => {
      expect(screen.queryByText('Loading cluster status')).toBeNull();
    });
  });

  it('mounts the state live region before the first response, so the state arriving is a change', async () => {
    vi.stubGlobal('fetch', clusterFetchMock({ status: clusterStatus() }).fetch);

    renderClusterView();

    // A live region announces mutations made after it is already in the
    // accessibility tree. One inserted with its sentence already in it
    // announces nothing at all, so the region has to exist — and say it
    // has no answer yet — before the response lands.
    const region = screen.getByTestId('cluster-state-text');
    expect(region.getAttribute('aria-live')).toBe('polite');
    expect(region.getAttribute('role')).toBe('status');
    expect(region.textContent).toBe(
      'State: not read yet. This console has no answer from the gateway.',
    );

    await waitFor(() => {
      expect(screen.getByTestId('cluster-state-text').textContent).toBe(
        'State: Ready. This replica is serving traffic.',
      );
    });
    expect(screen.getByTestId('cluster-state-text')).toBe(region);
  });

  it('says a leader task is not held here, never that another replica holds it', async () => {
    vi.stubGlobal('fetch', clusterFetchMock({ status: clusterStatus() }).fetch);

    renderClusterView();

    // `held_by_this_instance` is one bit about this process. When the
    // lease is wedged it is false on every replica at once, and this is
    // the table an operator reads during exactly that incident.
    const tasks = await screen.findByRole('region', { name: 'Leader tasks' });
    expect(within(tasks).getByText('Not this replica')).toBeTruthy();
    expect(within(tasks).queryByText('Another replica')).toBeNull();
  });

  it('reports an idle audit queue as empty rather than as a fresh event', async () => {
    const base = clusterStatus();
    vi.stubGlobal(
      'fetch',
      clusterFetchMock({
        status: {
          ...base,
          // What the gateway reports while the audit writer is idle: an
          // empty queue and an age of zero.
          audit: { ...base.audit, queue_depth: 0, oldest_age_secs: 0 },
        },
      }).fetch,
    );

    renderClusterView();

    const audit = await screen.findByRole('region', { name: 'Audit queue' });
    expect(within(audit).getByText('Nothing queued')).toBeTruthy();
    expect(within(audit).queryByText('Under a second ago')).toBeNull();
  });
});

function renderClusterView({
  token = jwtWithRoles(['admin']),
}: {
  token?: string | null;
} = {}) {
  window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  if (token !== null) {
    window.sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  }

  render(
    <MemoryRouter>
      <ClusterView />
    </MemoryRouter>,
  );
}

/** The `<section aria-label="...">` a group of facts is rendered into. */
function sectionByLabel(label: string): HTMLElement {
  return screen.getByRole('region', { name: label });
}

function clusterFetchMock({
  status,
  roles = { admin: { permissions: ['*'] } },
  clusterStatusCode = 200,
}: {
  status: ClusterStatus;
  roles?: Record<string, { permissions: string[] }>;
  clusterStatusCode?: number;
}) {
  const state = { clusterRequests: 0 };

  const fetch = vi.fn((input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');

    if (url.pathname === '/v1/admin/policy') {
      return Promise.resolve(
        jsonResponse(200, {
          schema_version: '0.1.0',
          id: 'test-policy',
          default_action: 'deny',
          enforcement_mode: 'enforce',
          roles,
          routes: [],
          rules: [],
        }),
      );
    }

    if (url.pathname === '/v1/admin/cluster') {
      state.clusterRequests += 1;
      if (clusterStatusCode !== 200) {
        return Promise.resolve(
          jsonResponse(clusterStatusCode, {
            error:
              clusterStatusCode === 403
                ? 'permission denied'
                : 'cluster status is unavailable',
          }),
        );
      }

      return Promise.resolve(jsonResponse(200, status));
    }

    return Promise.reject(new Error(`unexpected fetch: ${url.pathname}`));
  });

  return {
    fetch,
    get clusterRequests() {
      return state.clusterRequests;
    },
  };
}

/**
 * The `GET /v1{ADMIN_PREFIX}/cluster` body, field for field as
 * `gateway/src/cluster_status.rs` serializes it.
 */
function clusterStatus(overrides: Partial<ClusterStatus> = {}): ClusterStatus {
  return {
    mode: 'cluster',
    ready: true,
    state: 'ready',
    reason: null,
    schema: {
      current_version: 10,
      binary_min: 10,
      binary_max: 10,
      compatible: true,
    },
    replicas: { ready: 2, total: 3 },
    binary_versions: [
      { version: '1.0.1', count: 2 },
      { version: '1.0.2', count: 1 },
    ],
    local: {
      instance_id: '00000000-0000-0000-0000-000000000001',
      boot_id: '00000000-0000-0000-0000-000000000002',
      boot_age_secs: 4_210,
      hostname: null,
      instance_ready: true,
      draining: false,
      compiled_security_revision: 7,
      observed_security_revision: 7,
      revision_lag: 0,
    },
    reconcile: { last_pass_age_secs: 3, failures_total: 0 },
    projector: {
      fence: 4,
      checkpoint_position: 120,
      stream_head: 128,
      lag_events: 8,
      leader_present: true,
      last_flush_age_secs: 0.5,
    },
    leader_tasks: [
      {
        name: 'audit_retention',
        held_by_this_instance: false,
        fence: 4,
        last_success_age_secs: 12,
        last_failure_code: null,
      },
    ],
    audit: {
      queue_depth: 3,
      queue_capacity: 8_192,
      oldest_age_secs: 0.25,
      dropped_total: 0,
    },
    pools: { database: { size: 8, available: 6, waiting: 0, timeouts_total: 0 } },
    ...overrides,
  };
}

/**
 * GitHub's heading-to-anchor rule, as far as this file's headings need it:
 * lowercase, drop everything but word characters, spaces and hyphens
 * (backticks and slashes included), then spaces to hyphens.
 */
function githubAnchor(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\w\- ]+/g, '')
    .replace(/ +/g, '-');
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jwtWithRoles(roles: string[]): string {
  return [
    base64UrlJson({ alg: 'none', typ: 'JWT' }),
    base64UrlJson({ sub: 'test-user', roles }),
    'signature',
  ].join('.');
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
