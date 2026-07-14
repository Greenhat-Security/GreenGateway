import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import type { GatewayStatus } from '../lib/status';
import { StatusPage } from './StatusPage';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('StatusPage', () => {
  it('renders gateway status and active config summary fields', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, gatewayStatus()));
    vi.stubGlobal('fetch', fetchMock);

    renderStatusPage();

    expect(await screen.findByText('0.1.0')).toBeTruthy();
    expect(screen.getByText('2h 3m')).toBeTruthy();
    expect(screen.getByText('127.0.0.1:8080')).toBeTruthy();
    expect(screen.getByText('status-policy')).toBeTruthy();
    expect(screen.getByText('17.5 req/s, burst 31')).toBeTruthy();
    expect(screen.getByText('4.25 req/s, burst 9')).toBeTruthy();
    expect(screen.getByText('2 configured')).toBeTruthy();
    expect(screen.getByText('https://example.test')).toBeTruthy();
    expect(screen.getByText('https://ops.example.test')).toBeTruthy();
    expect(screen.getByText('3')).toBeTruthy();
    expect(screen.getByText('NAT64 prefixes')).toBeTruthy();
    expect(screen.getByText('Deny non-global IPs')).toBeTruthy();

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/admin/status',
      expect.objectContaining({
        headers: expect.objectContaining({ Accept: 'application/json' }),
      }),
    );
  });

  it.each([
    {
      status: 401,
      body: { error: 'unauthorized' },
      text: 'Bearer token required',
    },
    {
      status: 403,
      body: { error: 'forbidden' },
      text: 'Admin role required',
    },
  ])('renders a distinct $status error state', async ({ status, body, text }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(status, body)));

    renderStatusPage();

    expect(await screen.findByText(text)).toBeTruthy();
  });
});

function renderStatusPage() {
  render(
    <MemoryRouter>
      <StatusPage />
    </MemoryRouter>,
  );
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
    },
  });
}

function gatewayStatus(overrides: Partial<GatewayStatus> = {}): GatewayStatus {
  return {
    version: '0.1.0',
    uptime_seconds: 7384,
    listen_addr: '127.0.0.1:8080',
    auth_enabled: true,
    rbac: {
      policy_loaded: true,
      policy_id: 'status-policy',
    },
    audit_sinks: {
      stdout: true,
      file: false,
      sqlite: true,
      broadcast: true,
    },
    rate_limits: {
      read: {
        requests_per_second: 17.5,
        burst: 31,
      },
      write: {
        requests_per_second: 4.25,
        burst: 9,
      },
    },
    cors_allow_origins: [
      'https://example.test',
      'https://ops.example.test',
    ],
    trust_proxy_headers: false,
    csrf_enabled: true,
    egress: {
      allowed_hosts_count: 3,
      nat64_prefixes_count: 2,
      deny_private_ips: true,
    },
    ...overrides,
  };
}
