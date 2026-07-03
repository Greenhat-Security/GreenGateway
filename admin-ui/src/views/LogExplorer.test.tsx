import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';

import { AuditEvent } from '../lib/audit';
import { LogExplorer } from './LogExplorer';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('LogExplorer', () => {
  it('loads the next cursor page and appends results', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(200, {
          events: [auditEvent({ event_id: 'first', event_type: 'audit.first' })],
          next_cursor: 7,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          events: [
            auditEvent({ event_id: 'second', event_type: 'audit.second' }),
          ],
          next_cursor: null,
        }),
      );
    vi.stubGlobal('fetch', fetchMock);

    renderLogExplorer();

    expect(await screen.findByText('audit.first')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));

    expect(await screen.findByText('audit.second')).toBeTruthy();
    expect(screen.getByText('audit.first')).toBeTruthy();

    const secondUrl = new URL(
      String(fetchMock.mock.calls[1][0]),
      'http://localhost',
    );
    expect(secondUrl.pathname).toBe('/v1/admin/audit');
    expect(secondUrl.searchParams.get('before_id')).toBe('7');
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
    {
      status: 503,
      body: { error: 'audit query store not configured' },
      text: 'Audit store unavailable',
    },
  ])('renders a meaningful $status error state', async ({ status, body, text }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(status, body)));

    renderLogExplorer();

    expect(await screen.findByText(text)).toBeTruthy();
  });

  it('expands a row to reveal the complete event JSON', async () => {
    const event = auditEvent({
      event_id: 'event-1',
      actor: {
        user_id: 'alice',
        roles: ['admin', 'operator'],
        auth_mode: 'bearer_token',
      },
      payload: {
        path: '/admin',
        status: 201,
        method: 'POST',
        latency_ms: 12,
      },
      schema_version: 1,
      user_agent: 'curl/8.8.0',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          events: [event],
          next_cursor: null,
        }),
      ),
    );

    renderLogExplorer();

    expect(await screen.findByText('http.request_observed')).toBeTruthy();
    fireEvent.click(
      screen.getByRole('button', { name: 'Expand event event-1' }),
    );

    const json = screen.getByTestId('event-json-event-1');
    expect(json.textContent).toContain('"schema_version": 1');
    expect(json.textContent).toContain('"roles": [');
    expect(json.textContent).toContain('"user_agent": "curl/8.8.0"');
    expect(json.textContent).toContain('"latency_ms": 12');
  });
});

function renderLogExplorer() {
  render(
    <MemoryRouter>
      <LogExplorer />
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

function auditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    event_id: 'event',
    event_type: 'http.request_observed',
    timestamp: '2024-06-01T12:00:00Z',
    schema_version: 1,
    request_id: 'req-1',
    source_ip: '127.0.0.1',
    user_agent: null,
    actor: {
      user_id: 'admin-user',
      roles: ['admin'],
      auth_mode: 'bearer_token',
    },
    payload: {
      path: '/health',
      status: 200,
      method: 'GET',
    },
    ...overrides,
  };
}
