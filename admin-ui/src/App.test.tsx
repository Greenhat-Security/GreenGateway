import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { AdminShell } from './App';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.localStorage.removeItem('greengateway_admin_theme');
  delete document.documentElement.dataset.theme;
});

describe('AdminShell', () => {
  it('persists the selected color theme on the document element', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('light');

    fireEvent.click(
      screen.getByRole('button', { name: 'Switch to dark theme' }),
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(window.localStorage.getItem('greengateway_admin_theme')).toBe(
      'dark',
    );
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('rehydrates the selected color theme from localStorage on mount', () => {
    window.localStorage.setItem('greengateway_admin_theme', 'dark');

    render(
      <MemoryRouter initialEntries={['/']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(
      screen.getByRole('button', { name: 'Switch to light theme' }),
    ).toBeTruthy();
  });

  it('registers the traffic inventory route and navigation entry', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoints: [],
            next_cursor: null,
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter initialEntries={['/traffic']}>
        <AdminShell />
      </MemoryRouter>,
    );

    expect(screen.getByRole('link', { name: 'Traffic' })).toBeTruthy();
    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'Traffic inventory',
      }),
    ).toBeTruthy();
  });

  it('registers the traffic endpoint detail route', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            endpoint: {
              method: 'GET',
              endpoint_template: '/users/{id}',
              first_seen: '2026-07-04T08:00:00Z',
              last_seen: '2026-07-04T10:00:00Z',
              call_count: 10,
              distinct_principal_count: 1,
              is_new: false,
              reviewed: false,
              reviewed_at: null,
              reviewed_by: null,
              covered_by_rule: true,
              latency: {
                count: 10,
                p50_ms: 8,
                p95_ms: 15,
                p99_ms: 20,
                sample_count: 10,
              },
              status_counts: [{ status: 200, count: 10 }],
              updated_at: '2026-07-04T10:01:00Z',
            },
            principals: {
              principals: [],
              next_cursor: null,
            },
            audit: {
              available: false,
              match_strategy: 'stateless_path_template',
              match_limitations:
                'Matches literal paths and immediate well-known identifier templates; statefully learned slug templates are not reverse-mapped.',
              omitted_reason: 'AUDIT_SQLITE_PATH not configured',
            },
          }),
          {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
            },
          },
        ),
      ),
    );

    render(
      <MemoryRouter
        initialEntries={[
          '/traffic/detail?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D',
        ]}
      >
        <AdminShell />
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole('heading', {
        level: 2,
        name: 'GET /users/{id}',
      }),
    ).toBeTruthy();
  });
});
