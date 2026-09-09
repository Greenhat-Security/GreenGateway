import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { observation } from '../../tests/fixtures/traffic-overview';
import { AdminApiError } from '../lib/api';
import { fetchTrafficEndpoints } from '../lib/traffic';
import { TrafficOverview, TrafficOverviewData } from './TrafficOverview';
import { useAdminCapabilities, useAdminIdentityVersion } from '../lib/adminCapabilities';
vi.mock('../lib/traffic', async original => ({ ...await original<typeof import('../lib/traffic')>(), fetchTrafficEndpoints: vi.fn() }));
vi.mock('../lib/adminCapabilities', async original => ({ ...await original<typeof import('../lib/adminCapabilities')>(), useAdminCapabilities: vi.fn(), useAdminIdentityVersion: vi.fn() }));
beforeEach(() => {
  vi.mocked(fetchTrafficEndpoints).mockReset();
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'ready', permissions: ['admin:traffic:read'] });
  vi.mocked(useAdminIdentityVersion).mockReturnValue(1);
});
afterEach(cleanup);
const mount = () => render(<MemoryRouter><TrafficOverviewData /></MemoryRouter>);
it('conceals data while checking permissions and preserves the view after renewal', async () => {
  vi.mocked(fetchTrafficEndpoints).mockResolvedValue({ endpoints: [observation()], next_cursor: null });
  const { rerender } = render(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  await screen.findByRole('img');
  fireEvent.change(screen.getByLabelText('Method'), { target: { value: 'GET' } });
  fireEvent.click(screen.getByRole('button', { name: /^Table$/ }));
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'loading', permissions: [] });
  rerender(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  expect(screen.queryByRole('table')).toBeNull();
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'ready', permissions: ['admin:traffic:read'] });
  rerender(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  expect(screen.getByRole('table')).toBeTruthy();
  expect((screen.getByLabelText('Method') as HTMLSelectElement).value).toBe('GET');
  expect(fetchTrafficEndpoints).toHaveBeenCalledTimes(1);
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'forbidden', permissions: [] });
  rerender(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  expect(screen.queryByRole('table', { hidden: true })).toBeNull();
});
it('drops retained observations when identity changes during a permission check', async () => {
  vi.mocked(fetchTrafficEndpoints).mockResolvedValueOnce({ endpoints: [observation()], next_cursor: null })
    .mockResolvedValueOnce({ endpoints: [], next_cursor: null });
  const { rerender } = render(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  await screen.findByRole('img');
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'loading', permissions: [] });
  vi.mocked(useAdminIdentityVersion).mockReturnValue(2);
  rerender(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  expect(screen.queryByRole('img', { hidden: true })).toBeNull();
  vi.mocked(useAdminCapabilities).mockReturnValue({ status: 'ready', permissions: ['admin:traffic:read'] });
  rerender(<MemoryRouter><TrafficOverview /></MemoryRouter>);
  await screen.findByText('No traffic observed yet');
  expect(fetchTrafficEndpoints).toHaveBeenCalledTimes(2);
});
it('filters flow and table counts and links to endpoint details', async () => {
  vi.mocked(fetchTrafficEndpoints).mockResolvedValue({ endpoints: [observation(), observation('POST', '/api/search', 40, 'https://search.example.test', false)], next_cursor: null });
  mount(); await screen.findByRole('img', { name: 'Request flow by method and destination' });
  fireEvent.change(screen.getByLabelText('Method'), { target: { value: 'POST' } });
  fireEvent.click(screen.getByRole('button', { name: /^Table$/ }));
  expect(screen.getByRole('table').textContent).toContain('40');
  expect(screen.getByRole('table').textContent).not.toContain('120');
  fireEvent.click(screen.getByRole('button', { name: /https:\/\/search.example.test/ }));
  expect(screen.getByRole('link', { name: 'POST /api/search' }).getAttribute('href')).toContain('method=POST&endpoint_template=%2Fapi%2Fsearch');
});
it('reports an empty deployment without fabricated sample traffic', async () => {
  vi.mocked(fetchTrafficEndpoints).mockResolvedValue({ endpoints: [], next_cursor: null }); mount();
  await screen.findByText('No traffic observed yet'); expect(screen.queryByRole('img')).toBeNull();
});
it('deduplicates pages and removes old observations when access is denied', async () => {
  vi.mocked(fetchTrafficEndpoints).mockResolvedValueOnce({ endpoints: [observation()], next_cursor: 'next' })
    .mockResolvedValueOnce({ endpoints: [observation(), observation('POST', '/b', 20)], next_cursor: 'last' })
    .mockRejectedValueOnce(new AdminApiError(403, 'Forbidden'));
  mount(); fireEvent.click(await screen.findByRole('button', { name: 'Load more endpoints' }));
  await screen.findByText(/Lifetime observations for 2 loaded/);
  fireEvent.click(screen.getByRole('button', { name: 'Load more endpoints' }));
  await screen.findByRole('alert'); expect(screen.queryByRole('img')).toBeNull();
});
it('retries a failed request and clears filters with no matches', async () => {
  vi.mocked(fetchTrafficEndpoints).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({ endpoints: [observation()], next_cursor: null });
  mount(); fireEvent.click(await screen.findByRole('button', { name: 'Retry' }));
  await screen.findByRole('img'); fireEvent.change(screen.getByLabelText('Endpoint'), { target: { value: 'missing' } });
  expect(screen.getByText('No matching observations')).toBeTruthy(); fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
  await waitFor(() => expect(screen.getByRole('img')).toBeTruthy());
});
