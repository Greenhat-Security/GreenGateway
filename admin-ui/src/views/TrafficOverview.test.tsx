import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { observation } from '../../tests/fixtures/traffic-overview';
import { AdminApiError } from '../lib/api';
import { fetchTrafficEndpoints } from '../lib/traffic';
import { TrafficOverviewData } from './TrafficOverview';
vi.mock('../lib/traffic', async original => ({ ...await original<typeof import('../lib/traffic')>(), fetchTrafficEndpoints: vi.fn() }));
beforeEach(() => vi.mocked(fetchTrafficEndpoints).mockReset());
afterEach(cleanup);
const mount = () => render(<MemoryRouter><TrafficOverviewData /></MemoryRouter>);
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
