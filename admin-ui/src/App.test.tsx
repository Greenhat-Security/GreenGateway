import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it } from 'vitest';

import { AdminShell } from './App';

afterEach(() => {
  cleanup();
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
});
