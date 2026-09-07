import { useSyncExternalStore } from 'react';
import { AdminApiError, fetchAdminCapabilities } from './api';
export type AdminCapabilitiesState = Readonly<{
  status: 'loading' | 'ready' | 'unauthenticated' | 'forbidden' | 'unavailable';
  permissions: readonly string[];
}>;
const EMPTY: AdminCapabilitiesState = { status: 'loading', permissions: [] };
const MIN_REFRESH_MS = 5_000;
let state = EMPTY;
let sequence = 0;
let lastStarted = -Infinity;
let controller: AbortController | null = null;
let pending: ReturnType<typeof setTimeout> | undefined;
let deadline: ReturnType<typeof setTimeout> | undefined;
const listeners = new Set<() => void>();

function publish(next: AdminCapabilitiesState) {
  state = next;
  for (const listener of listeners) listener();
}

function cancel() {
  sequence += 1;
  controller?.abort();
  controller = null;
  clearTimeout(deadline);
  clearTimeout(pending);
  pending = undefined;
}

async function load() {
  pending = undefined;
  if (!listeners.size) return;
  lastStarted = Date.now();
  const request = ++sequence;
  controller = new AbortController();
  publish(EMPTY);
  try {
    const activeController = controller;
    const result = await Promise.race([
      fetchAdminCapabilities(activeController.signal),
      new Promise<never>((_, reject) => {
        deadline = setTimeout(() => {
          reject(new Error('Admin permissions request timed out.'));
          activeController.abort();
        }, 10_000);
      }),
    ]);
    if (request !== sequence) return;
    publish({ status: 'ready', permissions: result.permissions });
  } catch (error) {
    if (request !== sequence) return;
    const status = error instanceof AdminApiError && error.status === 401
      ? 'unauthenticated'
      : error instanceof AdminApiError && error.status === 403 ? 'forbidden' : 'unavailable';
    publish({ status, permissions: [] });
  } finally {
    if (request === sequence) { clearTimeout(deadline); controller = null; }
  }
}

/** Drop old grants immediately; coalesce manual retries to one per 5s. */
export function refreshAdminCapabilities() {
  if (!listeners.size) return;
  cancel();
  publish(EMPTY);
  const delay = Math.max(0, MIN_REFRESH_MS - (Date.now() - lastStarted));
  if (delay === 0) void load();
  else pending = setTimeout(() => { void load(); }, delay);
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    refreshAdminCapabilities();
  }
  return () => {
    listeners.delete(listener);
    if (!listeners.size) {
      cancel();
      state = EMPTY;
      lastStarted = -Infinity;
    }
  };
}

export function useAdminCapabilities() {
  return useSyncExternalStore(subscribe,
    () => state,
    () => EMPTY);
}

export function hasAdminPermission(state: AdminCapabilitiesState, permission: string) {
  return state.status === 'ready' && state.permissions.includes(permission);
}
