import { useSyncExternalStore } from 'react';
import { AdminApiError, fetchAdminCapabilities } from './api';
import { ADMIN_TOKEN_STORAGE_KEY } from './auth';
import {
  adminIdentityChanged, getAdminIdentityVersion, isAdminUnauthenticated, subscribeAdminSession,
  type AdminSessionEvent,
} from './adminSession';

export type AdminCapabilitiesState = Readonly<{
  status: 'loading' | 'ready' | 'unauthenticated' | 'forbidden' | 'unavailable';
  permissions: readonly string[];
}>;
const EMPTY: AdminCapabilitiesState = { status: 'loading', permissions: [] };
const REFRESH_MS = 60_000;
const MIN_REFRESH_MS = 5_000;
let state = EMPTY;
let identityVersion = getAdminIdentityVersion();
let sequence = 0;
let lastStarted = -Infinity;
let controller: AbortController | null = null;
let pending: ReturnType<typeof setTimeout> | undefined;
let deadline: ReturnType<typeof setTimeout> | undefined;
let stop: (() => void) | undefined;
const listeners = new Set<() => void>();

function publish(next: AdminCapabilitiesState) {
  identityVersion = getAdminIdentityVersion();
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
  if (!listeners.size || document.visibilityState === 'hidden') return;
  lastStarted = Date.now();
  const request = ++sequence;
  const identity = getAdminIdentityVersion();
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
    if (request !== sequence || identity !== getAdminIdentityVersion()) return;
    publish({ status: 'ready', permissions: result.permissions });
  } catch (error) {
    if (request !== sequence || identity !== getAdminIdentityVersion()) return;
    const status = error instanceof AdminApiError && error.status === 401
      ? 'unauthenticated'
      : error instanceof AdminApiError && error.status === 403 ? 'forbidden' : 'unavailable';
    publish({ status, permissions: [] });
  } finally {
    if (request === sequence) { clearTimeout(deadline); controller = null; }
  }
}

/** Drop old grants immediately; coalesce retries/focus/navigation to one per 5s. */
export function refreshAdminCapabilities() {
  if (!listeners.size) return;
  cancel();
  publish(EMPTY);
  if (document.visibilityState === 'hidden') return;
  const delay = Math.max(0, MIN_REFRESH_MS - (Date.now() - lastStarted));
  if (delay === 0) void load();
  else pending = setTimeout(() => { void load(); }, delay);
}

function sessionEvent(event: AdminSessionEvent) {
  if (event.kind === 'authenticated') return;
  if (event.kind === 'unauthenticated') {
    cancel();
    publish({ status: 'unauthenticated', permissions: [] });
  } else if (event.kind === 'identity') {
    cancel();
    // A different identity must not wait for the old identity's refresh budget.
    lastStarted = -Infinity;
    refreshAdminCapabilities();
  } else if (event.kind === 'navigation') {
    refreshIfIdle();
  } else if (event.kind !== 'forbidden' || !event.capabilitiesRequest) {
    refreshAdminCapabilities();
  }
}

function refreshIfIdle() {
  // A request already in progress will answer with current server permissions.
  if (!controller && pending === undefined) refreshAdminCapabilities();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    const unsubscribeSession = subscribeAdminSession(sessionEvent);
    const onFocus = () => refreshIfIdle();
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') { cancel(); publish(EMPTY); }
      else refreshAdminCapabilities();
    };
    const onStorage = (event: StorageEvent) => {
      try {
        if (event.storageArea === window.sessionStorage &&
            (event.key === ADMIN_TOKEN_STORAGE_KEY || event.key === null)) adminIdentityChanged();
      } catch { /* Storage can be disabled; cookie sessions still refresh on focus. */ }
    };
    window.addEventListener('focus', onFocus);
    window.addEventListener('storage', onStorage);
    document.addEventListener('visibilitychange', onVisibility);
    const interval = setInterval(() => {
      if (document.visibilityState !== 'hidden' && state.status !== 'unauthenticated') refreshAdminCapabilities();
    }, REFRESH_MS);
    stop = () => {
      unsubscribeSession();
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('storage', onStorage);
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(interval);
    };
    refreshAdminCapabilities();
  }
  return () => {
    listeners.delete(listener);
    if (!listeners.size) {
      stop?.();
      stop = undefined;
      cancel();
      state = EMPTY;
      lastStarted = -Infinity;
    }
  };
}

export function useAdminCapabilities() {
  return useSyncExternalStore(subscribe,
    () => identityVersion === getAdminIdentityVersion() ? state : EMPTY,
    () => EMPTY);
}

export function hasAdminPermission(state: AdminCapabilitiesState, permission: string) {
  return state.status === 'ready' && state.permissions.includes(permission);
}

export function useAdminIdentityVersion() {
  return useSyncExternalStore(subscribeAdminSession, getAdminIdentityVersion, getAdminIdentityVersion);
}

export function useAdminUnauthenticated() {
  return useSyncExternalStore(subscribeAdminSession, isAdminUnauthenticated, isAdminUnauthenticated);
}
