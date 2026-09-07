import { adminIdentityChanged, adminSessionEnded, subscribeAdminSession } from './adminSession';

/** Upgrade cleanup only. Never read or reuse the legacy stored credential. */
export const ADMIN_TOKEN_STORAGE_KEY = 'greengateway_admin_token';
let token: string | null = null;
let bearerSelected = false;

export function removeLegacyAdminToken() {
  if (typeof window === 'undefined') return;
  try { window.sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY); } catch {
    // Disabled browser storage must not prevent memory-only authentication.
  }
}

export function getMemoryToken(): string | null { return token; }

export function setMemoryToken(value: string) {
  removeLegacyAdminToken();
  token = value.trim() || null;
  bearerSelected = token !== null;
  adminIdentityChanged();
}

export function clearMemoryToken() {
  removeLegacyAdminToken();
  token = null;
  bearerSelected = false;
  adminIdentityChanged();
}

/** A rejected bearer must never silently fall back to an ambient cookie. */
export function adminRequestCredentials(): RequestCredentials {
  return bearerSelected ? 'omit' : 'same-origin';
}

export function assertAdminRequestOrigin(input: string) {
  const url = new URL(input, window.location.origin);
  if (url.origin !== window.location.origin || url.username || url.password) {
    throw new Error('Admin requests must use the current origin.');
  }
}

export function authHeaders(): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// This listener is installed before UI subscribers, so none can reuse a token
// while processing an expiry event. Old requests are guarded by identityVersion.
subscribeAdminSession((event) => {
  if (event.kind === 'unauthenticated') token = null;
});

if (typeof window !== 'undefined') {
  removeLegacyAdminToken();
  window.addEventListener('pagehide', () => {
    token = null;
    removeLegacyAdminToken();
    adminSessionEnded();
  });
}
