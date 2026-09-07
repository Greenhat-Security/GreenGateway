export const ADMIN_TOKEN_STORAGE_KEY = 'greengateway_admin_token';

export function getStoredToken(): string | null {
  const storage = sessionStorageOrNull();
  if (!storage) {
    return null;
  }

  const token = storage.getItem(ADMIN_TOKEN_STORAGE_KEY);
  return token && token.trim().length > 0 ? token : null;
}

export function setStoredToken(token: string): boolean {
  const storage = sessionStorageOrNull();
  if (!storage) {
    return false;
  }

  const trimmed = token.trim();
  if (trimmed.length === 0) {
    storage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  } else {
    storage.setItem(ADMIN_TOKEN_STORAGE_KEY, trimmed);
  }

  return true;
}

export function clearStoredToken(): boolean {
  const storage = sessionStorageOrNull();
  if (!storage) {
    return false;
  }

  storage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  return true;
}

export function authHeaders(): Record<string, string> {
  const token = getStoredToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function sessionStorageOrNull(): Storage | null {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}
