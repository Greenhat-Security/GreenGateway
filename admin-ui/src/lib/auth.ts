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

export function decodeJwtRolesClaim(token: string): string[] | null {
  const payloadSegment = token.split('.')[1];
  if (!payloadSegment) {
    return null;
  }

  const payloadText = decodeBase64UrlSegment(payloadSegment);
  if (payloadText === null) {
    return null;
  }

  try {
    const payload: unknown = JSON.parse(payloadText);
    if (!isJsonObject(payload) || !Array.isArray(payload.roles)) {
      return null;
    }
    if (!payload.roles.every((role): role is string => typeof role === 'string')) {
      return null;
    }

    return payload.roles;
  } catch {
    return null;
  }
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

function decodeBase64UrlSegment(segment: string): string | null {
  if (typeof atob !== 'function') {
    return null;
  }

  try {
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const paddingLength = (4 - (normalized.length % 4)) % 4;
    const binary = atob(`${normalized}${'='.repeat(paddingLength)}`);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
