const DEFAULT_ADMIN_BASE_PATH = '/admin';
const DEFAULT_ADMIN_API_BASE_PATH = '/v1/admin';

export function adminBasePath(): string {
  return runtimePathPrefix(
    'greengateway-admin-base',
    DEFAULT_ADMIN_BASE_PATH,
  );
}

export function adminApiUrl(path: string): string {
  const suffix = path.startsWith('/') ? path : `/${path}`;
  return `${adminApiBasePath()}${suffix}`;
}

function adminApiBasePath(): string {
  return runtimePathPrefix(
    'greengateway-admin-api-base',
    DEFAULT_ADMIN_API_BASE_PATH,
  );
}

function runtimePathPrefix(metaName: string, fallback: string): string {
  if (typeof document === 'undefined') {
    return fallback;
  }

  const configured = document
    .querySelector<HTMLMetaElement>(`meta[name="${metaName}"]`)
    ?.content.trim();

  if (!configured || !configured.startsWith('/')) {
    return fallback;
  }

  return configured.length > 1 ? configured.replace(/\/+$/, '') : fallback;
}
