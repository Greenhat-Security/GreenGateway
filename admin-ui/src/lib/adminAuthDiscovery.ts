import { adminApiUrl } from './config';

/** The cookie contract, accepted only for this UI's own admin API prefix. */
export type AdminSessionOffer = Readonly<{
  loginUrl: string;
  completionUrl: string;
  logoutUrl: string;
}>;

/**
 * How this gateway completes SSO, decided once per page load.
 *
 * - `cookie`: a well-formed session offer for this UI's admin API prefix.
 * - `bearer`: `/version` answered and advertised no session. This is the only
 *   answer that counts as "no session offered".
 * - `unconfirmed`: the management-origin route answered 401, 403 or 404. The
 *   gateway never answers it that way while sessions are enabled, but both a
 *   gateway without sessions and a proxy that does not forward the route do,
 *   so the answer does not say which completion is safe.
 * - `unavailable`: no usable answer, including a malformed advertisement.
 *
 * Only `cookie` and `bearer` let the SSO completion post its code.
 */
export type AdminAuthDiscovery =
  | Readonly<{ kind: 'cookie'; session: AdminSessionOffer }>
  | Readonly<{ kind: 'bearer'; loginConfigured: boolean }>
  | Readonly<{ kind: 'unconfirmed' }>
  | Readonly<{ kind: 'unavailable' }>;

export type AdminAuthDiscoverySource = Readonly<{
  /** The page's answer. Every caller shares the first request. */
  current: () => Promise<AdminAuthDiscovery>;
  /** Asks again only after `unavailable`; any other answer is final. */
  retry: () => Promise<AdminAuthDiscovery>;
}>;

const UNCONFIRMED: AdminAuthDiscovery = { kind: 'unconfirmed' };
const UNAVAILABLE: AdminAuthDiscovery = { kind: 'unavailable' };

/**
 * With sessions enabled the gateway registers `auth/config` and exempts it
 * from authentication and RBAC, so it answers 200 with an offer. Without
 * sessions the route is not registered, and this credential-less request is
 * answered by authentication (401), authorization (403) or the router (404).
 * A proxy that does not forward the route can answer any of these too, so
 * none of them is a statement that no session is offered.
 */
const NOT_SERVED_STATUSES = new Set([401, 403, 404]);

/**
 * One answer drives both the SSO completion and the panel, so they cannot
 * disagree about the credential mode. It is not keyed by identity: the first
 * sign-in's rejected permissions request changes the identity while the
 * completion is still using this answer.
 */
export function createAdminAuthDiscovery(): AdminAuthDiscoverySource {
  let answer: Promise<AdminAuthDiscovery> | null = null;
  const current = () => {
    answer ??= discoverAdminAuth();
    return answer;
  };
  const retry = () => {
    const previous = current();
    return previous.then((result) => {
      if (result.kind === 'unavailable' && answer === previous) {
        answer = discoverAdminAuth();
      }
      return current();
    });
  };
  return { current, retry };
}

/**
 * `/version` answers on a unified listener. A split management listener only
 * serves the prefix-aware `auth/config` route. Discovery bypasses the shared
 * admin client, so it never attaches a bearer token and a rejection cannot
 * end the current session.
 */
export async function discoverAdminAuth(): Promise<AdminAuthDiscovery> {
  try {
    const response = await fetch('/version', { cache: 'no-store' });
    if (response.ok) {
      const body: unknown = await response.json();
      if (isVersionResponse(body)) {
        return versionDiscovery(body);
      }
    }
  } catch {
    // Fall back to the management-origin discovery route.
  }

  try {
    const response = await fetch(adminApiUrl('/auth/config'), {
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    });
    if (NOT_SERVED_STATUSES.has(response.status)) {
      return UNCONFIRMED;
    }
    if (!response.ok) {
      return UNAVAILABLE;
    }
    const body: unknown = await response.json();
    // This route exists only to advertise a session, so a success without a
    // valid offer is malformed rather than an absent offer.
    const session = isJsonRecord(body) ? adminSessionOffer(body.admin_session) : null;
    return session === null ? UNAVAILABLE : { kind: 'cookie', session };
  } catch {
    return UNAVAILABLE;
  }
}

function versionDiscovery(body: VersionResponse): AdminAuthDiscovery {
  if (body.admin_session === undefined || body.admin_session === null) {
    return { kind: 'bearer', loginConfigured: body.admin_login_configured };
  }
  const session = adminSessionOffer(body.admin_session);
  // A malformed advertisement is not an absent one: fail closed rather than
  // completing SSO as a bearer token.
  return session === null ? UNAVAILABLE : { kind: 'cookie', session };
}

function adminSessionOffer(value: unknown): AdminSessionOffer | null {
  const offer = {
    loginUrl: adminApiUrl('/auth/login'),
    completionUrl: adminApiUrl('/auth/callback'),
    logoutUrl: adminApiUrl('/auth/logout'),
  };
  if (
    !isJsonRecord(value) ||
    value.completion_mode !== 'cookie' ||
    value.login_url !== offer.loginUrl ||
    value.completion_url !== offer.completionUrl ||
    value.logout_url !== offer.logoutUrl
  ) {
    return null;
  }
  return offer;
}

type VersionResponse = {
  admin_login_configured: boolean;
  admin_session?: unknown;
};

function isVersionResponse(value: unknown): value is VersionResponse {
  return isJsonRecord(value) && typeof value.admin_login_configured === 'boolean';
}

export function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
