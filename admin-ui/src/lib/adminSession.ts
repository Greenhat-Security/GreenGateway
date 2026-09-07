/** Signals contain no tokens, claims or policy contents. */
export type AdminSessionEvent =
  | { kind: 'identity' | 'authenticated' | 'unauthenticated' | 'policy' | 'navigation' }
  | { kind: 'forbidden'; capabilitiesRequest: boolean };

let identityVersion = 0;
let unauthenticated = false;
const listeners = new Set<(event: AdminSessionEvent) => void>();
export const getAdminIdentityVersion = () => identityVersion;
export const isAdminUnauthenticated = () => unauthenticated;

export function subscribeAdminSession(listener: (event: AdminSessionEvent) => void) {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

function emit(event: AdminSessionEvent) {
  for (const listener of listeners) listener(event);
}

export function adminAuthenticationSucceeded(requestVersion: number) {
  if (requestVersion === identityVersion && unauthenticated) {
    unauthenticated = false;
    emit({ kind: 'authenticated' });
  }
}

export function adminIdentityChanged() {
  identityVersion += 1;
  unauthenticated = false;
  emit({ kind: 'identity' });
}

export function adminAuthorizationFailed(status: number, requestVersion: number, capabilitiesRequest: boolean) {
  if (requestVersion !== identityVersion) return;
  if (status === 401 && !unauthenticated) {
    unauthenticated = true;
    identityVersion += 1;
    emit({ kind: 'unauthenticated' });
  } else if (status === 403) {
    emit({ kind: 'forbidden', capabilitiesRequest });
  }
}

export const adminPolicyChanged = () => emit({ kind: 'policy' });
export const adminNavigationChanged = () => emit({ kind: 'navigation' });
