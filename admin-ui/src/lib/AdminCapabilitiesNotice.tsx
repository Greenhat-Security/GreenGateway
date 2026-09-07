import type { AdminCapabilitiesState } from './adminCapabilities';
import { refreshAdminCapabilities } from './adminCapabilities';

/** Keep capability availability separate from a resource's own denial/error. */
export function AdminCapabilitiesNotice({ state }: { state: AdminCapabilitiesState }) {
  if (state.status === 'ready') return null;
  if (state.status === 'loading') return <p role="status">Checking admin permissions…</p>;
  const message = state.status === 'unauthenticated'
    ? 'Sign in to check your admin permissions.'
    : state.status === 'forbidden'
      ? 'Your session cannot read admin permissions.'
      : 'Admin permissions are temporarily unavailable. Protected actions are disabled.';
  return <div className="error-panel alert warning" role="alert">
    <p>{message}</p>
    <button type="button" className="secondary-button" onClick={refreshAdminCapabilities}>
      Retry permissions
    </button>
  </div>;
}
