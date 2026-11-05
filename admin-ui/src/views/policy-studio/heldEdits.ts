import { useSyncExternalStore } from 'react';

import type { PolicyDraft } from '../../lib/policyDrafts';

// The open draft's unsaved edits, held while the admin session is signed
// out. An ended session replaces every admin view, the Policy Studio
// included, so the Studio's candidate would otherwise be lost with it.
// They stay in page memory only, never in browser storage, and the Studio
// shows them again only after the gateway answers their draft to the new
// session: a draft is visible to its owner alone, so another principal's
// session never sees them.
export type HeldPolicyEdits = Readonly<{
  // The draft as it was open, so a save made from the held edits is still
  // bound to the revision they were made on.
  draft: PolicyDraft;
  serverSource: string;
  source: string;
}>;

let held: HeldPolicyEdits | null = null;
const listeners = new Set<() => void>();

export function holdPolicyEdits(edits: HeldPolicyEdits) {
  held = edits;
  changed();
}

export function heldPolicyEdits(): HeldPolicyEdits | null {
  return held;
}

export function releaseHeldPolicyEdits() {
  if (held === null) {
    return;
  }
  held = null;
  changed();
}

export function useHoldsPolicyEdits(): boolean {
  return useSyncExternalStore(subscribe, holdsEdits, holdsEdits);
}

function holdsEdits(): boolean {
  return held !== null;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function changed() {
  if (typeof window !== 'undefined') {
    if (held === null) {
      window.removeEventListener('beforeunload', warnBeforeUnload);
    } else {
      window.addEventListener('beforeunload', warnBeforeUnload);
    }
  }
  for (const listener of listeners) listener();
}

// Reloading or leaving the page discards held edits, so it asks first, as
// the Studio does while it shows them.
function warnBeforeUnload(event: BeforeUnloadEvent) {
  event.preventDefault();
  event.returnValue = '';
}
