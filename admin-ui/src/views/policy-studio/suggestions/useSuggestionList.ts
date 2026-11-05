import { useCallback, useEffect, useRef, useState } from 'react';

import { AdminApiError } from '../../../lib/api';
import {
  fetchSuggestions,
  type RuleSuggestion,
  type RuleSuggestionState,
} from '../../../lib/suggestions';
import type { StudioAlert } from '../StudioAlert';
import type { SuggestionMark } from './model';

export type SuggestionFilter = RuleSuggestionState | 'all';

export type SuggestionList = Readonly<{
  filter: SuggestionFilter;
  rows: readonly RuleSuggestion[];
  marks: ReadonlyMap<string, SuggestionMark>;
  nextCursor: string | null;
  loading: boolean;
  // When the first page on screen was read, as an ISO timestamp.
  loadedAt: string | null;
  alert: StudioAlert | null;
}>;

export type SuggestionListHandle = Readonly<{
  list: SuggestionList;
  setFilter: (filter: SuggestionFilter) => void;
  // Read the first page again; the answer replaces what is on screen.
  refresh: () => Promise<void>;
  loadMore: () => Promise<void>;
  // Show a row as an answer since the listing returned it, with the mark
  // that says what that answer established.
  update: (suggestion: RuleSuggestion, mark: SuggestionMark | null) => void;
  mark: (id: string, mark: SuggestionMark | null) => void;
}>;

// The suggestions listing, in page memory only. It is read when `enabled`
// first holds and then only when the operator asks, or after an answer that
// may have moved a suggestion.
export function useSuggestionList(enabled: boolean): SuggestionListHandle {
  const [list, setList] = useState<SuggestionList>({
    filter: 'open',
    rows: [],
    marks: new Map(),
    nextCursor: null,
    loading: false,
    loadedAt: null,
    alert: null,
  });
  const generation = useRef(0);
  const filterRef = useRef<SuggestionFilter>('open');

  const load = useCallback(async (filter: SuggestionFilter, cursor: string | null) => {
    const current = ++generation.current;
    setList((previous) => ({ ...previous, loading: true }));
    try {
      const page = await fetchSuggestions({
        state: filter === 'all' ? null : filter,
        cursor,
      });
      if (current !== generation.current) return;
      setList((previous) => {
        const rows = cursor === null ? [...page.suggestions] : [...previous.rows];
        if (cursor !== null) {
          const known = new Set(rows.map((row) => row.id));
          for (const row of page.suggestions) {
            if (!known.has(row.id)) rows.push(row);
          }
        }
        // A fresh first page shows what the gateway holds now, so only the
        // marks a listing cannot show survive it.
        const marks = new Map<string, SuggestionMark>();
        for (const [id, mark] of previous.marks) {
          if (mark.kind === 'rule_live' && rows.some((row) => row.id === id)) {
            marks.set(id, mark);
          } else if (cursor !== null) {
            marks.set(id, mark);
          }
        }
        return {
          filter,
          rows,
          marks,
          nextCursor: page.next_cursor,
          loading: false,
          loadedAt: cursor === null ? new Date().toISOString() : previous.loadedAt,
          alert: null,
        };
      });
    } catch (error) {
      if (current !== generation.current) return;
      setList((previous) => ({
        ...previous,
        filter,
        loading: false,
        alert: listAlert(error),
      }));
    }
  }, []);

  const [requested, setRequested] = useState(false);
  useEffect(() => {
    if (enabled && !requested) {
      setRequested(true);
      void load(filterRef.current, null);
    }
  }, [enabled, requested, load]);

  const setFilter = useCallback(
    (filter: SuggestionFilter) => {
      filterRef.current = filter;
      setList((previous) => ({ ...previous, filter, rows: [], nextCursor: null }));
      void load(filter, null);
    },
    [load],
  );

  const refresh = useCallback(() => load(filterRef.current, null), [load]);

  const loadMore = useCallback(async () => {
    const cursor = list.nextCursor;
    if (cursor !== null) {
      await load(filterRef.current, cursor);
    }
  }, [list.nextCursor, load]);

  const update = useCallback((suggestion: RuleSuggestion, mark: SuggestionMark | null) => {
    setList((previous) => {
      const marks = new Map(previous.marks);
      if (mark === null) marks.delete(suggestion.id);
      else marks.set(suggestion.id, mark);
      return {
        ...previous,
        rows: previous.rows.map((row) => (row.id === suggestion.id ? suggestion : row)),
        marks,
      };
    });
  }, []);

  const mark = useCallback((id: string, next: SuggestionMark | null) => {
    setList((previous) => {
      const marks = new Map(previous.marks);
      if (next === null) marks.delete(id);
      else marks.set(id, next);
      return { ...previous, marks };
    });
  }, []);

  return { list, setFilter, refresh, loadMore, update, mark };
}

function listAlert(error: unknown): StudioAlert {
  if (error instanceof AdminApiError) {
    if (error.status === 403) {
      return {
        title: 'Suggestions permission required',
        message: 'This session does not hold admin:suggestions:read.',
        tone: 'error',
      };
    }
    if (error.status === 404) {
      return {
        title: 'Suggestions unavailable',
        message:
          'This gateway keeps no discovery suggestions: they need DISCOVERY_SQLITE_PATH (or cluster mode) and POLICY_FILE.',
        tone: 'warning',
      };
    }
    if (error.status === 503) {
      return {
        title: 'Suggestions unavailable',
        message:
          'The gateway could not settle a pending suggestion acceptance, so it lists none rather than show one as open whose rule may already be live. Read them again later.',
        tone: 'error',
      };
    }
    return {
      title: 'Suggestions could not be read',
      message: error.message,
      tone: 'error',
    };
  }
  return {
    title: 'Suggestions could not be read',
    message: 'The gateway did not answer. Read them again when the connection is back.',
    tone: 'error',
  };
}
