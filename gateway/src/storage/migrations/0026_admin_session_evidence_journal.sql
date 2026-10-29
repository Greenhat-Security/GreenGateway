-- Migration 26: admin session evidence in the authority-event journal, with
-- journal capacity held for every session's withdrawal (issue #425).
--
-- Migration 19 writes one admin_session_evidence row for every grant and
-- every withdrawal of a cluster admin session (logout, replacement by a new
-- sign-in, a provider rejection, expiry), in the change's own statement.
-- Migration 21 left those rows out of the journal because a full journal
-- refuses the mutation that would append to it, and a session withdrawal
-- must never be refused for that reason: a logout that cannot commit keeps a
-- session the operator asked to end. This migration makes the capacity
-- decision and adds the journal source:
--
-- - admin_session_evidence is the fourth journal source. A grant and every
--   withdrawal journal their evidence rows in the same statement that writes
--   them, under the evidence rows' own event IDs, so the dispatcher delivers
--   them like every other committed event.
-- - authority_event_state.reserved_withdrawals holds one unit of journal
--   capacity for the withdrawal of every session that has been granted and
--   not yet withdrawn. A grant takes two units, one for its own event and one
--   held for its withdrawal, and only while retained_events + 2 <= capacity:
--   at capacity the grant is refused and its whole transaction rolls back. A
--   withdrawal spends the unit its grant held and checks no capacity at all,
--   so a logout, a replacement, a rejection and the expiry prune always
--   commit with their evidence journaled. Each session is withdrawn at most
--   once (UNIQUE (session_id, action)), so one held unit is always enough.
-- - retained_events now counts the units in use: the retained journal rows
--   plus the held units. Every other producer still appends only while
--   retained_events < capacity, so it can never spend a unit a session
--   holds; retention still gives back exactly the rows it deletes and never
--   a held unit. The CHECK below keeps the held units inside that count.
-- - Holding a unit per grant is a reversible default, not part of the
--   journal's contract (docs/authority-evidence.md, "Admin session
--   withdrawals and journal capacity"). The journal rows and the evidence
--   rows do not depend on it: a later release that decided otherwise would
--   change the producer statements and give the held units back by
--   subtracting reserved_withdrawals from retained_events.
--
-- Existing state:
--
-- - Evidence committed before this migration is journaled after every row
--   already in the journal, in its own commit order (committed_at, then
--   event ID), with its own commit time as journaled_at, so retention judges
--   it by its real age. Those positions follow the rows already journaled
--   instead of interleaving with them: for these rows position order is
--   this migration's order, and committed_at still says when each one
--   committed.
-- - Every admin_sessions row that exists now, live or past a deadline the
--   prune has not reached yet, gets its held unit, so its withdrawal is
--   never refused either.
-- - The capacity is not changed. A deployment whose units in use now exceed
--   it refuses grants and every other journaled change until retention frees
--   room, and still records every withdrawal.

ALTER TABLE greengateway.authority_event_journal
    DROP CONSTRAINT authority_event_journal_source_check,
    ADD CONSTRAINT authority_event_journal_source_check CHECK (
        source IN (
            'connection_change_evidence',
            'service_token_change_evidence',
            'jwt_revocation_evidence',
            'admin_session_evidence'
        )
    );

ALTER TABLE greengateway.authority_event_state
    ADD COLUMN reserved_withdrawals bigint NOT NULL DEFAULT 0 CHECK (reserved_withdrawals >= 0),
    ADD CONSTRAINT authority_event_state_reserved_withdrawals_retained CHECK (
        reserved_withdrawals <= retained_events
    );

INSERT INTO greengateway.authority_event_journal (position, event_id, source, journaled_at)
SELECT state.last_position
           + row_number() OVER (ORDER BY evidence.committed_at, evidence.event_id),
       evidence.event_id, 'admin_session_evidence', evidence.committed_at
FROM greengateway.admin_session_evidence AS evidence
CROSS JOIN greengateway.authority_event_state AS state
WHERE state.singleton;

UPDATE greengateway.authority_event_state
SET last_position = last_position + existing.journaled,
    retained_events = retained_events + existing.journaled + existing.sessions,
    reserved_withdrawals = existing.sessions
FROM (
    SELECT (SELECT count(*) FROM greengateway.admin_session_evidence) AS journaled,
           (SELECT count(*) FROM greengateway.admin_sessions) AS sessions
) AS existing
WHERE singleton;
