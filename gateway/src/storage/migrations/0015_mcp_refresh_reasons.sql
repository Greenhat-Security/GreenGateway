-- Migration 15: allow precise, bounded MCP upstream failure categories in
-- current and historical Connection status rows.

ALTER TABLE greengateway.connection_current_status
    DROP CONSTRAINT connection_current_status_reason_check,
    ADD CONSTRAINT connection_current_status_reason_check CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied',
            'secret_unavailable', 'invalid_response',
            'upstream_method_not_found', 'upstream_error',
            'upstream_transport_failure', 'catalog_stale'
        )
    );

ALTER TABLE greengateway.connection_status_history
    DROP CONSTRAINT connection_status_history_reason_check,
    ADD CONSTRAINT connection_status_history_reason_check CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'catalog_refreshed', 'request_failed', 'egress_denied',
            'secret_unavailable', 'invalid_response',
            'upstream_method_not_found', 'upstream_error',
            'upstream_transport_failure', 'catalog_stale'
        )
    );
