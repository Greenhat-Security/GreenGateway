use std::fs;

use serde_json::json;

use crate::connections::model::ConnectionTestProfile;

use super::*;

#[test]
fn overlay_etag_maximum_id_and_revisions_fit_the_admin_schema_bound() {
    let id = format!(
        "a{}",
        "z".repeat(super::super::model::MAX_CONNECTION_ID_BYTES - 1)
    );
    ConnectionId::parse(id.clone()).expect("the maximum-length fixture must be a valid ID");
    let etag = OverlayEtag::for_revisions(&id, u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(etag.as_str().len(), 204);
    assert!(etag.as_str().len() <= 256);
}

#[test]
fn exact_overlay_schema_version_survives_restart_and_future_replay_fails_closed() {
    let (_directory, path, store) = temporary_store("overlay-version-replay");
    let created = store.create(candidate()).expect("Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Version","version":"1"}}"#;
    let digest = spec_digest(spec);
    store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            0,
            0,
            spec,
            &digest,
            &[],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: r#"{"schema_version":"0.1.0"}"#.to_owned(),
                source_reports_json: r#"{"schema_version":"0.1.0","sources":[]}"#.to_owned(),
                expected_overlay_revision: 0,
            }),
            1,
            "operator",
            &[],
        )
        .expect("the exact supported overlay should publish");
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("store should restart");
    assert_eq!(
        reopened
            .openapi_overlay(&created.id)
            .expect("supported overlay should replay")
            .expect("overlay should exist")
            .schema_version,
        "0.1.0"
    );
    reopened
            .connection_guard()
            .execute(
                "UPDATE connection_openapi_overlays SET schema_version = '0.1.1' WHERE connection_id = ?1",
                params![created.id.as_str()],
            )
            .expect("future-version corruption fixture should update");
    assert!(matches!(
        reopened.openapi_overlay(&created.id),
        Err(ConnectionStoreError::CorruptRecord { .. })
    ));
    drop(reopened);

    assert!(matches!(
        SqliteConnectionStore::open(&path),
        Err(ConnectionStoreError::CorruptRecord { .. })
    ));
}

fn candidate() -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": "Billing API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": "billing-token"
        },
        "tls": {},
        "discovery": {
            "type": "managed_openapi",
            "path": "/openapi.json",
            "use_connection_authentication": true
        }
    }))
    .expect("candidate should deserialize")
}

fn mcp_candidate() -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": "Managed MCP",
        "enabled": true,
        "kind": "mcp_streamable_http",
        "endpoint": {
            "base_url": "https://mcp.example.test",
            "base_path": "/mcp"
        },
        "authentication": {
            "type": "none"
        },
        "tls": {},
        "discovery": {
            "type": "managed_mcp",
            "use_connection_authentication": false
        }
    }))
    .expect("MCP candidate should deserialize")
}

fn mcp_catalog_entry(name: &str, description: &str) -> StoredMcpCatalogEntry {
    StoredMcpCatalogEntry {
        remote_tool_name: name.to_owned(),
        title: None,
        description: description.to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {}
        }),
        annotations: None,
    }
}

fn mcp_resource(uri: &str, name: &str) -> StoredMcpResource {
    StoredMcpResource {
        uri: uri.to_owned(),
        name: name.to_owned(),
        title: Some(format!("{name} title")),
        description: Some(format!("{name} description")),
        mime_type: Some("application/json".to_owned()),
        size: Some(42),
    }
}

fn mcp_resource_template(uri_template: &str, name: &str) -> StoredMcpResourceTemplate {
    StoredMcpResourceTemplate {
        uri_template: uri_template.to_owned(),
        name: name.to_owned(),
        title: Some(format!("{name} title")),
        description: Some(format!("{name} description")),
        mime_type: Some("application/json".to_owned()),
    }
}

fn persist_oversized_mcp_resource_catalog(
    store: &SqliteConnectionStore,
    connection_id: &ConnectionId,
    locator_canary: &str,
) {
    let oversized_description = "😀".repeat(MAX_MCP_RESOURCE_DESCRIPTION_CHARS);
    let mut connection = store.connection_guard();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("corrupt MCP fixture transaction should begin");
    {
        let mut statement = transaction
            .prepare(
                r#"
                    INSERT INTO connection_mcp_catalog_resources (
                        connection_id, uri, name, title, description, mime_type, size, ordinal
                    ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, NULL, ?5)
                    "#,
            )
            .expect("corrupt MCP resource insert should prepare");
        for ordinal in 0..MAX_CATALOG_ENTRIES {
            let uri = if ordinal == 0 {
                format!("gg://resource/first?token={locator_canary}")
            } else {
                format!("gg://resource/{ordinal:04}")
            };
            statement
                .execute(params![
                    connection_id.as_str(),
                    uri,
                    format!("resource-{ordinal:04}"),
                    oversized_description,
                    i64::try_from(ordinal).expect("fixture ordinal should fit"),
                ])
                .expect("corrupt MCP resource fixture should insert");
        }
    }
    transaction
        .execute(
            r#"
                UPDATE connection_mcp_catalogs
                SET resource_count = ?1
                WHERE connection_id = ?2
                "#,
            params![
                i64::try_from(MAX_CATALOG_ENTRIES).expect("fixture count should fit"),
                connection_id.as_str(),
            ],
        )
        .expect("corrupt MCP resource count should update");
    transaction
        .commit()
        .expect("corrupt MCP fixture transaction should commit");
}

fn openapi_catalog_entry(name: &str) -> StoredOpenApiCatalogEntry {
    StoredOpenApiCatalogEntry {
        tool_name: name.to_owned(),
        operation_id: Some(format!("{name}Operation")),
        selected_scheme_names: vec!["oauth".to_owned(), "api_key".to_owned(), "oauth".to_owned()],
        definition: json!({
            "name": name,
            "description": format!("{name} operation"),
            "input_json_schema": {
                "type": "object",
                "properties": {}
            },
            "upstream": {
                "method": "GET",
                "path_template": format!("/{name}"),
                "query_params": []
            }
        }),
    }
}

fn spec_digest(spec: &str) -> String {
    hex::encode(Sha256::digest(spec.as_bytes()))
}

fn openapi_catalog_entries_with_minimum_bytes(
    prefix: &str,
    minimum_bytes: usize,
) -> Vec<StoredOpenApiCatalogEntry> {
    const FILLER_BYTES: usize = 240_000;
    let filler = "x".repeat(FILLER_BYTES);
    let mut entries = Vec::new();
    let mut aggregate_bytes = 0_usize;
    while aggregate_bytes < minimum_bytes {
        let mut entry = openapi_catalog_entry(&format!("{prefix}-{:03}", entries.len()));
        entry.definition["input_json_schema"]["description"] = Value::String(filler.clone());
        let encoded =
            serde_json::to_vec(&entry.definition).expect("large definition should serialize");
        assert!(encoded.len() <= MAX_OPENAPI_CATALOG_ENTRY_BYTES);
        aggregate_bytes = aggregate_bytes.saturating_add(encoded.len());
        entries.push(entry);
    }
    entries
}

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new(name: &str) -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "greengateway-connection-{name}-{}.sqlite",
                Uuid::new_v4()
            )),
        }
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(format!("{}-wal", self.path.display()));
        let _ = fs::remove_file(format!("{}-shm", self.path.display()));
    }
}

fn temporary_store(name: &str) -> (TemporaryDatabase, PathBuf, SqliteConnectionStore) {
    let database = TemporaryDatabase::new(name);
    let path = database.path.clone();
    let store = SqliteConnectionStore::open(&path).expect("store should open");
    (database, path, store)
}

#[test]
fn migrations_are_ordered_idempotent_and_restart_safe() {
    let (_directory, path, store) = temporary_store("migration");
    assert_eq!(store.count().expect("count should work"), 0);
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("reopen should be idempotent");
    let connection = reopened.connection_guard();
    let versions = connection
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version")
        .expect("migration query should prepare")
        .query_map([], |row| row.get::<_, u32>(0))
        .expect("migration query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("migration rows should read");
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
}

#[test]
fn persisted_v0_options_profile_survives_restart_but_cannot_be_rewritten() {
    let (_directory, path, store) = temporary_store("legacy-v0-options-restart");
    let mut write = candidate();
    write.test_profile = Some(ConnectionTestProfile {
        method: "GET".to_owned(),
        path: "/ready".to_owned(),
        expected_statuses: vec![200, 204],
    });
    let created = store
        .create(write)
        .expect("pre-upgrade Connection fixture should create");
    drop(store);

    // Simulate a record written by an earlier v0 release, when OPTIONS was
    // accepted in the persisted test profile.
    let mut legacy_write = created.write.clone();
    legacy_write
        .test_profile
        .as_mut()
        .expect("fixture should retain its test profile")
        .method = "OPTIONS".to_owned();
    let legacy_json =
        serde_json::to_string(&legacy_write).expect("legacy v0 fixture should serialize");
    let connection = Connection::open(&path).expect("fixture database should open directly");
    connection
        .execute(
            "UPDATE connection_records SET spec_json = ?1 WHERE id = ?2",
            params![legacy_json, created.id.as_str()],
        )
        .expect("legacy v0 fixture should persist");
    drop(connection);

    let reopened = SqliteConnectionStore::open(&path)
        .expect("legacy OPTIONS must not become a corrupt record on restart");
    let loaded = reopened
        .get(&created.id)
        .expect("legacy Connection should remain readable")
        .expect("legacy Connection should remain present");
    assert_eq!(
        loaded
            .write
            .test_profile
            .as_ref()
            .expect("legacy profile should remain visible")
            .method,
        "OPTIONS"
    );

    let create_error = reopened
        .create(loaded.write.clone())
        .expect_err("new writes must not accept a legacy OPTIONS profile");
    assert!(matches!(
        create_error,
        ConnectionStoreError::Validation { problems }
            if problems == vec!["test_profile.method:unsafe_method"]
    ));
    let replace_error = reopened
        .replace(&loaded.id, &loaded.etag(), loaded.write.clone())
        .expect_err("replacement writes must require GET or HEAD");
    assert!(matches!(
        replace_error,
        ConnectionStoreError::Validation { problems }
            if problems == vec!["test_profile.method:unsafe_method"]
    ));
    drop(reopened);

    let restarted = SqliteConnectionStore::open(&path)
        .expect("rejected rewrites must leave the legacy record restart-safe");
    assert_eq!(
        restarted
            .list()
            .expect("legacy Connection collection should remain readable")
            .len(),
        1
    );
}

#[test]
fn migration_four_preserves_populated_v3_status_state_and_indexes() {
    let database = TemporaryDatabase::new("migration-v3-populated");
    let path = database.path.clone();
    let connection_id = ConnectionId::new_managed();
    let write = mcp_candidate();
    let spec_json = serde_json::to_string(&write).expect("v3 fixture candidate should serialize");
    let timestamp = "2026-07-28T00:00:00Z";
    {
        let connection = Connection::open(&path).expect("v3 fixture database should open directly");
        connection
            .execute_batch(CONFIGURE_SQL)
            .expect("v3 fixture pragmas should apply");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("v3 fixture migration table should create");
        for migration in MIGRATIONS.iter().take(3) {
            connection
                .execute_batch(migration.sql)
                .expect("v3 fixture migration should apply");
            connection
                    .execute(
                        "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![migration.version, timestamp],
                    )
                    .expect("v3 fixture migration should record");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 1, 0, 0, 1, 1, ?5, ?5)
                    "#,
                params![
                    connection_id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    timestamp,
                ],
            )
            .expect("v3 fixture Connection should insert");
        for table in ["connection_current_status", "connection_status_history"] {
            connection
                    .execute(
                        &format!(
                            r#"
                            INSERT INTO {table} (
                                connection_id, status_revision, observed_connection_revision,
                                observed_credential_revision, observed_tls_revision,
                                observed_discovery_revision, state, reason, observed_at,
                                latency_ms, catalog_age_secs, catalog_entry_count
                            ) VALUES (?1, 1, 1, 0, 0, 1, 'healthy', 'test_succeeded', ?2, 12, NULL, NULL)
                            "#
                        ),
                        params![connection_id.as_str(), timestamp],
                    )
                    .expect("populated v3 status row should insert");
        }
    }

    let store =
        SqliteConnectionStore::open(&path).expect("migration 4 should upgrade populated v3 state");
    let preserved = store
        .latest_status(&connection_id)
        .expect("migrated current status should load")
        .expect("migrated current status should remain");
    assert_eq!(preserved.state, ConnectionOperationalState::Healthy);
    assert_eq!(preserved.reason, ConnectionStatusReason::TestSucceeded);
    assert_eq!(preserved.latency_ms, Some(12));
    let history = store
        .status_history(&connection_id, 10)
        .expect("migrated status history should load");
    assert_eq!(history, vec![preserved]);
    {
        let connection = store.connection_guard();
        let indexes = connection
            .prepare(
                r#"
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'index'
                      AND name IN (
                        'idx_connection_status_revision',
                        'idx_connection_status_latest',
                        'idx_connection_mcp_catalog_ordinal'
                      )
                    ORDER BY name ASC
                    "#,
            )
            .expect("migrated index query should prepare")
            .query_map([], |row| row.get::<_, String>(0))
            .expect("migrated index query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("migrated indexes should read");
        assert_eq!(
            indexes,
            vec![
                "idx_connection_mcp_catalog_ordinal".to_owned(),
                "idx_connection_status_latest".to_owned(),
                "idx_connection_status_revision".to_owned(),
            ]
        );
    }
    let record = store
        .get(&connection_id)
        .expect("migrated Connection should load")
        .expect("migrated Connection should remain");
    let refreshed = store
        .append_status(
            &connection_id,
            &record.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::CatalogRefreshed,
                latency_ms: Some(8),
                catalog_age_secs: Some(0),
                catalog_entry_count: Some(1),
            },
        )
        .expect("migration 4 status constraint should accept catalog_refreshed");
    assert_eq!(refreshed.reason, ConnectionStatusReason::CatalogRefreshed);
    drop(store);

    let reopened = SqliteConnectionStore::open(&path)
        .expect("populated migration 4 database should pass restart validation");
    assert_eq!(
        reopened
            .status_history(&connection_id, 10)
            .expect("restarted history should load")
            .len(),
        2
    );
}

#[test]
fn migration_five_preserves_populated_v4_catalog_state() {
    let database = TemporaryDatabase::new("migration-v4-populated");
    let path = database.path.clone();
    let connection_id = ConnectionId::new_managed();
    let write = mcp_candidate();
    let spec_json = serde_json::to_string(&write).expect("v4 fixture candidate should serialize");
    let timestamp = "2026-07-28T00:00:00Z";
    {
        let connection = Connection::open(&path).expect("v4 fixture database should open directly");
        connection
            .execute_batch(CONFIGURE_SQL)
            .expect("v4 fixture pragmas should apply");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("v4 fixture migration table should create");
        for migration in MIGRATIONS.iter().take(4) {
            connection
                .execute_batch(migration.sql)
                .expect("v4 fixture migration should apply");
            connection
                    .execute(
                        "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![migration.version, timestamp],
                    )
                    .expect("v4 fixture migration should record");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 1, 0, 0, 1, 0, ?5, ?5)
                    "#,
                params![
                    connection_id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    timestamp,
                ],
            )
            .expect("v4 fixture Connection should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_mcp_catalogs (
                        connection_id, catalog_revision, observed_etag, refreshed_at, entry_count
                    ) VALUES (?1, 1, '"fixture-etag"', ?2, 1)
                    "#,
                params![connection_id.as_str(), timestamp],
            )
            .expect("v4 fixture catalog should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_mcp_catalog_entries (
                        connection_id, remote_tool_name, description, input_schema_json, ordinal
                    ) VALUES (?1, 'alpha', 'Alpha', '{}', 0)
                    "#,
                params![connection_id.as_str()],
            )
            .expect("v4 fixture catalog entry should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, 'managed_tool', ?2, ?3)
                    "#,
                params![
                    connection_id.as_str(),
                    format!("{}:alpha", connection_id.as_str()),
                    timestamp
                ],
            )
            .expect("v4 fixture dependency should insert");
    }

    let store =
        SqliteConnectionStore::open(&path).expect("migration 5 should upgrade populated v4");
    assert_eq!(
        store
            .mcp_catalog(&connection_id)
            .expect("migrated MCP catalog should load")
            .expect("migrated MCP catalog should remain")
            .entries
            .len(),
        1
    );
    assert!(store
        .openapi_catalogs()
        .expect("new OpenAPI catalog table should load")
        .is_empty());
    let connection = store.connection_guard();
    let versions = connection
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version")
        .expect("migration query should prepare")
        .query_map([], |row| row.get::<_, u32>(0))
        .expect("migration query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("migration rows should read");
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
}

#[test]
fn migration_six_preserves_populated_v5_mcp_catalog_state() {
    let database = TemporaryDatabase::new("migration-v5-populated");
    let path = database.path.clone();
    let connection_id = ConnectionId::new_managed();
    let write = mcp_candidate();
    let spec_json = serde_json::to_string(&write).expect("v5 fixture candidate should serialize");
    let timestamp = "2026-07-28T00:00:00Z";
    {
        let connection = Connection::open(&path).expect("v5 fixture database should open directly");
        connection
            .execute_batch(CONFIGURE_SQL)
            .expect("v5 fixture pragmas should apply");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("v5 fixture migration table should create");
        for migration in MIGRATIONS.iter().take(5) {
            connection
                .execute_batch(migration.sql)
                .expect("v5 fixture migration should apply");
            connection
                    .execute(
                        "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![migration.version, timestamp],
                    )
                    .expect("v5 fixture migration should record");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 1, 0, 0, 1, 0, ?5, ?5)
                    "#,
                params![
                    connection_id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    timestamp,
                ],
            )
            .expect("v5 fixture Connection should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_mcp_catalogs (
                        connection_id, catalog_revision, observed_etag, refreshed_at, entry_count
                    ) VALUES (?1, 7, '"fixture-etag"', ?2, 1)
                    "#,
                params![connection_id.as_str(), timestamp],
            )
            .expect("v5 fixture MCP catalog should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_mcp_catalog_entries (
                        connection_id, remote_tool_name, description, input_schema_json, ordinal
                    ) VALUES (?1, 'alpha', 'Alpha', '{}', 0)
                    "#,
                params![connection_id.as_str()],
            )
            .expect("v5 fixture MCP entry should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, 'managed_tool', ?2, ?3)
                    "#,
                params![
                    connection_id.as_str(),
                    format!("{}:alpha", connection_id.as_str()),
                    timestamp,
                ],
            )
            .expect("v5 fixture managed-tool dependency should insert");
    }

    let store =
        SqliteConnectionStore::open(&path).expect("migration 6 should upgrade populated v5");
    let catalog = store
        .mcp_catalog(&connection_id)
        .expect("migrated MCP catalog should load")
        .expect("migrated MCP catalog should remain");
    assert_eq!(catalog.catalog_revision, 7);
    assert_eq!(catalog.entries.len(), 1);
    assert!(catalog.resources.is_empty());
    assert!(catalog.resource_templates.is_empty());
    let connection = store.connection_guard();
    let versions = connection
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version")
        .expect("migration query should prepare")
        .query_map([], |row| row.get::<_, u32>(0))
        .expect("migration query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("migration rows should read");
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
}

#[test]
fn migration_seven_backfills_test_and_refresh_activity_from_populated_v6_history() {
    let database = TemporaryDatabase::new("migration-v6-populated-activity");
    let path = database.path.clone();
    let connection_id = ConnectionId::new_managed();
    let write = mcp_candidate();
    let spec_json = serde_json::to_string(&write).expect("v6 fixture candidate should serialize");
    let migration_timestamp = "2026-07-28T00:00:00Z";
    let test_success_at = "2026-07-28T00:00:01Z";
    let refresh_success_at = "2026-07-28T00:00:02Z";
    let test_failure_at = "2026-07-28T00:00:03Z";
    let refresh_failure_at = "2026-07-28T00:00:04Z";
    {
        let connection = Connection::open(&path).expect("v6 fixture database should open directly");
        connection
            .execute_batch(CONFIGURE_SQL)
            .expect("v6 fixture pragmas should apply");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("v6 fixture migration table should create");
        for migration in MIGRATIONS.iter().take(6) {
            connection
                .execute_batch(migration.sql)
                .expect("v6 fixture migration should apply");
            connection
                    .execute(
                        "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![migration.version, migration_timestamp],
                    )
                    .expect("v6 fixture migration should record");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 1, 0, 0, 1, 4, ?5, ?5)
                    "#,
                params![
                    connection_id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    migration_timestamp,
                ],
            )
            .expect("v6 fixture Connection should insert");
        for (revision, reason, observed_at, catalog_entry_count) in [
            (1_i64, "test_succeeded", test_success_at, None),
            (2_i64, "catalog_refreshed", refresh_success_at, Some(1_i64)),
            (3_i64, "request_failed", test_failure_at, None),
        ] {
            connection
                .execute(
                    r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at,
                            latency_ms, catalog_age_secs, catalog_entry_count
                        ) VALUES (
                            ?1, ?2, 1, 0, 0, 1, 'degraded', ?3, ?4, NULL, NULL, ?5
                        )
                        "#,
                    params![
                        connection_id.as_str(),
                        revision,
                        reason,
                        observed_at,
                        catalog_entry_count,
                    ],
                )
                .expect("v6 fixture history row should insert");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_current_status (
                        connection_id, status_revision, observed_connection_revision,
                        observed_credential_revision, observed_tls_revision,
                        observed_discovery_revision, state, reason, observed_at,
                        latency_ms, catalog_age_secs, catalog_entry_count
                    ) VALUES (
                        ?1, 4, 1, 0, 0, 1, 'degraded', 'invalid_response', ?2,
                        NULL, NULL, 0
                    )
                    "#,
                params![connection_id.as_str(), refresh_failure_at],
            )
            .expect("v6 fixture current status should insert");
    }

    let store = SqliteConnectionStore::open(&path)
        .expect("migration 7 should upgrade populated v6 activity");
    let activity = store
        .activity_times()
        .expect("migrated activity should load")
        .remove(&connection_id)
        .expect("migrated Connection activity should remain");
    assert_eq!(activity.last_test_at.as_deref(), Some(test_failure_at));
    assert_eq!(
        activity.last_refresh_at.as_deref(),
        Some(refresh_failure_at)
    );
    drop(store);

    let reopened = SqliteConnectionStore::open(&path)
        .expect("populated migration 7 database should pass restart validation");
    let restarted_activity = reopened
        .activity_times()
        .expect("restarted activity should load")
        .remove(&connection_id)
        .expect("restarted Connection activity should remain");
    assert_eq!(restarted_activity, activity);
}

#[test]
fn migrations_eight_and_nine_preserve_bindings_and_openapi_catalogs() {
    let database = TemporaryDatabase::new("migration-v7-headers-and-overlays");
    let path = database.path.clone();
    let connection_id = ConnectionId::new_managed();
    let write = candidate();
    let spec_json = serde_json::to_string(&write).expect("v7 fixture candidate should serialize");
    let timestamp = "2026-09-03T00:00:00Z";
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Existing","version":"1"}}"#;
    let digest = spec_digest(spec);
    {
        let connection = Connection::open(&path).expect("v7 fixture database should open directly");
        connection
            .execute_batch(CONFIGURE_SQL)
            .expect("v7 fixture pragmas should apply");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("v7 fixture migration table should create");
        for migration in MIGRATIONS.iter().take(7) {
            connection
                .execute_batch(migration.sql)
                .expect("v7 fixture migration should apply");
            connection
                    .execute(
                        "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                        params![migration.version, timestamp],
                    )
                    .expect("v7 fixture migration should record");
        }
        connection
            .execute(
                r#"
                    INSERT INTO connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES (?1, ?2, ?3, ?4, 1, 1, 0, 1, 0, ?5, ?5)
                    "#,
                params![
                    connection_id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    timestamp,
                ],
            )
            .expect("v7 fixture Connection should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_credential_bindings (
                        connection_id, purpose, secret_id, binding_version, updated_at
                    ) VALUES (?1, 'http_authentication', 'billing-token', 1, ?2)
                    "#,
                params![connection_id.as_str(), timestamp],
            )
            .expect("v7 fixture credential binding should insert");
        connection
            .execute(
                r#"
                    INSERT INTO connection_openapi_catalogs (
                        connection_id, spec_revision, catalog_revision, observed_etag,
                        spec_digest, spec, refreshed_at, entry_count
                    ) VALUES (?1, 2, 3, ?2, ?3, ?4, ?5, 0)
                    "#,
                params![
                    connection_id.as_str(),
                    ConnectionEtag::for_record(
                        &connection_id,
                        &ConnectionRevisions {
                            connection: 1,
                            credential: 1,
                            tls: 0,
                            discovery: 1,
                            status: 0,
                        },
                    )
                    .as_str(),
                    digest,
                    spec,
                    timestamp,
                ],
            )
            .expect("v7 OpenAPI catalog should insert");
    }

    let store = SqliteConnectionStore::open(&path)
        .expect("migrations 8 and 9 should upgrade a populated v7 database");
    let persisted = store
        .get(&connection_id)
        .expect("migrated Connection should load")
        .expect("migrated Connection should remain");
    assert_eq!(persisted.write, write);
    {
        let connection = store.connection_guard();
        let migrated = connection
            .query_row(
                r#"
                    SELECT purpose, header_name, secret_id, binding_version, updated_at
                    FROM connection_credential_bindings
                    WHERE connection_id = ?1
                    "#,
                params![connection_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .expect("migrated binding should load");
        assert_eq!(
            migrated,
            (
                "http_authentication".to_owned(),
                String::new(),
                "billing-token".to_owned(),
                1,
                timestamp.to_owned(),
            )
        );
    }

    let mut replacement = persisted.write.clone();
    replacement.additional_headers = serde_json::from_value(json!([
        {"header_name": "CF-Access-Client-Id", "secret_id": "cf-client-id"},
        {"header_name": "CF-Access-Client-Secret", "secret_id": "cf-client-secret"}
    ]))
    .expect("additional headers should deserialize");
    let replaced = store
        .replace(&connection_id, &persisted.etag(), replacement)
        .expect("additional headers should persist after migration");
    assert_eq!(replaced.revisions.connection, 2);
    assert_eq!(replaced.revisions.credential, 2);
    assert_ne!(replaced.etag(), persisted.etag());

    let connection = store.connection_guard();
    let rows = connection
        .prepare(
            r#"
                SELECT purpose, header_name, secret_id, binding_version
                FROM connection_credential_bindings
                WHERE connection_id = ?1
                ORDER BY purpose, header_name
                "#,
        )
        .expect("binding query should prepare")
        .query_map(params![connection_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .expect("binding query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("binding rows should read");
    assert_eq!(
        rows,
        vec![
            (
                ADDITIONAL_HEADER_BINDING_PURPOSE.to_owned(),
                "cf-access-client-id".to_owned(),
                "cf-client-id".to_owned(),
                2,
            ),
            (
                ADDITIONAL_HEADER_BINDING_PURPOSE.to_owned(),
                "cf-access-client-secret".to_owned(),
                "cf-client-secret".to_owned(),
                2,
            ),
            (
                "http_authentication".to_owned(),
                String::new(),
                "billing-token".to_owned(),
                2,
            ),
        ]
    );
    drop(connection);
    drop(store);

    let reopened =
        SqliteConnectionStore::open(&path).expect("migrated database should remain restart-safe");
    assert_eq!(
        reopened
            .get(&connection_id)
            .expect("restarted Connection should load")
            .expect("restarted Connection should remain"),
        replaced
    );
    let catalog = reopened
        .openapi_catalog(&connection_id)
        .expect("migrated OpenAPI catalog should load")
        .expect("migrated OpenAPI catalog should remain");
    assert_eq!(catalog.spec_revision, 2);
    assert_eq!(catalog.catalog_revision, 3);
    assert_eq!(catalog.overlay_revision, 0);
    assert!(reopened
        .openapi_overlays()
        .expect("new overlay table should load")
        .is_empty());

    let connection = reopened.connection_guard();
    let versions = connection
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version")
        .expect("migration query should prepare")
        .query_map([], |row| row.get::<_, u32>(0))
        .expect("migration query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("migration rows should read");
    assert_eq!(versions, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    assert!(connection
        .prepare("SELECT source_digest, values_json FROM connection_enum_source_values LIMIT 0")
        .is_ok());
    assert!(connection
        .prepare("SELECT title, annotations_json FROM connection_mcp_catalog_entries LIMIT 0")
        .is_ok());
}

#[test]
fn mcp_catalog_replacement_is_atomic_revisioned_and_dependency_aware() {
    let (_directory, path, store) = temporary_store("mcp-catalog");
    let created = store
        .create(mcp_candidate())
        .expect("MCP connection should create");
    let mut annotated_alpha = mcp_catalog_entry("alpha", "Alpha");
    annotated_alpha.title = Some("Alpha lookup".to_owned());
    annotated_alpha.annotations = Some(crate::tools::definitions::ToolAnnotations {
        read_only_hint: Some(true),
        open_world_hint: Some(false),
        ..crate::tools::definitions::ToolAnnotations::default()
    });
    let first = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[annotated_alpha.clone(), mcp_catalog_entry("beta", "Beta")],
            &[mcp_resource("gg://resource/alpha", "resource-alpha")],
            &[mcp_resource_template(
                "gg://resource/{id}",
                "resource-by-id",
            )],
        )
        .expect("first MCP catalog should publish");
    assert_eq!(first.catalog_revision, 1);
    assert_eq!(first.entries[0], annotated_alpha);
    assert_eq!(first.resources.len(), 1);
    assert_eq!(first.resource_templates.len(), 1);
    assert_eq!(
        store
            .dependencies(&created.id)
            .expect("dependencies should load")
            .into_iter()
            .filter(|dependency| dependency.kind == ConnectionDependencyKind::ManagedTool)
            .map(|dependency| dependency.consumer_id)
            .collect::<Vec<_>>(),
        vec![
            format!("{}:alpha", created.id),
            format!("{}:beta", created.id),
        ]
    );

    let second = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[
                mcp_catalog_entry("beta", "Beta changed"),
                mcp_catalog_entry("gamma", "Gamma"),
            ],
            &[mcp_resource("gg://resource/beta", "resource-beta")],
            &[mcp_resource_template(
                "gg://resource/{slug}",
                "resource-by-slug",
            )],
        )
        .expect("second MCP catalog should publish");
    assert_eq!(second.catalog_revision, 2);
    assert_eq!(
        second
            .entries
            .iter()
            .map(|entry| entry.remote_tool_name.as_str())
            .collect::<Vec<_>>(),
        vec!["beta", "gamma"]
    );
    assert_eq!(second.resources[0].uri, "gg://resource/beta");
    assert_eq!(
        second.resource_templates[0].uri_template,
        "gg://resource/{slug}"
    );

    let mut discovery_removed = created.write.clone();
    discovery_removed.discovery = None;
    assert!(matches!(
        store.replace(&created.id, &created.etag(), discovery_removed),
        Err(ConnectionStoreError::DependencyConflict { count: 2, .. })
    ));
    assert!(matches!(
        store.replace(&created.id, &created.etag(), candidate()),
        Err(ConnectionStoreError::DependencyConflict { count: 2, .. })
    ));
    assert_eq!(
        store
            .get(&created.id)
            .expect("catalog-bearing Connection should still load")
            .expect("catalog-bearing Connection should remain")
            .write,
        created.write,
        "an incompatible update must not strand the managed catalog"
    );

    let duplicate = [
        mcp_catalog_entry("duplicate", "First"),
        mcp_catalog_entry("duplicate", "Second"),
    ];
    assert!(matches!(
        store.replace_mcp_catalog(&created.id, &created.etag(), &duplicate, &[], &[]),
        Err(ConnectionStoreError::Validation { .. })
    ));
    let duplicate_resources = [
        mcp_resource("gg://duplicate", "first"),
        mcp_resource("gg://duplicate", "second"),
    ];
    assert!(matches!(
        store.replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_catalog_entry("replacement", "Replacement")],
            &duplicate_resources,
            &[],
        ),
        Err(ConnectionStoreError::Validation { .. })
    ));
    let retained = store
        .mcp_catalog(&created.id)
        .expect("catalog should load")
        .expect("catalog should remain");
    assert_eq!(retained.catalog_revision, 2);
    assert_eq!(
        retained
            .entries
            .iter()
            .map(|entry| entry.remote_tool_name.as_str())
            .collect::<Vec<_>>(),
        vec!["beta", "gamma"]
    );
    assert_eq!(retained.resources, second.resources);
    assert_eq!(retained.resource_templates, second.resource_templates);

    drop(store);
    let reopened = SqliteConnectionStore::open(&path).expect("catalog store should reopen");
    assert_eq!(
        reopened
            .mcp_catalog(&created.id)
            .expect("reopened catalog should load"),
        Some(retained)
    );
}

#[test]
fn multi_byte_remote_tool_name_rejects_as_invalid_input_not_a_storage_failure() {
    let (_directory, _path, store) = temporary_store("mcp-multi-byte-tool-name");
    let created = store
        .create(mcp_candidate())
        .expect("MCP connection should create");
    // 74 CJK characters sit inside the 128-character name limit, but the
    // derived dependency key is 36 + 1 + 222 bytes.
    let remote_tool_name = "\u{4e2d}".repeat(74);
    assert!(remote_tool_name.chars().count() <= MAX_MCP_TOOL_NAME_CHARS);
    assert!(
        managed_tool_dependency_id(&created.id, &remote_tool_name).len()
            > MAX_DEPENDENCY_FIELD_BYTES,
        "fixture must actually overflow the managed tool dependency key"
    );

    let error = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_catalog_entry(&remote_tool_name, "Multi-byte tool")],
            &[],
            &[],
        )
        .expect_err("an unstorable remote tool name must reject the catalog");
    match error {
            ConnectionStoreError::Validation { problems } => assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains("managed tool dependency key")),
                "unexpected problems: {problems:?}"
            ),
            other => panic!(
                "an unstorable remote tool name must reject as invalid input rather than a retryable storage failure, got: {other}"
            ),
        }
    assert!(
        store
            .mcp_catalog(&created.id)
            .expect("catalog read should succeed")
            .is_none(),
        "a rejected catalog must not persist partial rows"
    );
}

#[test]
fn mcp_catalog_combined_count_and_byte_limits_preserve_last_known_good() {
    let (_directory, _path, store) = temporary_store("mcp-catalog-limits");
    let created = store
        .create(mcp_candidate())
        .expect("MCP connection should create");
    let baseline = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_catalog_entry("baseline", "Baseline")],
            &[mcp_resource("gg://baseline", "baseline-resource")],
            &[mcp_resource_template(
                "gg://baseline/{id}",
                "baseline-template",
            )],
        )
        .expect("baseline MCP catalog should publish");

    let maximum_tools = (0..MAX_CATALOG_ENTRIES)
        .map(|index| mcp_catalog_entry(&format!("tool-{index:04}"), "Bounded"))
        .collect::<Vec<_>>();
    assert!(matches!(
        store.replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &maximum_tools,
            &[mcp_resource("gg://overflow", "overflow")],
            &[],
        ),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog entries",
            ..
        })
    ));

    let filler = "x".repeat(255_000);
    let oversized_bytes = (0..66)
        .map(|index| StoredMcpCatalogEntry {
            remote_tool_name: format!("large-{index:03}"),
            title: None,
            description: "Large bounded schema".to_owned(),
            input_schema: json!({
                "type": "object",
                "description": filler.clone()
            }),
            annotations: None,
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        store.replace_mcp_catalog(&created.id, &created.etag(), &oversized_bytes, &[], &[],),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            ..
        })
    ));
    assert_eq!(
        store
            .mcp_catalog(&created.id)
            .expect("retained catalog should load"),
        Some(baseline),
        "invalid count and byte candidates must not replace the last-known-good catalog"
    );
}

#[test]
fn aggregate_mcp_catalog_byte_bound_preserves_all_last_known_good_catalogs() {
    let (_directory, _path, store) = temporary_store("mcp-aggregate-byte-bound");
    let first = store
        .create(mcp_candidate())
        .expect("first MCP Connection should create");
    let mut second_candidate = mcp_candidate();
    second_candidate.display_name = "Second managed MCP".to_owned();
    let second = store
        .create(second_candidate)
        .expect("second MCP Connection should create");
    let baseline = store
        .replace_mcp_catalog(
            &second.id,
            &second.etag(),
            &[mcp_catalog_entry("baseline", "Baseline")],
            &[],
            &[],
        )
        .expect("second MCP baseline should publish");

    let maximum_description = "😀".repeat(MAX_MCP_TOOL_DESCRIPTION_CHARS);
    let first_entries = (0..MAX_CATALOG_ENTRIES / 2)
        .map(|index| mcp_catalog_entry(&format!("first-{index:04}"), &maximum_description))
        .collect::<Vec<_>>();
    let first_bytes = validate_mcp_catalog(&first.id, &first_entries, &[], &[])
        .expect("first half-bound catalog should validate")
        .stored_bytes;
    store
        .replace_mcp_catalog(&first.id, &first.etag(), &first_entries, &[], &[])
        .expect("first half-bound catalog should publish");
    drop(first_entries);

    let second_entries = (0..MAX_CATALOG_ENTRIES / 2)
        .map(|index| mcp_catalog_entry(&format!("second-{index:04}"), &maximum_description))
        .collect::<Vec<_>>();
    let second_bytes = validate_mcp_catalog(&second.id, &second_entries, &[], &[])
        .expect("second half-bound catalog should validate")
        .stored_bytes;
    assert!(first_bytes <= MAX_MANAGED_MCP_CATALOG_BYTES);
    assert!(second_bytes <= MAX_MANAGED_MCP_CATALOG_BYTES);
    assert!(
        first_bytes
            .checked_add(second_bytes)
            .is_some_and(|total| total > MAX_MANAGED_MCP_CATALOG_BYTES),
        "the two independently valid catalogs must exceed the global byte bound"
    );

    assert!(matches!(
        store.replace_mcp_catalog(&second.id, &second.etag(), &second_entries, &[], &[],),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        })
    ));
    assert_eq!(
        store
            .mcp_catalog(&first.id)
            .expect("retained first catalog should load")
            .expect("retained first catalog should remain")
            .entries
            .len(),
        MAX_CATALOG_ENTRIES / 2,
        "aggregate rejection must not disturb another Connection's catalog"
    );
    assert_eq!(
        store
            .mcp_catalog(&second.id)
            .expect("retained second catalog should load"),
        Some(baseline),
        "aggregate rejection must preserve the prior catalog"
    );
}

#[test]
fn corrupt_aggregate_mcp_bytes_are_preflighted_on_load_and_restart() {
    const LOCATOR_CANARY: &str = "OVERSIZED_MCP_LOCATOR_CANARY";

    let (_directory, path, store) = temporary_store("mcp-aggregate-byte-corruption");
    let created = store
        .create(mcp_candidate())
        .expect("MCP Connection should create");
    store
        .replace_mcp_catalog(&created.id, &created.etag(), &[], &[], &[])
        .expect("empty MCP catalog should publish");
    persist_oversized_mcp_resource_catalog(&store, &created.id, LOCATOR_CANARY);

    let load_error = store
        .mcp_catalogs()
        .expect_err("oversized aggregate must fail before catalog rows load");
    assert!(matches!(
        &load_error,
        ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        }
    ));
    assert!(!format!("{load_error:?}").contains(LOCATOR_CANARY));
    assert!(!load_error.to_string().contains(LOCATOR_CANARY));
    drop(store);

    let restart_error = SqliteConnectionStore::open(&path)
        .err()
        .expect("oversized aggregate must fail startup validation");
    assert!(matches!(
        &restart_error,
        ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: MAX_MANAGED_MCP_CATALOG_BYTES,
        }
    ));
    assert!(!format!("{restart_error:?}").contains(LOCATOR_CANARY));
    assert!(!restart_error.to_string().contains(LOCATOR_CANARY));
}

#[test]
fn mcp_resource_locators_reject_secret_bearing_components_without_leaking() {
    let (_directory, _path, store) = temporary_store("mcp-catalog-safe-locators");
    let created = store
        .create(mcp_candidate())
        .expect("MCP connection should create");
    let baseline = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_catalog_entry("baseline", "Baseline")],
            &[mcp_resource("gg://resource/baseline", "baseline-resource")],
            &[mcp_resource_template(
                "gg://resource/{id}",
                "baseline-template",
            )],
        )
        .expect("baseline MCP catalog should publish");

    let invalid_candidates = [
        (
            vec![mcp_resource(
                "gg://resource/alpha?token=QUERY_SECRET_CANARY",
                "query-secret",
            )],
            Vec::new(),
            "QUERY_SECRET_CANARY",
        ),
        (
            Vec::new(),
            vec![mcp_resource_template(
                "gg://resource/{id}?token=TEMPLATE_QUERY_SECRET_CANARY",
                "template-query-secret",
            )],
            "TEMPLATE_QUERY_SECRET_CANARY",
        ),
        (
            vec![mcp_resource(
                "gg://resource/alpha#RESOURCE_FRAGMENT_SECRET_CANARY",
                "resource-fragment-secret",
            )],
            Vec::new(),
            "RESOURCE_FRAGMENT_SECRET_CANARY",
        ),
        (
            Vec::new(),
            vec![mcp_resource_template(
                "gg://resource/{id}#TEMPLATE_FRAGMENT_SECRET_CANARY",
                "template-fragment-secret",
            )],
            "TEMPLATE_FRAGMENT_SECRET_CANARY",
        ),
        (
            vec![mcp_resource(
                "gg://RESOURCE_USERINFO_SECRET_CANARY@resource/alpha",
                "resource-userinfo-secret",
            )],
            Vec::new(),
            "RESOURCE_USERINFO_SECRET_CANARY",
        ),
        (
            Vec::new(),
            vec![mcp_resource_template(
                "gg://TEMPLATE_USERINFO_SECRET_CANARY@resource/{id}",
                "template-userinfo-secret",
            )],
            "TEMPLATE_USERINFO_SECRET_CANARY",
        ),
    ];

    for (resources, resource_templates, canary) in invalid_candidates {
        let error = store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                &[mcp_catalog_entry("replacement", "Replacement")],
                &resources,
                &resource_templates,
            )
            .expect_err("secret-bearing MCP locator should fail closed");
        assert!(matches!(error, ConnectionStoreError::Validation { .. }));
        assert!(
            !error.to_string().contains(canary),
            "validation Display must not contain the rejected locator"
        );
        assert!(
            !format!("{error:?}").contains(canary),
            "validation Debug must not contain the rejected locator"
        );
        assert_eq!(
            store
                .mcp_catalog(&created.id)
                .expect("retained catalog should load"),
            Some(baseline.clone()),
            "invalid locator candidates must not replace the last-known-good catalog"
        );
    }
}

#[test]
fn empty_mcp_catalog_is_removed_on_incompatible_update_or_delete() {
    let (_directory, path, store) = temporary_store("empty-mcp-catalog-cleanup");
    let converted_source = store
        .create(mcp_candidate())
        .expect("convertible MCP Connection should create");
    store
        .replace_mcp_catalog(
            &converted_source.id,
            &converted_source.etag(),
            &[],
            &[],
            &[],
        )
        .expect("empty MCP catalog should publish");
    let converted = store
        .replace(&converted_source.id, &converted_source.etag(), candidate())
        .expect("empty catalog should permit an incompatible update");
    assert!(
        store
            .mcp_catalog(&converted.id)
            .expect("converted catalog lookup should work")
            .is_none(),
        "incompatible update must remove the obsolete durable catalog"
    );
    store
        .delete(&converted.id, &converted.etag())
        .expect("converted Connection should delete");

    let deleted = store
        .create(mcp_candidate())
        .expect("deletable MCP Connection should create");
    store
        .replace_mcp_catalog(&deleted.id, &deleted.etag(), &[], &[], &[])
        .expect("deletable empty MCP catalog should publish");
    store
        .delete(&deleted.id, &deleted.etag())
        .expect("empty managed MCP Connection should delete");
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("cleaned catalog store should reopen");
    assert!(
        reopened
            .mcp_catalogs()
            .expect("reopened catalogs should load")
            .is_empty(),
        "converted and deleted Connections must leave no durable catalog rows"
    );
}

#[test]
fn openapi_catalog_replacement_is_atomic_revisioned_and_dependency_aware() {
    let (_directory, path, store) = temporary_store("openapi-catalog");
    let created = store
        .create(candidate())
        .expect("OpenAPI Connection should create");
    let first_spec = r#"{"openapi":"3.1.0","info":{"title":"First","version":"1"}}"#;
    let first_digest = spec_digest(first_spec);
    let first = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            0,
            0,
            first_spec,
            &first_digest,
            &[
                openapi_catalog_entry("alpha"),
                openapi_catalog_entry("beta"),
            ],
        )
        .expect("first OpenAPI catalog should publish");
    assert_eq!(first.spec_revision, 1);
    assert_eq!(first.catalog_revision, 1);
    assert_eq!(
        first.entries[0].selected_scheme_names,
        vec!["api_key".to_owned(), "oauth".to_owned()]
    );
    assert_eq!(
        store
            .dependencies(&created.id)
            .expect("OpenAPI dependencies should load")
            .into_iter()
            .filter(|dependency| dependency.kind == ConnectionDependencyKind::ManagedTool)
            .map(|dependency| dependency.consumer_id)
            .collect::<Vec<_>>(),
        vec!["alpha".to_owned(), "beta".to_owned()]
    );

    assert!(matches!(
        store.replace_openapi_catalog(
            &created.id,
            &created.etag(),
            0,
            1,
            first_spec,
            &first_digest,
            &[openapi_catalog_entry("stale")],
        ),
        Err(ConnectionStoreError::Conflict { .. })
    ));
    assert!(matches!(
        store.replace_openapi_catalog(
            &created.id,
            &created.etag(),
            1,
            1,
            first_spec,
            &"0".repeat(SHA256_HEX_CHARS),
            &[openapi_catalog_entry("invalid-digest")],
        ),
        Err(ConnectionStoreError::Validation { .. })
    ));
    assert_eq!(
        store
            .openapi_catalog(&created.id)
            .expect("retained OpenAPI catalog should load")
            .expect("retained OpenAPI catalog should remain"),
        first
    );

    let second = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            1,
            1,
            first_spec,
            &first_digest,
            &[openapi_catalog_entry("gamma")],
        )
        .expect("same-spec OpenAPI catalog should publish");
    assert_eq!(second.spec_revision, 1);
    assert_eq!(second.catalog_revision, 2);

    let second_spec = r#"{"openapi":"3.1.0","info":{"title":"Second","version":"2"}}"#;
    let second_digest = spec_digest(second_spec);
    let third = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            1,
            2,
            second_spec,
            &second_digest,
            &[openapi_catalog_entry("delta")],
        )
        .expect("changed-spec OpenAPI catalog should publish");
    assert_eq!(third.spec_revision, 2);
    assert_eq!(third.catalog_revision, 3);

    let mut duplicate = openapi_catalog_entry("duplicate");
    duplicate.operation_id = None;
    assert!(matches!(
        store.replace_openapi_catalog(
            &created.id,
            &created.etag(),
            2,
            3,
            second_spec,
            &second_digest,
            &[duplicate.clone(), duplicate],
        ),
        Err(ConnectionStoreError::Validation { .. })
    ));
    assert_eq!(
        store
            .openapi_catalog(&created.id)
            .expect("catalog should load after failed replacement")
            .expect("catalog should survive failed replacement"),
        third
    );

    let mut compatible = created.write.clone();
    compatible.display_name = "Renamed OpenAPI".to_owned();
    let replaced = store
        .replace(&created.id, &created.etag(), compatible)
        .expect("compatible OpenAPI update should retain catalog");
    assert_eq!(
        store
            .openapi_catalog(&created.id)
            .expect("retained catalog should load")
            .expect("compatible update should retain catalog"),
        third
    );

    let mut incompatible = replaced.write.clone();
    incompatible.discovery = None;
    assert!(matches!(
        store.replace(&replaced.id, &replaced.etag(), incompatible),
        Err(ConnectionStoreError::DependencyConflict { count: 1, .. })
    ));
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("OpenAPI catalog store should reopen");
    assert_eq!(
        reopened
            .openapi_catalog(&created.id)
            .expect("reopened OpenAPI catalog should load"),
        Some(third)
    );
}

#[test]
fn openapi_overlay_catalog_reports_and_enum_prune_are_one_atomic_revision() {
    let (_directory, path, store) = temporary_store("openapi-overlay-atomic");
    let created = store.create(candidate()).expect("Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Overlay","version":"1"}}"#;
    let digest = spec_digest(spec);
    let first_document = r#"{"schema_version":"0.1.0","tools":{}}"#;
    let first_reports = r#"{"schema_version":"0.1.0","sources":[]}"#;
    let first = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            0,
            0,
            spec,
            &digest,
            &[openapi_catalog_entry("alpha")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: first_document.to_owned(),
                source_reports_json: first_reports.to_owned(),
                expected_overlay_revision: 0,
            }),
            1,
            "operator-a",
            &[],
        )
        .expect("overlay and catalog should publish together");
    assert_eq!(first.overlay_revision, 1);
    let stored = store
        .openapi_overlay(&created.id)
        .expect("overlay should load")
        .expect("overlay should exist");
    assert_eq!(stored.overlay_json, first_document);
    assert_eq!(stored.source_reports_json.as_deref(), Some(first_reports));
    assert_eq!(
        stored
            .etag(created.revisions.connection, first.catalog_revision)
            .as_str(),
        format!("\"overlay:{}:c1:r1:o1\"", created.id)
    );
    assert_eq!(
        store.openapi_overlays().expect("bulk overlays"),
        vec![stored.clone()]
    );

    drop(store);
    let store = SqliteConnectionStore::open(&path)
        .expect("overlay and non-empty source reports should survive restart");
    assert_eq!(
        store
            .openapi_overlay(&created.id)
            .expect("restarted overlay lookup"),
        Some(stored.clone())
    );

    {
        let connection = store.connection_guard();
        connection
            .execute(
                r#"
                    INSERT INTO connection_enum_source_values (
                        connection_id, source_id, overlay_revision, source_digest,
                        values_revision, connection_revision, credential_revision,
                        values_json, resolved_at
                    ) VALUES (?1, 'industries', 1, ?2, 1, 1, 0, ?3, ?4)
                    "#,
                params![
                    created.id.as_str(),
                    "a".repeat(SHA256_HEX_CHARS),
                    r#"{"version":1,"values":["software"]}"#,
                    utc_timestamp().expect("timestamp"),
                ],
            )
            .expect("enum provenance fixture should insert");
    }

    let stale = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            1,
            spec,
            &digest,
            &[openapi_catalog_entry("stale")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: r#"{"schema_version":"0.1.0","description":"stale"}"#.to_owned(),
                source_reports_json: first_reports.to_owned(),
                expected_overlay_revision: 0,
            }),
            1,
            "operator-b",
            &[],
        )
        .expect_err("stale overlay CAS must reject the whole catalog write");
    assert!(matches!(
        stale,
        ConnectionStoreError::OverlayConflict { .. }
    ));
    assert_eq!(
        store
            .openapi_catalog(&created.id)
            .expect("catalog after rejection"),
        Some(first.clone())
    );
    assert_eq!(
        store
            .openapi_overlay(&created.id)
            .expect("overlay after rejection"),
        Some(stored.clone())
    );

    let second_document = r#"{"schema_version":"0.1.0","description":"replacement","tools":{}}"#;
    let second_reports = r#"{"schema_version":"0.1.0","sources":[{"id":"industries","kind":"enum","state":"last_known_good","item_count":1,"resolved_at":"2026-09-03T00:00:00Z"}]}"#;
    {
        let connection = store.connection_guard();
        connection
            .execute_batch(
                r#"
                    CREATE TRIGGER fail_openapi_overlay_update
                    BEFORE UPDATE ON connection_openapi_overlays
                    BEGIN
                        SELECT RAISE(ABORT, 'injected overlay failure');
                    END;
                    "#,
            )
            .expect("failure trigger should install");
    }
    store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            1,
            spec,
            &digest,
            &[openapi_catalog_entry("must-roll-back")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: second_document.to_owned(),
                source_reports_json: second_reports.to_owned(),
                expected_overlay_revision: 1,
            }),
            2,
            "operator-injected-failure",
            &[],
        )
        .expect_err("a failure after catalog and enum work must roll back everything");
    {
        let connection = store.connection_guard();
        connection
            .execute_batch("DROP TRIGGER fail_openapi_overlay_update")
            .expect("failure trigger should drop");
        let enum_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_enum_source_values WHERE connection_id = ?1",
                params![created.id.as_str()],
                |row| row.get(0),
            )
            .expect("rolled-back enum count");
        assert_eq!(enum_count, 1, "enum prune must roll back");
    }
    assert_eq!(
        store
            .openapi_catalog(&created.id)
            .expect("catalog after injected failure"),
        Some(first.clone()),
        "catalog replacement must roll back"
    );
    assert_eq!(
        store
            .openapi_overlay(&created.id)
            .expect("overlay after injected failure"),
        Some(stored.clone()),
        "overlay mutation must roll back"
    );
    let second = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            1,
            spec,
            &digest,
            &[openapi_catalog_entry("beta")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: second_document.to_owned(),
                source_reports_json: second_reports.to_owned(),
                expected_overlay_revision: 1,
            }),
            2,
            "operator-b",
            &[],
        )
        .expect("second overlay should publish");
    assert_eq!(second.overlay_revision, 2);
    let enum_count: i64 = store
        .connection_guard()
        .query_row(
            "SELECT COUNT(*) FROM connection_enum_source_values WHERE connection_id = ?1",
            params![created.id.as_str()],
            |row| row.get(0),
        )
        .expect("enum prune count");
    assert_eq!(enum_count, 0, "overlay mutation must prune stale values");

    // A resolver may refresh only the safe report snapshot. That CAS
    // advances the catalog transaction while preserving the exact
    // authoring document/revision and every durable enum value.
    {
        let connection = store.connection_guard();
        let credential_generation_digest = "c".repeat(SHA256_HEX_CHARS);
        connection
            .execute(
                r#"
                    INSERT INTO connection_enum_source_values (
                        connection_id, source_id, overlay_revision, source_digest,
                        values_revision, connection_revision, credential_revision,
                        credential_generation_digest, values_json, resolved_at
                    ) VALUES (?1, 'industries', 2, ?2, 1, 1, 0, ?3, ?4, ?5)
                    "#,
                params![
                    created.id.as_str(),
                    "b".repeat(SHA256_HEX_CHARS),
                    credential_generation_digest,
                    r#"{"version":1,"values":["software"]}"#,
                    utc_timestamp().expect("timestamp"),
                ],
            )
            .expect("current enum provenance fixture should insert");
        let stored_digest: Option<String> = connection
                .query_row(
                    "SELECT credential_generation_digest FROM connection_enum_source_values WHERE connection_id = ?1 AND source_id = 'industries'",
                    params![created.id.as_str()],
                    |row| row.get(0),
                )
                .expect("credential generation digest should read");
        assert_eq!(
            stored_digest.as_deref(),
            Some(credential_generation_digest.as_str())
        );
    }
    let refreshed_reports = r#"{"schema_version":"0.1.0","sources":[{"id":"industries","kind":"enum","state":"fresh","item_count":1,"resolved_at":"2026-09-03T00:00:00Z"}]}"#;
    let report_catalog = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            2,
            spec,
            &digest,
            &[openapi_catalog_entry("beta")],
            Some(&StoredOverlayWrite::Reports {
                source_reports_json: refreshed_reports.to_owned(),
                expected_overlay_revision: 2,
            }),
            2,
            "resolver",
            &[],
        )
        .expect("report-only CAS should commit");
    assert_eq!(report_catalog.catalog_revision, 3);
    assert_eq!(report_catalog.overlay_revision, 2);
    let report_overlay = store
        .openapi_overlay(&created.id)
        .expect("report overlay lookup")
        .expect("overlay remains stored");
    assert_eq!(report_overlay.overlay_json, second_document);
    assert_eq!(report_overlay.overlay_revision, 2);
    assert_eq!(
        report_overlay.source_reports_json.as_deref(),
        Some(refreshed_reports)
    );
    assert_eq!(report_overlay.updated_at, report_catalog.refreshed_at);
    let enum_count: i64 = store
        .connection_guard()
        .query_row(
            "SELECT COUNT(*) FROM connection_enum_source_values WHERE connection_id = ?1",
            params![created.id.as_str()],
            |row| row.get(0),
        )
        .expect("enum rows should remain after report-only CAS");
    assert_eq!(enum_count, 1);

    drop(store);
    let store = SqliteConnectionStore::open(&path).expect("overlay store should restart");
    let (boot_catalogs, boot_overlays) = store
        .openapi_catalogs_with_overlays()
        .expect("restart must read the catalog/overlay pair atomically");
    assert_eq!(boot_catalogs.len(), 1);
    assert_eq!(boot_overlays.len(), 1);
    assert_eq!(boot_overlays[0].overlay_revision, 2);
    assert_eq!(boot_overlays[0].overlay_json, second_document);
    assert_eq!(
        boot_overlays[0].source_reports_json.as_deref(),
        Some(refreshed_reports)
    );
    assert_eq!(
        boot_catalogs[0].overlay_revision, boot_overlays[0].overlay_revision,
        "boot catalog and exact durable overlay must remain joinable"
    );

    let preserved = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            3,
            spec,
            &digest,
            &[openapi_catalog_entry("beta")],
            None,
            2,
            "operator-refresh",
            &[],
        )
        .expect("refresh-style publish should preserve the exact overlay");
    assert_eq!(preserved.overlay_revision, 2);
    assert_eq!(
        store
            .openapi_overlay(&created.id)
            .expect("preserved overlay lookup"),
        Some(boot_overlays[0].clone())
    );

    let deleted = store
        .replace_openapi_catalog_with_overlay(
            &created.id,
            &created.etag(),
            1,
            4,
            spec,
            &digest,
            &[openapi_catalog_entry("alpha")],
            Some(&StoredOverlayWrite::Delete {
                expected_overlay_revision: 2,
            }),
            0,
            "operator-c",
            &[],
        )
        .expect("overlay delete and bare catalog should commit together");
    assert_eq!(deleted.overlay_revision, 0);
    assert!(store
        .openapi_overlay(&created.id)
        .expect("deleted overlay lookup")
        .is_none());
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("overlay store should restart");
    assert!(reopened
        .openapi_overlays()
        .expect("restart bulk overlays")
        .is_empty());
    assert_eq!(
        reopened
            .openapi_catalog(&created.id)
            .expect("restart catalog")
            .expect("catalog retained")
            .overlay_revision,
        0
    );
}

#[test]
fn enum_source_values_publish_atomically_and_use_exact_generation_cas() {
    let (_directory, path, store) = temporary_store("enum-source-cas");
    let created = store.create(candidate()).expect("Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Enums","version":"1"}}"#;
    let digest = spec_digest(spec);
    let overlay = StoredOverlayWrite::Put {
            schema_version: "0.1.0".to_owned(),
            overlay_json: r#"{"schema_version":"0.1.0","tools":{}}"#.to_owned(),
            source_reports_json: r#"{"schema_version":"0.1.0","sources":[{"id":"regions","kind":"enum","state":"fresh","item_count":2,"resolved_at":"2026-09-03T00:00:00Z"}]}"#.to_owned(),
            expected_overlay_revision: 0,
        };
    let first_write = StoredEnumSourceValueWrite {
        connection_id: created.id.clone(),
        source_id: "regions".to_owned(),
        overlay_revision: 1,
        source_digest: "a".repeat(SHA256_HEX_CHARS),
        expected_values_revision: 0,
        connection_revision: created.revisions.connection,
        credential_revision: created.revisions.credential,
        credential_generation_digest: Some("b".repeat(SHA256_HEX_CHARS)),
        values: vec![json!("na"), json!("eu")],
        labels: Some(vec!["North America".to_owned(), "Europe".to_owned()]),
        resolved_at: "2026-09-03T00:00:00Z".to_owned(),
    };
    let catalog = store
        .replace_openapi_catalog_with_overlay_and_enum_values(
            &created.id,
            &created.etag(),
            0,
            0,
            spec,
            &digest,
            &[openapi_catalog_entry("enum_tool")],
            Some(&overlay),
            1,
            "enum-resolver",
            &[],
            std::slice::from_ref(&first_write),
        )
        .expect("catalog, overlay, and initial enum values should publish together");
    assert_eq!((catalog.catalog_revision, catalog.overlay_revision), (1, 1));

    let first = store
        .enum_source_values_for_connection(&created.id)
        .expect("typed enum values should load");
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].values_revision, 1);
    assert_eq!(first[0].values, first_write.values);
    assert_eq!(first[0].labels, first_write.labels);

    let mut second_write = first_write.clone();
    second_write.expected_values_revision = 1;
    second_write.values = vec![json!("apac"), json!(true)];
    second_write.labels = None;
    second_write.resolved_at = "2026-09-03T00:01:00Z".to_owned();
    let second = store
        .replace_enum_source_value(&second_write, 1)
        .expect("the exact enum values revision should replace");
    assert_eq!(second.values_revision, 2);
    assert_eq!(second.values, second_write.values);

    let stale = store
        .replace_enum_source_value(&first_write, 0)
        .expect_err("a stale resolver must not overwrite the winner");
    assert!(matches!(
        stale,
        ConnectionStoreError::EnumSourceConflict {
            current_values_revision: 2,
            ..
        }
    ));

    let mut wrong_source_generation = second_write.clone();
    wrong_source_generation.expected_values_revision = 2;
    wrong_source_generation.source_digest = "c".repeat(SHA256_HEX_CHARS);
    assert!(matches!(
        store.replace_enum_source_value(&wrong_source_generation, 2),
        Err(ConnectionStoreError::EnumSourceConflict {
            current_values_revision: 2,
            ..
        })
    ));
    assert_eq!(
        store
            .enum_source_values()
            .expect("winner should remain after stale CAS"),
        vec![second.clone()]
    );

    let mut oversized = second_write.clone();
    oversized.expected_values_revision = 2;
    oversized.values = (0..1_024)
        .map(|index| json!(format!("{index:04}-{}", "a".repeat(1_019))))
        .collect();
    let rejected = store
        .replace_enum_source_value(&oversized, 2)
        .expect_err("a values document above 256 KiB must fail closed");
    assert!(matches!(rejected, ConnectionStoreError::Validation { .. }));
    assert_eq!(
        store
            .enum_source_values()
            .expect("oversize rejection should leave the winner"),
        vec![second.clone()]
    );

    let mut suspicious = second_write.clone();
    suspicious.expected_values_revision = 2;
    suspicious.values = vec![json!("region ghp_canary")];
    let rejected = store
        .replace_enum_source_value(&suspicious, 2)
        .expect_err("embedded secret-shaped tokens must not enter the LKG store");
    assert!(matches!(rejected, ConnectionStoreError::Validation { .. }));
    assert_eq!(
        store
            .enum_source_values()
            .expect("suspicious-value rejection should leave the winner"),
        vec![second.clone()]
    );

    for spoofed in [
        "north\u{2028}america",
        "north\u{2029}america",
        "north\u{202e}america",
    ] {
        let mut non_printable = second_write.clone();
        non_printable.expected_values_revision = 2;
        non_printable.values = vec![json!(spoofed)];
        non_printable.labels = None;
        assert!(matches!(
            store.replace_enum_source_value(&non_printable, 2),
            Err(ConnectionStoreError::Validation { .. })
        ));
        non_printable.values = vec![json!("safe")];
        non_printable.labels = Some(vec![spoofed.to_owned()]);
        assert!(matches!(
            store.replace_enum_source_value(&non_printable, 2),
            Err(ConnectionStoreError::Validation { .. })
        ));
    }

    let mut future_timestamp = second_write.clone();
    future_timestamp.expected_values_revision = 2;
    future_timestamp.resolved_at = "2099-01-01T00:00:00Z".to_owned();
    assert!(matches!(
        store.replace_enum_source_value(&future_timestamp, 2),
        Err(ConnectionStoreError::Validation { .. })
    ));

    drop(store);
    let reopened = SqliteConnectionStore::open(&path).expect("enum store should restart");
    assert_eq!(
        reopened
            .enum_source_values_for_connection(&created.id)
            .expect("restart should bulk-read the exact winner"),
        vec![second]
    );
    let connection = Connection::open(&path).expect("enum database should open directly");
    connection
        .execute(
            "UPDATE connection_enum_source_values SET values_json = ?1 WHERE connection_id = ?2",
            params![r#"{"version":2,"values":["future"]}"#, created.id.as_str()],
        )
        .expect("future enum codec fixture should write");
    drop(connection);
    assert_eq!(
        reopened
            .enum_source_revisions()
            .expect("metadata-only scan must not decode values_json")
            .len(),
        1
    );
    assert!(matches!(
        reopened.enum_source_value(&created.id, "regions"),
        Err(ConnectionStoreError::CorruptRecord {
            reason: "invalid enum source values",
            ..
        })
    ));
    drop(reopened);
    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::CorruptRecord {
            reason: "invalid enum source values",
            ..
        })
    ));
}

#[test]
fn empty_openapi_catalog_is_removed_on_incompatible_update_and_delete_cascades() {
    let (_directory, path, store) = temporary_store("empty-openapi-catalog-cleanup");
    let source = store
        .create(candidate())
        .expect("convertible OpenAPI Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Empty","version":"1"}}"#;
    let digest = spec_digest(spec);
    store
        .replace_openapi_catalog(&source.id, &source.etag(), 0, 0, spec, &digest, &[])
        .expect("empty OpenAPI catalog should publish");
    let converted = store
        .replace(&source.id, &source.etag(), mcp_candidate())
        .expect("empty OpenAPI catalog should permit cross-kind update");
    assert!(store
        .openapi_catalog(&converted.id)
        .expect("converted catalog lookup should work")
        .is_none());
    store
        .delete(&converted.id, &converted.etag())
        .expect("converted Connection should delete");

    let deleted = store
        .create(candidate())
        .expect("deletable OpenAPI Connection should create");
    store
        .replace_openapi_catalog(&deleted.id, &deleted.etag(), 0, 0, spec, &digest, &[])
        .expect("deletable empty OpenAPI catalog should publish");
    store
        .delete(&deleted.id, &deleted.etag())
        .expect("empty OpenAPI catalog should cascade on delete");
    drop(store);

    let reopened = SqliteConnectionStore::open(&path).expect("cleaned OpenAPI store should reopen");
    assert!(reopened
        .openapi_catalogs()
        .expect("OpenAPI catalogs should load")
        .is_empty());
}

#[test]
fn combined_mcp_and_openapi_catalog_bound_is_enforced_in_both_replacements() {
    let (_directory, _path, store) = temporary_store("combined-catalog-bound");
    let mcp = store
        .create(mcp_candidate())
        .expect("MCP Connection should create");
    let openapi = store
        .create(candidate())
        .expect("OpenAPI Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Bound","version":"1"}}"#;
    let digest = spec_digest(spec);
    store
        .replace_openapi_catalog(
            &openapi.id,
            &openapi.etag(),
            0,
            0,
            spec,
            &digest,
            &[
                openapi_catalog_entry("openapi-a"),
                openapi_catalog_entry("openapi-b"),
            ],
        )
        .expect("small OpenAPI catalog should publish");
    let oversized_mcp = (0..(MAX_CATALOG_ENTRIES - 1))
        .map(|index| mcp_catalog_entry(&format!("m{index:04}"), "Bounded"))
        .collect::<Vec<_>>();
    assert!(matches!(
        store.replace_mcp_catalog(&mcp.id, &mcp.etag(), &oversized_mcp, &[], &[]),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection catalog entries",
            ..
        })
    ));

    let bounded_mcp = oversized_mcp
        .into_iter()
        .take(MAX_CATALOG_ENTRIES - 2)
        .collect::<Vec<_>>();
    store
        .replace_mcp_catalog(&mcp.id, &mcp.etag(), &bounded_mcp, &[], &[])
        .expect("combined catalog at the exact limit should publish");
    assert!(matches!(
        store.replace_openapi_catalog(
            &openapi.id,
            &openapi.etag(),
            1,
            1,
            spec,
            &digest,
            &[
                openapi_catalog_entry("openapi-a"),
                openapi_catalog_entry("openapi-b"),
                openapi_catalog_entry("openapi-c"),
            ],
        ),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection catalog entries",
            ..
        })
    ));
}

#[test]
fn aggregate_openapi_definition_byte_bound_preserves_prior_catalogs() {
    let (_directory, _path, store) = temporary_store("openapi-aggregate-byte-bound");
    let first = store
        .create(candidate())
        .expect("first OpenAPI Connection should create");
    let mut second_candidate = candidate();
    second_candidate.display_name = "Second OpenAPI".to_owned();
    let second = store
        .create(second_candidate)
        .expect("second OpenAPI Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Bytes","version":"1"}}"#;
    let digest = spec_digest(spec);

    let first_entries = openapi_catalog_entries_with_minimum_bytes(
        "first",
        MAX_MANAGED_OPENAPI_CATALOG_BYTES / 2 + 1,
    );
    let first_catalog = store
        .replace_openapi_catalog(
            &first.id,
            &first.etag(),
            0,
            0,
            spec,
            &digest,
            &first_entries,
        )
        .expect("first catalog below the aggregate bound should publish");
    drop(first_entries);

    let second_entries = openapi_catalog_entries_with_minimum_bytes(
        "second",
        MAX_MANAGED_OPENAPI_CATALOG_BYTES / 2 + 1,
    );
    assert!(matches!(
        store.replace_openapi_catalog(
            &second.id,
            &second.etag(),
            0,
            0,
            spec,
            &digest,
            &second_entries,
        ),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        })
    ));
    drop(second_entries);
    assert_eq!(
        store
            .openapi_catalog(&first.id)
            .expect("first catalog should load"),
        Some(first_catalog)
    );
    assert!(store
        .openapi_catalog(&second.id)
        .expect("second catalog lookup should work")
        .is_none());
    assert!(store
        .dependencies(&second.id)
        .expect("second dependencies should load")
        .is_empty());

    let oversized = openapi_catalog_entries_with_minimum_bytes(
        "oversized",
        MAX_MANAGED_OPENAPI_CATALOG_BYTES + 1,
    );
    assert!(matches!(
        store.replace_openapi_catalog(&second.id, &second.etag(), 0, 0, spec, &digest, &oversized,),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        })
    ));
    assert!(store
        .openapi_catalog(&second.id)
        .expect("pre-transaction rejection should leave no catalog")
        .is_none());
}

#[test]
fn aggregate_openapi_definition_byte_corruption_is_rejected_on_restart() {
    let (_directory, path, store) = temporary_store("openapi-byte-corrupt-restart");
    let created = store
        .create(candidate())
        .expect("OpenAPI Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Bytes","version":"1"}}"#;
    let digest = spec_digest(spec);
    store
        .replace_openapi_catalog(&created.id, &created.etag(), 0, 0, spec, &digest, &[])
        .expect("empty OpenAPI catalog should publish");
    drop(store);

    let entries = openapi_catalog_entries_with_minimum_bytes(
        "corrupt",
        MAX_MANAGED_OPENAPI_CATALOG_BYTES + 1,
    );
    let mut connection = Connection::open(&path).expect("catalog database should open directly");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("corruption fixture transaction should begin");
    for (ordinal, entry) in entries.iter().enumerate() {
        transaction
            .execute(
                r#"
                    INSERT INTO connection_openapi_catalog_entries (
                        connection_id, tool_name, operation_id,
                        selected_scheme_names_json, definition_json, ordinal
                    ) VALUES (?1, ?2, ?3, '[]', ?4, ?5)
                    "#,
                params![
                    created.id.as_str(),
                    entry.tool_name,
                    entry.operation_id,
                    serde_json::to_string(&entry.definition)
                        .expect("corrupt fixture definition should serialize"),
                    i64::try_from(ordinal).expect("fixture ordinal should fit SQLite"),
                ],
            )
            .expect("oversized aggregate fixture entry should insert");
    }
    transaction
        .execute(
            r#"
                UPDATE connection_openapi_catalogs
                SET entry_count = ?1
                WHERE connection_id = ?2
                "#,
            params![
                i64::try_from(entries.len()).expect("fixture count should fit SQLite"),
                created.id.as_str()
            ],
        )
        .expect("oversized aggregate fixture count should update");
    transaction
        .commit()
        .expect("corruption fixture transaction should commit");
    drop(connection);

    assert!(matches!(
        SqliteConnectionStore::open(&path),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        })
    ));
}

#[test]
fn orphan_managed_tool_dependency_is_rejected_on_restart() {
    let (_directory, path, store) = temporary_store("orphan-managed-tool-restart");
    let created = store.create(candidate()).expect("Connection should create");
    drop(store);

    let connection = Connection::open(&path).expect("database should open directly");
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .expect("foreign keys should enable");
    connection
        .execute(
            r#"
                INSERT INTO connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                ) VALUES (?1, 'managed_tool', 'orphan-tool', ?2)
                "#,
            params![
                created.id.as_str(),
                utc_timestamp().expect("fixture timestamp should format")
            ],
        )
        .expect("orphan dependency fixture should insert");
    drop(connection);

    assert!(matches!(
        SqliteConnectionStore::open(&path),
        Err(ConnectionStoreError::CorruptRecord {
            id,
            reason: "managed tool dependencies do not match durable catalog entries",
        }) if id == "<catalog-dependencies>"
    ));
}

#[test]
fn corrupt_openapi_catalog_definition_is_rejected_on_restart() {
    let (_directory, path, store) = temporary_store("openapi-corrupt-restart");
    let created = store
        .create(candidate())
        .expect("OpenAPI Connection should create");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Corrupt","version":"1"}}"#;
    let digest = spec_digest(spec);
    store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            0,
            0,
            spec,
            &digest,
            &[openapi_catalog_entry("alpha")],
        )
        .expect("OpenAPI catalog should publish");
    drop(store);

    let connection = Connection::open(&path).expect("catalog database should open directly");
    connection
        .execute(
            r#"
                UPDATE connection_openapi_catalog_entries
                SET definition_json = '{}'
                WHERE connection_id = ?1
                "#,
            params![created.id.as_str()],
        )
        .expect("corrupt definition fixture should write");
    drop(connection);
    assert!(SqliteConnectionStore::open(&path).is_err());
}

#[test]
fn corrupt_mcp_resource_catalog_is_rejected_on_restart() {
    let (_directory, path, store) = temporary_store("mcp-resource-corrupt-restart");
    let created = store
        .create(mcp_candidate())
        .expect("MCP Connection should create");
    store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_catalog_entry("alpha", "Alpha")],
            &[mcp_resource("gg://resource/alpha", "resource-alpha")],
            &[mcp_resource_template(
                "gg://resource/{id}",
                "resource-by-id",
            )],
        )
        .expect("MCP resource catalog should publish");
    drop(store);

    let connection = Connection::open(&path).expect("catalog database should open directly");
    connection
        .execute(
            "UPDATE connection_mcp_catalogs SET resource_count = 2 WHERE connection_id = ?1",
            params![created.id.as_str()],
        )
        .expect("corrupt MCP resource count fixture should write");
    drop(connection);

    assert!(matches!(
        SqliteConnectionStore::open(&path),
        Err(ConnectionStoreError::CorruptRecord {
            reason: "stored MCP catalog metadata is inconsistent",
            ..
        })
    ));
}

#[test]
fn failed_migration_rolls_back_every_schema_change() {
    let mut connection = Connection::open_in_memory().expect("memory database should open");
    let path = Path::new(":memory:");
    let migrations = [
        Migration {
            version: 1,
            sql: "CREATE TABLE connection_test_one (id INTEGER PRIMARY KEY);",
        },
        Migration {
            version: 2,
            sql: "CREATE TABLE connection_test_two (id INTEGER PRIMARY KEY); INVALID SQL;",
        },
    ];

    assert!(run_migrations(&mut connection, path, &migrations).is_err());
    let table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'connection_%'",
            [],
            |row| row.get(0),
        )
        .expect("schema catalog query should work");
    assert_eq!(table_count, 0, "failed migration must roll back all DDL");
}

#[test]
fn final_schema_validation_rolls_back_migration_from_damaged_applied_prefix() {
    let mut connection = Connection::open_in_memory().expect("memory database should open");
    connection
        .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
        .expect("migration table should create");
    connection
        .execute_batch("CREATE TABLE connection_records (id TEXT PRIMARY KEY);")
        .expect("damaged applied schema should create");
    connection
        .execute(
            "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (1, ?1)",
            params![utc_timestamp().expect("timestamp should format")],
        )
        .expect("applied marker should insert");

    assert!(run_migrations(&mut connection, Path::new(":memory:"), MIGRATIONS).is_err());
    let version_two_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM connection_schema_migrations WHERE version = 2",
            [],
            |row| row.get(0),
        )
        .expect("migration marker query should work");
    let status_table_count: i64 = connection
        .query_row(
            r#"
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN ('connection_current_status', 'connection_status_history')
                "#,
            [],
            |row| row.get(0),
        )
        .expect("schema catalog query should work");
    assert_eq!(version_two_count, 0);
    assert_eq!(
        status_table_count, 0,
        "schema validation failure must roll back migration DDL"
    );
}

#[test]
fn non_contiguous_migration_history_fails_closed() {
    let mut connection = Connection::open_in_memory().expect("memory database should open");
    connection
        .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
        .expect("migration table should create");
    connection
        .execute(
            "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (2, ?1)",
            params![utc_timestamp().expect("timestamp should format")],
        )
        .expect("test migration marker should insert");

    assert!(matches!(
        run_migrations(&mut connection, Path::new(":memory:"), MIGRATIONS),
        Err(ConnectionStoreError::InvalidMigrationHistory)
    ));
    let versions: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM connection_schema_migrations",
            [],
            |row| row.get(0),
        )
        .expect("existing migration history should remain");
    assert_eq!(versions, 1);
}

#[test]
fn create_replace_restart_and_etag_conflict_are_transactional() {
    let (_directory, path, store) = temporary_store("crud");
    let created = store.create(candidate()).expect("create should succeed");
    assert_eq!(created.revisions.connection, 1);
    assert_eq!(created.revisions.credential, 1);
    assert_eq!(created.revisions.discovery, 1);
    let stale_etag = created.etag();

    let mut replacement = created.write.clone();
    replacement.description = Some("Updated".to_owned());
    let replaced = store
        .replace(&created.id, &stale_etag, replacement)
        .expect("replace should succeed");
    assert_eq!(replaced.revisions.connection, 2);
    assert_eq!(replaced.revisions.credential, 1);
    assert_eq!(replaced.revisions.discovery, 1);
    assert!(matches!(
        store.replace(&created.id, &stale_etag, replaced.write.clone()),
        Err(ConnectionStoreError::Conflict { .. })
    ));

    drop(store);
    let reopened = SqliteConnectionStore::open(path).expect("store should reopen");
    assert_eq!(
        reopened
            .get(&created.id)
            .expect("get should succeed")
            .expect("record should exist"),
        replaced
    );
}

#[test]
fn validation_and_sql_failure_leave_prior_record_and_bindings_unchanged() {
    let (_directory, _path, store) = temporary_store("rollback");
    let created = store.create(candidate()).expect("create should succeed");

    let mut invalid = created.write.clone();
    invalid.endpoint.base_url = "http://billing.example.test".to_owned();
    assert!(matches!(
        store.replace(&created.id, &created.etag(), invalid),
        Err(ConnectionStoreError::Validation { .. })
    ));

    {
        let connection = store.connection_guard();
        connection
            .execute_batch(
                r#"
                    CREATE TRIGGER fail_binding_insert
                    BEFORE INSERT ON connection_credential_bindings
                    BEGIN
                        SELECT RAISE(ABORT, 'forced binding failure');
                    END;
                    "#,
            )
            .expect("failure trigger should install");
    }
    let mut replacement = created.write.clone();
    replacement.display_name = "Replacement".to_owned();
    assert!(matches!(
        store.replace(&created.id, &created.etag(), replacement),
        Err(ConnectionStoreError::Sqlite { .. })
    ));

    let persisted = store
        .get(&created.id)
        .expect("get should succeed")
        .expect("record should remain");
    assert_eq!(persisted, created);
    let connection = store.connection_guard();
    let binding: String = connection
        .query_row(
            "SELECT secret_id FROM connection_credential_bindings WHERE connection_id = ?1",
            params![created.id.as_str()],
            |row| row.get(0),
        )
        .expect("original binding should remain");
    assert_eq!(binding, "billing-token");
}

#[test]
fn dependencies_block_delete_without_cascading() {
    let (_directory, _path, store) = temporary_store("dependencies");
    let created = store.create(candidate()).expect("create should succeed");
    store
        .add_dependency(
            &created.id,
            ConnectionDependencyKind::ManualTool,
            "billing.get",
        )
        .expect("dependency should insert");

    assert!(matches!(
        store.delete(&created.id, &created.etag()),
        Err(ConnectionStoreError::DependencyConflict { count: 1, .. })
    ));
    assert!(store
        .get(&created.id)
        .expect("get should succeed")
        .is_some());

    store
        .remove_dependency(
            &created.id,
            ConnectionDependencyKind::ManualTool,
            "billing.get",
        )
        .expect("dependency should remove");
    store
        .delete(&created.id, &created.etag())
        .expect("unreferenced connection should delete");
    assert!(store
        .get(&created.id)
        .expect("get should succeed")
        .is_none());
}

#[test]
fn dependency_kind_replacement_is_atomic_and_tracks_current_runtime_consumers() {
    let (_directory, _path, store) = temporary_store("dependency-replacement");
    let first = store.create(candidate()).expect("create should succeed");
    let mut second_candidate = candidate();
    second_candidate.display_name = "Second API".to_owned();
    let second = store
        .create(second_candidate)
        .expect("second create should succeed");

    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ProxyRoute,
            &[(first.id.clone(), "route-a".to_owned())],
        )
        .expect("initial dependency set should replace");
    store
        .add_dependency(&first.id, ConnectionDependencyKind::ManualTool, "tool-a")
        .expect("unrelated dependency kind should insert");

    let missing = ConnectionId::parse("missing-connection").expect("stable missing ID");
    assert!(matches!(
        store.replace_dependencies_for_kind(
            ConnectionDependencyKind::ProxyRoute,
            &[(missing, "route-b".to_owned())],
        ),
        Err(ConnectionStoreError::NotFound { .. })
    ));
    assert_eq!(
        store
            .dependencies(&first.id)
            .expect("failed replacement must roll back"),
        vec![
            ConnectionDependency {
                kind: ConnectionDependencyKind::ManualTool,
                consumer_id: "tool-a".to_owned(),
            },
            ConnectionDependency {
                kind: ConnectionDependencyKind::ProxyRoute,
                consumer_id: "route-a".to_owned(),
            },
        ]
    );

    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ProxyRoute,
            &[(second.id.clone(), "route-b".to_owned())],
        )
        .expect("current route dependencies should publish atomically");
    assert_eq!(
        store
            .dependencies(&first.id)
            .expect("unrelated kind should remain"),
        vec![ConnectionDependency {
            kind: ConnectionDependencyKind::ManualTool,
            consumer_id: "tool-a".to_owned(),
        }]
    );
    assert_eq!(
        store
            .dependencies(&second.id)
            .expect("new route dependency should load"),
        vec![ConnectionDependency {
            kind: ConnectionDependencyKind::ProxyRoute,
            consumer_id: "route-b".to_owned(),
        }]
    );
    assert!(matches!(
        store.delete(&second.id, &second.etag()),
        Err(ConnectionStoreError::DependencyConflict { count: 1, .. })
    ));
}

#[test]
fn dependency_detail_and_counts_are_sorted_bounded_admin_metadata() {
    let (_directory, _path, store) = temporary_store("dependency-detail");
    let first = store.create(candidate()).expect("create should succeed");
    let mut second_candidate = candidate();
    second_candidate.display_name = "Second API".to_owned();
    let second = store
        .create(second_candidate)
        .expect("second create should succeed");

    store
        .add_dependency(
            &first.id,
            ConnectionDependencyKind::ProxyRoute,
            "billing-route",
        )
        .expect("route dependency should insert");
    store
        .add_dependency(
            &first.id,
            ConnectionDependencyKind::ManualTool,
            "billing.get",
        )
        .expect("tool dependency should insert");
    store
        .add_dependency(
            &second.id,
            ConnectionDependencyKind::ManagedTool,
            "catalog.get",
        )
        .expect("managed tool dependency should insert");

    assert_eq!(
        store
            .dependencies(&first.id)
            .expect("dependency detail should load"),
        vec![
            ConnectionDependency {
                kind: ConnectionDependencyKind::ManualTool,
                consumer_id: "billing.get".to_owned(),
            },
            ConnectionDependency {
                kind: ConnectionDependencyKind::ProxyRoute,
                consumer_id: "billing-route".to_owned(),
            },
        ]
    );
    let counts = store
        .dependency_counts()
        .expect("dependency counts should load");
    assert_eq!(counts.get(&first.id), Some(&2));
    assert_eq!(counts.get(&second.id), Some(&1));

    let missing =
        ConnectionId::parse("00000000-0000-0000-0000-000000000000").expect("id should parse");
    assert!(matches!(
        store.dependencies(&missing),
        Err(ConnectionStoreError::NotFound { .. })
    ));
}

#[test]
fn dependencies_are_transactionally_bounded_and_idempotent() {
    let (_directory, path, store) = temporary_store("dependency-limit");
    let created = store.create(candidate()).expect("create should succeed");
    {
        let mut connection = store.connection_guard();
        let transaction = connection
            .transaction()
            .expect("seed transaction should begin");
        for index in 0..MAX_CONNECTION_DEPENDENCIES {
            transaction
                .execute(
                    r#"
                        INSERT INTO connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at
                        ) VALUES (?1, 'manual_tool', ?2, ?3)
                        "#,
                    params![
                        created.id.as_str(),
                        format!("consumer-{index}"),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("bounded dependency should insert");
        }
        transaction
            .commit()
            .expect("seed transaction should commit");
    }

    store
        .add_dependency(
            &created.id,
            ConnectionDependencyKind::ManualTool,
            "consumer-0",
        )
        .expect("existing dependency should remain an idempotent success");
    assert!(matches!(
        store.add_dependency(
            &created.id,
            ConnectionDependencyKind::ManualTool,
            "one-too-many"
        ),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection dependencies",
            maximum: MAX_CONNECTION_DEPENDENCIES,
        })
    ));
    {
        let connection = store.connection_guard();
        connection
            .execute(
                r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, 'manual_tool', 'one-too-many', ?2)
                    "#,
                params![
                    created.id.as_str(),
                    utc_timestamp().expect("timestamp should format")
                ],
            )
            .expect("direct corruption should bypass the application bound");
    }
    drop(store);
    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection dependencies",
            maximum: MAX_CONNECTION_DEPENDENCIES,
        })
    ));
}

#[test]
fn credential_binding_rows_are_hard_bounded() {
    let (_directory, path, store) = temporary_store("binding-limit");
    let created = store.create(candidate()).expect("create should succeed");
    {
        let mut connection = store.connection_guard();
        let transaction = connection
            .transaction()
            .expect("seed transaction should begin");
        for index in 1..MAX_CREDENTIALS {
            transaction
                .execute(
                    r#"
                        INSERT INTO connection_credential_bindings (
                            connection_id, purpose, secret_id, binding_version, updated_at
                        ) VALUES (?1, ?2, ?3, 1, ?4)
                        "#,
                    params![
                        created.id.as_str(),
                        format!("test-purpose-{index}"),
                        format!("test-secret-{index}"),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("bounded test binding should insert");
        }
        transaction
            .commit()
            .expect("seed transaction should commit");
    }

    assert!(matches!(
        store.create(candidate()),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        })
    ));
    assert_eq!(store.count().expect("count should work"), 1);

    {
        let connection = store.connection_guard();
        connection
            .execute(
                r#"
                    INSERT INTO connection_credential_bindings (
                        connection_id, purpose, secret_id, binding_version, updated_at
                    ) VALUES (?1, 'one-too-many', 'one-too-many', 1, ?2)
                    "#,
                params![
                    created.id.as_str(),
                    utc_timestamp().expect("timestamp should format")
                ],
            )
            .expect("direct corruption should bypass the application bound");
    }
    drop(store);
    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        })
    ));
}

#[test]
fn binding_count_includes_each_configured_additional_header() {
    let mut write = candidate();
    write.additional_headers = serde_json::from_value(json!([
        {"header_name": "X-Tenant", "secret_id": "tenant-secret"},
        {"header_name": "X-Optional"},
        {"header_name": "CF-Access-Client-Secret", "secret_id": "access-secret"}
    ]))
    .expect("additional headers should deserialize");

    assert_eq!(binding_count(&write), 3);
    let revisions = ConnectionRevisions {
        connection: 7,
        credential: 5,
        tls: 0,
        discovery: 2,
        status: 0,
    };
    assert_eq!(expected_bindings(&write, &revisions).len(), 3);
}

#[test]
fn status_observations_are_bound_to_the_tested_config_revision() {
    let (_directory, _path, store) = temporary_store("status-etag");
    let created = store.create(candidate()).expect("create should succeed");
    let stale_etag = created.etag();
    let healthy = ConnectionStatusUpdate {
        state: ConnectionOperationalState::Healthy,
        reason: ConnectionStatusReason::TestSucceeded,
        latency_ms: Some(5),
        catalog_age_secs: None,
        catalog_entry_count: None,
    };
    store
        .append_status(&created.id, &stale_etag, healthy.clone())
        .expect("initial observation should append");

    let mut replacement = created.write.clone();
    replacement.display_name = "Billing API v2".to_owned();
    let replaced = store
        .replace(&created.id, &stale_etag, replacement)
        .expect("replacement should succeed");
    assert!(
        store
            .latest_status(&created.id)
            .expect("latest status query should succeed")
            .is_none(),
        "reconfiguration must invalidate the prior current observation"
    );
    assert!(matches!(
        store.append_status(&created.id, &stale_etag, healthy.clone()),
        Err(ConnectionStoreError::Conflict { .. })
    ));
    assert!(
        store
            .latest_status(&created.id)
            .expect("latest status query should succeed")
            .is_none(),
        "a late stale test must not mark the replacement healthy"
    );
    store
        .append_status(&created.id, &replaced.etag(), healthy)
        .expect("observation for the replacement should append");
}

#[test]
fn activity_timestamps_track_successes_and_ambiguous_failures_in_the_correct_lane() {
    let (_directory, _path, store) = temporary_store("status-activity-lanes");
    let created = store
        .create(mcp_candidate())
        .expect("Connection should create");

    let tested = store
        .append_status(
            &created.id,
            &created.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(3),
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("test success should append");
    let mut expected_test_at = tested
        .observed_at
        .clone()
        .expect("test success should carry an observation time");
    let initial_activity = store
        .activity_times()
        .expect("initial activity should load")
        .remove(&created.id)
        .expect("initial activity should exist");
    assert_eq!(
        initial_activity,
        ConnectionActivityTimes {
            last_test_at: Some(expected_test_at.clone()),
            last_refresh_at: None,
        }
    );

    let current = store
        .get(&created.id)
        .expect("Connection should load")
        .expect("Connection should remain");
    let refreshed = store
        .append_status(
            &created.id,
            &current.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::CatalogRefreshed,
                latency_ms: Some(5),
                catalog_age_secs: Some(0),
                catalog_entry_count: Some(2),
            },
        )
        .expect("refresh success should append");
    let mut expected_refresh_at = refreshed.observed_at.clone();
    let refreshed_activity = store
        .activity_times()
        .expect("refreshed activity should load")
        .remove(&created.id)
        .expect("refreshed activity should exist");
    assert_eq!(
        refreshed_activity,
        ConnectionActivityTimes {
            last_test_at: Some(expected_test_at.clone()),
            last_refresh_at: expected_refresh_at.clone(),
        }
    );

    for reason in [
        ConnectionStatusReason::RequestFailed,
        ConnectionStatusReason::EgressDenied,
        ConnectionStatusReason::SecretUnavailable,
        ConnectionStatusReason::InvalidResponse,
    ] {
        let current = store
            .get(&created.id)
            .expect("Connection should load before test failure")
            .expect("Connection should remain before test failure");
        let test_failure = store
            .append_status(
                &created.id,
                &current.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Degraded,
                    reason,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("test-lane failure should append");
        expected_test_at = test_failure
            .observed_at
            .clone()
            .expect("test-lane failure should carry an observation time");
        let test_failure_activity = store
            .activity_times()
            .expect("test-failure activity should load")
            .remove(&created.id)
            .expect("test-failure activity should exist");
        assert_eq!(
            test_failure_activity,
            ConnectionActivityTimes {
                last_test_at: Some(expected_test_at.clone()),
                last_refresh_at: expected_refresh_at.clone(),
            },
            "{reason:?} without a catalog count must update only the test lane"
        );

        let current = store
            .get(&created.id)
            .expect("Connection should load before refresh failure")
            .expect("Connection should remain before refresh failure");
        let refresh_failure = store
            .append_status(
                &created.id,
                &current.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Degraded,
                    reason,
                    latency_ms: None,
                    catalog_age_secs: Some(0),
                    catalog_entry_count: Some(0),
                },
            )
            .expect("refresh-lane failure should append");
        expected_refresh_at = refresh_failure.observed_at.clone();
        let refresh_failure_activity = store
            .activity_times()
            .expect("refresh-failure activity should load")
            .remove(&created.id)
            .expect("refresh-failure activity should exist");
        assert_eq!(
            refresh_failure_activity,
            ConnectionActivityTimes {
                last_test_at: Some(expected_test_at.clone()),
                last_refresh_at: expected_refresh_at.clone(),
            },
            "{reason:?} with a catalog count must update only the refresh lane"
        );
    }

    let before_replace = ConnectionActivityTimes {
        last_test_at: Some(expected_test_at),
        last_refresh_at: expected_refresh_at,
    };
    let current = store
        .get(&created.id)
        .expect("Connection should load before replacement")
        .expect("Connection should remain before replacement");
    let mut replacement = current.write.clone();
    replacement.display_name = "Managed MCP after edit".to_owned();
    store
        .replace(&created.id, &current.etag(), replacement)
        .expect("Connection replacement should succeed");
    assert!(
        store
            .latest_status(&created.id)
            .expect("latest status should load after replacement")
            .is_none(),
        "replacement must still invalidate the revision-bound current status"
    );
    let after_replace = store
        .activity_times()
        .expect("activity should load after replacement")
        .remove(&created.id)
        .expect("activity should remain after replacement");
    assert_eq!(
        after_replace, before_replace,
        "configuration replacement must preserve both historical activity timestamps"
    );
}

#[test]
fn malformed_bounded_activity_timestamps_fail_closed_on_restart() {
    for column in ["last_test_at", "last_refresh_at"] {
        let (_database, path, store) =
            temporary_store(&format!("status-activity-corrupt-{column}"));
        let created = store
            .create(mcp_candidate())
            .expect("Connection should create");
        store
            .connection_guard()
            .execute(
                &format!("UPDATE connection_records SET {column} = ?1 WHERE id = ?2"),
                params!["bounded-but-not-rfc3339", created.id.as_str()],
            )
            .expect("bounded malformed timestamp fixture should persist");
        drop(store);

        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::CorruptRecord {
                id,
                reason: "invalid connection activity timestamp",
            }) if id == created.id.to_string()
        ));
    }
}

#[test]
fn bounded_status_append_rejects_expired_and_contended_locks_without_writing() {
    let (_directory, _path, store) = temporary_store("status-bounded-lock");
    let created = store.create(candidate()).expect("create should succeed");
    let update = ConnectionStatusUpdate {
        state: ConnectionOperationalState::Healthy,
        reason: ConnectionStatusReason::TestSucceeded,
        latency_ms: Some(5),
        catalog_age_secs: None,
        catalog_entry_count: None,
    };

    assert!(matches!(
        store.append_status_before(&created.id, &created.etag(), update.clone(), Instant::now(),),
        Err(ConnectionStoreError::DeadlineExceeded { .. })
    ));

    let _connection_guard = store.connection_guard();
    let started = Instant::now();
    assert!(matches!(
        store.append_status_before(
            &created.id,
            &created.etag(),
            update.clone(),
            Instant::now() + Duration::from_secs(1),
        ),
        Err(ConnectionStoreError::Busy { .. })
    ));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "in-process lock contention must fail fast"
    );
    drop(_connection_guard);
    assert!(
        store
            .latest_status(&created.id)
            .expect("latest status query should succeed")
            .is_none(),
        "rejected bounded appends must not persist a status"
    );

    let (status, updated) = store
        .append_status_before(
            &created.id,
            &created.etag(),
            update,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("bounded append should succeed once contention clears");
    assert_eq!(status.state, ConnectionOperationalState::Healthy);
    assert_eq!(
        updated.revisions.status,
        created.revisions.status + 1,
        "the committed record returned for runtime publication must carry the new status revision"
    );
}

#[test]
fn status_commit_refreshes_busy_timeout_from_current_deadline_budget() {
    let (_directory, path, store) = temporary_store("status-commit-deadline");
    {
        let connection = store.connection_guard();
        connection
            .execute_batch(
                "
                    PRAGMA wal_checkpoint(TRUNCATE);
                    PRAGMA journal_mode = DELETE;
                    CREATE TABLE commit_deadline_probe (value INTEGER NOT NULL);
                    ",
            )
            .expect("commit-deadline fixture should initialize");
    }

    let mut blocker = Connection::open(&path).expect("blocking connection should open");
    let blocking_read = blocker
        .transaction()
        .expect("blocking read transaction should begin");
    blocking_read
        .query_row("SELECT COUNT(*) FROM commit_deadline_probe", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("blocking read should acquire a shared lock");

    let mut connection = store.connection_guard();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(500);
    refresh_status_busy_timeout(&connection, &path, Some(deadline))
        .expect("initial timeout should configure");
    // What the connection was actually told to wait, read back from
    // SQLite. `busy_timeout` sets the value `PRAGMA busy_timeout`
    // reports, so the budget in force is directly observable and does
    // not have to be inferred from how long a blocked commit happened
    // to take.
    let configured_busy_timeout = |connection: &Connection| -> i64 {
        connection
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("SQLite reports the busy timeout in force")
    };
    // Essentially the whole 500ms budget: the refresh spends a sliver
    // of it computing `deadline - now`, and SQLite stores whole
    // milliseconds, so 499 is as legitimate as 500. The distinction
    // this test rests on is 500-ish versus 150-or-less, which no
    // rounding blurs.
    let initial_budget_ms = configured_busy_timeout(&connection);
    assert!(
        (450..=500).contains(&initial_budget_ms),
        "the first refresh configures the whole 500ms budget, got {initial_budget_ms}ms"
    );
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("writer transaction should begin");
    transaction
        .execute("INSERT INTO commit_deadline_probe (value) VALUES (1)", [])
        .expect("writer should reach commit while the reader holds its shared lock");

    std::thread::sleep(Duration::from_millis(350));
    refresh_status_busy_timeout(&transaction, &path, Some(deadline))
        .expect("commit timeout should use only the fresh remaining budget");
    // The property, measured directly: the budget the commit will wait
    // under is what is LEFT of the deadline, not the full initial one.
    // At least 350ms of the 500ms deadline is gone, so a refreshed
    // budget cannot exceed 150ms however loaded the machine is -- an
    // over-running sleep only makes it smaller -- while a commit that
    // reused the stale timeout would still report 500.
    //
    // This replaces timing the commit itself. That measurement was
    // still load-sensitive after b62bed9 narrowed it to the commit:
    // SQLite's busy handler returns at approximately, not exactly, the
    // budget it was given, and under a loaded suite one of its sleep
    // increments overruns -- a 150ms budget was observed blocking for
    // 441ms against a 400ms bound. The overshoot is the scheduler's,
    // not the budget's, and the budget is what this test guards.
    let refreshed_budget_ms = configured_busy_timeout(&transaction);
    assert!(
        refreshed_budget_ms <= 150,
        "commit must not reuse the stale initial 500ms busy timeout; \
             it was configured with {refreshed_budget_ms}ms"
    );
    assert!(
        refreshed_budget_ms < initial_budget_ms,
        "the refreshed budget must be smaller than the initial one \
             ({refreshed_budget_ms}ms is not below {initial_budget_ms}ms)"
    );
    let commit_error = transaction
        .commit()
        .expect_err("the blocked commit must not persist after its deadline");
    // Assert the raw lock failure rather than the mapped variant. SQLite's
    // busy handler returns at approximately -- not strictly after -- the
    // deadline it was given, so mapping against `deadline` here is a coin
    // flip between DeadlineExceeded and Busy. The mapping is covered without
    // any timing dependence by
    // `busy_errors_map_to_deadline_exceeded_only_once_the_deadline_has_passed`.
    assert!(
        matches!(
            commit_error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ),
        "the blocked commit must fail on the reader's lock"
    );
    drop(blocking_read);
    drop(connection);
    let persisted: i64 = store
        .connection_guard()
        .query_row("SELECT COUNT(*) FROM commit_deadline_probe", [], |row| {
            row.get(0)
        })
        .expect("rolled-back fixture should remain readable");
    assert_eq!(
        persisted, 0,
        "the timed-out commit must roll back synchronously"
    );
}

#[test]
fn busy_errors_map_to_deadline_exceeded_only_once_the_deadline_has_passed() {
    fn busy() -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None)
    }

    let path = std::path::Path::new("status-error-mapping");
    let now = Instant::now();

    assert!(
        matches!(
            status_sqlite_error(
                path,
                "status transaction commit",
                busy(),
                Some(
                    now.checked_sub(Duration::from_millis(1))
                        .expect("test clock should be past process start")
                ),
            ),
            ConnectionStoreError::DeadlineExceeded { .. }
        ),
        "a lock failure at or after the deadline is a deadline overrun"
    );

    assert!(
        matches!(
            status_sqlite_error(
                path,
                "status transaction commit",
                busy(),
                Some(now + Duration::from_secs(60)),
            ),
            ConnectionStoreError::Busy { .. }
        ),
        "a lock failure with budget remaining is contention, not an overrun"
    );

    assert!(
        matches!(
            status_sqlite_error(path, "status transaction commit", busy(), None),
            ConnectionStoreError::Busy { .. }
        ),
        "an unbounded caller can never see a deadline overrun"
    );
}

#[test]
fn status_history_is_safe_revisioned_and_globally_bounded() {
    let (_directory, path, store) = temporary_store("status");
    let created = store.create(candidate()).expect("create should succeed");
    let update = ConnectionStatusUpdate {
        state: ConnectionOperationalState::Healthy,
        reason: ConnectionStatusReason::TestSucceeded,
        latency_ms: Some(12),
        catalog_age_secs: Some(4),
        catalog_entry_count: Some(3),
    };
    let status = store
        .append_status(&created.id, &created.etag(), update)
        .expect("status should append");
    assert_eq!(status.latency_ms, Some(12));
    let loaded = store
        .get(&created.id)
        .expect("get should succeed")
        .expect("record should exist");
    assert_eq!(loaded.revisions.status, 1);
    let serialized =
        serde_json::to_string(&loaded.safe_summary(Some(status))).expect("should serialize");
    assert!(!serialized.contains("billing-token"));
    assert!(!serialized.contains("billing.example.test"));

    {
        let mut connection = store.connection_guard();
        let transaction = connection
            .transaction()
            .expect("history seed transaction should begin");
        for revision in
            2..=u64::try_from(MAX_STATUS_HISTORY_ROWS + 1).expect("history limit should fit u64")
        {
            transaction
                .execute(
                    r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'degraded', 'request_failed', ?3
                        )
                        "#,
                    params![
                        created.id.as_str(),
                        u64_to_i64(&created.id, revision).expect("test revision should fit SQLite"),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("history seed row should insert");
        }
        transaction
            .execute(
                "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                params![
                    i64::try_from(MAX_STATUS_HISTORY_ROWS + 1)
                        .expect("history limit should fit SQLite"),
                    created.id.as_str()
                ],
            )
            .expect("history revision should update");
        transaction
            .commit()
            .expect("history seed transaction should commit");
    }
    store
        .append_status(
            &created.id,
            &created.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(8),
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("bounded append should succeed");

    let connection = Connection::open(path).expect("database should open");
    let history_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM connection_status_history",
            [],
            |row| row.get(0),
        )
        .expect("status count should query");
    assert_eq!(
        history_count,
        i64::try_from(MAX_STATUS_HISTORY_ROWS - 1).expect("history limit should fit SQLite")
    );
    let current_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM connection_current_status",
            [],
            |row| row.get(0),
        )
        .expect("current status count should query");
    assert_eq!(current_count, 1);
}

#[test]
fn global_history_pruning_preserves_every_connections_current_status() {
    let (_directory, _path, store) = temporary_store("status-fairness");
    let quiet = store
        .create(candidate())
        .expect("quiet connection should create");
    let mut noisy_candidate = candidate();
    noisy_candidate.display_name = "Noisy API".to_owned();
    let noisy = store
        .create(noisy_candidate)
        .expect("noisy connection should create");
    let quiet_test = store
        .append_status(
            &quiet.id,
            &quiet.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(3),
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("quiet status should append");
    let quiet_test_at = quiet_test
        .observed_at
        .expect("quiet test should carry an observation time");
    let quiet_after_test = store
        .get(&quiet.id)
        .expect("quiet Connection should load")
        .expect("quiet Connection should remain");
    let quiet_refresh = store
        .append_status(
            &quiet.id,
            &quiet_after_test.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::CatalogRefreshed,
                latency_ms: Some(4),
                catalog_age_secs: Some(0),
                catalog_entry_count: Some(1),
            },
        )
        .expect("quiet refresh should append");
    let quiet_refresh_at = quiet_refresh
        .observed_at
        .expect("quiet refresh should carry an observation time");
    store
        .append_status(
            &noisy.id,
            &noisy.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Degraded,
                reason: ConnectionStatusReason::RequestFailed,
                latency_ms: None,
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("initial noisy status should append");

    {
        let mut connection = store.connection_guard();
        let transaction = connection
            .transaction()
            .expect("history seed transaction should begin");
        for revision in
            2..=u64::try_from(MAX_STATUS_HISTORY_ROWS).expect("history limit should fit u64")
        {
            transaction
                .execute(
                    r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'degraded', 'request_failed', ?3
                        )
                        "#,
                    params![
                        noisy.id.as_str(),
                        u64_to_i64(&noisy.id, revision).expect("test revision should fit SQLite"),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("noisy history row should insert");
        }
        let seeded_revision =
            i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("history limit should fit SQLite");
        transaction
            .execute(
                "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                params![seeded_revision, noisy.id.as_str()],
            )
            .expect("noisy record revision should update");
        transaction
            .execute(
                r#"
                    UPDATE connection_current_status
                    SET status_revision = ?1
                    WHERE connection_id = ?2
                    "#,
                params![seeded_revision, noisy.id.as_str()],
            )
            .expect("noisy current revision should update");
        transaction
            .commit()
            .expect("history seed transaction should commit");
    }
    store
        .append_status(
            &noisy.id,
            &noisy.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(4),
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("bounded noisy append should succeed");

    let quiet_latest = store
        .latest_status(&quiet.id)
        .expect("quiet latest query should succeed")
        .expect("quiet current status must be retained");
    assert_eq!(quiet_latest.state, ConnectionOperationalState::Healthy);
    assert_eq!(
        quiet_latest.reason,
        ConnectionStatusReason::CatalogRefreshed
    );
    assert!(
        store
            .status_history(&quiet.id, MAX_STATUS_HISTORY_ROWS)
            .expect("quiet history query should succeed")
            .is_empty(),
        "global pruning fixture must remove both quiet activity history rows"
    );
    let quiet_activity = store
        .activity_times()
        .expect("quiet activity should load")
        .remove(&quiet.id)
        .expect("quiet activity metadata must be retained");
    assert_eq!(
        quiet_activity,
        ConnectionActivityTimes {
            last_test_at: Some(quiet_test_at),
            last_refresh_at: Some(quiet_refresh_at),
        },
        "durable activity timestamps must survive global history pruning"
    );
    let connection = store.connection_guard();
    let total_status_rows: i64 = connection
        .query_row(
            r#"
                SELECT
                    (SELECT COUNT(*) FROM connection_current_status)
                    + (SELECT COUNT(*) FROM connection_status_history)
                "#,
            [],
            |row| row.get(0),
        )
        .expect("total status rows should query");
    assert_eq!(
        total_status_rows,
        i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit SQLite")
    );
}

#[test]
fn persisted_status_row_bound_is_enforced_on_restart() {
    let (_directory, path, store) = temporary_store("status-restart-limit");
    let created = store.create(candidate()).expect("create should succeed");
    store
        .append_status(
            &created.id,
            &created.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: None,
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .expect("initial status should append");
    {
        let mut connection = store.connection_guard();
        let transaction = connection
            .transaction()
            .expect("status corruption transaction should begin");
        for revision in
            2..=u64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit u64")
        {
            transaction
                .execute(
                    r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'healthy', 'test_succeeded', ?3
                        )
                        "#,
                    params![
                        created.id.as_str(),
                        u64_to_i64(&created.id, revision).expect("test revision should fit SQLite"),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("over-limit status row should insert");
        }
        let latest_revision =
            i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit SQLite");
        transaction
            .execute(
                "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                params![latest_revision, created.id.as_str()],
            )
            .expect("record status revision should update");
        transaction
                .execute(
                    "UPDATE connection_current_status SET status_revision = ?1 WHERE connection_id = ?2",
                    params![latest_revision, created.id.as_str()],
                )
                .expect("current status revision should update");
        transaction
            .commit()
            .expect("status corruption transaction should commit");
    }
    drop(store);

    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: MAX_STATUS_HISTORY_ROWS,
        })
    ));
}

#[test]
fn persisted_catalog_count_bound_is_enforced_on_restart() {
    let (_directory, path, store) = temporary_store("catalog-restart-limit");
    let created = store.create(candidate()).expect("create should succeed");
    store
        .append_status(
            &created.id,
            &created.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: None,
                catalog_age_secs: None,
                catalog_entry_count: Some(1),
            },
        )
        .expect("initial status should append");
    drop(store);

    let connection = Connection::open(&path).expect("database should open");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = ON;")
        .expect("test corruption pragma should enable");
    connection
            .execute(
                "UPDATE connection_current_status SET catalog_entry_count = ?1 WHERE connection_id = ?2",
                params![
                    i64::try_from(MAX_CATALOG_ENTRIES + 1)
                        .expect("catalog test count should fit SQLite"),
                    created.id.as_str()
                ],
            )
            .expect("invalid catalog count should be written for the corruption test");
    connection
        .execute_batch("PRAGMA ignore_check_constraints = OFF;")
        .expect("test corruption pragma should disable");
    drop(connection);

    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::CorruptRecord {
            reason: "current connection status is stale or invalid",
            ..
        })
    ));
}

#[test]
fn configured_managed_connection_bound_is_enforced_on_restart() {
    let (_directory, path, store) = temporary_store("record-restart-limit");
    store
        .create(candidate())
        .expect("first record should create");
    let mut second = candidate();
    second.display_name = "Second API".to_owned();
    store.create(second).expect("second record should create");
    drop(store);

    assert!(matches!(
        SqliteConnectionStore::open_with_maximum(path, 1),
        Err(ConnectionStoreError::LimitExceeded {
            resource: "managed connections",
            maximum: 1,
        })
    ));
}

#[test]
fn record_and_bindings_are_read_from_one_wal_snapshot() {
    let (_directory, path, first_store) = temporary_store("read-snapshot");
    let created = first_store
        .create(candidate())
        .expect("connection should create");
    let second_store = SqliteConnectionStore::open(&path).expect("second store handle should open");

    let mut first_connection = first_store.connection_guard();
    let read_transaction = first_connection
        .transaction()
        .expect("deferred read transaction should begin");
    let old_record = load_raw_by_id(&read_transaction, &path, &created.id)
        .expect("old record should load")
        .expect("old record should exist")
        .into_stored()
        .expect("old record should validate");

    let mut replacement = created.write.clone();
    replacement.authentication = ConnectionAuthentication::StaticBearer {
        secret_id: Some("billing-token-v2".to_owned()),
    };
    let replaced = second_store
        .replace(&created.id, &created.etag(), replacement)
        .expect("concurrent replacement should commit in WAL mode");
    validate_record_bindings(&read_transaction, &path, &old_record)
        .expect("binding validation must use the original read snapshot");
    read_transaction
        .commit()
        .expect("read transaction should commit");
    drop(first_connection);

    assert_eq!(
        first_store
            .get(&created.id)
            .expect("subsequent get should succeed")
            .expect("record should remain"),
        replaced
    );
}

#[test]
fn configured_path_that_cannot_be_opened_fails_closed() {
    let directory = std::env::temp_dir().join(format!(
        "greengateway-connection-directory-{}",
        Uuid::new_v4()
    ));
    fs::create_dir(&directory).expect("temp directory should create");
    let error = match SqliteConnectionStore::open(&directory) {
        Ok(_) => panic!("opening a directory as SQLite must fail"),
        Err(error) => error,
    };
    fs::remove_dir(&directory).expect("empty temp directory should remove");
    assert!(matches!(
        error,
        ConnectionStoreError::Open { .. } | ConnectionStoreError::Sqlite { .. }
    ));
}

#[test]
fn corrupt_persisted_document_fails_closed_and_is_not_returned() {
    let (_directory, path, store) = temporary_store("corrupt");
    let created = store.create(candidate()).expect("create should succeed");
    drop(store);
    let connection = Connection::open(&path).expect("database should open");
    connection
        .execute(
            "UPDATE connection_records SET spec_json = ?1 WHERE id = ?2",
            params![r#"{"enabled":true}"#, created.id.as_str()],
        )
        .expect("test corruption should write");
    drop(connection);

    assert!(matches!(
        SqliteConnectionStore::open(&path),
        Err(ConnectionStoreError::CorruptRecord { .. })
    ));
    assert!(fs::metadata(path).is_ok());
}

#[test]
fn mismatched_persisted_binding_fails_closed() {
    let (_directory, path, store) = temporary_store("corrupt-binding");
    let created = store.create(candidate()).expect("create should succeed");
    {
        let connection = store.connection_guard();
        connection
            .execute(
                r#"
                    UPDATE connection_credential_bindings
                    SET secret_id = 'different-secret'
                    WHERE connection_id = ?1
                    "#,
                params![created.id.as_str()],
            )
            .expect("test corruption should write");
    }

    drop(store);
    assert!(matches!(
        SqliteConnectionStore::open(path),
        Err(ConnectionStoreError::CorruptRecord {
            reason: "credential binding rows do not match the stored connection document",
            ..
        })
    ));
}
