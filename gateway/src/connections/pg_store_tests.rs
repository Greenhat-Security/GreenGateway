use super::*;
use crate::connections::status::ConnectionOperationalState;
use crate::storage::postgres::PostgresFoundation;
use serde_json::json;

fn locator() -> Option<String> {
    let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
    let file = std::env::var(&key).ok()?;
    if file.trim().is_empty() {
        return None;
    }
    let contents = std::fs::read_to_string(file).ok()?;
    let trimmed = contents.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

struct DsnFile {
    path: String,
    directory: std::path::PathBuf,
}

impl Drop for DsnFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn write_dsn_file(dsn: &str) -> DsnFile {
    let directory =
        std::env::temp_dir().join(format!("greengateway-conn-pg-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&directory).expect("temp directory should create");
    let path = directory.join("database-url");
    std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("DSN permissions should set");
    }
    DsnFile {
        path: path.display().to_string(),
        directory,
    }
}

struct TestDatabase {
    dsn: String,
    admin_dsn: String,
    name: String,
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let admin_dsn = self.admin_dsn.clone();
        let name = self.name.clone();
        std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async move {
                let Ok((client, connection)) =
                    tokio_postgres::connect(&admin_dsn, tokio_postgres::NoTls).await
                else {
                    return;
                };
                let connection = tokio::spawn(connection);
                let _ = client
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await;
                let _ = connection.await;
            });
        });
    }
}

async fn create_test_database(admin_dsn: &str) -> TestDatabase {
    let name = format!("ggw_conn_test_{}", uuid::Uuid::new_v4().simple());
    let (client, connection) = tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls)
        .await
        .expect("admin connection");
    let connection_task = tokio::spawn(connection);
    client
        .batch_execute(&format!("CREATE DATABASE {name}"))
        .await
        .expect("test database should create");
    drop(client);
    let _ = connection_task.await;
    let database_start = admin_dsn
        .rfind('/')
        .expect("locator DSN has a database path segment");
    let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
    TestDatabase {
        dsn,
        admin_dsn: admin_dsn.to_owned(),
        name,
    }
}

async fn migrated_store(
    dsn: &str,
    maximum: usize,
) -> (PostgresConnectionStore, deadpool_postgres::Pool) {
    let dsn_file = write_dsn_file(dsn);
    let mut config = crate::config::Config::test_defaults();
    config.state_backend = crate::config::StateBackend::Postgres;
    config.deployment_id = Some("deploy-conn-pg".to_owned());
    config.database.url_file = Some(dsn_file.path.clone());
    config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
    let foundation = PostgresFoundation::establish(&config)
        .await
        .expect("test database should establish");
    crate::storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
        .await
        .expect("schema should migrate");
    let pool = foundation.pool().clone();
    (
        PostgresConnectionStore::new(pool.clone(), maximum)
            .expect("the test maximum is within the hard ceiling"),
        pool,
    )
}

fn http_candidate(display_name: &str) -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": display_name,
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

async fn count(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
    pool.get()
        .await
        .expect("count checkout")
        .query_one(sql, &[])
        .await
        .expect("count query")
        .get(0)
}

async fn wait_for_advisory_waiters(pool: &deadpool_postgres::Pool, expected: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let client = pool.get().await.expect("advisory waiter probe checkout");
                let waiting: i64 = client
                    .query_one(
                        r#"
                        SELECT COUNT(*)
                        FROM pg_locks
                        WHERE locktype = 'advisory'
                          AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                          AND NOT granted
                        "#,
                        &[],
                    )
                    .await
                    .expect("advisory waiter probe")
                    .get(0);
                if waiting >= expected {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {expected} advisory-lock waiters"));
}

fn policy_with_tools(id: &str, tool_names: &[&str]) -> crate::rbac::policy::Policy {
    let tools = tool_names
        .iter()
        .map(|name| ((*name).to_owned(), json!({})))
        .collect::<serde_json::Map<_, _>>();
    crate::rbac::policy::Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "id": id,
        "default_action": "deny",
        "tools": tools
    }))
    .expect("policy race fixture should validate")
}

/// An etag that cannot match any live record: fabricated revisions no
/// committed write could produce.
fn fabricated_stale_etag(id: &ConnectionId) -> ConnectionEtag {
    ConnectionEtag::for_record(
        id,
        &ConnectionRevisions {
            connection: 999,
            credential: 999,
            tls: 999,
            discovery: 999,
            status: 999,
        },
    )
}

#[tokio::test]
async fn records_create_replace_delete_with_cas_and_shared_state_bumps() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;

    let security_before = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    let state_before = store.state_revision().await.expect("state revision");

    // Create: revision-1 record, one binding row (the bearer secret),
    // one immutable document version, one outbox row identifying the
    // connection, and both revision counters advanced.
    let created = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("create should commit");
    assert_eq!(created.revisions.connection, 1);
    assert_eq!(created.revisions.credential, 1, "a secret is bound");
    let stored = store.get(&created.id).await.expect("get").expect("exists");
    assert_eq!(stored.write.display_name, "Billing API");
    assert_eq!(store.count().await.expect("count"), 1);
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_credential_bindings"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_documents"
        )
        .await,
        1,
        "the create wrote the immutable version"
    );
    assert_eq!(
        count(
            &pool,
            &format!(
                "SELECT COUNT(*) FROM greengateway.security_outbox \
                     WHERE resource_type = 'connection' AND resource_id = '{}'",
                created.id.as_str()
            )
        )
        .await,
        1
    );
    let security_after = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    assert!(
        security_after > security_before,
        "the security revision advanced"
    );
    assert!(
        store.state_revision().await.expect("state") > state_before,
        "the connections high-water mark advanced"
    );

    // Replace with the current etag wins; a fabricated stale etag
    // loses with Conflict and writes nothing.
    let stale_etag = fabricated_stale_etag(&created.id);
    // The etag of the CURRENT record is the precondition; use the
    // current one to win and a fabricated stale one to lose.
    let current_etag = store
        .get(&created.id)
        .await
        .expect("get")
        .expect("exists")
        .etag();
    let winner_candidate = http_candidate("Renamed API");
    let replaced = store
        .replace(&created.id, &current_etag, winner_candidate, "op-3")
        .await
        .expect("replace should win");
    assert_eq!(replaced.revisions.connection, 2);
    assert_eq!(
        replaced.revisions.credential, 1,
        "the authentication axis is unchanged"
    );

    // An identical candidate is a committed no-op.
    let identical_etag = replaced.etag();
    let no_op = store
        .replace(
            &created.id,
            &identical_etag,
            http_candidate("Renamed API"),
            "op-4",
        )
        .await
        .expect("identical replace is a no-op");
    assert_eq!(
        no_op.etag(),
        identical_etag,
        "the no-op returns the record unchanged"
    );

    // A stale etag loses with Conflict and writes nothing.
    let lost = store
        .replace(&created.id, &stale_etag, http_candidate("Loser"), "op-5")
        .await
        .expect_err("the stale etag must lose");
    assert!(
        matches!(lost, ConnectionStoreError::Conflict { .. }),
        "{lost}"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_documents"
        )
        .await,
        2,
        "only the create and the winning replace wrote versions"
    );

    // Delete: a dependency row blocks it; without one it cascades.
    let etag = store
        .get(&created.id)
        .await
        .expect("get")
        .expect("exists")
        .etag();
    pool.get()
        .await
        .expect("dep checkout")
        .execute(
            "INSERT INTO greengateway.connection_dependencies \
                 (connection_id, consumer_kind, consumer_id, created_at) \
                 VALUES ($1::text::uuid, 'proxy_route', 'route-a', '2026-01-01T00:00:00Z')",
            &[&created.id.as_str()],
        )
        .await
        .expect("dependency insert");
    let blocked = store
        .delete(&created.id, &etag, "op-6")
        .await
        .expect_err("a referenced connection must not delete");
    assert!(
        matches!(blocked, ConnectionStoreError::DependencyConflict { .. }),
        "{blocked}"
    );
    pool.get()
        .await
        .expect("dep checkout")
        .execute("DELETE FROM greengateway.connection_dependencies", &[])
        .await
        .expect("dependency cleanup");
    store
        .delete(&created.id, &etag, "op-7")
        .await
        .expect("delete should commit");
    assert_eq!(store.count().await.expect("count"), 0);
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_documents"
        )
        .await,
        0,
        "the delete cascaded through the version history"
    );
}

#[tokio::test]
async fn additional_header_bindings_round_trip_and_advance_the_credential_axis() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;

    let mut write = http_candidate("Access-fronted API");
    write.additional_headers = serde_json::from_value(json!([
        {"header_name": "CF-Access-Client-Id", "secret_id": "access-client-id"},
        {"header_name": "CF-Access-Client-Secret", "secret_id": "access-client-secret"}
    ]))
    .expect("additional headers should deserialize");
    let created = store
        .create(write, "additional-create", None)
        .await
        .expect("Connection with additional headers should create");
    assert_eq!(created.revisions.credential, 1);

    let client = pool.get().await.expect("binding checkout");
    let rows = client
        .query(
            r#"
                SELECT purpose, header_name, secret_id, binding_version
                FROM greengateway.connection_credential_bindings
                WHERE connection_id = $1::text::uuid
                ORDER BY purpose, header_name
                "#,
            &[&created.id.as_str()],
        )
        .await
        .expect("binding rows should query")
        .into_iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, i64>(3),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![
            (
                "additional_header".to_owned(),
                "cf-access-client-id".to_owned(),
                "access-client-id".to_owned(),
                1,
            ),
            (
                "additional_header".to_owned(),
                "cf-access-client-secret".to_owned(),
                "access-client-secret".to_owned(),
                1,
            ),
            (
                "http_authentication".to_owned(),
                String::new(),
                "billing-token".to_owned(),
                1,
            ),
        ]
    );
    drop(client);

    let mut replacement = created.write.clone();
    replacement.additional_headers[0].secret_id = Some("rotated-client-id".to_owned());
    let replaced = store
        .replace(
            &created.id,
            &created.etag(),
            replacement,
            "additional-replace",
        )
        .await
        .expect("Connection with additional headers should replace");
    assert_eq!(replaced.revisions.connection, 2);
    assert_eq!(replaced.revisions.credential, 2);
    assert_ne!(replaced.etag(), created.etag());
    assert_eq!(
        store
            .get(&created.id)
            .await
            .expect("Connection should load")
            .expect("Connection should remain"),
        replaced
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_credential_bindings"
        )
        .await,
        3
    );
}

#[tokio::test]
async fn concurrent_same_etag_replaces_produce_exactly_one_winner() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(http_candidate("Race Base"), "op-1", None)
        .await
        .expect("create should commit");
    let etag = created.etag();

    let store_a = PostgresConnectionStore::new(pool.clone(), 64).expect("store a");
    let store_b = PostgresConnectionStore::new(pool.clone(), 64).expect("store b");
    let (a, b) = tokio::join!(
        store_a.replace(
            &created.id,
            &etag,
            http_candidate("Replica A Wins"),
            "replica-a"
        ),
        store_b.replace(
            &created.id,
            &etag,
            http_candidate("Replica B Wins"),
            "replica-b"
        )
    );
    let winners = usize::from(a.is_ok()) + usize::from(b.is_ok());
    assert_eq!(winners, 1, "exactly one racing writer commits");
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_documents"
        )
        .await,
        2,
        "create plus exactly one winning version"
    );
}

#[tokio::test]
async fn capacity_and_binding_tamper_fail_closed() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 1).await;

    store
        .create(http_candidate("Only One"), "op-1", None)
        .await
        .expect("first create fits");
    let limited = store
        .create(http_candidate("Second"), "op-2", None)
        .await
        .expect_err("the capacity limit must hold");
    assert!(
        matches!(limited, ConnectionStoreError::LimitExceeded { .. }),
        "{limited}"
    );

    // Out-of-band binding edits are corruption: reads fail closed
    // instead of serving a record whose secret wiring disagrees.
    let created = store.list().await.expect("list").pop().expect("record");
    pool.get()
        .await
        .expect("tamper checkout")
        .execute(
            "UPDATE greengateway.connection_credential_bindings \
                 SET secret_id = 'tampered' WHERE connection_id = $1::text::uuid",
            &[&created.id.as_str()],
        )
        .await
        .expect("tamper should apply");
    let corrupt = store
        .get(&created.id)
        .await
        .expect_err("a tampered binding must fail closed");
    assert!(
        matches!(corrupt, ConnectionStoreError::CorruptRecord { .. }),
        "{corrupt}"
    );
}

/// The same shape as `http_candidate`, with the bearer secret under
/// the caller's control: changing it moves the credential axis, so
/// the derived binding row's `secret_id` *and* `binding_version` both
/// change with the record.
fn http_candidate_with_secret(display_name: &str, secret_id: &str) -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": display_name,
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": secret_id
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

/// The capacity bound is global, so the lock that makes it hold has to
/// be global too. Two replicas race the last free slot from separate
/// pools: without the `connection_state_revision` lock taken before
/// the count, both read `maximum - 1` under READ COMMITTED and both
/// commit, and the store ends up over its configured maximum.
#[tokio::test]
async fn concurrent_creates_at_capacity_produce_exactly_one_winner() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store_a, pool_a) = migrated_store(&database.dsn, 1).await;
    let (store_b, _pool_b) = migrated_store(&database.dsn, 1).await;

    let (a, b) = tokio::join!(
        store_a.create(http_candidate("Replica A"), "replica-a", None),
        store_b.create(http_candidate("Replica B"), "replica-b", None)
    );
    let winners = usize::from(a.is_ok()) + usize::from(b.is_ok());
    assert_eq!(winners, 1, "the last free slot is taken exactly once");
    let loser = match (a, b) {
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
        _ => unreachable!("exactly one winner was just asserted"),
    };
    assert!(
        matches!(
            loser,
            ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: 1,
            }
        ),
        "{loser}"
    );
    assert_eq!(
        count(
            &pool_a,
            "SELECT COUNT(*) FROM greengateway.connection_records"
        )
        .await,
        1,
        "the loser's transaction wrote nothing"
    );
    assert_eq!(
        count(
            &pool_a,
            "SELECT COUNT(*) FROM greengateway.connection_documents"
        )
        .await,
        1,
        "and appended no specification version"
    );
}

/// A record and the credential bindings it is validated against must
/// come from one instant, or a replacement committing between the two
/// reads makes a healthy record read as corrupt. The SQLite store gets
/// this from its single transaction
/// (`record_and_bindings_are_read_from_one_wal_snapshot`); here it is
/// the reader's `REPEATABLE READ` snapshot.
#[tokio::test]
async fn record_and_bindings_are_read_from_one_snapshot() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (reader, reader_pool) = migrated_store(&database.dsn, 64).await;
    let (writer, _writer_pool) = migrated_store(&database.dsn, 64).await;

    let created = reader
        .create(
            http_candidate_with_secret("Snapshot", "billing-token"),
            "op-1",
            None,
        )
        .await
        .expect("create should commit");

    // The negative control, and the reason the snapshot is needed:
    // read the record and its bindings as two autocommit statements
    // and let a replacement land between them. The record is healthy
    // and the bindings are healthy, but they describe two different
    // instants, so the comparison reports corruption.
    let client = reader_pool.get().await.expect("reader checkout");
    let stale = load_record(&client, &created.id, OPERATION_GET)
        .await
        .expect("record read")
        .expect("record exists");
    let replaced = writer
        .replace(
            &created.id,
            &stale.etag(),
            http_candidate_with_secret("Snapshot", "billing-token-v2"),
            "op-2",
        )
        .await
        .expect("the concurrent replacement should commit");
    let spurious = validate_bindings(&client, &stale)
        .await
        .expect_err("two autocommit reads see two instants");
    assert!(
        matches!(spurious, ConnectionStoreError::CorruptRecord { .. }),
        "{spurious}"
    );
    drop(client);

    // The same interleaving inside the reader's snapshot: the bindings
    // are read from the instant the record was, so the commit in
    // between is invisible and the healthy record stays healthy.
    let client = reader_pool.get().await.expect("reader checkout");
    begin_snapshot(&client, OPERATION_GET)
        .await
        .expect("the reader's snapshot should begin");
    let snapshot = load_record(&client, &created.id, OPERATION_GET)
        .await
        .expect("record read")
        .expect("record exists");
    let replaced_again = writer
        .replace(
            &created.id,
            &replaced.etag(),
            http_candidate_with_secret("Snapshot", "billing-token-v3"),
            "op-3",
        )
        .await
        .expect("the second concurrent replacement should commit");
    validate_bindings(&client, &snapshot)
        .await
        .expect("binding validation must use the record's own snapshot");
    commit(&client, OPERATION_GET)
        .await
        .expect("the read transaction should commit");
    drop(client);

    // And the public readers serve the committed state afterwards.
    let after = reader
        .get(&created.id)
        .await
        .expect("get should succeed")
        .expect("the record remains");
    assert_eq!(after.etag(), replaced_again.etag());
    assert_eq!(reader.list().await.expect("list should succeed").len(), 1);
}

/// A persisted dependency count past the bound is refused, not served:
/// the SQLite reader raises `LimitExceeded` for the same row
/// (store.rs `dependency_counts`), where saturating the conversion
/// would have skipped the bound entirely.
#[tokio::test]
async fn dependency_counts_fail_closed_above_the_dependency_bound() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(http_candidate("Counted"), "op-1", None)
        .await
        .expect("create should commit");

    let excess = i32::try_from(MAX_CONNECTION_DEPENDENCIES + 1)
        .expect("the dependency bound fits in an int4");
    pool.get()
        .await
        .expect("dependency checkout")
        .execute(
            r#"
                INSERT INTO greengateway.connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                )
                SELECT $1::text::uuid, 'proxy_route', 'route-' || series.ordinal,
                       '2026-01-01T00:00:00Z'
                FROM generate_series(1, $2::int) AS series(ordinal)
                "#,
            &[&created.id.as_str(), &excess],
        )
        .await
        .expect("out-of-band dependency rows should insert");

    let error = store
        .dependency_counts()
        .await
        .expect_err("a count past the bound must fail closed");
    assert!(
        matches!(
            error,
            ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                ..
            }
        ),
        "{error}"
    );
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
        "authentication": { "type": "none" },
        "tls": {},
        "discovery": {
            "type": "managed_mcp",
            "use_connection_authentication": false
        }
    }))
    .expect("MCP candidate should deserialize")
}

fn mcp_entry(name: &str) -> StoredMcpCatalogEntry {
    StoredMcpCatalogEntry {
        remote_tool_name: name.to_owned(),
        title: None,
        description: format!("{name} description"),
        input_schema: json!({ "type": "object", "properties": {} }),
        annotations: None,
    }
}

/// Changing a Connection's managed-catalog kind while a catalog is
/// still published must be refused, not silently applied.
///
/// The catalog's rows are attributed to the kind that produced them: an
/// MCP catalog's entries each own a `managed_tool` dependency row, and
/// the tool registry serves definitions derived from them. Letting the
/// kind change out from under those rows would leave the registry
/// advertising MCP tools for a Connection the authority now says is an
/// OpenAPI one -- tools bound to an upstream contract nothing checks
/// them against any more. The SQLite reference refuses it
/// (`store.rs`, the `managed_catalog_kind_changed` branch of `replace`)
/// and so must the authority.
///
/// Withdraw the catalog first and the same replace is allowed, which is
/// what makes this a guard rather than a permanent lock.
#[tokio::test]
async fn changing_the_catalog_kind_under_a_published_catalog_is_refused() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(mcp_candidate(), "op-1", None)
        .await
        .expect("MCP connection should create");
    store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_entry("alpha"), mcp_entry("beta")],
            &[],
            &[],
            0,
            "op-2",
        )
        .await
        .expect("catalog replace should win");
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_dependencies \
                 WHERE consumer_kind = 'managed_tool'",
        )
        .await,
        2,
        "the published catalog owns one managed-tool dependency per entry"
    );

    let current = store
        .get(&created.id)
        .await
        .expect("record read")
        .expect("record exists");
    let mut different_kind: ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Now an OpenAPI connection",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://mcp.example.test",
            "base_path": "/mcp"
        },
        "authentication": { "type": "none" },
        "tls": {},
        "discovery": {
            "type": "managed_openapi",
            "use_connection_authentication": false
        }
    }))
    .expect("OpenAPI candidate should deserialize");

    let refused = store
        .replace(&created.id, &current.etag(), different_kind.clone(), "op-3")
        .await
        .expect_err("the kind change must be refused while a catalog is published");
    assert!(
        matches!(
            refused,
            ConnectionStoreError::DependencyConflict { count: 2, .. }
        ),
        "the refusal names the managed-tool rows that block it, got {refused:?}"
    );

    // Nothing partially applied: the record, its catalog, and its
    // dependency rows are exactly as they were.
    let unchanged = store
        .get(&created.id)
        .await
        .expect("record read")
        .expect("record exists");
    assert_eq!(
        unchanged, current,
        "a refused kind change leaves the record untouched"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_mcp_catalogs",
        )
        .await,
        1,
        "the published catalog survives the refusal"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_dependencies \
                 WHERE consumer_kind = 'managed_tool'",
        )
        .await,
        2,
        "the dependency rows survive the refusal"
    );

    // Withdraw the catalog, and the same replace is now allowed: the
    // guard tracks live rows, it does not pin the kind forever.
    store
        .replace_mcp_catalog(&created.id, &unchanged.etag(), &[], &[], &[], 1, "op-4")
        .await
        .expect("emptying the catalog should win");
    let after_withdrawal = store
        .get(&created.id)
        .await
        .expect("record read")
        .expect("record exists");
    different_kind.display_name = "Now an OpenAPI connection".to_owned();
    let replaced = store
        .replace(
            &created.id,
            &after_withdrawal.etag(),
            different_kind,
            "op-5",
        )
        .await
        .expect("the kind change is allowed once no managed-tool rows remain");
    assert_eq!(
        replaced.write.kind,
        crate::connections::model::ConnectionKind::HttpApi
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_mcp_catalogs",
        )
        .await,
        0,
        "the obsolete catalog is dropped with the kind change"
    );
}

#[tokio::test]
async fn mcp_catalog_replaces_with_cas_revisions_dependencies_and_outbox() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(mcp_candidate(), "op-1", None)
        .await
        .expect("MCP connection should create");
    let etag = created.etag();

    // The first replace publishes revision 1 with the managed-tool
    // dependency per entry, and bumps the shared security revision and
    // the connections high-water mark with an outbox row naming the
    // connection.
    let security_before: i64 = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    let mut annotated_alpha = mcp_entry("alpha");
    annotated_alpha.title = Some("Alpha lookup".to_owned());
    annotated_alpha.annotations = Some(crate::tools::definitions::ToolAnnotations {
        read_only_hint: Some(true),
        open_world_hint: Some(false),
        ..crate::tools::definitions::ToolAnnotations::default()
    });
    let catalog = store
        .replace_mcp_catalog(
            &created.id,
            &etag,
            &[annotated_alpha.clone(), mcp_entry("beta")],
            &[],
            &[],
            0,
            "op-2",
        )
        .await
        .expect("catalog replace should win");
    assert_eq!(catalog.catalog_revision, 1);
    assert_eq!(catalog.entries.len(), 2);
    assert_eq!(catalog.entries[0], annotated_alpha);
    let loaded = store
        .mcp_catalog(&created.id)
        .await
        .expect("catalog read")
        .expect("catalog exists");
    assert_eq!(loaded, catalog);
    assert_eq!(
        store.mcp_catalogs().await.expect("list").len(),
        1,
        "the listing loads every catalog"
    );
    let security_after: i64 = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    assert!(
        security_after > security_before,
        "catalog replaces bump the shared revision"
    );
    assert!(
        store.state_revision().await.expect("state") > 0,
        "the connections high-water mark advanced"
    );
    let dependencies = store.dependencies(&created.id).await.expect("dependencies");
    assert_eq!(
        dependencies.len(),
        2,
        "one managed-tool dependency per entry"
    );
    assert!(dependencies
        .iter()
        .all(|dep| dep.kind == ConnectionDependencyKind::ManagedTool));

    // A stale CONNECTION etag loses with Conflict and leaves the
    // catalog untouched. Catalog replaces do not change the record's
    // etag (refresh loops rely on that), so staleness comes from a
    // record replacement: rename the connection, then present the
    // pre-rename etag.
    let mut renamed = mcp_candidate();
    renamed.display_name = "Renamed MCP".to_owned();
    let fresh_record_etag = store
        .replace(&created.id, &etag, renamed, "op-3")
        .await
        .expect("record replace should win")
        .etag();
    let stale = store
        .replace_mcp_catalog(
            &created.id,
            &etag,
            &[mcp_entry("gamma")],
            &[],
            &[],
            1,
            "op-4",
        )
        .await
        .expect_err("the stale connection etag must lose");
    assert!(
        matches!(stale, ConnectionStoreError::Conflict { .. }),
        "{stale}"
    );
    assert_eq!(
        store
            .mcp_catalog(&created.id)
            .await
            .expect("catalog read")
            .expect("exists")
            .entries
            .len(),
        2
    );

    // The record's new etag wins; the managed-tool dependencies are
    // REPLACED (not accumulated) and the catalog revision increments.
    let second = store
        .replace_mcp_catalog(
            &created.id,
            &fresh_record_etag,
            &[mcp_entry("alpha"), mcp_entry("beta"), mcp_entry("delta")],
            &[],
            &[],
            1,
            "op-5",
        )
        .await
        .expect("the fresh etag should win");
    assert_eq!(second.catalog_revision, 2);
    let dependencies = store.dependencies(&created.id).await.expect("dependencies");
    assert_eq!(dependencies.len(), 3, "dependencies follow the new catalog");
}

/// The retained half of the MCP catalog byte budget must measure the
/// same three tables the candidate half does (`validate_mcp_catalog`'s
/// `stored_bytes`). Summing entries alone made every stored resource
/// and resource template free, so the two halves of the comparison
/// described different quantities.
/// Two replicas refresh from the same prior catalog. The connection
/// ETag does not move on a catalog replacement, so only the catalog's
/// own revision can tell the second, older discovery result from a
/// legitimate follow-on refresh. Without this CAS the slower, older
/// result would commit last and replace the newer catalog.
#[tokio::test]
async fn a_stale_catalog_revision_is_refused_even_under_a_fresh_connection_etag() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, _pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(mcp_candidate(), "op-1", None)
        .await
        .expect("MCP connection should create");

    // Both replicas observed "no catalog yet" (revision 0).
    let first = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_entry("alpha")],
            &[],
            &[],
            0,
            "replica-a",
        )
        .await
        .expect("the first discovery commits");
    assert_eq!(first.catalog_revision, 1);

    // The second replica's discovery was slower. Its connection ETag is
    // still current (catalog replacements do not move it), so only the
    // catalog revision it observed can stop it.
    let stale = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_entry("older-view")],
            &[],
            &[],
            0,
            "replica-b",
        )
        .await
        .expect_err("a discovery from a superseded catalog must be refused");
    assert!(
        matches!(stale, ConnectionStoreError::Conflict { .. }),
        "the refusal is a conflict, got {stale}"
    );
    let live = store
        .mcp_catalog(&created.id)
        .await
        .expect("catalog read")
        .expect("catalog exists");
    assert_eq!(live.catalog_revision, 1);
    assert_eq!(
        live.entries[0].remote_tool_name, "alpha",
        "the newer catalog stays live"
    );

    // A refresh that observed revision 1 is the legitimate follow-on.
    let next = store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            &[mcp_entry("beta")],
            &[],
            &[],
            1,
            "replica-b",
        )
        .await
        .expect("a refresh from the live catalog commits");
    assert_eq!(next.catalog_revision, 2);
}

/// Two replicas create under the same collection `If-Match`. Each passed
/// its own process-local check (both snapshots were empty), so only the
/// authority can decide: under the singleton lock it re-derives the
/// collection ETag from its records and refuses the second create.
/// Without this, both inserts succeed and the caller's precondition is
/// decoration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_creates_under_one_collection_etag_produce_exactly_one_winner() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (replica_a, _pool_a) = migrated_store(&database.dsn, 64).await;
    let (replica_b, _pool_b) = migrated_store(&database.dsn, 64).await;
    let replica_a = std::sync::Arc::new(replica_a);
    let replica_b = std::sync::Arc::new(replica_b);

    // The derivation the control plane would supply: here, the sorted
    // ids joined, which is enough to change the moment a row lands.
    fn derive(records: &BTreeMap<ConnectionId, StoredConnection>) -> String {
        if records.is_empty() {
            "empty".to_owned()
        } else {
            records
                .keys()
                .map(ConnectionId::as_str)
                .collect::<Vec<_>>()
                .join(",")
        }
    }
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let create_on = |store: std::sync::Arc<PostgresConnectionStore>, name: &'static str| {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            store
                .create(
                    http_candidate(name),
                    "op",
                    Some(super::super::store::CollectionCheck {
                        expected_etag: "empty",
                        compute: &derive,
                    }),
                )
                .await
        })
    };
    let (first, second) = tokio::join!(
        create_on(replica_a.clone(), "Replica A"),
        create_on(replica_b.clone(), "Replica B")
    );
    let outcomes = [first.expect("task"), second.expect("task")];
    let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(
        winners, 1,
        "exactly one create wins the collection precondition"
    );
    let loser = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .expect("one create loses");
    assert!(
        matches!(loser, ConnectionStoreError::CollectionConflict { current } if current != "empty"),
        "the loser is told the collection moved, got {loser}"
    );
    assert_eq!(
        replica_a.count().await.expect("count"),
        1,
        "the loser wrote nothing"
    );
}

#[tokio::test]
async fn retained_mcp_catalog_bytes_charge_entries_resources_and_templates() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(mcp_candidate(), "op-1", None)
        .await
        .expect("MCP connection should create");

    let entry = mcp_entry("alpha");
    let resource = StoredMcpResource {
        uri: "res://alpha".to_owned(),
        name: "alpha".to_owned(),
        title: Some("Alpha".to_owned()),
        description: None,
        mime_type: Some("text/plain".to_owned()),
        size: Some(12),
    };
    let template = StoredMcpResourceTemplate {
        uri_template: "res://alpha/{id}".to_owned(),
        name: "alpha-template".to_owned(),
        title: None,
        description: Some("templated alpha".to_owned()),
        mime_type: None,
    };
    store
        .replace_mcp_catalog(
            &created.id,
            &created.etag(),
            std::slice::from_ref(&entry),
            std::slice::from_ref(&resource),
            std::slice::from_ref(&template),
            0,
            "op-2",
        )
        .await
        .expect("catalog replace should win");

    fn optional_len(value: &Option<String>) -> usize {
        value.as_ref().map_or(0, String::len)
    }
    let encoded_schema =
        serde_json::to_string(&entry.input_schema).expect("entry schema should encode");
    let entry_bytes = entry.remote_tool_name.len() + entry.description.len() + encoded_schema.len();
    let resource_bytes = resource.uri.len()
        + resource.name.len()
        + optional_len(&resource.title)
        + optional_len(&resource.description)
        + optional_len(&resource.mime_type)
        + 8;
    let template_bytes = template.uri_template.len()
        + template.name.len()
        + optional_len(&template.title)
        + optional_len(&template.description)
        + optional_len(&template.mime_type);

    let client = pool.get().await.expect("pooled client");
    let retained = mcp_catalog_bytes(&client, None, "test retained bytes")
        .await
        .expect("retained byte count should read");
    assert_eq!(
            retained,
            entry_bytes + resource_bytes + template_bytes,
            "the retained sum charges entries, resources AND resource templates,              exactly as store.rs mcp_catalog_bytes does"
        );
    assert!(
        retained > entry_bytes,
        "resources and templates are not free: summing entries alone under-counts by {}",
        resource_bytes + template_bytes
    );

    // The bytes are the ones serde_json wrote, not a jsonb rendering:
    // the schema column is text, so this is byte-identical to SQLite.
    let stored_schema_bytes: i64 = client
            .query_one(
                // octet_length is int4; the sum above is int8 because SUM
                // widens. Cast so both read back as the same Rust type.
                "SELECT octet_length(input_schema_json)::bigint                  FROM greengateway.connection_mcp_catalog_entries",
                &[],
            )
            .await
            .expect("stored schema length should read")
            .get(0);
    assert_eq!(
        usize::try_from(stored_schema_bytes).expect("length fits"),
        encoded_schema.len(),
        "the persisted schema is verbatim, so both stores count the same bytes"
    );

    // The replacement preflight excludes the connection it is about to
    // rewrite, so the only stored catalog contributes nothing.
    let excluded = mcp_catalog_bytes(&client, Some(&created.id), "test retained bytes")
        .await
        .expect("excluding byte count should read");
    assert_eq!(
        excluded, 0,
        "the connection being replaced is excluded from all three tables"
    );
}

fn openapi_entry(tool_name: &str) -> StoredOpenApiCatalogEntry {
    StoredOpenApiCatalogEntry {
        tool_name: tool_name.to_owned(),
        operation_id: Some("listInvoices".to_owned()),
        selected_scheme_names: vec![],
        definition: json!({
            "name": tool_name,
            "description": "Lists invoices.",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "upstream": {
                "method": "GET",
                "path_template": "/v1/invoices",
                "body": { "mode": "whole_args_json" }
            }
        }),
    }
}

/// The PostgreSQL authority must make an overlay and its compiled
/// catalog one durable unit. A stale overlay precondition rolls back
/// all catalog work, a successful source-plan change prunes enum LKG
/// rows in that same unit, and a fresh store sees the exact document
/// and report bytes needed to rebuild runtime plans after restart.
#[tokio::test]
async fn openapi_overlay_catalog_cas_prune_and_restart_are_atomic() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let api = store
        .create(http_candidate("Overlay API"), "overlay-op-1", None)
        .await
        .expect("connection should create");
    let digest = reservation_spec_digest();
    let first_document = r#"{"schema_version":"0.1.0","tools":{}}"#;
    let first_reports = r#"{"schema_version":"0.1.0","sources":[{"id":"regions","kind":"enum","state":"fresh","item_count":2}]}"#;
    let first = store
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("overlay_first")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: first_document.to_owned(),
                source_reports_json: first_reports.to_owned(),
                expected_overlay_revision: 0,
            }),
            1,
            "overlay-op-2",
            &[],
        )
        .await
        .expect("overlay and catalog should publish together");
    assert_eq!((first.catalog_revision, first.overlay_revision), (1, 1));

    let source_digest = "a".repeat(64);
    let credential_generation_digest = "b".repeat(64);
    let values_json = r#"{"version":1,"values":["na","eu"],"labels":["North America","Europe"]}"#;
    let resolved_at = "2026-09-03T00:00:00Z";
    let client = pool.get().await.expect("enum seed checkout");
    client
        .execute(
            r#"
                INSERT INTO greengateway.connection_enum_source_values (
                    connection_id, source_id, overlay_revision, source_digest,
                    values_revision, connection_revision, credential_revision,
                    credential_generation_digest, values_json, resolved_at
                ) VALUES ($1::text::uuid, 'regions', 1, $2, 1, 1, 1, $3, $4, $5)
                "#,
            &[
                &api.id.as_str(),
                &source_digest,
                &credential_generation_digest,
                &values_json,
                &resolved_at,
            ],
        )
        .await
        .expect("future enum LKG row should seed");
    let stored_credential_generation_digest: Option<String> = client
        .query_one(
            "SELECT credential_generation_digest \
                 FROM greengateway.connection_enum_source_values \
                 WHERE connection_id = $1::text::uuid AND source_id = 'regions'",
            &[&api.id.as_str()],
        )
        .await
        .expect("credential generation digest should read")
        .get(0);
    assert_eq!(
        stored_credential_generation_digest.as_deref(),
        Some(credential_generation_digest.as_str())
    );
    drop(client);

    let seeded = store
        .enum_source_values_for_connection(&api.id)
        .await
        .expect("typed enum LKG read should succeed");
    assert_eq!(seeded.len(), 1);
    assert_eq!(seeded[0].values, vec![json!("na"), json!("eu")]);
    let replacement = StoredEnumSourceValueWrite {
        connection_id: api.id.clone(),
        source_id: "regions".to_owned(),
        overlay_revision: 1,
        source_digest: source_digest.clone(),
        expected_values_revision: 1,
        connection_revision: api.revisions.connection,
        credential_revision: api.revisions.credential,
        credential_generation_digest: Some(credential_generation_digest.clone()),
        values: vec![json!("apac"), json!(true)],
        labels: None,
        resolved_at: "2026-09-03T00:01:00Z".to_owned(),
    };
    let replaced = store
        .replace_enum_source_value(&replacement, 1)
        .await
        .expect("exact PostgreSQL enum CAS should publish");
    assert_eq!(replaced.values_revision, 2);
    assert_eq!(replaced.values, replacement.values);
    assert!(matches!(
        store.replace_enum_source_value(&replacement, 1).await,
        Err(ConnectionStoreError::EnumSourceConflict {
            current_values_revision: 2,
            ..
        })
    ));

    let stale = store
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            first.spec_revision,
            first.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("must_not_commit")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: first_document.to_owned(),
                source_reports_json: first_reports.to_owned(),
                expected_overlay_revision: 0,
            }),
            1,
            "overlay-stale",
            &[],
        )
        .await
        .expect_err("stale overlay revision must reject the transaction");
    assert!(matches!(
        stale,
        ConnectionStoreError::OverlayConflict {
            current_catalog_revision: 1,
            current_overlay_revision: 1,
            ..
        }
    ));
    let after_stale = store
        .openapi_catalog(&api.id)
        .await
        .expect("catalog after stale CAS")
        .expect("catalog remains");
    assert_eq!(after_stale, first, "catalog replacement rolled back");
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_enum_source_values",
        )
        .await,
        1,
        "enum prune rolled back with the rejected catalog"
    );

    let second_document =
        r#"{"schema_version":"0.1.0","tools":{},"defaults":{"body_mode":"fields"}}"#;
    let second_reports = r#"{"schema_version":"0.1.0","sources":[{"id":"regions","kind":"enum","state":"last_known_good","item_count":2,"resolved_at":"2026-09-03T00:00:00Z"}]}"#;
    let first_overlay = store
        .openapi_overlay(&api.id)
        .await
        .expect("overlay before injected failure")
        .expect("first overlay remains");
    pool.get()
        .await
        .expect("failure trigger checkout")
        .batch_execute(
            r#"
                CREATE FUNCTION greengateway.fail_openapi_overlay_update()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'injected overlay failure';
                END;
                $$;
                CREATE TRIGGER fail_openapi_overlay_update
                BEFORE UPDATE ON greengateway.connection_openapi_overlays
                FOR EACH ROW EXECUTE FUNCTION greengateway.fail_openapi_overlay_update();
                "#,
        )
        .await
        .expect("failure trigger should install");
    store
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            first.spec_revision,
            first.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("must_roll_back")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: second_document.to_owned(),
                source_reports_json: second_reports.to_owned(),
                expected_overlay_revision: 1,
            }),
            2,
            "overlay-injected-failure",
            &[],
        )
        .await
        .expect_err("a failure after prune/catalog work must roll back the transaction");
    pool.get()
        .await
        .expect("failure trigger cleanup checkout")
        .batch_execute(
            r#"
                DROP TRIGGER fail_openapi_overlay_update
                    ON greengateway.connection_openapi_overlays;
                DROP FUNCTION greengateway.fail_openapi_overlay_update();
                "#,
        )
        .await
        .expect("failure trigger should drop");
    let (after_failure_catalog, after_failure_overlay) = store
        .openapi_catalog_with_overlay(&api.id)
        .await
        .expect("atomic pair after injected failure");
    assert_eq!(after_failure_catalog, Some(first.clone()));
    assert_eq!(after_failure_overlay, Some(first_overlay));
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_enum_source_values",
        )
        .await,
        1,
        "enum prune must roll back with the catalog and overlay"
    );
    let second = store
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            first.spec_revision,
            first.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("overlay_second")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: second_document.to_owned(),
                source_reports_json: second_reports.to_owned(),
                expected_overlay_revision: 1,
            }),
            2,
            "overlay-op-3",
            &[],
        )
        .await
        .expect("current overlay CAS should publish");
    assert_eq!((second.catalog_revision, second.overlay_revision), (2, 2));
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_enum_source_values",
        )
        .await,
        0,
        "a source-plan-changing overlay atomically prunes enum LKG rows"
    );

    let restarted = PostgresConnectionStore::new(pool.clone(), 64).expect("fresh store");
    let restarted_overlay = restarted
        .openapi_overlay(&api.id)
        .await
        .expect("restart overlay read")
        .expect("overlay survives restart");
    assert_eq!(restarted_overlay.overlay_json, second_document);
    assert_eq!(
        restarted_overlay.source_reports_json.as_deref(),
        Some(second_reports)
    );
    assert_eq!(
        restarted
            .openapi_catalog(&api.id)
            .await
            .expect("restart catalog read")
            .expect("catalog survives restart")
            .overlay_revision,
        2
    );

    let report_only_reports = r#"{"schema_version":"0.1.0","sources":[{"id":"regions","kind":"enum","state":"refreshed","item_count":2,"resolved_at":"2026-09-03T01:00:00Z"}]}"#;
    let client = pool.get().await.expect("report-only seed checkout");
    client
        .execute(
            r#"
                INSERT INTO greengateway.connection_enum_source_values (
                    connection_id, source_id, overlay_revision, source_digest,
                    values_revision, connection_revision, credential_revision,
                    credential_generation_digest, values_json, resolved_at
                ) VALUES ($1::text::uuid, 'regions', 2, $2, 2, 1, 1, $3, $4, $5)
                "#,
            &[
                &api.id.as_str(),
                &source_digest,
                &credential_generation_digest,
                &values_json,
                &resolved_at,
            ],
        )
        .await
        .expect("report-only enum LKG row should seed");
    client
        .execute(
            "UPDATE greengateway.connection_openapi_overlays \
                 SET updated_at = '2020-01-01T00:00:00Z' \
                 WHERE connection_id = $1::text::uuid",
            &[&api.id.as_str()],
        )
        .await
        .expect("report-only timestamp fixture should update");
    drop(client);
    let before_report_update = restarted
        .openapi_overlay(&api.id)
        .await
        .expect("overlay before report-only update")
        .expect("overlay remains before report-only update");
    let third = restarted
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            second.spec_revision,
            second.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("overlay_reported")],
            Some(&StoredOverlayWrite::Reports {
                source_reports_json: report_only_reports.to_owned(),
                expected_overlay_revision: 2,
            }),
            2,
            "overlay-report-only",
            &[],
        )
        .await
        .expect("report-only update should commit with the catalog");
    assert_eq!((third.catalog_revision, third.overlay_revision), (3, 2));
    let after_report_update = restarted
        .openapi_overlay(&api.id)
        .await
        .expect("overlay after report-only update")
        .expect("overlay remains after report-only update");
    assert_eq!(
        after_report_update.schema_version,
        before_report_update.schema_version
    );
    assert_eq!(
        after_report_update.overlay_json,
        before_report_update.overlay_json
    );
    assert_eq!(after_report_update.overlay_revision, 2);
    assert_eq!(
        after_report_update.source_reports_json.as_deref(),
        Some(report_only_reports)
    );
    assert_ne!(
        after_report_update.updated_at, before_report_update.updated_at,
        "report-only updates advance the stored report timestamp"
    );
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_enum_source_values",
        )
        .await,
        1,
        "report-only updates preserve enum LKG rows"
    );
    let stored_report_digest: Option<String> = pool
        .get()
        .await
        .expect("report-only digest checkout")
        .query_one(
            "SELECT credential_generation_digest \
                 FROM greengateway.connection_enum_source_values \
                 WHERE connection_id = $1::text::uuid AND source_id = 'regions'",
            &[&api.id.as_str()],
        )
        .await
        .expect("report-only credential digest should remain readable")
        .get(0);
    assert_eq!(
        stored_report_digest.as_deref(),
        Some(credential_generation_digest.as_str())
    );

    let deleted = restarted
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            third.spec_revision,
            third.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("overlay_restored")],
            Some(&StoredOverlayWrite::Delete {
                expected_overlay_revision: 2,
            }),
            0,
            "overlay-op-4",
            &[],
        )
        .await
        .expect("overlay delete should publish its restored catalog atomically");
    assert_eq!((deleted.catalog_revision, deleted.overlay_revision), (4, 0));
    assert!(restarted
        .openapi_overlay(&api.id)
        .await
        .expect("deleted overlay lookup")
        .is_none());
    assert_eq!(
        count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_enum_source_values",
        )
        .await,
        0,
        "overlay deletion prunes enum LKG rows"
    );

    let orphan_reports = restarted
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            deleted.spec_revision,
            deleted.catalog_revision,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("must_not_commit_without_overlay")],
            Some(&StoredOverlayWrite::Reports {
                source_reports_json: report_only_reports.to_owned(),
                expected_overlay_revision: 0,
            }),
            0,
            "overlay-orphan-reports",
            &[],
        )
        .await
        .expect_err("reports cannot be stored without an overlay");
    assert!(matches!(
        orphan_reports,
        ConnectionStoreError::Validation { .. }
    ));
    assert_eq!(
        restarted
            .openapi_catalog(&api.id)
            .await
            .expect("catalog after orphan report rejection")
            .expect("catalog remains after orphan report rejection"),
        deleted,
        "orphan report rejection rolls back the catalog replacement"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enum_source_initial_cas_has_one_cross_replica_winner() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store_a, pool) = migrated_store(&database.dsn, 64).await;
    let store_b = PostgresConnectionStore::new(pool.clone(), 64).expect("second replica");
    let api = store_a
        .create(http_candidate("Enum CAS API"), "enum-cas-create", None)
        .await
        .expect("connection should create");
    let digest = reservation_spec_digest();
    store_a
        .replace_openapi_catalog_with_overlay(
            &api.id,
            &api.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("enum_cas_tool")],
            Some(&StoredOverlayWrite::Put {
                schema_version: "0.1.0".to_owned(),
                overlay_json: r#"{"schema_version":"0.1.0","tools":{}}"#.to_owned(),
                source_reports_json: StoredOpenApiSourceReports::empty()
                    .canonical_json()
                    .expect("empty reports serialize"),
                expected_overlay_revision: 0,
            }),
            1,
            "enum-cas-overlay",
            &[],
        )
        .await
        .expect("overlay should publish");

    let write = |value: &str| StoredEnumSourceValueWrite {
        connection_id: api.id.clone(),
        source_id: "regions".to_owned(),
        overlay_revision: 1,
        source_digest: "a".repeat(64),
        expected_values_revision: 0,
        connection_revision: api.revisions.connection,
        credential_revision: api.revisions.credential,
        credential_generation_digest: Some("b".repeat(64)),
        values: vec![json!(value)],
        labels: None,
        resolved_at: "2026-09-03T00:00:00Z".to_owned(),
    };
    let a_write = write("replica-a");
    let b_write = write("replica-b");
    let (a, b) = tokio::join!(
        store_a.replace_enum_source_value(&a_write, 0),
        store_b.replace_enum_source_value(&b_write, 0),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let loser = match (a, b) {
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
        _ => unreachable!("one winner was asserted"),
    };
    assert!(matches!(
        loser,
        ConnectionStoreError::EnumSourceConflict {
            current_values_revision: 1,
            ..
        }
    ));
    let rows = store_a
        .enum_source_values_for_connection(&api.id)
        .await
        .expect("winner should read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].values_revision, 1);
    assert!(rows[0].values == a_write.values || rows[0].values == b_write.values);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_and_overlay_name_adoption_serialize_in_commit_order_across_replicas() {
    use crate::storage::{
        PolicyCommitPrecondition, PolicyCommitRequest, PolicyControlPlane, PostgresPolicyStore,
    };

    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let store = std::sync::Arc::new(store);
    let policy_store = std::sync::Arc::new(PostgresPolicyStore::new(pool.clone()));
    let initial_policy = policy_with_tools("initial", &[]);
    let initial_diff = json!({"action":"initialize"});
    let initial = PolicyControlPlane::commit(
        policy_store.as_ref(),
        PolicyCommitRequest {
            precondition: PolicyCommitPrecondition::Initialize,
            candidate: &initial_policy,
            actor_user_id: "installer",
            diff_summary: &initial_diff,
        },
    )
    .await
    .expect("initial policy should commit");
    let digest = reservation_spec_digest();

    // Policy queues first behind a session-held lock. PostgreSQL wakes
    // advisory waiters in queue order, so the overlay observes that
    // authoritative commit and must refuse adoption of its name.
    let policy_first_api = store
        .create(http_candidate("Policy-first API"), "race-create-a", None)
        .await
        .expect("policy-first Connection should create");
    let blocker = pool.get().await.expect("blocker checkout");
    blocker
        .execute(
            "SELECT pg_advisory_lock($1)",
            &[&*crate::storage::postgres_policy::POLICY_OVERLAY_LOCK_KEY],
        )
        .await
        .expect("session lock should acquire");
    let policy_task = {
        let policy_store = policy_store.clone();
        let expected = initial.etag.clone();
        tokio::spawn(async move {
            let candidate = policy_with_tools("policy-first", &["policy_first_name"]);
            let diff = json!({"action":"policy-first"});
            PolicyControlPlane::commit(
                policy_store.as_ref(),
                PolicyCommitRequest {
                    precondition: PolicyCommitPrecondition::Expected { etag: expected },
                    candidate: &candidate,
                    actor_user_id: "policy-replica",
                    diff_summary: &diff,
                },
            )
            .await
        })
    };
    wait_for_advisory_waiters(&pool, 1).await;
    let overlay_task = {
        let store = store.clone();
        let api = policy_first_api.clone();
        let digest = digest.clone();
        tokio::spawn(async move {
            store
                    .replace_openapi_catalog_with_overlay(
                        &api.id,
                        &api.etag(),
                        0,
                        0,
                        RESERVATION_SPEC,
                        &digest,
                        &[openapi_entry("policy_first_name")],
                        Some(&StoredOverlayWrite::Put {
                            schema_version: "0.1.0".to_owned(),
                            overlay_json: r#"{"schema_version":"0.1.0","tools":{"listInvoices":{"rename":"policy_first_name"}}}"#.to_owned(),
                            source_reports_json: r#"{"schema_version":"0.1.0","sources":[]}"#.to_owned(),
                            expected_overlay_revision: 0,
                        }),
                        1,
                        "overlay-replica",
                        &["policy_first_name".to_owned()],
                    )
                    .await
        })
    };
    wait_for_advisory_waiters(&pool, 2).await;
    blocker
        .execute(
            "SELECT pg_advisory_unlock($1)",
            &[&*crate::storage::postgres_policy::POLICY_OVERLAY_LOCK_KEY],
        )
        .await
        .expect("session lock should release");
    let policy_first = policy_task
        .await
        .expect("policy task should join")
        .expect("policy queued first should commit");
    let rejected = overlay_task
        .await
        .expect("overlay task should join")
        .expect_err("overlay queued second must observe and reject policy adoption");
    assert!(matches!(
        rejected,
        ConnectionStoreError::ToolNameConflict {
            ref tool_name,
            ref lane,
            ref owner_id,
            ..
        } if tool_name == "policy_first_name"
            && lane == "policy"
            && owner_id == "active-policy"
    ));
    assert!(store
        .openapi_catalog(&policy_first_api.id)
        .await
        .expect("policy-first catalog lookup")
        .is_none());
    assert!(store
        .openapi_overlay(&policy_first_api.id)
        .await
        .expect("policy-first overlay lookup")
        .is_none());

    // Reverse the queue. The overlay sees the older policy and adopts
    // the unclaimed name; the later policy is deliberately allowed to
    // grant that now-existing tool.
    let overlay_first_api = store
        .create(http_candidate("Overlay-first API"), "race-create-b", None)
        .await
        .expect("overlay-first Connection should create");
    blocker
        .execute(
            "SELECT pg_advisory_lock($1)",
            &[&*crate::storage::postgres_policy::POLICY_OVERLAY_LOCK_KEY],
        )
        .await
        .expect("session lock should reacquire");
    let overlay_task = {
        let store = store.clone();
        let api = overlay_first_api.clone();
        let digest = digest.clone();
        tokio::spawn(async move {
            store
                    .replace_openapi_catalog_with_overlay(
                        &api.id,
                        &api.etag(),
                        0,
                        0,
                        RESERVATION_SPEC,
                        &digest,
                        &[openapi_entry("overlay_first_name")],
                        Some(&StoredOverlayWrite::Put {
                            schema_version: "0.1.0".to_owned(),
                            overlay_json: r#"{"schema_version":"0.1.0","tools":{"listInvoices":{"rename":"overlay_first_name"}}}"#.to_owned(),
                            source_reports_json: r#"{"schema_version":"0.1.0","sources":[]}"#.to_owned(),
                            expected_overlay_revision: 0,
                        }),
                        1,
                        "overlay-replica",
                        &["overlay_first_name".to_owned()],
                    )
                    .await
        })
    };
    wait_for_advisory_waiters(&pool, 1).await;
    let policy_task = {
        let policy_store = policy_store.clone();
        let expected = policy_first.etag.clone();
        tokio::spawn(async move {
            let candidate = policy_with_tools(
                "overlay-first",
                &["policy_first_name", "overlay_first_name"],
            );
            let diff = json!({"action":"overlay-first-followed-by-policy"});
            PolicyControlPlane::commit(
                policy_store.as_ref(),
                PolicyCommitRequest {
                    precondition: PolicyCommitPrecondition::Expected { etag: expected },
                    candidate: &candidate,
                    actor_user_id: "policy-replica",
                    diff_summary: &diff,
                },
            )
            .await
        })
    };
    wait_for_advisory_waiters(&pool, 2).await;
    blocker
        .execute(
            "SELECT pg_advisory_unlock($1)",
            &[&*crate::storage::postgres_policy::POLICY_OVERLAY_LOCK_KEY],
        )
        .await
        .expect("session lock should release after reverse queue");
    let overlay_first = overlay_task
        .await
        .expect("overlay-first task should join")
        .expect("overlay queued first should commit");
    assert_eq!(
        (
            overlay_first.catalog_revision,
            overlay_first.overlay_revision
        ),
        (1, 1)
    );
    let final_policy = policy_task
        .await
        .expect("final policy task should join")
        .expect("policy queued after a valid overlay is allowed");
    assert!(final_policy.policy.tools.contains_key("overlay_first_name"));
    assert!(store
        .openapi_overlay(&overlay_first_api.id)
        .await
        .expect("overlay-first row should load")
        .is_some());
}

fn local_tools_document(tool_names: &[&str]) -> Value {
    json!({
        "schema_version": "0.1.0",
        "tools": tool_names.iter().map(|name| json!({
            "name": name,
            "description": "Echoes the provided message.",
            "input_json_schema": {
                "type": "object",
                "required": ["message"],
                "properties": { "message": { "type": "string" } },
                "additionalProperties": false
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/echo",
                "body": { "mode": "whole_args_json" }
            }
        })).collect::<Vec<_>>()
    })
}

const RESERVATION_SPEC: &str = "{\"openapi\":\"3.1.0\"}";

fn reservation_spec_digest() -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(RESERVATION_SPEC.as_bytes()))
}

fn mcp_resource(uri: &str) -> StoredMcpResource {
    StoredMcpResource {
        uri: uri.to_owned(),
        name: format!("resource {uri}"),
        title: None,
        description: None,
        mime_type: Some("text/plain".to_owned()),
        size: None,
    }
}

async fn published_mcp_catalog(store: &PostgresConnectionStore) -> StoredConnection {
    let mcp = store
        .create(mcp_candidate(), "op-1", None)
        .await
        .expect("create");
    store
        .replace_mcp_catalog(
            &mcp.id,
            &mcp.etag(),
            &[mcp_entry("alpha"), mcp_entry("beta")],
            &[mcp_resource("file:///a"), mcp_resource("file:///b")],
            &[],
            0,
            "op-2",
        )
        .await
        .expect("MCP catalog publishes");
    assert_eq!(store.mcp_catalogs().await.expect("loads").len(), 1);
    mcp
}

/// Persisted catalog rows carry ordinals 0..n; a gap left by an
/// out-of-band edit (the schema allows it) is corruption when loaded.
#[tokio::test]
async fn persisted_mcp_ordinals_shifted_out_of_band_load_as_corruption() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let mcp = published_mcp_catalog(&store).await;
    pool.get()
        .await
        .expect("client")
        .execute(
            "UPDATE greengateway.connection_mcp_catalog_entries SET ordinal = ordinal + 7 \
                 WHERE connection_id = $1::text::uuid",
            &[&mcp.id.as_str()],
        )
        .await
        .expect("tamper");
    let error = store
        .mcp_catalogs()
        .await
        .expect_err("non-contiguous persisted ordinals are corruption");
    assert!(
        matches!(error, ConnectionStoreError::CorruptRecord { .. }),
        "{error}"
    );
}

/// A persisted catalog is re-validated when loaded, as the standalone
/// loader does: a resource locator carrying a query component (nothing
/// in the schema forbids it) is a validator verdict, surfaced as
/// corruption.
#[tokio::test]
async fn persisted_mcp_resources_duplicated_out_of_band_load_as_corruption() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let mcp = published_mcp_catalog(&store).await;
    pool.get()
        .await
        .expect("client")
        .execute(
            "UPDATE greengateway.connection_mcp_catalog_resources SET uri = 'file:///b?leak=1' \
                 WHERE connection_id = $1::text::uuid AND ordinal = 1",
            &[&mcp.id.as_str()],
        )
        .await
        .expect("tamper");
    let error = store
        .mcp_catalogs()
        .await
        .expect_err("a persisted catalog the validator rejects is corruption");
    assert!(
        matches!(error, ConnectionStoreError::CorruptRecord { .. }),
        "{error}"
    );
}

/// A persisted OpenAPI entry whose stored JSON is not what this binary
/// would write for it -- here the same definition with a trailing space,
/// which still parses and still validates -- was edited out of band:
/// corruption, never a definition to activate.
#[tokio::test]
async fn persisted_openapi_entry_edited_out_of_band_loads_as_corruption() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let api = store
        .create(http_candidate("Billing API"), "op-3", None)
        .await
        .expect("create");
    store
        .replace_openapi_catalog(
            &api.id,
            &api.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &reservation_spec_digest(),
            &[openapi_entry("billing.list"), openapi_entry("billing.get")],
            "op-4",
        )
        .await
        .expect("OpenAPI catalog publishes");
    assert_eq!(store.openapi_catalogs().await.expect("loads").len(), 1);
    pool.get()
        .await
        .expect("client")
        .execute(
            "UPDATE greengateway.connection_openapi_catalog_entries \
                 SET definition_json = definition_json || ' ' \
                 WHERE connection_id = $1::text::uuid AND ordinal = 0",
            &[&api.id.as_str()],
        )
        .await
        .expect("tamper");
    let error = store
        .openapi_catalogs()
        .await
        .expect_err("a definition that is not what this binary would write is corruption");
    assert!(
        matches!(error, ConnectionStoreError::CorruptRecord { .. }),
        "{error}"
    );
}

/// A delete waits for a dependency batch the background flusher has
/// already taken but not yet written: flushes and mutations share one
/// lock, so the batch lands before the delete is judged -- and refuses
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_delete_waits_for_an_in_flight_dependency_flush() {
    use crate::connections::control_plane::{
        ClusterConnectionStoreSeed, ConnectionControlPlane, ConnectionMutationError,
    };
    use crate::connections::managed_store::{ClusterConnectionsBoot, ManagedConnectionStore};
    use crate::connections::store::ConnectionDependencyKind;
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, _pool) = migrated_store(&database.dsn, 64).await;
    let config = crate::config::Config::test_defaults();
    let control_plane = ConnectionControlPlane::from_config_with_cluster_seed(
        &config,
        Some(ClusterConnectionStoreSeed {
            store: ManagedConnectionStore::Postgres {
                store: std::sync::Arc::new(store),
                boot: std::sync::Arc::new(ClusterConnectionsBoot {
                    mcp_catalogs: Vec::new(),
                    openapi_catalogs: Vec::new(),
                    openapi_inventory_catalogs: Vec::new(),
                    openapi_overlays: Vec::new(),
                    enum_source_values: std::sync::Mutex::new(Some(Vec::new())),
                }),
            },
            records: Vec::new(),
        }),
    )
    .expect("cluster control plane should build");
    let snapshot = control_plane.runtime_snapshot();
    let record = control_plane
        .create_managed(
            snapshot.collection_etag(),
            http_candidate("Referenced API"),
            "op-1",
        )
        .await
        .expect("create");
    control_plane
        .replace_runtime_dependencies(
            ConnectionDependencyKind::ProxyRoute,
            &[(record.id.clone(), "route-1".to_owned())],
        )
        .expect("the dependency set queues");

    // The background flush takes the batch and stalls before writing.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    control_plane.set_flush_hook_for_test(std::sync::Arc::new(move || {
        let _ = released
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv();
    }));
    let flusher = {
        let control_plane = control_plane.clone();
        tokio::spawn(async move { control_plane.flush_pending_dependencies().await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let mut deleter = {
        let control_plane = control_plane.clone();
        let (id, etag) = (record.id.clone(), record.etag());
        tokio::spawn(async move { control_plane.delete_managed(&id, &etag, "op-2").await })
    };
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut deleter)
            .await
            .is_err(),
        "the delete waits for the in-flight flush"
    );
    release.send(()).expect("the flush is waiting");
    flusher
        .await
        .expect("task")
        .expect("the flush writes its batch");
    let refused = deleter
        .await
        .expect("task")
        .expect_err("the flushed guard refuses the delete");
    assert!(
        matches!(
            refused,
            ConnectionMutationError::Store(ConnectionStoreError::DependencyConflict { .. })
        ),
        "{refused}"
    );
}

/// Cluster mode queues dependency guard rows for a background flush.
/// An admin delete flushes them first, so a Connection a live route
/// references is refused even before the background task has run --
/// and a delete after the reference is gone succeeds.
#[tokio::test]
async fn delete_flushes_queued_dependency_guards_before_it_is_judged() {
    use crate::connections::control_plane::{
        ClusterConnectionStoreSeed, ConnectionControlPlane, ConnectionMutationError,
    };
    use crate::connections::managed_store::{ClusterConnectionsBoot, ManagedConnectionStore};
    use crate::connections::store::ConnectionDependencyKind;
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let config = crate::config::Config::test_defaults();
    let control_plane = ConnectionControlPlane::from_config_with_cluster_seed(
        &config,
        Some(ClusterConnectionStoreSeed {
            store: ManagedConnectionStore::Postgres {
                store: std::sync::Arc::new(store),
                boot: std::sync::Arc::new(ClusterConnectionsBoot {
                    mcp_catalogs: Vec::new(),
                    openapi_catalogs: Vec::new(),
                    openapi_inventory_catalogs: Vec::new(),
                    openapi_overlays: Vec::new(),
                    enum_source_values: std::sync::Mutex::new(Some(Vec::new())),
                }),
            },
            records: Vec::new(),
        }),
    )
    .expect("cluster control plane should build");
    let snapshot = control_plane.runtime_snapshot();
    let record = control_plane
        .create_managed(
            snapshot.collection_etag(),
            http_candidate("Referenced API"),
            "op-1",
        )
        .await
        .expect("create");

    // A route references the Connection; in cluster mode the guard row
    // is only queued.
    control_plane
        .replace_runtime_dependencies(
            ConnectionDependencyKind::ProxyRoute,
            &[(record.id.clone(), "route-1".to_owned())],
        )
        .expect("the dependency set queues");
    let client = pool.get().await.expect("client");
    let queued_only: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                &[&record.id.as_str()],
            )
            .await
            .expect("count")
            .get(0);
    assert_eq!(queued_only, 0, "nothing is written until a flush");

    let refused = control_plane
        .delete_managed(&record.id, &record.etag(), "op-2")
        .await
        .expect_err("a referenced Connection must not be deleted");
    assert!(
        matches!(
            refused,
            ConnectionMutationError::Store(ConnectionStoreError::DependencyConflict { .. })
        ),
        "{refused}"
    );
    let flushed: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                &[&record.id.as_str()],
            )
            .await
            .expect("count")
            .get(0);
    assert_eq!(
        flushed, 1,
        "the delete flushed the guard before judging itself"
    );

    // The reference goes away; the next delete flushes that too and
    // succeeds.
    control_plane
        .replace_runtime_dependencies(ConnectionDependencyKind::ProxyRoute, &[])
        .expect("the empty set queues");
    control_plane
        .delete_managed(&record.id, &record.etag(), "op-3")
        .await
        .expect("an unreferenced Connection deletes");
}

/// The authority itself refuses a tool name another lane holds, so two
/// lanes can never both commit a name that only one replica-side
/// registry could install (the review of PR 8). Replacing the holder's
/// catalog without the name frees it.
#[tokio::test]
async fn tool_names_are_reserved_across_lanes_at_the_authority() {
    use crate::storage::{PolicyCommitError, PolicyCommitPrecondition, ToolControlPlane};
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let tools = crate::storage::PostgresToolStore::new(pool.clone());
    tools.seed_empty_document().await.expect("seed");
    let digest = reservation_spec_digest();
    let api = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("create");
    store
        .replace_openapi_catalog(
            &api.id,
            &api.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("shared_tool")],
            "op-2",
        )
        .await
        .expect("the OpenAPI lane publishes first");

    // The local lane cannot take the name; nothing is written.
    let active = tools.active_tools().await.expect("active").expect("seeded");
    let refused = tools
        .commit_tools(
            PolicyCommitPrecondition::Expected {
                etag: active.etag.clone(),
            },
            &local_tools_document(&["shared_tool"]),
            "op-3",
            &json!({"action": "test"}),
        )
        .await
        .expect_err("the name is held by the OpenAPI lane");
    assert!(
        matches!(
            &refused,
            PolicyCommitError::ToolNameTaken { tool_name, lane, owner_id }
                if tool_name == "shared_tool" && lane == "openapi" && owner_id == api.id.as_str()
        ),
        "{refused}"
    );
    let unchanged = tools.active_tools().await.expect("active").expect("seeded");
    assert_eq!(
        unchanged.version, active.version,
        "a refused commit writes nothing"
    );

    // Nor can a second Connection.
    let other = store
        .create(http_candidate("Other API"), "op-4", None)
        .await
        .expect("create");
    let refused = store
        .replace_openapi_catalog(
            &other.id,
            &other.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("shared_tool")],
            "op-5",
        )
        .await
        .expect_err("the name is held by another Connection");
    assert!(
        matches!(
            &refused,
            ConnectionStoreError::ToolNameConflict { tool_name, lane, owner_id, .. }
                if tool_name == "shared_tool" && lane == "openapi" && owner_id == api.id.as_str()
        ),
        "{refused}"
    );

    // Replacing the holder's catalog without the name frees it for the
    // local lane -- and then the OpenAPI lane cannot take it back.
    let api_now = store
        .get(&api.id)
        .await
        .expect("get")
        .expect("the Connection exists");
    store
        .replace_openapi_catalog(
            &api.id,
            &api_now.etag(),
            1,
            1,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("renamed_tool")],
            "op-6",
        )
        .await
        .expect("republish without the name");
    let committed = tools
        .commit_tools(
            PolicyCommitPrecondition::Expected {
                etag: unchanged.etag.clone(),
            },
            &local_tools_document(&["shared_tool"]),
            "op-7",
            &json!({"action": "test"}),
        )
        .await
        .expect("the local lane takes the freed name");
    assert!(committed.version > unchanged.version);
    let api_now = store
        .get(&api.id)
        .await
        .expect("get")
        .expect("the Connection exists");
    let refused = store
        .replace_openapi_catalog(
            &api.id,
            &api_now.etag(),
            // The spec is unchanged, so its revision stays at 1; only
            // the catalog revision advanced.
            1,
            2,
            RESERVATION_SPEC,
            &digest,
            &[openapi_entry("shared_tool"), openapi_entry("renamed_tool")],
            "op-8",
        )
        .await
        .expect_err("the local lane holds it now");
    assert!(
        matches!(
            &refused,
            ConnectionStoreError::ToolNameConflict { tool_name, lane, owner_id, .. }
                if tool_name == "shared_tool" && lane == "local" && owner_id == "tools"
        ),
        "{refused}"
    );
    // A refused catalog publish wrote nothing: the previous catalog
    // and its reservation stand.
    let client = pool.get().await.expect("client");
    let held: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.tool_name_reservations WHERE tool_name = 'renamed_tool' AND lane = 'openapi'",
                &[],
            )
            .await
            .expect("count")
            .get(0);
    assert_eq!(held, 1);
}

/// Two lanes racing to publish one name: exactly one wins, on the
/// authority's own guarantee rather than any replica's registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_cross_lane_publishes_of_one_tool_name_produce_exactly_one_winner() {
    use crate::storage::{PolicyCommitPrecondition, ToolControlPlane};
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let store = std::sync::Arc::new(store);
    let tools = std::sync::Arc::new(crate::storage::PostgresToolStore::new(pool.clone()));
    tools.seed_empty_document().await.expect("seed");
    let digest = reservation_spec_digest();
    // The local lane must be able to win on its own terms, or a parse
    // failure would masquerade as losing every race.
    let seeded = tools.active_tools().await.expect("active").expect("seeded");
    tools
        .commit_tools(
            PolicyCommitPrecondition::Expected {
                etag: seeded.etag.clone(),
            },
            &local_tools_document(&["warmup_tool"]),
            "op-w",
            &json!({"action": "warmup"}),
        )
        .await
        .expect("the local lane commits an uncontested name");
    for round in 0..4 {
        let name = format!("raced_{round}");
        let api = store
            .create(http_candidate(&format!("API {round}")), "op-c", None)
            .await
            .expect("create");
        let active = tools.active_tools().await.expect("active").expect("seeded");
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let local = {
            let (tools, barrier, name) = (tools.clone(), barrier.clone(), name.clone());
            let etag = active.etag.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                tools
                    .commit_tools(
                        PolicyCommitPrecondition::Expected { etag },
                        &local_tools_document(&[name.as_str()]),
                        "op-l",
                        &json!({"action": "race"}),
                    )
                    .await
                    .is_ok()
            })
        };
        let openapi = {
            let (store, barrier, name, digest) =
                (store.clone(), barrier.clone(), name.clone(), digest.clone());
            let (id, etag) = (api.id.clone(), api.etag());
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .replace_openapi_catalog(
                        &id,
                        &etag,
                        0,
                        0,
                        RESERVATION_SPEC,
                        &digest,
                        &[openapi_entry(&name)],
                        "op-o",
                    )
                    .await
                    .is_ok()
            })
        };
        let (local_won, openapi_won) = tokio::join!(local, openapi);
        let winners =
            usize::from(local_won.expect("task")) + usize::from(openapi_won.expect("task"));
        assert_eq!(
            winners, 1,
            "round {round}: exactly one lane publishes '{name}'"
        );
        let client = pool.get().await.expect("client");
        let holders: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.tool_name_reservations WHERE tool_name = $1",
                &[&name],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(holders, 1, "round {round}: one reservation for '{name}'");
    }
}

#[tokio::test]
async fn openapi_catalog_triple_cas_and_status_append() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("OpenAPI connection should create");

    let entry = StoredOpenApiCatalogEntry {
        tool_name: "billing.list".to_owned(),
        operation_id: Some("listInvoices".to_owned()),
        selected_scheme_names: vec![],
        definition: json!({
            "name": "billing.list",
            "description": "Lists invoices.",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "upstream": {
                "method": "GET",
                "path_template": "/v1/invoices",
                "body": { "mode": "whole_args_json" }
            }
        }),
    };
    // Wrong digest shape is rejected before any transaction runs.
    let bad_digest = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            0,
            0,
            "{\"openapi\":\"3.1.0\"}",
            "not-a-sha256",
            std::slice::from_ref(&entry),
            "op-2",
        )
        .await
        .expect_err("an invalid digest must be rejected");
    assert!(
        matches!(bad_digest, ConnectionStoreError::Validation { .. }),
        "{bad_digest}"
    );

    let digest = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(b"{\"openapi\":\"3.1.0\"}"))
    };
    let catalog = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            0,
            0,
            "{\"openapi\":\"3.1.0\"}",
            &digest,
            std::slice::from_ref(&entry),
            "op-3",
        )
        .await
        .expect("the initial triple CAS (0,0) should win");
    assert_eq!(
        catalog.spec_revision, 1,
        "a new digest bumps the spec revision"
    );
    assert_eq!(catalog.catalog_revision, 1);
    assert_eq!(store.openapi_catalogs().await.expect("list").len(), 1);
    let inventory = store.openapi_inventory_catalogs().await.expect("inventory");
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].entries.len(), 1);

    // A stale catalog revision loses the triple CAS.
    let stale = store
        .replace_openapi_catalog(
            &created.id,
            &created.etag(),
            1,
            0,
            "{\"openapi\":\"3.1.0\"}",
            &digest,
            std::slice::from_ref(&entry),
            "op-4",
        )
        .await
        .expect_err("the stale catalog revision must lose");
    assert!(
        matches!(stale, ConnectionStoreError::Conflict { .. }),
        "{stale}"
    );

    // Status appends: etag CAS, latest reads, history, and no
    // security-revision bump (status is observational state).
    let security_before: i64 = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    let etag = store
        .get(&created.id)
        .await
        .expect("get")
        .expect("exists")
        .etag();
    let status = store
        .append_status(
            &created.id,
            &etag,
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(42),
                catalog_age_secs: None,
                catalog_entry_count: Some(1),
            },
        )
        .await
        .expect("status should append");
    assert_eq!(status.state, ConnectionOperationalState::Healthy);
    let latest = store
        .latest_status(&created.id)
        .await
        .expect("latest")
        .expect("status exists");
    assert_eq!(latest.state, ConnectionOperationalState::Healthy);
    assert_eq!(latest.latency_ms, Some(42));
    let history = store
        .status_history(&created.id, 10)
        .await
        .expect("history");
    assert_eq!(history.len(), 1);
    let security_after: i64 = count(
        &pool,
        "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
    )
    .await;
    assert_eq!(
        security_after, security_before,
        "status appends must not bump the security revision"
    );

    // Dependency replacement: kind-scoped, owner-checked.
    store
        .add_dependency(
            &created.id,
            ConnectionDependencyKind::ProxyRoute,
            "route-payments",
        )
        .await
        .expect("dependency should add");
    store
        .add_dependency(
            &created.id,
            ConnectionDependencyKind::ProxyRoute,
            "route-payments",
        )
        .await
        .expect("duplicate add is an idempotent no-op");
    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ManualTool,
            &[(created.id.clone(), "manual.echo".to_owned())],
            0,
        )
        .await
        .expect("manual-tool dependencies should replace");
    let deps = store.dependencies(&created.id).await.expect("dependencies");
    assert_eq!(
        deps.len(),
        3,
        "managed_tool from the catalog + proxy_route + manual_tool"
    );
    let missing = store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ControlPlane,
            &[(
                ConnectionId::parse("11111111-1111-1111-1111-111111111111").expect("id"),
                "ghost".to_owned(),
            )],
            0,
        )
        .await
        .expect_err("an unknown owner must be refused");
    assert!(
        matches!(missing, ConnectionStoreError::NotFound { .. }),
        "{missing}"
    );
}

/// Replicas flush derived dependency sets independently: a set from an
/// older tools document never replaces the guards a newer document
/// derived; a re-flush of the same document and a newer document do,
/// and unfenced kinds (revision 0) keep replacing as before.
#[tokio::test]
async fn a_stale_dependency_flush_never_replaces_a_newer_documents_guards() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, _pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("connection should create");
    let manual_tools = |deps: Vec<ConnectionDependency>| {
        let mut names = deps
            .into_iter()
            .filter(|dep| dep.kind == ConnectionDependencyKind::ManualTool)
            .map(|dep| dep.consumer_id)
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let dep = |name: &str| (created.id.clone(), name.to_owned());
    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ManualTool,
            &[dep("tool-at-11")],
            11,
        )
        .await
        .expect("flush at 11");
    assert_eq!(
        manual_tools(store.dependencies(&created.id).await.expect("deps")),
        vec!["tool-at-11".to_owned()]
    );
    store
        .replace_dependencies_for_kind(ConnectionDependencyKind::ManualTool, &[], 10)
        .await
        .expect("a stale flush is accepted and ignored");
    assert_eq!(
        manual_tools(store.dependencies(&created.id).await.expect("deps")),
        vec!["tool-at-11".to_owned()],
        "the older document's empty set did not erase the guard"
    );
    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ManualTool,
            &[dep("tool-at-11"), dep("tool-at-11-b")],
            11,
        )
        .await
        .expect("a re-flush of the same document replaces");
    assert_eq!(
        manual_tools(store.dependencies(&created.id).await.expect("deps")),
        vec!["tool-at-11".to_owned(), "tool-at-11-b".to_owned()]
    );
    store
        .replace_dependencies_for_kind(
            ConnectionDependencyKind::ManualTool,
            &[dep("tool-at-12")],
            12,
        )
        .await
        .expect("flush at 12");
    assert_eq!(
        manual_tools(store.dependencies(&created.id).await.expect("deps")),
        vec!["tool-at-12".to_owned()]
    );
    store
        .replace_dependencies_for_kind(ConnectionDependencyKind::ProxyRoute, &[dep("route-a")], 0)
        .await
        .expect("unfenced flush");
    store
        .replace_dependencies_for_kind(ConnectionDependencyKind::ProxyRoute, &[], 0)
        .await
        .expect("unfenced flush replaces");
    let routes = store
        .dependencies(&created.id)
        .await
        .expect("deps")
        .into_iter()
        .filter(|dep| dep.kind == ConnectionDependencyKind::ProxyRoute)
        .count();
    assert_eq!(
        routes, 0,
        "revision 0 sets replace unconditionally, as before"
    );
}

/// The durable bound on an operation ID counts characters, as the
/// validator and the SQLite backend do: 100 non-ASCII characters (400
/// bytes) publish in cluster mode too.
#[tokio::test]
async fn operation_ids_are_bounded_by_characters_not_bytes() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, _pool) = migrated_store(&database.dsn, 64).await;
    let api = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("connection should create");
    let mut entry = openapi_entry("billing.list");
    entry.operation_id = Some("\u{1F600}".repeat(100));
    store
        .replace_openapi_catalog(
            &api.id,
            &api.etag(),
            0,
            0,
            RESERVATION_SPEC,
            &reservation_spec_digest(),
            &[entry],
            "op-2",
        )
        .await
        .expect("a 100-character non-ASCII operation id publishes");
}

/// A status write moves the authority's status revision and no security
/// revision, so another replica's runtime record keeps its old one; the
/// views read the revision from the authority instead.
#[tokio::test]
async fn status_revisions_are_read_from_the_authority() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, _pool) = migrated_store(&database.dsn, 64).await;
    let created = store
        .create(http_candidate("Billing API"), "op-1", None)
        .await
        .expect("connection should create");
    let before = store
        .status_revisions(std::slice::from_ref(&created.id))
        .await
        .expect("revisions");
    assert_eq!(
        before.get(&created.id).copied(),
        Some(created.revisions.status)
    );
    let etag = store
        .get(&created.id)
        .await
        .expect("get")
        .expect("exists")
        .etag();
    store
        .append_status(
            &created.id,
            &etag,
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(42),
                catalog_age_secs: None,
                catalog_entry_count: Some(1),
            },
        )
        .await
        .expect("status should append");
    let after = store
        .status_revisions(std::slice::from_ref(&created.id))
        .await
        .expect("revisions");
    assert_eq!(
        after.get(&created.id).copied(),
        Some(created.revisions.status + 1),
        "the authority's status revision moved with the write"
    );
    let unknown = ConnectionId::parse("11111111-1111-1111-1111-111111111111").expect("id");
    assert!(!after.contains_key(&unknown));
    assert!(store.status_revisions(&[]).await.expect("empty").is_empty());
}

/// The global status-history bound covers every persisted status row,
/// and a connection's current-status row is never pruned -- so the
/// prune has to reserve one history slot per live connection. Without
/// the reservation the store over-retains by exactly the number of
/// connections and `current + history <= MAX_STATUS_HISTORY_ROWS` --
/// the bound the restart preflight asserts -- stops holding. Same
/// shape as the SQLite store's
/// `global_history_pruning_preserves_every_connections_current_status`.
#[tokio::test]
async fn global_history_pruning_preserves_every_connections_current_status() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database = create_test_database(&admin_dsn).await;
    let (store, pool) = migrated_store(&database.dsn, 64).await;
    let maximum = crate::connections::model::MAX_STATUS_HISTORY_ROWS;
    let seed_limit = i64::try_from(maximum).expect("history limit should fit PostgreSQL");

    let quiet = store
        .create(http_candidate("Quiet API"), "op-1", None)
        .await
        .expect("quiet connection should create");
    let noisy = store
        .create(http_candidate("Noisy API"), "op-2", None)
        .await
        .expect("noisy connection should create");

    // Quiet writes the two OLDEST history rows in the database and then
    // never speaks again: it is the connection a global prune would
    // otherwise evict entirely.
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
        .await
        .expect("quiet status should append");
    let quiet_test_at = quiet_test
        .observed_at
        .expect("quiet test should carry an observation time");
    let quiet_after_test = store
        .get(&quiet.id)
        .await
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
        .await
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
        .await
        .expect("initial noisy status should append");

    // Seed the noisy connection's history out of band, exactly as the
    // SQLite fixture does, so the very next append has to prune.
    let client = pool.get().await.expect("seed checkout");
    client
        .execute(
            r#"
                INSERT INTO greengateway.connection_status_history (
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at
                )
                SELECT $1::text::uuid, revision, 1, 1, 0, 1,
                       'degraded', 'request_failed', $2
                FROM generate_series(2, $3::bigint) AS revision
                "#,
            &[
                &noisy.id.as_str(),
                &utc_timestamp().expect("timestamp should format"),
                &seed_limit,
            ],
        )
        .await
        .expect("noisy history rows should seed");
    client
        .execute(
            "UPDATE greengateway.connection_records SET status_revision = $1 \
                 WHERE id = $2::text::uuid",
            &[&seed_limit, &noisy.id.as_str()],
        )
        .await
        .expect("noisy record revision should update");
    client
        .execute(
            "UPDATE greengateway.connection_current_status SET status_revision = $1 \
                 WHERE connection_id = $2::text::uuid",
            &[&seed_limit, &noisy.id.as_str()],
        )
        .await
        .expect("noisy current revision should update");
    drop(client);

    let noisy_current = store
        .get(&noisy.id)
        .await
        .expect("noisy Connection should load")
        .expect("noisy Connection should remain");
    store
        .append_status(
            &noisy.id,
            &noisy_current.etag(),
            ConnectionStatusUpdate {
                state: ConnectionOperationalState::Healthy,
                reason: ConnectionStatusReason::TestSucceeded,
                latency_ms: Some(4),
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        )
        .await
        .expect("bounded noisy append should succeed");

    // Every connection keeps its current-status row, and the prune
    // reserved a slot for each of them: the total is exactly the bound,
    // not the bound plus one row per live connection.
    let current_rows = count(
        &pool,
        "SELECT COUNT(*) FROM greengateway.connection_current_status",
    )
    .await;
    assert_eq!(current_rows, 2, "both connections keep a current status");
    let history_rows = count(
        &pool,
        "SELECT COUNT(*) FROM greengateway.connection_status_history",
    )
    .await;
    assert_eq!(
        history_rows,
        seed_limit - current_rows,
        "history is trimmed to the budget MINUS the retained current-status rows"
    );
    let total_status_rows = count(
        &pool,
        r#"
            SELECT
                (SELECT COUNT(*) FROM greengateway.connection_current_status)
                + (SELECT COUNT(*) FROM greengateway.connection_status_history)
            "#,
    )
    .await;
    assert_eq!(
        total_status_rows, seed_limit,
        "the persisted status-row bound the restart preflight asserts must hold"
    );

    // The quiet connection lost its history to the global prune but
    // kept the state that is never pruned.
    let quiet_latest = store
        .latest_status(&quiet.id)
        .await
        .expect("quiet latest query should succeed")
        .expect("quiet current status must be retained");
    assert_eq!(quiet_latest.state, ConnectionOperationalState::Healthy);
    assert_eq!(
        quiet_latest.reason,
        ConnectionStatusReason::CatalogRefreshed
    );
    assert!(
        store
            .status_history(&quiet.id, maximum)
            .await
            .expect("quiet history query should succeed")
            .is_empty(),
        "the global prune fixture removes both quiet history rows"
    );
    let quiet_activity = store
        .activity_times()
        .await
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
}
