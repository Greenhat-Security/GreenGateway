//! The contraction protocol (issue #426, requirement 4).
//!
//! The decision is unit-tested without a database. The protocol itself is
//! exercised end to end against PostgreSQL by a fixture that exists only
//! here: the shipped manifest, then an expand migration that creates a
//! legacy table and a contracting migration that drops it, numbered after
//! whatever the shipped manifest ends at. Members are written by the real
//! heartbeat with serving ranges standing in for the builds around the
//! contraction, so the fence the migrator raises is the one their next
//! heartbeat meets. No shipped object is contracted. The PostgreSQL tests
//! are gated on the test harness locator: CI sets it, a checkout without a
//! database skips.

use uuid::Uuid;

use super::*;
use crate::storage::compatibility::BINARY_CAPABILITIES;
use crate::storage::migrations::{self, MigrateError, Migration};

fn member(schema_version_max: i32, capabilities: &str) -> LiveMember {
    LiveMember {
        instance_id: Uuid::new_v4(),
        schema_version_max,
        capabilities: RecognizedCapabilities::parse(capabilities),
    }
}

fn fence(generation: i64, minimum_schema: i32, capabilities: &str) -> ContractFence {
    ContractFence {
        generation,
        minimum_schema,
        capabilities: capabilities.to_owned(),
    }
}

const FENCED: Contraction = Contraction {
    capabilities: &[Capability::OperationRequirements],
    backfill: None,
};

#[test]
fn the_raised_fence_demands_the_contracted_version_and_every_fenced_capability() {
    let live = [member(
        27,
        "operation_requirements,policy_role_descriptions",
    )];
    assert_eq!(
        decide(&ContractFence::open(), 27, &FENCED, None, &live),
        Ok(ContractionDecision {
            minimum_schema: 27,
            capabilities: BTreeSet::from([Capability::OperationRequirements]),
            raises: true,
            live_members: 1,
        }),
        "an open fence is raised to the migration's version and its capability"
    );

    // A raise never lowers anything: a higher minimum and the capabilities
    // already fenced are kept, and the contraction's are added.
    let higher = fence(4, 30, "policy_role_descriptions");
    let live = [member(
        30,
        "operation_requirements,policy_role_descriptions",
    )];
    assert_eq!(
        decide(&higher, 27, &FENCED, None, &live),
        Ok(ContractionDecision {
            minimum_schema: 30,
            capabilities: BTreeSet::from([
                Capability::OperationRequirements,
                Capability::PolicyRoleDescriptions,
            ]),
            raises: true,
            live_members: 1,
        })
    );

    // A fence that already demands all of it is left alone, so a repeated
    // decision writes nothing.
    let covering = fence(5, 30, "operation_requirements,policy_role_descriptions");
    let decision = decide(&covering, 27, &FENCED, None, &live).expect("admitted");
    assert!(!decision.raises);
    assert_eq!(decision.minimum_schema, 30);

    // With nobody live there is nobody to exclude; the raise is what keeps
    // a stopped or swept build out when it returns.
    let decision = decide(&ContractFence::open(), 27, &FENCED, None, &[]).expect("admitted");
    assert_eq!((decision.raises, decision.live_members), (true, 0));
}

#[test]
fn a_live_member_the_raised_fence_excludes_refuses_the_contraction() {
    let behind = member(26, "operation_requirements");
    let lacking = member(27, "policy_role_descriptions");
    let unbounded = member(27, &["operation_requirements"; 40].join(","));
    let eligible = member(28, "operation_requirements,future_capability");
    let live = [
        behind.clone(),
        lacking.clone(),
        unbounded.clone(),
        eligible.clone(),
    ];
    assert_eq!(
        decide(&ContractFence::open(), 27, &FENCED, None, &live),
        Err(ContractionRefusal::LiveMembersExcluded {
            excluded: vec![
                behind.instance_id,
                lacking.instance_id,
                unbounded.instance_id
            ],
            live: 4,
            minimum_schema: 27,
            capabilities: 1,
        }),
        "a serving range ending below the migration, a missing fenced capability, and an \
         advertisement outside the column's bounds each exclude; an unrecognized extra name \
         does not"
    );
    // The schema half alone decides when the contraction fences no
    // capability.
    let schema_only = Contraction {
        capabilities: &[],
        backfill: None,
    };
    assert!(matches!(
        decide(&ContractFence::open(), 27, &schema_only, None, &live),
        Err(ContractionRefusal::LiveMembersExcluded { ref excluded, .. })
            if excluded == &vec![behind.instance_id]
    ));
    // A capability fenced earlier is demanded of every live member too.
    let earlier = fence(1, 0, "policy_role_descriptions");
    assert!(matches!(
        decide(&earlier, 27, &FENCED, None, &[eligible.clone()]),
        Err(ContractionRefusal::LiveMembersExcluded { ref excluded, capabilities: 2, .. })
            if excluded == &vec![eligible.instance_id]
    ));
    assert!(decide(&ContractFence::open(), 27, &FENCED, None, &[eligible]).is_ok());
}

#[test]
fn an_unrecognized_fence_or_an_unverified_backfill_refuses() {
    assert_eq!(
        decide(
            &fence(2, 30, "future_capability,operation_requirements"),
            27,
            &FENCED,
            None,
            &[]
        ),
        Err(ContractionRefusal::FenceNotRecognized { unrecognized: 1 }),
        "a fence a newer build raised is never rewritten by this one"
    );

    let backfilled = Contraction {
        capabilities: &[],
        backfill: Some("fixture_backfill"),
    };
    for state in [
        None,
        Some(BackfillState::Missing),
        Some(BackfillState::Running),
        Some(BackfillState::Failed),
    ] {
        assert_eq!(
            decide(&ContractFence::open(), 27, &backfilled, state, &[]),
            Err(ContractionRefusal::BackfillUnverified {
                backfill: "fixture_backfill",
                state,
            }),
            "{state:?}"
        );
    }
    assert!(decide(
        &ContractFence::open(),
        27,
        &backfilled,
        Some(BackfillState::Verified),
        &[]
    )
    .is_ok());
    // A contraction that names no backfill reads none.
    assert!(decide(&ContractFence::open(), 27, &FENCED, None, &[]).is_ok());
}

#[test]
fn refusals_render_counts_and_versions_never_identifiers() {
    let excluded = Uuid::new_v4();
    let refusal = ContractionRefusal::LiveMembersExcluded {
        excluded: vec![excluded],
        live: 2,
        minimum_schema: 27,
        capabilities: 1,
    };
    assert_eq!(refusal.reason(), "live_members_excluded");
    let rendered = MigrateError::ContractionRefused {
        version: 27,
        refusal,
    }
    .to_string();
    assert!(
        rendered.contains("migration 27 contracts the schema"),
        "{rendered}"
    );
    assert!(
        rendered.contains("1 of 2 live cluster member(s)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("the contract fence was not raised"),
        "{rendered}"
    );
    assert!(rendered.contains("stays at version 26"), "{rendered}");
    assert!(rendered.contains("gateway migrate up"), "{rendered}");
    assert!(!rendered.contains(&excluded.to_string()), "{rendered}");

    let rendered = ContractionRefusal::FenceNotRecognized { unrecognized: 1 }.to_string();
    assert!(rendered.contains("1 capability name(s)"), "{rendered}");
    let rendered = ContractionRefusal::BackfillUnverified {
        backfill: "fixture_backfill",
        state: Some(BackfillState::Running),
    }
    .to_string();
    assert!(
        rendered.contains("still running or interrupted"),
        "{rendered}"
    );
}

/// No shipped migration contracts yet. When one does, the fence it raises
/// must be one this build meets, or the build that ships it could not serve
/// the schema it leaves behind; and the fence must exist before it.
#[test]
fn every_shipped_contraction_keeps_this_build_eligible() {
    let (_, serving_max) = migrations::schema_version_range();
    let contracting: Vec<&Migration> = migrations::shipped_manifest()
        .iter()
        .filter(|migration| migration.contraction().is_some())
        .collect();
    for migration in &contracting {
        let Some(contraction) = migration.contraction() else {
            continue;
        };
        assert!(
            migration.version > 20,
            "migration {} contracts before the contract fence exists (migration 20)",
            migration.version
        );
        assert!(
            migration.version <= i64::from(serving_max),
            "migration {} raises the fence past what this build serves",
            migration.version
        );
        for capability in contraction.capabilities {
            assert!(
                BINARY_CAPABILITIES.contains(capability),
                "migration {} fences {} out of this build",
                migration.version,
                capability.as_str()
            );
        }
    }
    assert!(
        contracting.is_empty(),
        "a shipped migration contracts the schema: document it in docs/deployment/postgres.md \
         and the HA state model, and publish it in upgrade-support-matrix.json"
    );
}

/// The published support matrix lists what this build contracts, so an
/// operator reads the rollback cutoff a migration brings before running it.
#[test]
fn the_published_matrix_lists_every_shipped_contraction() {
    use serde_json::{json, Value};

    let matrix: Value = serde_json::from_str(include_str!(
        "../../../docs/deployment/upgrade-support-matrix.json"
    ))
    .expect("the published support matrix is JSON");
    let shipped: Vec<Value> = migrations::shipped_manifest()
        .iter()
        .filter_map(|migration| {
            migration.contraction().map(|contraction| {
                json!({
                    "version": migration.version,
                    "migration": migration.name,
                    "capabilities": contraction
                        .capabilities
                        .iter()
                        .map(|capability| capability.as_str())
                        .collect::<Vec<_>>(),
                    "backfill": contraction.backfill,
                })
            })
        })
        .collect();
    assert_eq!(
        matrix["this_build"]["contractions"],
        Value::Array(shipped),
        "docs/deployment/upgrade-support-matrix.json must list every contracting migration \
         this build carries"
    );
}

// --- the fixture against a real PostgreSQL ----------------------------------

mod database {
    use super::*;
    use crate::ha::InstanceIdentity;
    use crate::storage::contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, DsnFile, TestDatabase, DATABASE,
    };
    use crate::storage::migrations::MigrateOutput;
    use crate::storage::postgres::PostgresFoundation;
    use crate::storage::{
        HeartbeatOutcome, MemberRegistration, MemberRevisions, PostgresMembershipStore,
    };

    const DEPLOYMENT: &str = "deploy-contraction-fixture";
    const WINDOW: Duration = Duration::from_secs(30);

    const EXPAND_SQL: &str = "CREATE TABLE greengateway.contraction_fixture_legacy (
    id integer PRIMARY KEY,
    note text NOT NULL
);
INSERT INTO greengateway.contraction_fixture_legacy (id, note) VALUES (1, 'kept until contracted');
";
    const CONTRACT_SQL: &str = "DROP TABLE greengateway.contraction_fixture_legacy;\n";
    /// Removes the table, then fails: the raise before it and the removal
    /// must both roll back.
    const FAILING_CONTRACT_SQL: &str =
        "DROP TABLE greengateway.contraction_fixture_legacy;\nSELECT 1 / 0;\n";
    /// Holds the contraction's transaction open, fence row locked, long
    /// enough for a heartbeat to arrive behind it.
    const PAUSED_CONTRACT_SQL: &str = "SELECT pg_sleep(2); -- contraction fixture: paused\n\
         DROP TABLE greengateway.contraction_fixture_legacy;\n";

    struct Fixture {
        foundation: PostgresFoundation,
        config: crate::config::Config,
        _dsn_file: DsnFile,
        _database: TestDatabase,
    }

    impl Fixture {
        fn pool(&self) -> &deadpool_postgres::Pool {
            self.foundation.pool()
        }

        /// The schema version the fixture expands to, and the one its
        /// contraction moves the schema to.
        fn versions() -> (i64, i64) {
            let shipped =
                i64::try_from(migrations::shipped_manifest().len()).expect("a short manifest");
            (shipped + 1, shipped + 2)
        }

        /// The shipped manifest, the expansion, and a contraction running
        /// `sql` as `contraction` describes.
        fn manifest(contraction: Contraction, sql: &'static str) -> Vec<Migration> {
            let (expand, contract) = Self::versions();
            let mut manifest = migrations::shipped_manifest().to_vec();
            manifest
                .push(Migration::new(expand, "contraction_fixture_expand", EXPAND_SQL).finalize());
            manifest.push(
                Migration::new(contract, "contraction_fixture_contract", sql)
                    .finalize()
                    .contracting(contraction),
            );
            manifest
        }

        async fn migrate(&self, manifest: &[Migration]) -> Result<MigrateOutput, MigrateError> {
            migrations::apply_manifest(self.pool(), &self.config.database, manifest, WINDOW).await
        }

        /// Migrate through the expansion only: the schema a contraction
        /// starts from.
        async fn expanded(
            contraction: Contraction,
            sql: &'static str,
        ) -> Option<(Self, Vec<Migration>)> {
            let Some(admin_dsn) = locator() else {
                eprintln!("skipping: no test database locator; CI runs this test");
                return None;
            };
            let database = create_test_database(&admin_dsn).await;
            let dsn_file = write_dsn_file(&database.dsn);
            let mut config = crate::config::Config::test_defaults();
            config.state_backend = crate::config::StateBackend::Postgres;
            config.deployment_id = Some(DEPLOYMENT.to_owned());
            config.database.url_file = Some(dsn_file.path.clone());
            config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
            let foundation = PostgresFoundation::establish(&config)
                .await
                .expect("the test database should establish");
            let fixture = Self {
                foundation,
                config,
                _dsn_file: dsn_file,
                _database: database,
            };
            let manifest = Self::manifest(contraction, sql);
            let through_expand = manifest.len() - 1;
            assert_eq!(
                fixture
                    .migrate(&manifest[..through_expand])
                    .await
                    .expect("the expansion applies"),
                MigrateOutput::Applied {
                    applied: through_expand
                }
            );
            Some((fixture, manifest))
        }

        fn member(&self) -> PostgresMembershipStore {
            PostgresMembershipStore::new(
                self.pool().clone(),
                DEPLOYMENT,
                InstanceIdentity::generate(),
            )
        }

        async fn stale(&self, member: &PostgresMembershipStore) {
            let updated = self
                .pool()
                .get()
                .await
                .expect("client")
                .execute(
                    "UPDATE greengateway.cluster_members
                     SET last_heartbeat_at = now() - interval '1 hour'
                     WHERE instance_id = $1::text::uuid",
                    &[&member.instance_id().to_string()],
                )
                .await
                .expect("backdate");
            assert_eq!(updated, 1);
        }

        /// The ledger's highest version, whether the legacy table is there,
        /// the fence (generation, minimum schema, capabilities, raised_by),
        /// and how many raises were audited.
        async fn state(&self) -> (i64, bool, (i64, i32, String, Option<String>), i64) {
            let row = self
                .pool()
                .get()
                .await
                .expect("client")
                .query_one(
                    "SELECT (SELECT max(version) FROM greengateway.schema_migrations) AS ledger,
                            to_regclass('greengateway.contraction_fixture_legacy') IS NOT NULL
                                AS legacy,
                            f.generation, f.minimum_schema, f.capabilities, f.raised_by,
                            (SELECT count(*) FROM greengateway.audit_events
                             WHERE event_type = 'cluster.contract_fence_raised') AS raises
                     FROM greengateway.contract_fence f",
                    &[],
                )
                .await
                .expect("state");
            (
                row.get("ledger"),
                row.get("legacy"),
                (
                    row.get("generation"),
                    row.get("minimum_schema"),
                    row.get("capabilities"),
                    row.get("raised_by"),
                ),
                row.get("raises"),
            )
        }
    }

    fn registration(schema_version: (i32, i32), capabilities: &[Capability]) -> MemberRegistration {
        MemberRegistration {
            binary_version: "fixture".to_owned(),
            schema_version,
            document_version: crate::cluster_membership::DOCUMENT_VERSION_RANGE,
            fingerprint: "a".repeat(64),
            capabilities: capabilities.to_vec(),
        }
    }

    async fn heartbeat(
        store: &PostgresMembershipStore,
        registration: &MemberRegistration,
    ) -> HeartbeatOutcome {
        store
            .heartbeat(registration, MemberRevisions::default(), None)
            .await
            .expect("heartbeat")
    }

    fn untouched(expand: i64) -> (i64, bool, (i64, i32, String, Option<String>), i64) {
        (expand, true, (0, 0, String::new(), None), 0)
    }

    /// The protocol end to end: while a live member, draining or not, runs a
    /// build the raised fence would exclude -- one whose serving range ends
    /// before the contraction, or one without the fenced capability -- the
    /// contraction is refused and nothing changes. Once both are stale it
    /// raises the fence, removes the legacy table and records itself in one
    /// commit, audits the raise, and neither excluded build can rejoin; an
    /// eligible member keeps heartbeating and a repeat run does nothing.
    #[tokio::test]
    async fn a_contraction_raises_the_fence_before_it_removes_anything() {
        let _guard = DATABASE.lock().await;
        let Some((fixture, manifest)) = Fixture::expanded(FENCED, CONTRACT_SQL).await else {
            return;
        };
        let (expand, contract) = Fixture::versions();
        let (expand32, contract32) = (
            i32::try_from(expand).expect("small"),
            i32::try_from(contract).expect("small"),
        );

        // The build that still reads the legacy table serves the expanded
        // schema only; a build prepared for the contraction serves both, and
        // one of those was built without the fenced capability.
        let retiring = fixture.member();
        let retiring_build =
            registration((expand32, expand32), &[Capability::OperationRequirements]);
        let lacking = fixture.member();
        let lacking_build = registration((expand32, contract32), &[]);
        let eligible = fixture.member();
        let eligible_build =
            registration((expand32, contract32), &[Capability::OperationRequirements]);
        for (store, build) in [
            (&retiring, &retiring_build),
            (&lacking, &lacking_build),
            (&eligible, &eligible_build),
        ] {
            assert_eq!(heartbeat(store, build).await, HeartbeatOutcome::Written);
        }
        lacking.mark_draining().await.expect("draining stamp");

        let refused = fixture
            .migrate(&manifest)
            .await
            .expect_err("excluded members are live");
        let MigrateError::ContractionRefused {
            version,
            refusal:
                ContractionRefusal::LiveMembersExcluded {
                    mut excluded,
                    live,
                    minimum_schema,
                    capabilities,
                },
        } = refused.clone()
        else {
            panic!("refused for the wrong reason: {refused}");
        };
        excluded.sort();
        let mut expected = vec![retiring.instance_id(), lacking.instance_id()];
        expected.sort();
        assert_eq!(
            (version, excluded, live, minimum_schema, capabilities),
            (contract, expected, 3, contract32, 1)
        );
        assert_eq!(fixture.state().await, untouched(expand), "nothing changed");

        // A stale row is not proof the build retired, but it is not live:
        // the raise is what keeps it out. The draining member still holds
        // the contraction until it is stale too.
        fixture.stale(&retiring).await;
        assert!(matches!(
            fixture.migrate(&manifest).await,
            Err(MigrateError::ContractionRefused {
                refusal: ContractionRefusal::LiveMembersExcluded { ref excluded, live: 2, .. },
                ..
            }) if excluded == &vec![lacking.instance_id()]
        ));
        assert_eq!(fixture.state().await, untouched(expand));
        fixture.stale(&lacking).await;

        assert_eq!(
            fixture
                .migrate(&manifest)
                .await
                .expect("the contraction applies"),
            MigrateOutput::Applied { applied: 1 }
        );
        assert_eq!(
            fixture.state().await,
            (
                contract,
                false,
                (
                    1,
                    contract32,
                    "operation_requirements".to_owned(),
                    Some(format!("migration.{contract}"))
                ),
                1
            ),
            "one commit raised the fence, removed the table and recorded the migration"
        );
        let payload: serde_json::Value = fixture
            .pool()
            .get()
            .await
            .expect("client")
            .query_one(
                "SELECT payload_json::text FROM greengateway.audit_events
                 WHERE event_type = 'cluster.contract_fence_raised'",
                &[],
            )
            .await
            .map(|row| serde_json::from_str(&row.get::<_, String>(0)).expect("payload JSON"))
            .expect("the raise is audited");
        assert_eq!(
            payload,
            serde_json::json!({
                "operation": format!("migration.{contract}"),
                "migration": "contraction_fixture_contract",
                "outcome": "raised",
                "previous_generation": 0,
                "fence_generation": 1,
                "previous_minimum_schema": 0,
                "minimum_schema": contract32,
                "capabilities": ["operation_requirements"],
                "live_members": 1,
            })
        );

        // Neither excluded build can come back, whatever its row did; the
        // eligible one keeps its place.
        assert_eq!(
            heartbeat(&retiring, &retiring_build).await,
            HeartbeatOutcome::Fenced
        );
        assert_eq!(
            heartbeat(&lacking, &lacking_build).await,
            HeartbeatOutcome::Fenced
        );
        assert_eq!(
            heartbeat(&fixture.member(), &retiring_build).await,
            HeartbeatOutcome::Fenced,
            "a fresh boot of the retiring build is refused too"
        );
        assert_eq!(
            heartbeat(&eligible, &eligible_build).await,
            HeartbeatOutcome::Written
        );

        assert_eq!(
            fixture.migrate(&manifest).await.expect("a repeat run"),
            MigrateOutput::UpToDate {
                applied: manifest.len()
            }
        );
        assert_eq!(fixture.state().await.2 .0, 1, "and raises nothing again");
    }

    /// A contraction that needs a backfill waits for the backfill ledger to
    /// record it verified: missing, running (including interrupted) and
    /// failed all refuse and change nothing.
    #[tokio::test]
    async fn a_contraction_waits_for_its_backfill_to_be_verified() {
        let _guard = DATABASE.lock().await;
        let backfilled = Contraction {
            capabilities: &[],
            backfill: Some("contraction_fixture"),
        };
        let Some((fixture, manifest)) = Fixture::expanded(backfilled, CONTRACT_SQL).await else {
            return;
        };
        let (expand, contract) = Fixture::versions();
        let client = fixture.pool().get().await.expect("client");
        for (state, row) in [
            (BackfillState::Missing, None),
            (BackfillState::Running, Some(("running", false))),
            (BackfillState::Failed, Some(("failed", true))),
        ] {
            client
                .execute("DELETE FROM greengateway.schema_backfills", &[])
                .await
                .expect("clear");
            if let Some((column, finished)) = row {
                client
                    .execute(
                        "INSERT INTO greengateway.schema_backfills (name, state, finished_at)
                         VALUES ('contraction_fixture', $1, CASE WHEN $2 THEN now() END)",
                        &[&column, &finished],
                    )
                    .await
                    .expect("record the backfill");
            }
            assert_eq!(
                fixture.migrate(&manifest).await,
                Err(MigrateError::ContractionRefused {
                    version: contract,
                    refusal: ContractionRefusal::BackfillUnverified {
                        backfill: "contraction_fixture",
                        state: Some(state),
                    },
                }),
                "{state:?}"
            );
            assert_eq!(fixture.state().await, untouched(expand), "{state:?}");
        }
        client
            .execute(
                "UPDATE greengateway.schema_backfills SET state = 'verified'
                 WHERE name = 'contraction_fixture'",
                &[],
            )
            .await
            .expect("verify the backfill");
        assert_eq!(
            fixture
                .migrate(&manifest)
                .await
                .expect("the contraction applies"),
            MigrateOutput::Applied { applied: 1 }
        );
        let (ledger, legacy, (generation, minimum_schema, capabilities, _), _) =
            fixture.state().await;
        assert_eq!(
            (ledger, legacy, generation, minimum_schema, capabilities),
            (
                contract,
                false,
                1,
                i32::try_from(contract).expect("small"),
                String::new()
            ),
            "a contraction that fences no capability raises the schema half alone"
        );
    }

    /// Abort leaves everything as it was: a contraction whose SQL fails after
    /// removing the table rolls back its fence raise with the removal, and a
    /// fence a newer build raised with a capability this build does not
    /// recognize refuses before anything is read.
    #[tokio::test]
    async fn an_aborted_contraction_leaves_the_fence_and_the_schema_as_they_were() {
        let _guard = DATABASE.lock().await;
        let Some((fixture, manifest)) = Fixture::expanded(FENCED, FAILING_CONTRACT_SQL).await
        else {
            return;
        };
        let (expand, contract) = Fixture::versions();
        assert_eq!(
            fixture.migrate(&manifest).await,
            Err(MigrateError::ApplyFailed)
        );
        assert_eq!(
            fixture.state().await,
            untouched(expand),
            "the raise, the removal and the ledger row rolled back together"
        );

        let client = fixture.pool().get().await.expect("client");
        client
            .execute(
                "UPDATE greengateway.contract_fence
                 SET generation = 1, capabilities = 'future_capability',
                     raised_at = now(), raised_by = 'fixture.newer_build'
                 WHERE singleton",
                &[],
            )
            .await
            .expect("a newer build raises the fence");
        assert_eq!(
            fixture.migrate(&manifest).await,
            Err(MigrateError::ContractionRefused {
                version: contract,
                refusal: ContractionRefusal::FenceNotRecognized { unrecognized: 1 },
            })
        );
        assert_eq!(
            fixture.state().await,
            (
                expand,
                true,
                (
                    1,
                    0,
                    "future_capability".to_owned(),
                    Some("fixture.newer_build".to_owned())
                ),
                0
            )
        );
    }

    /// A heartbeat that arrives while the contraction holds the fence row
    /// waits for its commit and is then judged against the raised fence: no
    /// excluded build can join behind the roster read.
    #[tokio::test]
    async fn a_heartbeat_racing_a_contraction_waits_for_it_and_is_refused() {
        let _guard = DATABASE.lock().await;
        let Some((fixture, manifest)) = Fixture::expanded(FENCED, PAUSED_CONTRACT_SQL).await else {
            return;
        };
        let (expand, contract) = Fixture::versions();
        let expand32 = i32::try_from(expand).expect("small");
        let fixture = std::sync::Arc::new(fixture);

        let migrating = tokio::spawn({
            let fixture = std::sync::Arc::clone(&fixture);
            async move { fixture.migrate(&manifest).await }
        });
        let observer = fixture.pool().get().await.expect("client");
        let mut paused = false;
        for _ in 0..100 {
            paused = observer
                .query_one(
                    "SELECT count(*) > 0 AS paused FROM pg_stat_activity
                     WHERE pid <> pg_backend_pid() AND state = 'active'
                       AND query LIKE '%contraction fixture: paused%'",
                    &[],
                )
                .await
                .expect("activity")
                .get("paused");
            if paused {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            paused,
            "the contraction reached its SQL with the fence row locked"
        );

        let retiring = fixture.member();
        let racing = tokio::spawn({
            let retiring = retiring.clone();
            async move {
                heartbeat(
                    &retiring,
                    &registration((expand32, expand32), &[Capability::OperationRequirements]),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !racing.is_finished(),
            "the heartbeat waits behind the contraction's row lock"
        );
        assert_eq!(
            migrating
                .await
                .expect("join")
                .expect("the contraction applies"),
            MigrateOutput::Applied { applied: 1 }
        );
        assert_eq!(
            racing.await.expect("join"),
            HeartbeatOutcome::Fenced,
            "and is judged against the fence the contraction committed"
        );
        let (ledger, legacy, (generation, ..), _) = fixture.state().await;
        assert_eq!((ledger, legacy, generation), (contract, false, 1));
    }
}
