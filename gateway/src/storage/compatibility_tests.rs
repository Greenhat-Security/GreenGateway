use super::*;

fn is_capability_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_CAPABILITY_NAME_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[test]
fn every_capability_name_is_bounded_shaped_and_in_canonical_order() {
    let names: Vec<&str> = Capability::KNOWN
        .iter()
        .map(|capability| capability.as_str())
        .collect();
    for name in &names {
        assert!(
            is_capability_name(name),
            "{name} must match migration 17's name shape"
        );
    }
    // Declaration order is the set's order, so it must also be name order:
    // that is what makes an advertisement canonical byte for byte.
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(names, sorted, "KNOWN must be unique and in name order");
    let mut declared = Capability::KNOWN.to_vec();
    declared.sort();
    assert_eq!(declared, Capability::KNOWN.to_vec());
    assert!(Capability::KNOWN.len() <= MAX_ADVERTISED_CAPABILITIES);
}

#[test]
fn this_binary_advertises_a_bounded_canonical_set_it_recognizes() {
    let rendered = advertisement(BINARY_CAPABILITIES).expect("the shipped set fits the column");
    assert_eq!(rendered, "operation_requirements,policy_role_descriptions");
    let recognized = RecognizedCapabilities::parse(&rendered);
    assert_eq!(recognized.unrecognized(), 0);
    for capability in BINARY_CAPABILITIES {
        assert!(recognized.contains(*capability));
    }
    assert_eq!(
        recognized.names(),
        vec!["operation_requirements", "policy_role_descriptions"]
    );
}

/// What a schema-18 gateway built before role descriptions advertises
/// (the prepared release of issue #426's pair) is still understood, and
/// grants this build exactly the protocol and nothing newer.
#[test]
fn a_prepared_members_advertisement_lacks_the_successors_capability() {
    let prepared = RecognizedCapabilities::parse("operation_requirements");
    assert!(prepared.contains(Capability::OperationRequirements));
    assert!(!prepared.contains(Capability::PolicyRoleDescriptions));
    assert_eq!(prepared.unrecognized(), 0);
}

#[test]
fn an_advertisement_is_sorted_and_deduplicated() {
    assert_eq!(
        advertisement(&[
            Capability::OperationRequirements,
            Capability::OperationRequirements
        ])
        .as_deref(),
        Some("operation_requirements")
    );
    assert_eq!(advertisement(&[]).as_deref(), Some(""));
}

#[test]
fn recognition_grants_only_compiled_in_names() {
    let empty = RecognizedCapabilities::parse("");
    assert!(!empty.contains(Capability::OperationRequirements));
    assert_eq!(empty.unrecognized(), 0);

    let newer = RecognizedCapabilities::parse("future_capability,operation_requirements");
    assert!(newer.contains(Capability::OperationRequirements));
    assert_eq!(newer.unrecognized(), 1, "a newer gateway's name is counted");
    assert_eq!(newer.names(), vec!["operation_requirements"]);

    for spelling in [
        "Operation_Requirements",
        "operation_requirements ",
        " operation_requirements",
        "operation-requirements",
        "operation_requirements\0",
    ] {
        let recognized = RecognizedCapabilities::parse(spelling);
        assert!(
            !recognized.contains(Capability::OperationRequirements),
            "{spelling:?} is not the compiled name"
        );
        assert_eq!(recognized.unrecognized(), 1);
    }
    let separators = RecognizedCapabilities::parse(",");
    assert!(separators.names().is_empty());
    assert_eq!(separators.unrecognized(), 2, "empty names grant nothing");
}

#[test]
fn an_advertisement_beyond_the_column_bounds_grants_nothing() {
    let mut names = vec!["operation_requirements".to_owned()];
    names.extend((0..MAX_ADVERTISED_CAPABILITIES).map(|index| format!("filler_{index}")));
    let too_many = RecognizedCapabilities::parse(&names.join(","));
    assert!(
        !too_many.contains(Capability::OperationRequirements),
        "a row breaking the cardinality bound is trusted for none of its names"
    );
    assert_eq!(too_many.unrecognized(), MAX_ADVERTISED_CAPABILITIES + 1);

    let oversized = format!("operation_requirements,{}", "a".repeat(4096));
    let oversized = RecognizedCapabilities::parse(&oversized);
    assert!(!oversized.contains(Capability::OperationRequirements));

    let exactly_full: Vec<String> = std::iter::once("operation_requirements".to_owned())
        .chain((1..MAX_ADVERTISED_CAPABILITIES).map(|index| format!("filler_{index}")))
        .collect();
    let full = RecognizedCapabilities::parse(&exactly_full.join(","));
    assert!(full.contains(Capability::OperationRequirements));
    assert_eq!(full.unrecognized(), MAX_ADVERTISED_CAPABILITIES - 1);
}

#[cfg(feature = "postgres")]
mod gate_tests {
    use uuid::Uuid;

    use super::super::*;

    const OWN: Uuid = Uuid::from_u128(1);
    const PEER: Uuid = Uuid::from_u128(2);

    fn requirement() -> OperationRequirement {
        OperationRequirement {
            operation: "fixture.write",
            minimum_schema: 17,
            document_format: Some(0),
            capability: Capability::OperationRequirements,
            backfill: Backfill::NotRequired,
            activation: Activation::LiveMembers,
        }
    }

    fn contract() -> BinaryContract {
        BinaryContract {
            schema: (17, 17),
            document: (0, 0),
            capabilities: BINARY_CAPABILITIES,
        }
    }

    fn member(instance_id: Uuid, live: bool, capabilities: &str) -> MemberAdvertisement {
        MemberAdvertisement {
            instance_id,
            live,
            schema_version: (17, 17),
            document_version: (0, 0),
            capabilities: RecognizedCapabilities::parse(capabilities),
        }
    }

    fn advertised(instance_id: Uuid) -> MemberAdvertisement {
        member(instance_id, true, "operation_requirements")
    }

    /// The gate over a database whose contract fence was never raised and
    /// whose backfill ledger is empty: the state every shipped deployment
    /// is in until an operation declaring a durable fence is admitted.
    fn gate(
        requirement: &OperationRequirement,
        binary: &BinaryContract,
        own_instance: Uuid,
        members: &[MemberAdvertisement],
    ) -> Result<OperationAdmission, OperationRefusal> {
        evaluate(
            requirement,
            binary,
            own_instance,
            members,
            &ContractFence::open(),
            None,
        )
    }

    fn fence(generation: i64, minimum_schema: i32, capabilities: &str) -> ContractFence {
        ContractFence {
            generation,
            minimum_schema,
            capabilities: capabilities.to_owned(),
        }
    }

    /// The registry's own invariants, as a function so the test below can
    /// prove it rejects each malformed entry rather than passing an empty
    /// list vacuously.
    fn registry_problems(
        registry: &[OperationRequirement],
        binary: &BinaryContract,
    ) -> Vec<String> {
        let mut problems = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        for entry in registry {
            let name = entry.operation;
            let shaped = !name.is_empty()
                && name.len() <= 64
                && name.split('.').count() >= 2
                && name.split('.').all(|word| {
                    word.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && word.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                });
            if !shaped {
                problems.push(format!("{name}: not a dotted lowercase name"));
            }
            if !names.insert(name) {
                problems.push(format!("{name}: registered twice"));
            }
            if !binary.capabilities.contains(&entry.capability) {
                problems.push(format!("{name}: capability not advertised by this build"));
            }
            if entry.minimum_schema > binary.schema.0 {
                problems.push(format!("{name}: schema above this build's serving range"));
            }
            if entry
                .document_format
                .is_some_and(|major| major < binary.document.0 || major > binary.document.1)
            {
                problems.push(format!("{name}: document format this build does not read"));
            }
            if entry.backfill != Backfill::NotRequired {
                problems.push(format!(
                    "{name}: needs a backfill, and no shipped migration runs one"
                ));
            }
        }
        problems
    }

    #[test]
    fn the_shipped_registry_is_pinned_and_its_checks_reject_malformed_entries() {
        assert_eq!(
            OPERATION_REQUIREMENTS,
            &[POLICY_ROLE_DESCRIPTIONS],
            "registering an operation is a protocol change: review its requirement, its new \
             capability and the docs in ha-state-model.md section 7 before updating this test"
        );
        assert_eq!(
            POLICY_ROLE_DESCRIPTIONS,
            OperationRequirement {
                operation: "policy.role_descriptions",
                minimum_schema: 17,
                document_format: Some(0),
                capability: Capability::PolicyRoleDescriptions,
                backfill: Backfill::NotRequired,
                activation: Activation::LiveMembers,
            }
        );
        assert!(registry_problems(OPERATION_REQUIREMENTS, &BinaryContract::shipped()).is_empty());

        let good = requirement();
        assert!(registry_problems(&[good], &contract()).is_empty());
        let malformed = [
            OperationRequirement {
                operation: "NoDots",
                ..good
            },
            OperationRequirement {
                minimum_schema: 18,
                operation: "fixture.schema",
                ..good
            },
            OperationRequirement {
                document_format: Some(1),
                operation: "fixture.document",
                ..good
            },
            OperationRequirement {
                backfill: Backfill::Required { name: "fixture" },
                operation: "fixture.backfill",
                ..good
            },
            good,
            good,
        ];
        assert_eq!(registry_problems(&malformed, &contract()).len(), 5);
        // A durable fence is something this release provides, so an entry
        // that declares one is not malformed.
        let fenced = OperationRequirement {
            activation: Activation::DurableFence,
            operation: "fixture.fence",
            ..good
        };
        assert!(registry_problems(&[fenced], &contract()).is_empty());
        let bare = BinaryContract {
            capabilities: &[],
            ..contract()
        };
        assert_eq!(registry_problems(&[good], &bare).len(), 1);
    }

    /// The registered operation against the prepared release's
    /// advertisement: refused while a prepared member is live, admitted
    /// once only members of this build remain.
    #[test]
    fn role_descriptions_wait_for_a_prepared_member_to_leave() {
        let prepared = member(PEER, true, "operation_requirements");
        let successor = member(OWN, true, "operation_requirements,policy_role_descriptions");
        assert_eq!(
            gate(
                &POLICY_ROLE_DESCRIPTIONS,
                &BinaryContract::shipped(),
                OWN,
                &[successor.clone(), prepared]
            ),
            Err(OperationRefusal::MembersLackRequirement {
                lacking: vec![PEER],
                live: 2
            })
        );
        let departed = member(PEER, false, "operation_requirements");
        assert_eq!(
            gate(
                &POLICY_ROLE_DESCRIPTIONS,
                &BinaryContract::shipped(),
                OWN,
                &[successor, departed]
            ),
            Ok(OperationAdmission { live_members: 1 })
        );
    }

    #[test]
    fn the_shipped_contract_is_this_builds_contract() {
        let shipped = BinaryContract::shipped();
        assert_eq!(
            shipped.schema,
            crate::storage::migrations::schema_version_range()
        );
        assert_eq!(
            shipped.document,
            crate::cluster_membership::DOCUMENT_VERSION_RANGE
        );
        assert_eq!(shipped.capabilities, BINARY_CAPABILITIES);
    }

    #[test]
    fn an_operation_is_admitted_once_every_live_member_advertises_it() {
        let members = [advertised(OWN), advertised(PEER)];
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &members),
            Ok(OperationAdmission { live_members: 2 })
        );
        // Alone is enough when this replica is the deployment.
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &[advertised(OWN)]),
            Ok(OperationAdmission { live_members: 1 })
        );
    }

    #[test]
    fn a_live_member_that_does_not_advertise_the_capability_holds_the_operation() {
        // A pre-protocol member advertises nothing at all.
        let members = [advertised(OWN), member(PEER, true, "")];
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &members),
            Err(OperationRefusal::MembersLackRequirement {
                lacking: vec![PEER],
                live: 2
            })
        );
        // A newer name it does not recognize is not the capability either.
        let members = [advertised(OWN), member(PEER, true, "future_capability")];
        assert!(matches!(
            gate(&requirement(), &contract(), OWN, &members),
            Err(OperationRefusal::MembersLackRequirement { .. })
        ));
        // A stale member is the deployment's past, not its present.
        let members = [advertised(OWN), member(PEER, false, "")];
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &members),
            Ok(OperationAdmission { live_members: 1 })
        );
    }

    #[test]
    fn a_member_must_recognize_the_schema_and_read_the_document_format() {
        let mut older_schema = advertised(PEER);
        older_schema.schema_version = (16, 16);
        assert!(matches!(
            gate(
                &requirement(),
                &contract(),
                OWN,
                &[advertised(OWN), older_schema]
            ),
            Err(OperationRefusal::MembersLackRequirement { .. })
        ));

        let mut other_format = advertised(PEER);
        other_format.document_version = (1, 1);
        assert!(matches!(
            gate(
                &requirement(),
                &contract(),
                OWN,
                &[advertised(OWN), other_format.clone()]
            ),
            Err(OperationRefusal::MembersLackRequirement { .. })
        ));
        // An operation that writes no document does not care.
        let no_document = OperationRequirement {
            document_format: None,
            ..requirement()
        };
        assert!(gate(
            &no_document,
            &contract(),
            OWN,
            &[advertised(OWN), other_format]
        )
        .is_ok());
    }

    #[test]
    fn a_roster_without_this_replica_live_cannot_admit_anything() {
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &[advertised(PEER)]),
            Err(OperationRefusal::RosterMissingThisReplica)
        );
        assert_eq!(
            gate(
                &requirement(),
                &contract(),
                OWN,
                &[
                    member(OWN, false, "operation_requirements"),
                    advertised(PEER)
                ]
            ),
            Err(OperationRefusal::RosterMissingThisReplica)
        );
        assert_eq!(
            gate(&requirement(), &contract(), OWN, &[]),
            Err(OperationRefusal::RosterMissingThisReplica)
        );
    }

    /// The pure gate judges a durable-fence operation exactly as it judges
    /// any other; raising the fence is the caller's transaction
    /// (`ClusterMembership`), never a side effect of an admission here.
    #[test]
    fn a_durable_fence_operation_is_judged_on_the_same_evidence() {
        let fenced = OperationRequirement {
            activation: Activation::DurableFence,
            ..requirement()
        };
        assert_eq!(
            gate(&fenced, &contract(), OWN, &[advertised(OWN)]),
            Ok(OperationAdmission { live_members: 1 })
        );
        assert!(matches!(
            gate(
                &fenced,
                &contract(),
                OWN,
                &[advertised(OWN), member(PEER, true, "")]
            ),
            Err(OperationRefusal::MembersLackRequirement { .. })
        ));
    }

    /// Only a backfill the ledger records as verified admits: one that never
    /// started, one still running or interrupted, one that failed, and a
    /// ledger that could not be read all refuse, and each says which.
    #[test]
    fn a_backfill_must_be_recorded_verified() {
        let members = [advertised(OWN)];
        let backfilled = OperationRequirement {
            backfill: Backfill::Required { name: "fixture" },
            ..requirement()
        };
        let open = ContractFence::open();
        for state in [
            None,
            Some(BackfillState::Missing),
            Some(BackfillState::Running),
            Some(BackfillState::Failed),
        ] {
            assert_eq!(
                evaluate(&backfilled, &contract(), OWN, &members, &open, state),
                Err(OperationRefusal::BackfillUnverified {
                    backfill: "fixture",
                    state
                }),
                "{state:?}"
            );
        }
        assert_eq!(
            evaluate(
                &backfilled,
                &contract(),
                OWN,
                &members,
                &open,
                Some(BackfillState::Verified)
            ),
            Ok(OperationAdmission { live_members: 1 })
        );
        // An operation that names no backfill ignores the ledger.
        assert!(evaluate(
            &requirement(),
            &contract(),
            OWN,
            &members,
            &open,
            Some(BackfillState::Failed)
        )
        .is_ok());
    }

    #[test]
    fn backfill_states_are_the_columns_values_and_nothing_else() {
        assert_eq!(
            BackfillState::from_column(None),
            Some(BackfillState::Missing)
        );
        for state in [
            BackfillState::Running,
            BackfillState::Verified,
            BackfillState::Failed,
        ] {
            assert_eq!(
                BackfillState::from_column(Some(state.as_str())),
                Some(state)
            );
        }
        for unknown in ["missing", "Verified", "verified ", "complete", ""] {
            assert_eq!(
                BackfillState::from_column(Some(unknown)),
                None,
                "{unknown:?}"
            );
        }
    }

    /// The fence a database is born with excludes nothing this release can
    /// build; every way a raise can move it excludes a build that falls
    /// short, and a name this build has never heard of is one it lacks.
    #[test]
    fn the_contract_fence_excludes_exactly_the_builds_that_fall_short() {
        let shipped = BinaryContract::shipped();
        assert_eq!(shipped.fenced_by(&ContractFence::open()), None);
        assert_eq!(
            shipped.fenced_by(&fence(1, shipped.schema.1, "operation_requirements")),
            None,
            "a fence this build meets admits it"
        );
        assert_eq!(
            shipped.fenced_by(&fence(2, shipped.schema.1 + 1, "")),
            Some(FenceExclusion {
                generation: 2,
                minimum_schema: shipped.schema.1 + 1,
                schema_max: shipped.schema.1,
                missing_capabilities: 0,
            }),
            "a minimum schema beyond this build's serving range"
        );
        assert_eq!(
            shipped
                .fenced_by(&fence(3, 0, "future_capability,operation_requirements"))
                .map(|exclusion| exclusion.missing_capabilities),
            Some(1),
            "a newer build's capability"
        );
        let bare = BinaryContract {
            capabilities: &[Capability::OperationRequirements],
            ..shipped
        };
        assert_eq!(
            bare.fenced_by(&fence(
                4,
                0,
                "operation_requirements,policy_role_descriptions"
            ))
            .map(|exclusion| exclusion.missing_capabilities),
            Some(1),
            "a recognized capability this build does not implement"
        );
        // A value outside the column's bounds cannot be shown to be met.
        let oversized =
            std::iter::repeat_n("operation_requirements", MAX_ADVERTISED_CAPABILITIES + 1)
                .collect::<Vec<_>>()
                .join(",");
        assert!(shipped.fenced_by(&fence(5, 0, &oversized)).is_some());
        assert!(shipped.fenced_by(&fence(6, 0, "a,,b")).is_some());
        let rendered = shipped
            .fenced_by(&fence(7, 0, "future_capability"))
            .expect("excluded")
            .to_string();
        assert!(
            !rendered.contains("future_capability"),
            "an unrecognized fenced name is counted, never echoed: {rendered}"
        );
    }

    /// A build the fence excludes admits nothing, whatever the roster says;
    /// a live member that falls short of the fence is a lacking member.
    #[test]
    fn the_fence_is_rechecked_at_every_admission() {
        let members = [advertised(OWN), advertised(PEER)];
        let beyond = fence(1, contract().schema.1 + 1, "");
        assert!(matches!(
            evaluate(&requirement(), &contract(), OWN, &members, &beyond, None),
            Err(OperationRefusal::ContractFenced(FenceExclusion {
                generation: 1,
                ..
            }))
        ));
        let raised = fence(2, 17, "operation_requirements,policy_role_descriptions");
        let successor = member(OWN, true, "operation_requirements,policy_role_descriptions");
        let prepared = member(PEER, true, "operation_requirements");
        assert_eq!(
            evaluate(
                &requirement(),
                &contract(),
                OWN,
                &[successor.clone(), prepared],
                &raised,
                None
            ),
            Err(OperationRefusal::MembersLackRequirement {
                lacking: vec![PEER],
                live: 2
            }),
            "the operation itself needs only the protocol, but the fence needs more"
        );
        let mut older_schema = member(
            PEER,
            true,
            "operation_requirements,policy_role_descriptions",
        );
        older_schema.schema_version = (16, 16);
        assert!(matches!(
            evaluate(
                &requirement(),
                &contract(),
                OWN,
                &[successor.clone(), older_schema],
                &raised,
                None
            ),
            Err(OperationRefusal::MembersLackRequirement { .. })
        ));
        assert_eq!(
            evaluate(
                &requirement(),
                &contract(),
                OWN,
                &[successor],
                &raised,
                None
            ),
            Ok(OperationAdmission { live_members: 1 })
        );
    }

    /// A raise is the union of the capabilities and the higher of the two
    /// minimum schemas, so it never lowers anything, and a repeat admission
    /// asks for no write at all.
    #[test]
    fn a_fence_target_only_moves_forward() {
        let fenced = OperationRequirement {
            activation: Activation::DurableFence,
            capability: Capability::PolicyRoleDescriptions,
            ..requirement()
        };
        assert_eq!(
            fence_target(&ContractFence::open(), &fenced),
            Ok(Some(FenceTarget {
                minimum_schema: 17,
                capabilities: "policy_role_descriptions".to_owned(),
            }))
        );
        assert_eq!(
            fence_target(&fence(1, 19, "operation_requirements"), &fenced),
            Ok(Some(FenceTarget {
                minimum_schema: 19,
                capabilities: "operation_requirements,policy_role_descriptions".to_owned(),
            })),
            "a higher minimum is kept and the existing name stays"
        );
        assert_eq!(
            fence_target(&fence(2, 19, "policy_role_descriptions"), &fenced),
            Ok(None),
            "a fence that already demands it all is left alone"
        );
        assert_eq!(
            fence_target(&fence(3, 16, "policy_role_descriptions"), &fenced),
            Ok(Some(FenceTarget {
                minimum_schema: 17,
                capabilities: "policy_role_descriptions".to_owned(),
            })),
            "the minimum schema rises on its own"
        );
        assert_eq!(
            fence_target(&fence(4, 0, "future_capability"), &fenced),
            Err(OperationRefusal::NotSupportedByThisBinary),
            "a name this build cannot carry forward is refused, never dropped"
        );
    }

    #[test]
    fn this_binary_must_meet_the_requirement_itself() {
        let members = [advertised(OWN)];
        for unsupported in [
            OperationRequirement {
                minimum_schema: 18,
                ..requirement()
            },
            OperationRequirement {
                document_format: Some(1),
                ..requirement()
            },
        ] {
            assert_eq!(
                gate(&unsupported, &contract(), OWN, &members),
                Err(OperationRefusal::NotSupportedByThisBinary)
            );
        }
        let bare = BinaryContract {
            capabilities: &[],
            ..contract()
        };
        assert_eq!(
            gate(&requirement(), &bare, OWN, &members),
            Err(OperationRefusal::NotSupportedByThisBinary)
        );
    }

    #[test]
    fn refusals_carry_stable_reasons_and_no_identifiers() {
        let refusals = [
            OperationRefusal::NotSupportedByThisBinary,
            OperationRefusal::ActivationFenceUnavailable,
            OperationRefusal::BackfillUnverified {
                backfill: "fixture",
                state: Some(BackfillState::Running),
            },
            OperationRefusal::RosterUnavailable,
            OperationRefusal::RosterMissingThisReplica,
            OperationRefusal::MembersLackRequirement {
                lacking: vec![PEER],
                live: 2,
            },
            OperationRefusal::ContractFenced(FenceExclusion {
                generation: 3,
                minimum_schema: 20,
                schema_max: 19,
                missing_capabilities: 1,
            }),
            OperationRefusal::MigrationInProgress,
            OperationRefusal::SchemaNotServed,
            OperationRefusal::BackfillUnverified {
                backfill: "fixture",
                state: None,
            },
        ];
        let reasons: Vec<&str> = refusals.iter().map(OperationRefusal::reason).collect();
        assert_eq!(
            reasons,
            [
                "operation_not_supported",
                "activation_fence_unavailable",
                "backfill_unverified",
                "roster_unavailable",
                "roster_missing_this_replica",
                "capability_not_advertised",
                "contract_fenced",
                "migration_in_progress",
                "schema_incompatible",
                "backfill_unverified",
            ]
        );
        for refusal in &refusals {
            let rendered = refusal.to_string();
            assert!(rendered.contains("nothing was written"), "{rendered}");
            assert!(!rendered.contains(&PEER.to_string()), "{rendered}");
            let payload = refusal.audit_payload(&requirement());
            assert_eq!(payload["reason"], refusal.reason());
            assert_eq!(payload["outcome"], "refused");
            assert_eq!(payload["operation"], "fixture.write");
            assert_eq!(payload["capability"], "operation_requirements");
            assert!(!payload.to_string().contains(&PEER.to_string()));
        }
        let counted = refusals[5].audit_payload(&requirement());
        assert_eq!(counted["lacking_members"], 1);
        assert_eq!(counted["live_members"], 2);
        assert!(refusals[0].audit_payload(&requirement())["lacking_members"].is_null());
        assert_eq!(
            refusals[2].audit_payload(&requirement())["backfill_state"],
            "running"
        );
        assert_eq!(
            refusals[9].audit_payload(&requirement())["backfill_state"],
            "unreadable"
        );
        assert!(refusals[0].audit_payload(&requirement())["backfill_state"].is_null());
        assert_eq!(
            refusals[6].audit_payload(&requirement())["fence_generation"],
            3
        );
        assert!(refusals[0].audit_payload(&requirement())["fence_generation"].is_null());
    }
}
