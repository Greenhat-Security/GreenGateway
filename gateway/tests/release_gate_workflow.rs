//! The `ha-release-gate` job's composition, asserted in-repo (issue #241,
//! PR 16).
//!
//! The gate's anti-vacuity guards are all per-leg: the `0 passed` grep and
//! the elapsed-time floor both run inside one matrix leg and can only see
//! the suite that leg was told to run. Nothing in them notices a leg that
//! is no longer there. Delete `- ha_import_drill` from the matrix and every
//! remaining leg still passes its own guards, the job still goes green, and
//! a reviewer reads that green as "the gate proved the cutover" while the
//! import drill has not run at all.
//!
//! So the composition is asserted here, against `gateway/Cargo.toml`'s own
//! list of `ha_*` test targets: adding a suite without giving it a leg
//! fails, and dropping a leg fails. `ha_performance` is the one deliberate
//! exclusion — its benchmarks are `#[ignore]`d and belong to
//! `nightly-performance.yml` — and it is excluded here BY NAME, so
//! excluding a second suite means editing this test and saying why.
//!
//! This needs no database and no `GATEWAY_TEST_HA_GATE`: it reads two files
//! and compares two lists, so `cargo test --workspace` runs it on every
//! pull request, which is where a dropped leg has to be caught.

use std::{collections::BTreeSet, fs, path::PathBuf};

/// The job key in `.github/workflows/ci.yml`, and the name a branch
/// protection rule's required-check list matches on.
const GATE_JOB: &str = "ha-release-gate";

/// The one `ha_*` target the gate deliberately does not run, and why.
const NOT_A_GATE_LEG: &str = "ha_performance";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the gateway crate should live directly under the repo root")
        .to_path_buf()
}

/// The workflow, with line endings normalised.
///
/// A Windows checkout with `core.autocrlf` on hands back `\r\n`, and the
/// searches below are for whole lines; normalising once here is what keeps
/// this test a statement about the workflow rather than about the developer
/// machine that read it.
fn workflow() -> String {
    let path = repo_root().join(".github/workflows/ci.yml");
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// Every `[[test]]` target in `gateway/Cargo.toml` whose name starts with
/// `ha_`, which is the definition of "an HA suite" this repository uses.
fn declared_ha_suites() -> BTreeSet<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n");
    manifest
        .lines()
        .filter_map(|line| line.trim().strip_prefix("name = "))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .filter(|name| name.starts_with("ha_"))
        .collect()
}

/// The suites the `ha-release-gate` matrix names, in the order it names
/// them.
///
/// A deliberately literal reader: it finds the job, finds its `suite:` list,
/// and takes the `- ha_*` items until the indentation stops being the
/// list's. A YAML parser would be shorter and would also silently accept a
/// `suite` key that had moved somewhere it does nothing.
fn matrix_suites(workflow: &str) -> Vec<String> {
    let job_header = format!("  {GATE_JOB}:");
    let job_start = workflow
        .lines()
        .position(|line| line == job_header)
        .unwrap_or_else(|| {
            panic!(
                "ci.yml declares no job named {GATE_JOB:?} at the top level; the required merge \
                 check for issue #241's HA suites is gone or renamed"
            )
        });
    let lines: Vec<&str> = workflow.lines().collect();
    // The job ends at the next top-level job key (two spaces of indent, no
    // more), so the search below cannot wander into a later job's matrix.
    let job_end = lines
        .iter()
        .enumerate()
        .skip(job_start + 1)
        .find(|(_, line)| {
            line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim_start().starts_with('#')
        })
        .map_or(lines.len(), |(index, _)| index);

    let suite_key = lines[job_start..job_end]
        .iter()
        .position(|line| line.trim() == "suite:")
        .unwrap_or_else(|| panic!("the {GATE_JOB} job declares no `suite:` matrix axis"))
        + job_start;

    lines[suite_key + 1..job_end]
        .iter()
        .map(|line| line.trim())
        .take_while(|line| line.starts_with("- "))
        .map(|line| line.trim_start_matches("- ").trim().to_owned())
        .collect()
}

#[test]
fn the_release_gate_job_exists_and_is_named_exactly() {
    let workflow = workflow();
    assert!(
        workflow.contains(&format!("\n  {GATE_JOB}:\n")),
        "ci.yml must declare a job keyed exactly {GATE_JOB:?}: branch protection matches a \
         required check by name, so renaming the job silently drops the requirement"
    );
    assert!(
        workflow.contains(&format!("name: {GATE_JOB} (${{{{ matrix.suite }}}})")),
        "each leg's display name must carry the job name and its suite, so a failing check \
         names the suite that failed"
    );
}

#[test]
fn the_release_gate_matrix_runs_every_ha_suite() {
    let listed = matrix_suites(&workflow());
    let listed_set: BTreeSet<String> = listed.iter().cloned().collect();
    assert_eq!(
        listed_set.len(),
        listed.len(),
        "the {GATE_JOB} matrix names a suite twice: {listed:?}"
    );

    let mut expected = declared_ha_suites();
    assert!(
        expected.remove(NOT_A_GATE_LEG),
        "{NOT_A_GATE_LEG} is no longer a declared test target, so this test's one documented \
         exclusion is stale"
    );

    let missing: Vec<&String> = expected.difference(&listed_set).collect();
    assert!(
        missing.is_empty(),
        "the {GATE_JOB} matrix does not run {missing:?}. Every per-leg guard in that job -- the \
         `0 passed` grep and the elapsed-time floor -- can only see the suite its own leg ran, \
         so a suite with no leg leaves the gate green having never run it. Add the leg, or, if \
         the omission is deliberate, name it beside {NOT_A_GATE_LEG} in this test with the \
         reason."
    );

    let unknown: Vec<&String> = listed_set.difference(&expected).collect();
    assert!(
        unknown.is_empty(),
        "the {GATE_JOB} matrix names {unknown:?}, which gateway/Cargo.toml declares no test \
         target for; that leg would fail on every run"
    );
}

#[test]
fn the_release_gate_still_guards_against_a_vacuous_pass() {
    let workflow = workflow();
    let job_text = {
        let start = workflow
            .find(&format!("\n  {GATE_JOB}:\n"))
            .expect("the gate job should exist");
        &workflow[start..]
    };

    // The two guards the deployment guide now names as the real
    // protection, asserted so a future edit cannot quietly remove one and
    // leave the documentation describing a gate that no longer exists.
    assert!(
        job_text.contains("GATEWAY_TEST_HA_GATE"),
        "the gate legs must set GATEWAY_TEST_HA_GATE, or every suite takes its silent-skip path"
    );
    assert!(
        job_text.contains("Check the locator resolves before trusting a pass"),
        "the gate must assert its database locator resolves before it trusts a pass count"
    );
    assert!(
        job_text.contains("test result: ok. 0 passed"),
        "the gate must fail a leg that ran no tests"
    );
    assert!(
        job_text.contains("e < 1.0"),
        "the gate must fail a leg that finished too fast to have started a database and two \
         gateway processes; the `0 passed` check alone cannot see a fully skipped suite, which \
         reports its whole pass count"
    );
}
