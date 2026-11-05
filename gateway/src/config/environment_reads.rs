//! Every environment read in the gateway's own source, and the ones found
//! in its dependencies (issue #433, PR 1).
//!
//! The configuration compiler's inputs are `gateway_config::compiler`'s
//! `inventory::CONFIG_INPUTS`, which the compiler's own tests hold it to.
//! The gateway reads them through one reader, `config::process_environment`,
//! and reads the environment outside the compiler too. [`ENVIRONMENT_READS`]
//! lists every file under `gateway/src` that calls a `std::env` variable
//! reader, what it reads and how many times; its test scans the source so
//! the table cannot fall behind. That scan is the edge of what this module
//! holds complete: it sees the reads written in `gateway/src`, and nothing a
//! dependency does. `gateway-config` reads no environment variable at all;
//! the compiler's zero-I/O scan refuses one there.
//!
//! Dependencies read the environment too, and one of those reads decides
//! trust: on Linux, `SSL_CERT_FILE` and `SSL_CERT_DIR` choose the platform
//! trust anchors of the egress and PostgreSQL TLS verifiers.
//! [`DEPENDENCY_READS`] records the reads found by reading the sources of the
//! dependencies the gateway calls into. It is a record, not a scan: a
//! dependency update can add a read without failing anything, and the
//! variables the Rust runtime reads for itself (`RUST_BACKTRACE`,
//! `RUST_MIN_STACK`) or that code compiled from C reads (the C library's
//! resolver, the bundled SQLite) are not listed at all.
//!
//! Only the tests read these tables.

use super::{inventory::config_input, CONNECTION_SECRET_ALIASES};

/// Who an environment read serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadPurpose {
    /// The running gateway reads it.
    Gateway,
    /// Only test code reads it, to find harness resources such as a
    /// disposable database. A deployment never sets it.
    TestHarness,
}

/// Which variables an environment read names.
#[derive(Clone, Copy, Debug)]
enum ReadNames {
    /// The compiler's `CONFIG_INPUTS`, through `process_environment`.
    ConfigInputs,
    /// Exactly these, written in the source.
    Fixed(&'static [&'static str]),
    /// Whatever the operator names in this configuration input. Operator
    /// secret aliases of the `environment` kind name the variable holding the
    /// secret, and it is read when a Connection credential is resolved.
    ///
    /// The name is any well-formed variable name, so an alias can name a
    /// configuration input, or a variable a dependency reads, and that
    /// variable then has a second reader. Nothing here refuses that yet; the
    /// configuration compiler is where the rule belongs.
    NamedBy(&'static str),
}

/// One source file that reads the process environment.
struct EnvironmentRead {
    /// Relative to the crate root, with forward slashes.
    file: &'static str,
    names: ReadNames,
    purpose: ReadPurpose,
    /// How many times the file names a `std::env` variable reader, so a read
    /// added to a file that already has one changes the table too.
    reads: usize,
}

/// Every file under `gateway/src` that calls a `std::env` variable reader.
///
/// Within the gateway's own source, `process_environment` is the compiler's
/// only window onto the process, and the other reads written for the running
/// gateway are the two rows below it. This is all the scan below can see: a
/// read inside a dependency, the standard library included, is in no file
/// here and is recorded in [`DEPENDENCY_READS`] instead. The test-harness
/// reads are kept here too, because a disposable-database locator is still an
/// environment input, and listing it is what lets the scan hold this table to
/// the source.
const ENVIRONMENT_READS: &[EnvironmentRead] = &[
    EnvironmentRead {
        file: "src/config.rs",
        names: ReadNames::ConfigInputs,
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    // This replica's hostname for the cluster status API, read once at
    // startup and only when `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`.
    EnvironmentRead {
        file: "src/admin_identity.rs",
        names: ReadNames::Fixed(&["HOSTNAME", "COMPUTERNAME"]),
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/connections/secret.rs",
        names: ReadNames::NamedBy(CONNECTION_SECRET_ALIASES),
        purpose: ReadPurpose::Gateway,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/admin_observability_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 2,
    },
    EnvironmentRead {
        file: "src/admin_policy_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/admin_tools_app_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/import/tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/contract_tests.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_BENCHMARK_ROWS"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/migrations.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_NODDL_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/postgres.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    EnvironmentRead {
        file: "src/storage/postgres_session.rs",
        names: ReadNames::Fixed(&["GATEWAY_TEST_POSTGRES_URL_FILE"]),
        purpose: ReadPurpose::TestHarness,
        reads: 1,
    },
    // The shared PostgreSQL harness: the disposable database's DSN, and the
    // CA bundle that makes a run a verified-TLS run.
    EnvironmentRead {
        file: "src/storage/postgres_test_support.rs",
        names: ReadNames::Fixed(&[
            "GATEWAY_TEST_POSTGRES_URL_FILE",
            "GATEWAY_TEST_POSTGRES_TLS_CA_FILE",
        ]),
        purpose: ReadPurpose::TestHarness,
        reads: 2,
    },
];

/// One environment read made inside a dependency the gateway calls into.
struct DependencyRead {
    /// The package whose source calls the `std::env` reader, as `Cargo.lock`
    /// names it, or `std` for the standard library.
    reader: &'static str,
    names: &'static [&'static str],
    /// The gateway calls that reach the read: each source file, relative to
    /// the crate root, and the call as that file spells it.
    reached_from: &'static [(&'static str, &'static str)],
}

/// The environment reads found inside dependencies, by reading their sources
/// at the versions `Cargo.lock` pins.
///
/// Nothing scans for these, so the table records what was found rather than
/// promising nothing else is read; the module documentation says what it
/// leaves out. Its test holds each row to the gateway call that reaches it
/// and to the lock file, so a row whose call or package goes away fails
/// instead of lingering.
const DEPENDENCY_READS: &[DependencyRead] = &[
    // The platform trust anchors of the egress and PostgreSQL TLS verifiers,
    // read each time one is built. On Linux, `rustls-platform-verifier`
    // loads them through `rustls_native_certs::load_native_certs`, and
    // either variable, when set, replaces the system's certificate
    // locations; a configured CA bundle is still added on top. Other
    // platforms ask the operating system instead and read neither.
    DependencyRead {
        reader: "rustls-native-certs",
        names: &["SSL_CERT_FILE", "SSL_CERT_DIR"],
        reached_from: &[
            (
                "src/egress/tls.rs",
                "rustls_platform_verifier::Verifier::new",
            ),
            (
                "src/storage/postgres.rs",
                "rustls_platform_verifier::Verifier::new",
            ),
        ],
    },
    // The worker thread count of the runtime `main` starts. A value that is
    // not a positive integer panics before the gateway runs.
    DependencyRead {
        reader: "tokio",
        names: &["TOKIO_WORKER_THREADS"],
        reached_from: &[("src/main.rs", "#[tokio::main]")],
    },
    // Whether log lines carry ANSI colour codes: any non-empty value turns
    // them off.
    DependencyRead {
        reader: "tracing-subscriber",
        names: &["NO_COLOR"],
        reached_from: &[("src/bootstrap.rs", "tracing_subscriber::fmt::layer()")],
    },
    // On Unix, where `gateway import-standalone` stages its private copies of
    // the source databases; the import names it when that fails.
    DependencyRead {
        reader: "std",
        names: &["TMPDIR"],
        reached_from: &[("src/import/source.rs", "std::env::temp_dir()")],
    },
];

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
    };

    use super::*;

    /// The environment reads table matches the source: the files that name a
    /// `std::env` variable reader are exactly the files it lists, each one
    /// names a reader as many times as its row says, and each listed name is
    /// one the file spells out.
    ///
    /// The keys are mostly built at runtime, so the scan cannot read the name
    /// a call asks for. The count is what catches a read added to a file that
    /// already has one; the row's names are then for its reviewer to update.
    #[test]
    fn the_environment_reads_table_lists_every_file_that_reads_the_environment() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut found = BTreeMap::new();
        collect_environment_readers(crate_root, &crate_root.join("src"), &mut found);

        let listed: BTreeMap<String, usize> = ENVIRONMENT_READS
            .iter()
            .map(|read| (read.file.to_owned(), read.reads))
            .collect();
        assert_eq!(
            listed.len(),
            ENVIRONMENT_READS.len(),
            "the table lists a file twice"
        );
        let unlisted: Vec<&String> = found
            .keys()
            .filter(|file| !listed.contains_key(*file))
            .collect();
        let stale: Vec<&String> = listed
            .keys()
            .filter(|file| !found.contains_key(*file))
            .collect();
        assert!(
            unlisted.is_empty() && stale.is_empty(),
            "{unlisted:?} read the environment without an entry in ENVIRONMENT_READS, \
             and {stale:?} are listed but no longer read it"
        );
        assert_eq!(
            found, listed,
            "a file names a std::env variable reader a different number of times than its \
             ENVIRONMENT_READS row records; review the reads and update the row"
        );

        for read in ENVIRONMENT_READS {
            let source = fs::read_to_string(crate_root.join(read.file))
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", read.file));
            match read.names {
                ReadNames::ConfigInputs => assert_eq!(read.file, "src/config.rs"),
                ReadNames::NamedBy(input) => {
                    assert_eq!(read.purpose, ReadPurpose::Gateway, "{}", read.file);
                    assert_eq!(config_input(input), Some(input), "{}", read.file);
                }
                ReadNames::Fixed(names) => {
                    for name in names {
                        assert!(
                            source.contains(&format!("\"{name}\"")),
                            "{} does not spell out {name}",
                            read.file
                        );
                        // No fixed read takes a configuration input, so the
                        // parser is the only reader written for one, and a
                        // harness locator is never one. An operator alias can
                        // still name one; see `ReadNames::NamedBy`.
                        assert_eq!(config_input(name), None, "{name} in {}", read.file);
                        assert_eq!(
                            name.starts_with("GATEWAY_TEST_"),
                            read.purpose == ReadPurpose::TestHarness,
                            "{name} in {}",
                            read.file
                        );
                    }
                }
            }
        }
    }

    /// Each dependency read is still reached the way its row says, from a
    /// package the lock file still has, and names a variable no other row
    /// accounts for.
    #[test]
    fn every_dependency_read_is_still_reached_from_the_gateway() {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let lock = fs::read_to_string(crate_root.join("../Cargo.lock"))
            .unwrap_or_else(|error| panic!("failed to read Cargo.lock: {error}"));
        let locked: BTreeSet<&str> = lock
            .lines()
            .filter_map(|line| line.strip_prefix("name = \""))
            .filter_map(|line| line.strip_suffix('"'))
            .collect();
        let fixed: BTreeSet<&str> = ENVIRONMENT_READS
            .iter()
            .filter_map(|read| match read.names {
                ReadNames::Fixed(names) => Some(names.iter().copied()),
                ReadNames::ConfigInputs | ReadNames::NamedBy(_) => None,
            })
            .flatten()
            .collect();

        let mut seen = BTreeSet::new();
        for read in DEPENDENCY_READS {
            assert!(
                read.reader == "std" || locked.contains(read.reader),
                "{} is no longer in Cargo.lock",
                read.reader
            );
            assert!(!read.reached_from.is_empty(), "{}", read.reader);
            for (file, call) in read.reached_from {
                let source = fs::read_to_string(crate_root.join(file))
                    .unwrap_or_else(|error| panic!("failed to read {file}: {error}"));
                assert!(
                    source.contains(call),
                    "{file} no longer calls {call}, which is how the gateway reaches {}",
                    read.reader
                );
            }
            for name in read.names {
                assert!(seen.insert(*name), "{name} is listed twice");
                assert_eq!(config_input(name), None, "{name} in {}", read.reader);
                assert!(!fixed.contains(name), "{name} in {}", read.reader);
                assert!(
                    !name.starts_with("GATEWAY_TEST_"),
                    "{name} in {}",
                    read.reader
                );
            }
        }
    }

    /// Every `.rs` file under `directory` that names a `std::env` variable
    /// reader, relative to the crate root, with how many times it does.
    fn collect_environment_readers(
        crate_root: &Path,
        directory: &Path,
        found: &mut BTreeMap<String, usize>,
    ) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
                .path();
            if path.is_dir() {
                collect_environment_readers(crate_root, &path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
                let relative = path
                    .strip_prefix(crate_root)
                    .expect("source files live under the crate root")
                    .to_string_lossy()
                    .replace('\\', "/");
                assert!(
                    !imports_an_environment_reader(&source),
                    "{relative} imports a std::env variable reader by name; call it by its \
                     env:: path so the environment reads scan can count it"
                );
                let reads = environment_reader_uses(&source);
                if reads > 0 {
                    found.insert(relative, reads);
                }
            }
        }
    }

    /// The `std::env` functions that read variables.
    const ENVIRONMENT_READERS: [&str; 4] = ["var", "var_os", "vars", "vars_os"];

    /// The length of the identifier `text` starts with.
    fn identifier_length(text: &str) -> usize {
        text.find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(text.len())
    }

    /// How many times the source names one of the `std::env` functions that
    /// read variables by its `env::` path, as a call or as a function value.
    /// A name in backticks is documentation, not a use. The reader names are
    /// matched after the path rather than written out with it, so this file
    /// does not count as a reader itself -- here or in the walk of
    /// `tests/env_example.rs`, which looks for the same calls.
    fn environment_reader_uses(source: &str) -> usize {
        source
            .match_indices("env::")
            .filter(|(index, path)| {
                let rest = &source[index + path.len()..];
                let (name, after) = rest.split_at(identifier_length(rest));
                ENVIRONMENT_READERS.contains(&name) && !after.starts_with('`')
            })
            .count()
    }

    /// Whether a `use` declaration in the source brings a variable reader
    /// into scope under its bare name, or all of `std::env` with a glob,
    /// where its calls would no longer carry the `env::` path the count above
    /// looks for. rustfmt starts every declaration on its own line, after at
    /// most a visibility.
    fn imports_an_environment_reader(source: &str) -> bool {
        source.match_indices("use ").any(|(index, _)| {
            let line_start = source[..index].rfind('\n').map_or(0, |newline| newline + 1);
            let qualifier = source[line_start..index].trim();
            let is_declaration = qualifier.is_empty()
                || qualifier == "pub"
                || (qualifier.starts_with("pub(") && qualifier.ends_with(')'));
            if !is_declaration {
                return false;
            }
            let declaration = &source[index..];
            let declaration = &declaration[..declaration.find(';').unwrap_or(declaration.len())];
            declaration.match_indices("env::").any(|(at, path)| {
                let rest = &declaration[at + path.len()..];
                if let Some(list) = rest.strip_prefix('{') {
                    let list = &list[..list.find('}').unwrap_or(list.len())];
                    return list.split(',').any(|item| {
                        let item = item.trim();
                        ENVIRONMENT_READERS.contains(&&item[..identifier_length(item)])
                    });
                }
                rest.starts_with('*')
                    || ENVIRONMENT_READERS.contains(&&rest[..identifier_length(rest)])
            })
        })
    }

    /// The scan's own fixtures are written with `ENV::` and rewritten before
    /// use, so the text of this file never names a reader.
    fn fixture_source(text: &str) -> String {
        text.replace("ENV::", "env::")
    }

    #[test]
    fn the_scan_counts_every_use_of_a_reader_and_refuses_an_imported_one() {
        let uses = fixture_source(
            "let a = std::ENV::var(key);\n\
             let b = ENV::var_os (key);\n\
             let c = ENV::vars();\n\
             let d = names.map(ENV::var);\n\
             // `ENV::var` in documentation, and ENV::VarError, are not uses.\n",
        );
        assert_eq!(environment_reader_uses(&uses), 4);
        assert!(!imports_an_environment_reader(&uses));
        assert!(!imports_an_environment_reader(&fixture_source(
            "use std::ENV::{self, VarError};"
        )));

        for import in [
            "use std::ENV::var;",
            "    use std::ENV::var_os as read;",
            "use std::{ENV::vars, fs};",
            "use std::ENV::{self, var};",
            "use std::ENV::{\n    VarError,\n    var_os,\n};",
            "pub(crate) use std::ENV::*;",
        ] {
            let import = fixture_source(import);
            assert!(imports_an_environment_reader(&import), "{import}");
        }
    }
}
