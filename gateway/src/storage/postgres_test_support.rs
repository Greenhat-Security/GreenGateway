//! How the PostgreSQL-gated tests reach their disposable database (issue
//! #425).
//!
//! The suites that run against a real database take their connections from
//! here, so the TLS policy a run uses is decided in one place by two
//! test-harness locators:
//!
//! - `GATEWAY_TEST_POSTGRES_URL_FILE` names a file holding the DSN of a
//!   privileged role on a disposable server. Without it the suites skip, so a
//!   checkout without a database still passes.
//! - `GATEWAY_TEST_POSTGRES_TLS_CA_FILE`, when set, names the PEM bundle the
//!   server's certificate chains to. Every connection is then made in
//!   `verify` mode with that bundle as an extra trust anchor, through the
//!   gateway's own DSN policy, `enforce_tls_policy`, session settings and
//!   rustls connector, so the chain and the hostname are both verified. CI's
//!   `postgres-foundation-tls` shard sets it against a server that refuses
//!   plaintext. Without it, connections use the documented `loopback-dev`
//!   exception, which is what `postgres-foundation-pg`'s service container
//!   answers.
//!
//! Both are harness plumbing, read through runtime keys like every
//! `GATEWAY_TEST_POSTGRES_*` locator: the `.env.example` drift test exists to
//! keep operator settings documented, and these are not operator settings.

use deadpool_postgres::Pool;
use tokio_postgres::{config::SslMode, NoTls};

use super::{
    apply_session_settings, build_pool, enforce_tls_policy, validated_dsn_config,
    verified_tls_connector, PostgresFoundation, PostgresFoundationError,
};
use crate::config::{Config, DatabaseSettings, DatabaseTlsMode, StateBackend};

/// The DSN of the disposable server's privileged role, or `None` when no
/// database is configured and the PostgreSQL suites skip.
///
/// A run that names a CA bundle is a verified-TLS run, and it must never pass
/// by skipping, so without a readable DSN it panics instead.
pub(crate) fn locator() -> Option<String> {
    let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
    let dsn = std::env::var(&key)
        .ok()
        .filter(|file| !file.trim().is_empty())
        .and_then(|file| std::fs::read_to_string(file).ok())
        .map(|contents| contents.trim().to_owned())
        .filter(|dsn| !dsn.is_empty());
    assert!(
        dsn.is_some() || tls_ca_file().is_none(),
        "GATEWAY_TEST_POSTGRES_TLS_CA_FILE is set but GATEWAY_TEST_POSTGRES_URL_FILE names no \
         readable DSN; a verified-TLS run must not pass by skipping its suites"
    );
    dsn
}

/// The CA bundle a verified-TLS run trusts, or `None` for a `loopback-dev`
/// run.
pub(crate) fn tls_ca_file() -> Option<String> {
    let key = "GATEWAY_TEST_POSTGRES_TLS_CA_FILE".to_owned();
    std::env::var(&key)
        .ok()
        .filter(|file| !file.trim().is_empty())
}

/// Put `settings` under this run's TLS policy: `verify` with the configured
/// CA bundle, or the `loopback-dev` exception when there is none.
pub(crate) fn use_test_tls(settings: &mut DatabaseSettings) {
    match tls_ca_file() {
        Some(ca_file) => {
            settings.tls_mode = DatabaseTlsMode::Verify;
            settings.tls_ca_file = Some(ca_file);
        }
        None => {
            settings.tls_mode = DatabaseTlsMode::LoopbackDev;
            settings.tls_ca_file = None;
        }
    }
}

/// The default database settings under this run's TLS policy.
pub(crate) fn test_settings() -> DatabaseSettings {
    let mut settings = DatabaseSettings::default();
    use_test_tls(&mut settings);
    settings
}

/// A DSN file the bounded reader accepts, plus a guard keeping the scratch
/// directory alive (and removing it) for as long as the test holds it.
pub(crate) struct DsnFile {
    pub(crate) path: String,
    directory: std::path::PathBuf,
}

impl Drop for DsnFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(crate) fn write_dsn_file(dsn: &str) -> DsnFile {
    let directory = std::env::temp_dir().join(format!(
        "greengateway-postgres-test-{}",
        uuid::Uuid::new_v4()
    ));
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

/// `PostgresFoundation::establish` on `dsn` under this run's TLS policy:
/// the production path from the DSN file to the startup connectivity check.
pub(crate) async fn test_pool(dsn: &str) -> PostgresFoundation {
    let dsn_file = write_dsn_file(dsn);
    let mut config = Config::test_defaults();
    config.state_backend = StateBackend::Postgres;
    config.database.url_file = Some(dsn_file.path.clone());
    use_test_tls(&mut config.database);
    PostgresFoundation::establish(&config)
        .await
        .expect("the test database should establish")
}

/// The pool `test_pool` builds, before anything connects: a teardown that
/// runs on a runtime of its own opens its connection there.
pub(crate) fn unconnected_pool(dsn: &str) -> Result<Pool, PostgresFoundationError> {
    Ok(pool_with(dsn, &test_settings())?.pool().clone())
}

/// `establish` without its DSN file and its connectivity check, in the same
/// order: the DSN policy, the TLS policy, the session settings, the
/// gateway's own `ssl_mode` decision and, under `verify`, the production
/// connector.
fn pool_with(
    dsn: &str,
    settings: &DatabaseSettings,
) -> Result<PostgresFoundation, PostgresFoundationError> {
    let mut pg_config = validated_dsn_config(dsn)?;
    enforce_tls_policy(&pg_config, settings)?;
    apply_session_settings(&mut pg_config, settings);
    match settings.tls_mode {
        DatabaseTlsMode::Verify => {
            pg_config.ssl_mode(SslMode::Require);
            build_pool(pg_config, verified_tls_connector(settings)?, settings)
        }
        DatabaseTlsMode::LoopbackDev => {
            pg_config.ssl_mode(SslMode::Disable);
            build_pool(pg_config, NoTls, settings)
        }
    }
}

mod tests {
    use std::net::SocketAddr;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::storage::{postgres::validate_connectivity, RepositoryErrorKind};

    /// This run's DSN when it is a verified-TLS run; `None` skips.
    fn verified_tls_dsn() -> Option<String> {
        tls_ca_file()?;
        locator()
    }

    async fn session_is_tls(pool: &Pool) -> bool {
        pool.get()
            .await
            .expect("a session should check out")
            .query_one(
                "SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid = pg_catalog.pg_backend_pid()",
                &[],
            )
            .await
            .expect("the session should report its own TLS state")
            .get(0)
    }

    /// `dsn` with its host and port replaced, everything else kept.
    fn with_authority(dsn: &str, host: &str, port: u16) -> String {
        let mut url = url::Url::parse(dsn).expect("the locator DSN is a URL");
        url.set_host(Some(host)).expect("the host should replace");
        url.set_port(Some(port)).expect("the port should replace");
        url.to_string()
    }

    /// The server the locator DSN names, as a socket address to dial.
    fn server_of(dsn: &str) -> (String, u16) {
        let config = validated_dsn_config(dsn).expect("the locator DSN validates");
        let host = match config.get_hosts().first() {
            Some(tokio_postgres::config::Host::Tcp(host)) => host.clone(),
            _ => panic!("the locator DSN names a TCP host"),
        };
        let port = config.get_ports().first().copied().unwrap_or(5432);
        (host, port)
    }

    /// A byte relay from a listener on `bind` to the server: TLS runs end to
    /// end through it, so the client verifies the real server's certificate
    /// against the name it dialled.
    struct Relay {
        address: SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl Relay {
        async fn start(bind: &str, server: (String, u16)) -> Self {
            let listener = TcpListener::bind((bind, 0))
                .await
                .unwrap_or_else(|error| panic!("the relay should bind {bind}: {error}"));
            let address = listener.local_addr().expect("the relay has an address");
            let task = tokio::spawn(async move {
                while let Ok((mut inbound, _)) = listener.accept().await {
                    let (host, port) = server.clone();
                    tokio::spawn(async move {
                        if let Ok(mut outbound) = TcpStream::connect((host.as_str(), port)).await {
                            let _ =
                                tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                        }
                    });
                }
            });
            Self { address, task }
        }
    }

    impl Drop for Relay {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A CA nobody else uses, generated for this run; its key never leaves
    /// the process.
    fn unrelated_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "GreenGateway unrelated test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("the CA key should generate");
        params
            .self_signed(&key)
            .expect("the CA certificate should build")
            .pem()
    }

    /// Every part of `dsn` that a rendered error must not carry.
    fn assert_no_dsn_material(rendered: &str, dsn: &str) {
        let config = validated_dsn_config(dsn).expect("the DSN validates");
        let (host, port) = server_of(dsn);
        let mut fragments = vec![
            dsn.to_owned(),
            "postgres://".to_owned(),
            "postgresql://".to_owned(),
            host,
            format!(":{port}"),
        ];
        fragments.extend(config.get_user().map(str::to_owned));
        fragments.extend(config.get_dbname().map(str::to_owned));
        fragments.extend(
            config
                .get_password()
                .map(|password| String::from_utf8_lossy(password).into_owned()),
        );
        for fragment in fragments {
            assert!(
                !rendered.contains(&fragment),
                "a rendered error leaks DSN material ({fragment:?}): {rendered}"
            );
        }
    }

    /// `dsn` under `settings` is refused the way a store and an operator see
    /// it: the connectivity check every store shares classifies the failure
    /// as unavailable, startup reports it exhausted naming that kind, and
    /// neither names the database.
    async fn assert_refused_as_unavailable(dsn: &str, mut settings: DatabaseSettings) {
        settings.startup_retry_limit = 0;
        let pool = pool_with(dsn, &settings).expect("the pool builds without connecting");
        let error = validate_connectivity(pool.pool())
            .await
            .expect_err("verification must refuse the server");
        assert_eq!(error.kind(), RepositoryErrorKind::Unavailable, "{error}");
        assert_no_dsn_material(&error.to_string(), dsn);

        let dsn_file = write_dsn_file(dsn);
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Postgres;
        config.database = settings;
        config.database.url_file = Some(dsn_file.path.clone());
        let error = PostgresFoundation::establish(&config)
            .await
            .expect_err("startup must refuse the server");
        let rendered = error.to_string();
        assert!(
            matches!(error, PostgresFoundationError::StartupExhausted { .. }),
            "{rendered}"
        );
        assert!(
            rendered.contains("database_pool failed: unavailable"),
            "an exhausted startup names the classified cause: {rendered}"
        );
        assert_no_dsn_material(&rendered, dsn);
        assert_no_dsn_material(&format!("{error:?}"), dsn);
    }

    /// The run's own connections are TLS, and its server accepts nothing
    /// else: a suite in a verified-TLS run cannot have passed over a
    /// plaintext session.
    #[tokio::test]
    async fn a_verified_tls_run_reaches_its_database_only_over_tls() {
        let Some(dsn) = verified_tls_dsn() else {
            eprintln!("skipping: not a verified-TLS run; CI's postgres-foundation-tls runs this");
            return;
        };
        let foundation = test_pool(&dsn).await;
        assert!(session_is_tls(foundation.pool()).await);
        let teardown = unconnected_pool(&dsn).expect("the teardown pool builds");
        assert!(session_is_tls(&teardown).await);

        let plaintext = DatabaseSettings {
            tls_mode: DatabaseTlsMode::LoopbackDev,
            ..DatabaseSettings::default()
        };
        let pool = pool_with(&dsn, &plaintext).expect("the plaintext pool builds");
        let error = validate_connectivity(pool.pool())
            .await
            .expect_err("the server of a verified-TLS run must refuse plaintext");
        assert_eq!(error.kind(), RepositoryErrorKind::Unavailable, "{error}");
    }

    #[tokio::test]
    async fn a_server_certificate_from_another_authority_is_unavailable_and_names_no_dsn() {
        let Some(dsn) = verified_tls_dsn() else {
            eprintln!("skipping: not a verified-TLS run; CI's postgres-foundation-tls runs this");
            return;
        };
        let directory = std::env::temp_dir().join(format!(
            "greengateway-postgres-test-ca-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let ca_file = directory.join("unrelated-ca.pem");
        std::fs::write(&ca_file, unrelated_ca_pem()).expect("the CA bundle should write");

        let settings = DatabaseSettings {
            tls_mode: DatabaseTlsMode::Verify,
            tls_ca_file: Some(ca_file.display().to_string()),
            ..DatabaseSettings::default()
        };
        assert_refused_as_unavailable(&dsn, settings).await;
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The certificate names `127.0.0.1` and `localhost`. The same server
    /// dialled through a relay on `127.0.0.2`, a loopback address it does not
    /// name, is refused; through a relay on `127.0.0.1` it is not, so the
    /// relay is not what fails.
    #[tokio::test]
    async fn a_server_certificate_for_another_name_is_unavailable_and_names_no_dsn() {
        let Some(dsn) = verified_tls_dsn() else {
            eprintln!("skipping: not a verified-TLS run; CI's postgres-foundation-tls runs this");
            return;
        };
        let named = Relay::start("127.0.0.1", server_of(&dsn)).await;
        let through_named = with_authority(&dsn, "127.0.0.1", named.address.port());
        let pool = pool_with(&through_named, &test_settings()).expect("the pool builds");
        validate_connectivity(pool.pool())
            .await
            .expect("a relay on a name the certificate carries reaches the server");

        let unnamed = Relay::start("127.0.0.2", server_of(&dsn)).await;
        let through_unnamed = with_authority(&dsn, "127.0.0.2", unnamed.address.port());
        assert_refused_as_unavailable(&through_unnamed, test_settings()).await;
    }
}
