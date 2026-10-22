//! The identity settings -- the admin surface, authentication, the identity
//! providers and CSRF protection -- compiled in pure stages (issue #433,
//! PR 2).
//!
//! `Config::from_env_vars` reads these in four blocks with other domains'
//! settings between them, and each block is requested where the legacy parser
//! requested it, so the read order does not move:
//!
//! 1. the admin surface ([`AdminSurfaceInputs`]): its prefix, its login and
//!    session, the pending-login bounds and the public origin;
//! 2. the authorization exemptions ([`RbacExemptionInputs`]);
//! 3. authentication ([`AuthenticationInputs`]): the switches, the cookie, the
//!    authentication exemptions, the legacy single JWT provider and service
//!    tokens;
//! 4. the identity providers and CSRF ([`ProviderAndCsrfInputs`]), after
//!    which [`compile`] checks the rules that need all four and returns the
//!    [`IdentityPlan`].
//!
//! Each block is parsed input by input before its rules are checked. A block
//! only checks rules whose inputs have all been read, which is also where the
//! legacy parser checked them.
//!
//! The one secret value in the plan is the OIDC client secret an
//! `AUTH_PROVIDERS` entry may carry. The legacy document holds it inline
//! rather than by reference, so the plan holds it too, inside
//! `AuthProviderConfig`, whose `Debug` redacts it; turning it into a
//! reference is a change to the input format, not to this stage. Nothing here
//! fetches a JWKS, resolves an issuer or opens a store: an unreachable issuer
//! is accepted exactly as the legacy parser accepts it.

use std::{env::VarError, time::Duration};

use super::{
    append_admin_login_exempt_paths, default_admin_exempt_paths, default_paths,
    diagnostic::ConfigRule,
    legacy_auth_providers, parse_admin_prefix, parse_auth_providers, parse_comma_separated_paths,
    parse_cookie_name, parse_header_name_string, parse_non_empty_string,
    parse_optional_cookie_domain, parse_optional_gateway_public_url, parse_optional_string,
    parse_optional_var, parse_var,
    stage::{Checked, Findings, Provenance, RawInput},
    validate_admin_login_provider, validate_jwks_max_key_age, validate_positive_bounded_u64,
    validate_positive_u64, validate_positive_usize, AuthMode, AuthProviderConfig,
    ADMIN_LOGIN_PENDING_MAX_ENTRIES, ADMIN_LOGIN_PENDING_MAX_PER_IP, ADMIN_LOGIN_PENDING_TTL_SECS,
    ADMIN_LOGIN_PROVIDER, ADMIN_PREFIX, ADMIN_SESSION_IDLE_TIMEOUT_SECS, ADMIN_SESSION_MAX_ENTRIES,
    ADMIN_SESSION_MODE, ADMIN_SESSION_TTL_SECS, AUTH_COOKIE_NAME, AUTH_ENABLED, AUTH_EXEMPT_PATHS,
    AUTH_MODE, AUTH_PROVIDERS, CSRF_COOKIE_DOMAIN, CSRF_COOKIE_NAME, CSRF_ENABLED,
    CSRF_EXEMPT_PATHS, CSRF_HEADER_NAME, DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
    DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP, DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
    DEFAULT_ADMIN_PREFIX, DEFAULT_AUTH_COOKIE_NAME, DEFAULT_AUTH_ENABLED, DEFAULT_AUTH_MODE,
    DEFAULT_CSRF_COOKIE_NAME, DEFAULT_CSRF_ENABLED, DEFAULT_CSRF_EXEMPT_PATHS,
    DEFAULT_CSRF_HEADER_NAME, DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS, DEFAULT_JWT_JWKS_TIMEOUT_MS,
    DEFAULT_ROLES_CLAIM, DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS, GATEWAY_PUBLIC_URL, JWT_AUDIENCE,
    JWT_ISSUER, JWT_JWKS_MAX_KEY_AGE_SECS, JWT_JWKS_TIMEOUT_MS, JWT_JWKS_URL, JWT_REQUIRE_JTI,
    MAX_PRINCIPAL_ISSUER_BYTES, RBAC_EXEMPT_PATHS, ROLES_CLAIM, SERVICE_TOKEN_CACHE_TTL_MS,
    SERVICE_TOKEN_SQLITE_PATH,
};
use crate::auth::admin_session::{AdminSessionConfig, AdminSessionStorage};

/// The admin surface's inputs, as the reader returned them.
pub(super) struct AdminSurfaceInputs {
    prefix: RawInput,
    login_provider: RawInput,
    session_mode: RawInput,
    session_ttl_secs: RawInput,
    session_idle_timeout_secs: RawInput,
    session_max_entries: RawInput,
    login_pending_ttl_secs: RawInput,
    login_pending_max_entries: RawInput,
    login_pending_max_per_ip: RawInput,
    public_url: RawInput,
}

impl AdminSurfaceInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            prefix: RawInput::new(ADMIN_PREFIX, get_var(ADMIN_PREFIX)),
            login_provider: RawInput::new(ADMIN_LOGIN_PROVIDER, get_var(ADMIN_LOGIN_PROVIDER)),
            session_mode: RawInput::new(ADMIN_SESSION_MODE, get_var(ADMIN_SESSION_MODE)),
            session_ttl_secs: RawInput::new(
                ADMIN_SESSION_TTL_SECS,
                get_var(ADMIN_SESSION_TTL_SECS),
            ),
            session_idle_timeout_secs: RawInput::new(
                ADMIN_SESSION_IDLE_TIMEOUT_SECS,
                get_var(ADMIN_SESSION_IDLE_TIMEOUT_SECS),
            ),
            session_max_entries: RawInput::new(
                ADMIN_SESSION_MAX_ENTRIES,
                get_var(ADMIN_SESSION_MAX_ENTRIES),
            ),
            login_pending_ttl_secs: RawInput::new(
                ADMIN_LOGIN_PENDING_TTL_SECS,
                get_var(ADMIN_LOGIN_PENDING_TTL_SECS),
            ),
            login_pending_max_entries: RawInput::new(
                ADMIN_LOGIN_PENDING_MAX_ENTRIES,
                get_var(ADMIN_LOGIN_PENDING_MAX_ENTRIES),
            ),
            login_pending_max_per_ip: RawInput::new(
                ADMIN_LOGIN_PENDING_MAX_PER_IP,
                get_var(ADMIN_LOGIN_PENDING_MAX_PER_IP),
            ),
            public_url: RawInput::new(GATEWAY_PUBLIC_URL, get_var(GATEWAY_PUBLIC_URL)),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.prefix,
            &self.login_provider,
            &self.session_mode,
            &self.session_ttl_secs,
            &self.session_idle_timeout_secs,
            &self.session_max_entries,
            &self.login_pending_ttl_secs,
            &self.login_pending_max_entries,
            &self.login_pending_max_per_ip,
            &self.public_url,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The admin surface, parsed: what the later identity blocks build on.
pub(super) struct AdminSurface {
    prefix: String,
    login_provider: Option<String>,
    session: Option<AdminSessionConfig>,
    login_pending_ttl_secs: u64,
    login_pending_max_entries: usize,
    login_pending_max_per_ip: usize,
    public_url: Option<String>,
    provenance: Vec<Provenance>,
}

impl AdminSurface {
    fn login_enabled(&self) -> bool {
        self.login_provider.is_some()
    }
}

/// Parses the admin surface, the session's idle limit against its lifetime
/// included, then checks the rule that needs the whole block: the session's
/// own settings need a session mode that reads them.
pub(super) fn compile_admin_surface(inputs: AdminSurfaceInputs) -> Checked<AdminSurface> {
    let mut findings = Findings::default();
    let surface = parse_admin_surface(&inputs, &mut findings);
    if surface.session.is_none()
        && (inputs.session_ttl_secs.is_set()
            || inputs.session_idle_timeout_secs.is_set()
            || inputs.session_max_entries.is_set())
    {
        findings.refuse(
            ADMIN_SESSION_MAX_ENTRIES,
            ConfigRule::AdminSessionSettingsWithoutMode,
            format!("{ADMIN_SESSION_TTL_SECS}, {ADMIN_SESSION_IDLE_TIMEOUT_SECS} and {ADMIN_SESSION_MAX_ENTRIES} require {ADMIN_SESSION_MODE}=standalone_memory or cluster_postgres"),
        );
    }
    Checked::new(surface, findings)
}

fn parse_admin_surface(inputs: &AdminSurfaceInputs, findings: &mut Findings) -> AdminSurface {
    let prefix = findings.input(ADMIN_PREFIX, |problems| {
        parse_admin_prefix(
            ADMIN_PREFIX,
            inputs.prefix.value(),
            DEFAULT_ADMIN_PREFIX,
            problems,
        )
    });
    let login_provider = findings.input(ADMIN_LOGIN_PROVIDER, |problems| {
        parse_optional_string(
            ADMIN_LOGIN_PROVIDER,
            inputs.login_provider.value(),
            problems,
        )
    });
    let session_mode = findings.input(ADMIN_SESSION_MODE, |problems| {
        parse_optional_string(ADMIN_SESSION_MODE, inputs.session_mode.value(), problems)
    });
    let storage = match session_mode.as_deref() {
        None | Some("disabled") => None,
        Some("standalone_memory") => Some(AdminSessionStorage::StandaloneMemory),
        Some("cluster_postgres") => Some(AdminSessionStorage::ClusterPostgres),
        Some(_) => {
            findings.refuse(
                ADMIN_SESSION_MODE,
                ConfigRule::Value,
                format!(
                    "{ADMIN_SESSION_MODE} must be disabled, standalone_memory or cluster_postgres"
                ),
            );
            None
        }
    };
    // The session's own settings are parsed only when a mode enables a
    // session store. Otherwise, being set at all is what the block's rule
    // refuses.
    let session = storage.map(|storage| parse_admin_session(inputs, storage, findings));
    let login_pending_ttl_secs = findings.input(ADMIN_LOGIN_PENDING_TTL_SECS, |problems| {
        let ttl_secs = parse_var(
            ADMIN_LOGIN_PENDING_TTL_SECS,
            inputs.login_pending_ttl_secs.value(),
            DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            "second duration",
            problems,
        );
        validate_positive_u64(
            ADMIN_LOGIN_PENDING_TTL_SECS,
            ttl_secs,
            DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            problems,
        )
    });
    let login_pending_max_entries = findings.input(ADMIN_LOGIN_PENDING_MAX_ENTRIES, |problems| {
        let max_entries = parse_var(
            ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            inputs.login_pending_max_entries.value(),
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            "entry count",
            problems,
        );
        validate_positive_usize(
            ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            max_entries,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            problems,
        )
    });
    let login_pending_max_per_ip = findings.input(ADMIN_LOGIN_PENDING_MAX_PER_IP, |problems| {
        let max_per_ip = parse_var(
            ADMIN_LOGIN_PENDING_MAX_PER_IP,
            inputs.login_pending_max_per_ip.value(),
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            "entry count",
            problems,
        );
        validate_positive_usize(
            ADMIN_LOGIN_PENDING_MAX_PER_IP,
            max_per_ip,
            DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            problems,
        )
    });
    let public_url = findings.input(GATEWAY_PUBLIC_URL, |problems| {
        parse_optional_gateway_public_url(GATEWAY_PUBLIC_URL, inputs.public_url.value(), problems)
    });

    AdminSurface {
        prefix,
        login_provider,
        session,
        login_pending_ttl_secs,
        login_pending_max_entries,
        login_pending_max_per_ip,
        public_url,
        provenance: inputs.provenance(),
    }
}

/// The settings of the session store `ADMIN_SESSION_MODE` enables.
fn parse_admin_session(
    inputs: &AdminSurfaceInputs,
    storage: AdminSessionStorage,
    findings: &mut Findings,
) -> AdminSessionConfig {
    let ttl_secs = findings.input(ADMIN_SESSION_TTL_SECS, |problems| {
        let ttl_secs = parse_optional_var(
            ADMIN_SESSION_TTL_SECS,
            inputs.session_ttl_secs.value(),
            "second duration",
            problems,
        )
        .unwrap_or(3600);
        validate_positive_bounded_u64(ADMIN_SESSION_TTL_SECS, ttl_secs, 86_400, 3600, problems)
    });
    // Unset, the idle limit is the absolute lifetime: it never binds, which
    // is the behavior before the setting existed. Set, it may shorten that
    // lifetime but never extend it.
    let idle_timeout_secs = match findings.input(ADMIN_SESSION_IDLE_TIMEOUT_SECS, |problems| {
        parse_optional_var(
            ADMIN_SESSION_IDLE_TIMEOUT_SECS,
            inputs.session_idle_timeout_secs.value(),
            "second duration",
            problems,
        )
    }) {
        Some(idle_timeout_secs) => findings.rule(
            ADMIN_SESSION_IDLE_TIMEOUT_SECS,
            ConfigRule::AdminSessionIdleTimeoutBounds,
            |problems| {
                validate_positive_bounded_u64(
                    ADMIN_SESSION_IDLE_TIMEOUT_SECS,
                    idle_timeout_secs,
                    ttl_secs,
                    ttl_secs,
                    problems,
                )
            },
        ),
        None => ttl_secs,
    };
    let max_entries = findings.input(ADMIN_SESSION_MAX_ENTRIES, |problems| {
        let max_entries = parse_optional_var(
            ADMIN_SESSION_MAX_ENTRIES,
            inputs.session_max_entries.value(),
            "entry count",
            problems,
        )
        .unwrap_or(1024);
        validate_positive_bounded_u64(
            ADMIN_SESSION_MAX_ENTRIES,
            max_entries,
            100_000,
            1024,
            problems,
        ) as usize
    });
    AdminSessionConfig {
        storage,
        ttl: Duration::from_secs(ttl_secs),
        idle_timeout: Duration::from_secs(idle_timeout_secs),
        max_entries,
    }
}

/// The authorization exemptions' input, as the reader returned it.
pub(super) struct RbacExemptionInputs {
    exempt_paths: RawInput,
}

impl RbacExemptionInputs {
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            exempt_paths: RawInput::list_replacing_its_default(
                RBAC_EXEMPT_PATHS,
                get_var(RBAC_EXEMPT_PATHS),
            ),
        }
    }
}

/// The paths authorization exempts, before an admin session store adds its
/// own.
pub(super) struct RbacExemptions {
    paths: Vec<String>,
    provenance: Vec<Provenance>,
}

pub(super) fn compile_rbac_exemptions(
    inputs: RbacExemptionInputs,
    surface: &AdminSurface,
) -> Checked<RbacExemptions> {
    let mut findings = Findings::default();
    let provenance = vec![inputs.exempt_paths.provenance()];
    let paths = admin_exempt_paths(
        RBAC_EXEMPT_PATHS,
        &inputs.exempt_paths,
        surface,
        &mut findings,
    );
    Checked::new(RbacExemptions { paths, provenance }, findings)
}

/// The authentication block's inputs, as the reader returned them.
pub(super) struct AuthenticationInputs {
    enabled: RawInput,
    mode: RawInput,
    cookie_name: RawInput,
    exempt_paths: RawInput,
    jwt_jwks_url: RawInput,
    jwt_issuer: RawInput,
    jwt_audience: RawInput,
    jwt_jwks_timeout_ms: RawInput,
    jwt_jwks_max_key_age_secs: RawInput,
    jwt_require_jti: RawInput,
    roles_claim: RawInput,
    service_token_sqlite_path: RawInput,
    service_token_cache_ttl_ms: RawInput,
}

impl AuthenticationInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            enabled: RawInput::new(AUTH_ENABLED, get_var(AUTH_ENABLED)),
            mode: RawInput::new(AUTH_MODE, get_var(AUTH_MODE)),
            cookie_name: RawInput::new(AUTH_COOKIE_NAME, get_var(AUTH_COOKIE_NAME)),
            exempt_paths: RawInput::list_replacing_its_default(
                AUTH_EXEMPT_PATHS,
                get_var(AUTH_EXEMPT_PATHS),
            ),
            jwt_jwks_url: RawInput::new(JWT_JWKS_URL, get_var(JWT_JWKS_URL)),
            jwt_issuer: RawInput::new(JWT_ISSUER, get_var(JWT_ISSUER)),
            jwt_audience: RawInput::new(JWT_AUDIENCE, get_var(JWT_AUDIENCE)),
            jwt_jwks_timeout_ms: RawInput::new(JWT_JWKS_TIMEOUT_MS, get_var(JWT_JWKS_TIMEOUT_MS)),
            jwt_jwks_max_key_age_secs: RawInput::new(
                JWT_JWKS_MAX_KEY_AGE_SECS,
                get_var(JWT_JWKS_MAX_KEY_AGE_SECS),
            ),
            jwt_require_jti: RawInput::new(JWT_REQUIRE_JTI, get_var(JWT_REQUIRE_JTI)),
            roles_claim: RawInput::new(ROLES_CLAIM, get_var(ROLES_CLAIM)),
            service_token_sqlite_path: RawInput::new(
                SERVICE_TOKEN_SQLITE_PATH,
                get_var(SERVICE_TOKEN_SQLITE_PATH),
            ),
            service_token_cache_ttl_ms: RawInput::new(
                SERVICE_TOKEN_CACHE_TTL_MS,
                get_var(SERVICE_TOKEN_CACHE_TTL_MS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.enabled,
            &self.mode,
            &self.cookie_name,
            &self.exempt_paths,
            &self.jwt_jwks_url,
            &self.jwt_issuer,
            &self.jwt_audience,
            &self.jwt_jwks_timeout_ms,
            &self.jwt_jwks_max_key_age_secs,
            &self.jwt_require_jti,
            &self.roles_claim,
            &self.service_token_sqlite_path,
            &self.service_token_cache_ttl_ms,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// Authentication, parsed.
pub(super) struct Authentication {
    enabled: bool,
    mode: AuthMode,
    cookie_name: String,
    exempt_paths: Vec<String>,
    jwt_jwks_url: Option<String>,
    jwt_issuer: Option<String>,
    jwt_audience: Option<String>,
    jwt_jwks_timeout_ms: u64,
    jwt_jwks_max_key_age_secs: u64,
    jwt_require_jti: bool,
    roles_claim: String,
    service_token_sqlite_path: Option<String>,
    service_token_cache_ttl_ms: u64,
    provenance: Vec<Provenance>,
}

/// Parses the authentication block. Every input here is checked on its own.
pub(super) fn compile_authentication(
    inputs: AuthenticationInputs,
    surface: &AdminSurface,
) -> Checked<Authentication> {
    let mut findings = Findings::default();
    let provenance = inputs.provenance();

    let enabled = findings.input(AUTH_ENABLED, |problems| {
        parse_var(
            AUTH_ENABLED,
            inputs.enabled.value(),
            DEFAULT_AUTH_ENABLED,
            "boolean",
            problems,
        )
    });
    let mode = findings.input(AUTH_MODE, |problems| {
        parse_var(
            AUTH_MODE,
            inputs.mode.value(),
            DEFAULT_AUTH_MODE,
            "auth mode",
            problems,
        )
    });
    let cookie_name = findings.input(AUTH_COOKIE_NAME, |problems| {
        parse_cookie_name(
            AUTH_COOKIE_NAME,
            inputs.cookie_name.value(),
            DEFAULT_AUTH_COOKIE_NAME,
            problems,
        )
    });
    let exempt_paths = admin_exempt_paths(
        AUTH_EXEMPT_PATHS,
        &inputs.exempt_paths,
        surface,
        &mut findings,
    );
    let jwt_jwks_url = findings.input(JWT_JWKS_URL, |problems| {
        parse_optional_string(JWT_JWKS_URL, inputs.jwt_jwks_url.value(), problems)
    });
    let jwt_issuer = findings.input(JWT_ISSUER, |problems| {
        let issuer = parse_optional_string(JWT_ISSUER, inputs.jwt_issuer.value(), problems);
        // The issuer becomes every principal's `issuer`, which
        // authentication holds to the principal bounds; an over-long one
        // would refuse every credential at runtime, so it is refused here
        // instead.
        if issuer
            .as_deref()
            .is_some_and(|issuer| issuer.len() > MAX_PRINCIPAL_ISSUER_BYTES)
        {
            problems.push(format!(
                "{JWT_ISSUER} must be at most {MAX_PRINCIPAL_ISSUER_BYTES} bytes"
            ));
        }
        issuer
    });
    let jwt_audience = findings.input(JWT_AUDIENCE, |problems| {
        parse_optional_string(JWT_AUDIENCE, inputs.jwt_audience.value(), problems)
    });
    let jwt_jwks_timeout_ms = findings.input(JWT_JWKS_TIMEOUT_MS, |problems| {
        parse_var(
            JWT_JWKS_TIMEOUT_MS,
            inputs.jwt_jwks_timeout_ms.value(),
            DEFAULT_JWT_JWKS_TIMEOUT_MS,
            "millisecond duration",
            problems,
        )
    });
    let jwt_jwks_max_key_age_secs = findings.input(JWT_JWKS_MAX_KEY_AGE_SECS, |problems| {
        let max_key_age_secs = parse_var(
            JWT_JWKS_MAX_KEY_AGE_SECS,
            inputs.jwt_jwks_max_key_age_secs.value(),
            DEFAULT_JWT_JWKS_MAX_KEY_AGE_SECS,
            "second duration",
            problems,
        );
        validate_jwks_max_key_age(JWT_JWKS_MAX_KEY_AGE_SECS, max_key_age_secs, problems)
    });
    let jwt_require_jti = findings.input(JWT_REQUIRE_JTI, |problems| {
        parse_var(
            JWT_REQUIRE_JTI,
            inputs.jwt_require_jti.value(),
            false,
            "boolean",
            problems,
        )
    });
    let roles_claim = findings.input(ROLES_CLAIM, |problems| {
        parse_non_empty_string(
            ROLES_CLAIM,
            inputs.roles_claim.value(),
            DEFAULT_ROLES_CLAIM,
            problems,
        )
    });
    let service_token_sqlite_path = findings.input(SERVICE_TOKEN_SQLITE_PATH, |problems| {
        parse_optional_string(
            SERVICE_TOKEN_SQLITE_PATH,
            inputs.service_token_sqlite_path.value(),
            problems,
        )
    });
    let service_token_cache_ttl_ms = findings.input(SERVICE_TOKEN_CACHE_TTL_MS, |problems| {
        let ttl_ms = parse_var(
            SERVICE_TOKEN_CACHE_TTL_MS,
            inputs.service_token_cache_ttl_ms.value(),
            DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_u64(
            SERVICE_TOKEN_CACHE_TTL_MS,
            ttl_ms,
            DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            problems,
        )
    });

    Checked::new(
        Authentication {
            enabled,
            mode,
            cookie_name,
            exempt_paths,
            jwt_jwks_url,
            jwt_issuer,
            jwt_audience,
            jwt_jwks_timeout_ms,
            jwt_jwks_max_key_age_secs,
            jwt_require_jti,
            roles_claim,
            service_token_sqlite_path,
            service_token_cache_ttl_ms,
            provenance,
        },
        findings,
    )
}

/// The identity providers' and CSRF protection's inputs, as the reader
/// returned them.
pub(super) struct ProviderAndCsrfInputs {
    auth_providers: RawInput,
    csrf_enabled: RawInput,
    csrf_cookie_name: RawInput,
    csrf_header_name: RawInput,
    csrf_cookie_domain: RawInput,
    csrf_exempt_paths: RawInput,
}

impl ProviderAndCsrfInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            auth_providers: RawInput::new(AUTH_PROVIDERS, get_var(AUTH_PROVIDERS)),
            csrf_enabled: RawInput::new(CSRF_ENABLED, get_var(CSRF_ENABLED)),
            csrf_cookie_name: RawInput::new(CSRF_COOKIE_NAME, get_var(CSRF_COOKIE_NAME)),
            csrf_header_name: RawInput::new(CSRF_HEADER_NAME, get_var(CSRF_HEADER_NAME)),
            csrf_cookie_domain: RawInput::new(CSRF_COOKIE_DOMAIN, get_var(CSRF_COOKIE_DOMAIN)),
            csrf_exempt_paths: RawInput::list_replacing_its_default(
                CSRF_EXEMPT_PATHS,
                get_var(CSRF_EXEMPT_PATHS),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.auth_providers,
            &self.csrf_enabled,
            &self.csrf_cookie_name,
            &self.csrf_header_name,
            &self.csrf_cookie_domain,
            &self.csrf_exempt_paths,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The validated identity settings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct IdentityPlan {
    pub(crate) admin_prefix: String,
    pub(crate) admin_login_provider: Option<String>,
    pub(crate) admin_session: Option<AdminSessionConfig>,
    pub(crate) admin_login_pending_ttl_secs: u64,
    pub(crate) admin_login_pending_max_entries: usize,
    pub(crate) admin_login_pending_max_per_ip: usize,
    pub(crate) gateway_public_url: Option<String>,
    pub(crate) rbac_exempt_paths: Vec<String>,
    pub(crate) auth_enabled: bool,
    pub(crate) auth_mode: AuthMode,
    pub(crate) auth_cookie_name: String,
    pub(crate) auth_exempt_paths: Vec<String>,
    /// `AUTH_PROVIDERS`, or the one provider the legacy `JWT_*` settings
    /// describe when it is unset.
    pub(crate) auth_providers: Vec<AuthProviderConfig>,
    pub(crate) jwt_jwks_url: Option<String>,
    pub(crate) jwt_issuer: Option<String>,
    pub(crate) jwt_audience: Option<String>,
    pub(crate) jwt_jwks_timeout_ms: u64,
    pub(crate) jwt_jwks_max_key_age_secs: u64,
    pub(crate) jwt_require_jti: bool,
    pub(crate) roles_claim: String,
    pub(crate) service_token_sqlite_path: Option<String>,
    pub(crate) service_token_cache_ttl_ms: u64,
    pub(crate) csrf_enabled: bool,
    pub(crate) csrf_cookie_name: String,
    pub(crate) csrf_header_name: String,
    pub(crate) csrf_cookie_domain: Option<String>,
    pub(crate) csrf_exempt_paths: Vec<String>,
    /// Where each of the four blocks' inputs came from, in the order they
    /// are read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// The identity providers and CSRF settings, each parsed on its own.
struct ParsedProvidersAndCsrf {
    auth_providers: Vec<AuthProviderConfig>,
    csrf_enabled: bool,
    csrf_cookie_name: String,
    csrf_header_name: String,
    csrf_cookie_domain: Option<String>,
    csrf_exempt_paths: Vec<String>,
}

/// Parses the last identity block, then checks the rules that need all four
/// and builds the plan.
pub(super) fn compile(
    inputs: ProviderAndCsrfInputs,
    surface: AdminSurface,
    rbac: RbacExemptions,
    authentication: Authentication,
) -> Checked<IdentityPlan> {
    let mut findings = Findings::default();
    let mut provenance = Vec::new();
    provenance.extend_from_slice(&surface.provenance);
    provenance.extend_from_slice(&rbac.provenance);
    provenance.extend_from_slice(&authentication.provenance);
    provenance.extend(inputs.provenance());

    let parsed = parse_providers_and_csrf(&inputs, &authentication, &mut findings);
    let plan = validate(
        surface,
        rbac,
        authentication,
        parsed,
        provenance,
        &mut findings,
    );
    Checked::new(plan, findings)
}

fn parse_providers_and_csrf(
    inputs: &ProviderAndCsrfInputs,
    authentication: &Authentication,
    findings: &mut Findings,
) -> ParsedProvidersAndCsrf {
    // An unset or blank AUTH_PROVIDERS falls back to the provider the legacy
    // JWT settings describe; one that does not parse is refused and falls
    // back to nothing.
    let auth_providers = findings
        .input(AUTH_PROVIDERS, |problems| {
            parse_auth_providers(AUTH_PROVIDERS, inputs.auth_providers.value(), problems)
        })
        .unwrap_or_else(|| {
            legacy_auth_providers(
                authentication.jwt_jwks_url.as_deref(),
                authentication.jwt_issuer.as_deref(),
                authentication.jwt_audience.as_deref(),
                authentication.jwt_jwks_timeout_ms,
                authentication.jwt_jwks_max_key_age_secs,
                authentication.jwt_require_jti,
                &authentication.roles_claim,
            )
        });
    let csrf_enabled = findings.input(CSRF_ENABLED, |problems| {
        parse_var(
            CSRF_ENABLED,
            inputs.csrf_enabled.value(),
            DEFAULT_CSRF_ENABLED,
            "boolean",
            problems,
        )
    });
    let csrf_cookie_name = findings.input(CSRF_COOKIE_NAME, |problems| {
        parse_cookie_name(
            CSRF_COOKIE_NAME,
            inputs.csrf_cookie_name.value(),
            DEFAULT_CSRF_COOKIE_NAME,
            problems,
        )
    });
    let csrf_header_name = findings.input(CSRF_HEADER_NAME, |problems| {
        parse_header_name_string(
            CSRF_HEADER_NAME,
            inputs.csrf_header_name.value(),
            DEFAULT_CSRF_HEADER_NAME,
            problems,
        )
    });
    let csrf_cookie_domain = findings.input(CSRF_COOKIE_DOMAIN, |problems| {
        parse_optional_cookie_domain(
            CSRF_COOKIE_DOMAIN,
            inputs.csrf_cookie_domain.value(),
            problems,
        )
    });
    let csrf_exempt_paths = findings.input(CSRF_EXEMPT_PATHS, |problems| {
        parse_comma_separated_paths(
            CSRF_EXEMPT_PATHS,
            inputs.csrf_exempt_paths.value(),
            &default_paths(DEFAULT_CSRF_EXEMPT_PATHS),
            problems,
        )
    });

    ParsedProvidersAndCsrf {
        auth_providers,
        csrf_enabled,
        csrf_cookie_name,
        csrf_header_name,
        csrf_cookie_domain,
        csrf_exempt_paths,
    }
}

/// The rules between the identity blocks: the admin login must name a usable
/// provider, and an admin session store needs the login, authentication and
/// CSRF protection it relies on and adds its own exempt routes.
fn validate(
    surface: AdminSurface,
    rbac: RbacExemptions,
    authentication: Authentication,
    parsed: ParsedProvidersAndCsrf,
    provenance: Vec<Provenance>,
    findings: &mut Findings,
) -> IdentityPlan {
    let AdminSurface {
        prefix: admin_prefix,
        login_provider: admin_login_provider,
        session: admin_session,
        login_pending_ttl_secs: admin_login_pending_ttl_secs,
        login_pending_max_entries: admin_login_pending_max_entries,
        login_pending_max_per_ip: admin_login_pending_max_per_ip,
        public_url: gateway_public_url,
        provenance: _,
    } = surface;
    let Authentication {
        enabled: auth_enabled,
        mode: auth_mode,
        cookie_name: auth_cookie_name,
        exempt_paths: mut auth_exempt_paths,
        jwt_jwks_url,
        jwt_issuer,
        jwt_audience,
        jwt_jwks_timeout_ms,
        jwt_jwks_max_key_age_secs,
        jwt_require_jti,
        roles_claim,
        service_token_sqlite_path,
        service_token_cache_ttl_ms,
        provenance: _,
    } = authentication;
    let ParsedProvidersAndCsrf {
        auth_providers,
        csrf_enabled,
        csrf_cookie_name,
        csrf_header_name,
        csrf_cookie_domain,
        csrf_exempt_paths,
    } = parsed;
    let mut rbac_exempt_paths = rbac.paths;

    findings.rule(
        AUTH_PROVIDERS,
        ConfigRule::AdminLoginProviderUnusable,
        |problems| {
            validate_admin_login_provider(
                admin_login_provider.as_deref(),
                &auth_providers,
                problems,
            )
        },
    );
    if let Some(mode) = admin_session
        .as_ref()
        .map(|session| session.storage.as_str())
    {
        if admin_login_provider.is_none()
            || !auth_enabled
            || auth_mode != AuthMode::Required
            || !csrf_enabled
        {
            findings.refuse(
                CSRF_EXEMPT_PATHS,
                ConfigRule::AdminSessionRequirements,
                format!("{ADMIN_SESSION_MODE}={mode} requires {ADMIN_LOGIN_PROVIDER}, {AUTH_ENABLED}=true, {AUTH_MODE}=required and {CSRF_ENABLED}=true"),
            );
        }
        if let Some(provider) = auth_providers
            .iter()
            .find(|provider| Some(provider.name.as_str()) == admin_login_provider.as_deref())
        {
            if !provider
                .redirect_uri
                .as_deref()
                .is_some_and(|uri| uri.starts_with("https://"))
            {
                findings.refuse(
                    CSRF_EXEMPT_PATHS,
                    ConfigRule::AdminSessionRequirements,
                    format!(
                        "{ADMIN_SESSION_MODE}={mode} requires an HTTPS admin login redirect_uri"
                    ),
                );
            }
        }
        let api_prefix = format!("/v1{admin_prefix}");
        if csrf_exempt_paths
            .iter()
            .any(|path| path == &api_prefix || path.starts_with(&format!("{api_prefix}/")))
        {
            findings.refuse(
                CSRF_EXEMPT_PATHS,
                ConfigRule::AdminSessionCsrfExemption,
                format!(
                    "{CSRF_EXEMPT_PATHS} cannot exempt admin API routes while {ADMIN_SESSION_MODE}={mode}"
                ),
            );
        }
        // Logout is usable after expiry, but always checks its own exact
        // origin and configured CSRF pair before revoking/clearing anything.
        for route in ["logout", "config"] {
            let path = format!("{api_prefix}/auth/{route}");
            auth_exempt_paths.push(path.clone());
            rbac_exempt_paths.push(path);
        }
    }

    IdentityPlan {
        admin_prefix,
        admin_login_provider,
        admin_session,
        admin_login_pending_ttl_secs,
        admin_login_pending_max_entries,
        admin_login_pending_max_per_ip,
        gateway_public_url,
        rbac_exempt_paths,
        auth_enabled,
        auth_mode,
        auth_cookie_name,
        auth_exempt_paths,
        auth_providers,
        jwt_jwks_url,
        jwt_issuer,
        jwt_audience,
        jwt_jwks_timeout_ms,
        jwt_jwks_max_key_age_secs,
        jwt_require_jti,
        roles_claim,
        service_token_sqlite_path,
        service_token_cache_ttl_ms,
        csrf_enabled,
        csrf_cookie_name,
        csrf_header_name,
        csrf_cookie_domain,
        csrf_exempt_paths,
        provenance,
    }
}

/// An exempt-path list whose default, and whose additions, follow the admin
/// surface: the default exempts the admin prefix, and while an admin login
/// provider is set its login and callback routes are added even to an
/// explicit list.
fn admin_exempt_paths(
    setting: &'static str,
    input: &RawInput,
    surface: &AdminSurface,
    findings: &mut Findings,
) -> Vec<String> {
    let login_enabled = surface.login_enabled();
    let mut paths = findings.input(setting, |problems| {
        parse_comma_separated_paths(
            setting,
            input.value(),
            &default_admin_exempt_paths(&surface.prefix, login_enabled),
            problems,
        )
    });
    append_admin_login_exempt_paths(&mut paths, &surface.prefix, login_enabled);
    paths
}
