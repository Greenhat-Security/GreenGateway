//! Value-free configuration diagnostics (issue #433, PR 1).
//!
//! A `ConfigError`'s problems are the operator-facing report. They name the
//! setting and, where it helps, quote the value that was refused, which is
//! right for a gateway describing its own environment and wrong for anything
//! that must not echo one: an import reading another deployment's settings,
//! or the validation and doctor flows of issue #242.
//!
//! A [`ConfigDiagnostic`] is the same report without the values. There is one
//! per problem, in the same order. Each names the inventoried variable its
//! problem begins with, carries a code read from how that variable was looked
//! up, and has a message built from those two and fixed text alone. Nothing
//! in it is copied from a value or from the problem's wording, so it is
//! value-free by construction rather than by redaction: there is no pattern
//! to miss.
//!
//! The code describes the input, not the rule that refused it. The rule is a
//! separate field, assigned by the configuration compiler's stages where each
//! rule is checked (issue #433, PR 2). Every problem is now found by one of
//! those stages and reaches the [`Report`] with the [`ConfigRule`] that
//! refused it, so every diagnostic names its rule. Neither changes a word of
//! the problems themselves.

use std::{collections::BTreeMap, env::VarError};

use super::inventory;

/// How one variable came back when `Config::from_env_vars` looked it up.
/// Never its value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupState {
    Unset,
    Empty,
    NotUnicode,
    Set,
}

/// How every inventoried variable `Config::from_env_vars` requested came
/// back.
#[derive(Default)]
pub(super) struct Lookups {
    states: BTreeMap<&'static str, LookupState>,
}

impl Lookups {
    /// Remembers how `name` came back.
    ///
    /// A name outside the inventory is not recorded. No problem can be
    /// attributed to one, and the inventory tests fail before a read the
    /// inventory does not list can ship.
    pub(super) fn record(&mut self, name: &str, value: &Result<String, VarError>) {
        let Some(name) = inventory::config_input(name) else {
            return;
        };
        let state = match value {
            Ok(value) if value.trim().is_empty() => LookupState::Empty,
            Ok(_) => LookupState::Set,
            Err(VarError::NotPresent) => LookupState::Unset,
            Err(VarError::NotUnicode(_)) => LookupState::NotUnicode,
        };
        self.states.insert(name, state);
    }

    /// A variable `from_env_vars` never requested had no effect on the
    /// parse, which is also what an unset one has.
    fn state(&self, name: &str) -> LookupState {
        self.states.get(name).copied().unwrap_or(LookupState::Unset)
    }
}

/// What a diagnostic records about the input its problem names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigDiagnosticCode {
    /// The variable is not set.
    Unset,
    /// The variable is set to an empty or whitespace-only value.
    Empty,
    /// The variable's value is not valid Unicode.
    NotUnicode,
    /// The variable is set to a value that was refused, on its own or in
    /// combination with another setting.
    Refused,
    /// The problem does not begin with an inventoried variable. No problem
    /// the parser records today has that shape; the code exists so such a
    /// problem would still be reported, rather than dropped or echoed.
    Unattributed,
}

/// The check that refused a problem one of the configuration compiler's
/// stages reports (issue #433, PR 2).
///
/// [`ConfigRule::Value`] is the refusal of one input's value on its own: it
/// does not parse, is out of bounds, or is not one of the accepted words.
/// Every other rule relates inputs, and is named for what it requires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigRule {
    /// The input's own value was refused.
    Value,
    /// `ADMIN_LISTEN_ADDR` resolves to the data listener's address.
    AdminListenerCollision,
    /// `GRPC_LISTEN_ADDR` resolves to the data or the admin listener's
    /// address.
    GrpcListenerCollision,
    /// A listener's certificate and private key files are not set together,
    /// or are not paired one key per certificate chain.
    TlsMaterialUnpaired,
    /// Admin TLS material is set without a separate admin listener to
    /// terminate it.
    AdminTlsWithoutAdminListener,
    /// A listener's client-certificate authentication is incomplete: its
    /// mode is on without TLS, a CA bundle or an identity source, or its CA or
    /// CRL file is set while its mode is `off`.
    ClientCertificateAuth,
    /// A client-certificate identity source is set while both listeners'
    /// modes are `off`.
    ClientCertIdentitySourceUnused,
    /// Admin session settings are set without a session mode that reads
    /// them.
    AdminSessionSettingsWithoutMode,
    /// `ADMIN_SESSION_IDLE_TIMEOUT_SECS` is not between 1 and the session's
    /// absolute lifetime, `ADMIN_SESSION_TTL_SECS`.
    AdminSessionIdleTimeoutBounds,
    /// `ADMIN_LOGIN_PROVIDER` names a provider that cannot serve the admin
    /// login.
    AdminLoginProviderUnusable,
    /// An admin session store is on without the login, authentication, CSRF
    /// protection or HTTPS redirect it relies on.
    AdminSessionRequirements,
    /// `CSRF_EXEMPT_PATHS` exempts admin API routes while an admin session
    /// store is on.
    AdminSessionCsrfExemption,
    /// `TRUST_PROXY_HEADERS` is on without a trusted proxy network.
    TrustedProxyNetworksRequired,
    /// An upstream route's cookie-session delegation is not backed by the
    /// authentication and CSRF settings it relies on, or overlaps an
    /// exemption.
    CookieSessionDelegation,
    /// `UPSTREAM_URL` and `UPSTREAM_ROUTES` are both set.
    UpstreamRoutingSourcesExclusive,
    /// A host-bound upstream route is configured without `POLICY_FILE`.
    HostRoutesRequirePolicy,
    /// A file-backed operator secret alias, or a keyring, is set without
    /// `CONNECTION_SECRETS_ROOT`, the directory its files are read from.
    SecretsRootRequired,
    /// `CONNECTION_LOCAL_SECRET_KEYRING` is set without
    /// `CONNECTIONS_SQLITE_PATH`, the store whose secrets it encrypts.
    LocalKeyringRequiresConnectionsStore,
    /// A secret provider's alias reuses the ID of an operator secret alias;
    /// the providers share one alias namespace.
    SecretAliasIdReserved,
    /// `CLUSTER_MEMBER_STALE_MS` is shorter than the heartbeats a live
    /// replica must be allowed to miss, a multiple of `CLUSTER_HEARTBEAT_MS`.
    ClusterMemberStaleWindow,
    /// `STATE_BACKEND=postgres` without a setting cluster mode requires: the
    /// deployment ID, the database URL file, the rate-limit keyring, or the
    /// admin login keyring while an admin login provider is set.
    ClusterModeRequirements,
    /// A local file or SQLite store is set while `STATE_BACKEND=postgres`,
    /// where PostgreSQL is the single authority.
    LocalAuthorityInClusterMode,
    /// `ADMIN_SESSION_MODE` names a session store the state backend cannot
    /// host.
    AdminSessionStoreBackend,
    /// A setting only cluster mode reads is set while `STATE_BACKEND` is
    /// `sqlite`.
    ClusterSettingInStandaloneMode,
    /// `PAYLOAD_CAPTURE_ENABLED` is on in standalone mode without
    /// `DISCOVERY_SQLITE_PATH` to store the captured shapes.
    PayloadCaptureDestination,
    /// Cluster mode's authority-event delivery settings do not fit
    /// together: a sink without the pseudonym key it needs, a file sink
    /// without its file, a file or key set for a sink that never reads it,
    /// or the same alias as the current and the previous key.
    AuthorityEventDelivery,
}

/// The problems the compiler's stages found, each with the rule that refused
/// it, in the order they are reported.
///
/// The one way in is [`Report::push`], which takes a problem and its rule
/// together, so the two lists stay one for one.
#[derive(Default)]
pub(super) struct Report {
    problems: Vec<String>,
    rules: Vec<ConfigRule>,
}

impl Report {
    pub(super) fn push(&mut self, rule: ConfigRule, problem: String) {
        self.rules.push(rule);
        self.problems.push(problem);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.problems.is_empty()
    }

    #[cfg(test)]
    pub(super) fn problems(&self) -> &[String] {
        &self.problems
    }

    #[cfg(test)]
    pub(super) fn rules(&self) -> &[ConfigRule] {
        &self.rules
    }

    /// The operator-facing problems, and one diagnostic per problem in the
    /// same order.
    pub(super) fn into_problems_and_diagnostics(
        self,
        lookups: &Lookups,
    ) -> (Vec<String>, Vec<ConfigDiagnostic>) {
        let diagnostics = self
            .problems
            .iter()
            .zip(&self.rules)
            .map(|(problem, rule)| diagnostic(problem, lookups, *rule))
            .collect();
        (self.problems, diagnostics)
    }
}

/// One configuration problem, without the value that caused it.
#[allow(dead_code)] // Fields are read by the parity tests until the #433 compiler reads them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConfigDiagnostic {
    /// The inventoried variable the problem begins with, or `None` when it
    /// begins with none.
    pub(crate) variable: Option<&'static str>,
    pub(crate) code: ConfigDiagnosticCode,
    /// The rule that refused the problem.
    pub(crate) rule: ConfigRule,
    /// Built from `variable`, `code` and fixed text only.
    pub(crate) message: String,
}

fn diagnostic(problem: &str, lookups: &Lookups, rule: ConfigRule) -> ConfigDiagnostic {
    let Some(variable) = attributed_variable(problem) else {
        return ConfigDiagnostic {
            variable: None,
            code: ConfigDiagnosticCode::Unattributed,
            rule,
            message: "a configuration problem names no inventoried setting".to_owned(),
        };
    };
    let (code, message) = match lookups.state(variable) {
        LookupState::Unset => (
            ConfigDiagnosticCode::Unset,
            format!("{variable} is not set"),
        ),
        LookupState::Empty => (
            ConfigDiagnosticCode::Empty,
            format!("{variable} is set but empty"),
        ),
        LookupState::NotUnicode => (
            ConfigDiagnosticCode::NotUnicode,
            format!("{variable} is not valid Unicode"),
        ),
        LookupState::Set => (
            ConfigDiagnosticCode::Refused,
            format!("{variable} is set to a value that was refused"),
        ),
    };
    ConfigDiagnostic {
        variable: Some(variable),
        code,
        rule,
        message,
    }
}

/// The inventoried variable a problem begins with.
///
/// Every problem the parser records starts with the name of the setting it is
/// about, followed by a space, `=`, `:`, `[` or `.` -- `FOO must be ...`,
/// `FOO=true requires ...`, `FOO[0].field ...`. The leading run of name
/// characters is looked up in the inventory, so the result is always one of
/// the inventory's own names and never text taken from the problem.
fn attributed_variable(problem: &str) -> Option<&'static str> {
    let end = problem
        .find(|character: char| {
            !(character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_')
        })
        .unwrap_or(problem.len());
    inventory::config_input(&problem[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_that_names_no_inventoried_setting_is_reported_without_its_text() {
        let mut report = Report::default();
        report.push(
            ConfigRule::Value,
            "lowercase lead quoting 'zqcanary-value'".to_owned(),
        );
        report.push(
            ConfigRule::ClusterModeRequirements,
            "NOT_A_GATEWAY_SETTING must be 'zqcanary-value'".to_owned(),
        );
        let (problems, diagnostics) = report.into_problems_and_diagnostics(&Lookups::default());

        assert_eq!(problems.len(), 2);
        assert_eq!(diagnostics.len(), 2);
        for diagnostic in &diagnostics {
            assert_eq!(diagnostic.variable, None);
            assert_eq!(diagnostic.code, ConfigDiagnosticCode::Unattributed);
            assert_eq!(
                diagnostic.message,
                "a configuration problem names no inventoried setting"
            );
        }
        // The rule travels with its problem.
        assert_eq!(diagnostics[0].rule, ConfigRule::Value);
        assert_eq!(diagnostics[1].rule, ConfigRule::ClusterModeRequirements);
    }

    #[test]
    fn attribution_takes_the_whole_leading_name_and_nothing_after_it() {
        for (problem, expected) in [
            ("LISTEN_ADDR must be a valid socket address", "LISTEN_ADDR"),
            (
                "ADMIN_SESSION_MODE=standalone_memory requires ADMIN_LOGIN_PROVIDER",
                "ADMIN_SESSION_MODE",
            ),
            ("UPSTREAM_ROUTES[0].id is required", "UPSTREAM_ROUTES"),
            (
                "CONNECTION_SECRET_ALIASES: invalid file key",
                "CONNECTION_SECRET_ALIASES",
            ),
            ("AUTH_PROVIDERS", "AUTH_PROVIDERS"),
        ] {
            assert_eq!(attributed_variable(problem), Some(expected), "{problem}");
        }
        // A prefix of a name is not the name.
        assert_eq!(attributed_variable("ADMIN_LISTEN must be set"), None);
        assert_eq!(attributed_variable(""), None);
    }

    #[test]
    fn a_requested_variable_is_reported_by_how_it_came_back() {
        let mut lookups = Lookups::default();
        lookups.record("LISTEN_ADDR", &Err(VarError::NotPresent));
        lookups.record("AUTH_MODE", &Ok(" \t ".to_owned()));
        lookups.record("AUTH_ENABLED", &Ok("maybe".to_owned()));
        // Not an inventoried name, so never recorded.
        lookups.record("NOT_A_GATEWAY_SETTING", &Ok("value".to_owned()));

        assert_eq!(lookups.state("LISTEN_ADDR"), LookupState::Unset);
        assert_eq!(lookups.state("AUTH_MODE"), LookupState::Empty);
        assert_eq!(lookups.state("AUTH_ENABLED"), LookupState::Set);
        assert_eq!(lookups.state("ADMIN_PREFIX"), LookupState::Unset);
        assert_eq!(lookups.states.len(), 3);
    }
}
