//! Connections and their secret material, compiled in pure stages (issue
//! #433, PR 2).
//!
//! One block, [`ConnectionInputs`]: the Connections store, the secrets root,
//! the operator secret aliases, the three keyrings and the five network
//! secret providers. The admin login and rate-limit keyrings sit here because
//! they share the Connections key-file shape and `CONNECTION_SECRETS_ROOT`;
//! whether the state backend reads them at all is a storage rule, checked in
//! `storage` once the backend is read.
//!
//! Everything here is a locator: an alias names the variable or file that
//! holds a secret, a keyring names its key files beneath the root, and a
//! provider document names where its profiles authenticate and what they
//! read. Nothing here opens the root or a key file, reads an aliased
//! variable, or reaches a provider; a root that does not exist is accepted
//! exactly as the legacy parser accepts it, and loading is activation's work.
//! Every type the plan holds prints these locators redacted or as counts.

use std::{collections::BTreeSet, env::VarError};

use super::{
    diagnostic::ConfigRule,
    parse_aws_provider_config, parse_azure_provider_config, parse_gcp_provider_config,
    parse_kubernetes_provider_config, parse_local_secret_keyring, parse_operator_secret_aliases,
    parse_optional_secret_root, parse_optional_string, parse_vault_provider_config,
    stage::{Checked, Findings, Provenance, RawInput},
    ADMIN_LOGIN_KEYRING, CONNECTIONS_SQLITE_PATH, CONNECTION_AWS_PROVIDER,
    CONNECTION_AZURE_PROVIDER, CONNECTION_GCP_PROVIDER, CONNECTION_KUBERNETES_PROVIDER,
    CONNECTION_LOCAL_SECRET_KEYRING, CONNECTION_SECRETS_ROOT, CONNECTION_SECRET_ALIASES,
    CONNECTION_VAULT_PROVIDER, RATE_LIMIT_KEYRING,
};
use crate::connections::{
    aws_secret::{validate_aws_provider_config, AwsProviderConfig, AwsProviderConfigError},
    azure_secret::{validate_azure_provider_config, AzureProviderConfig, AzureProviderConfigError},
    gcp_secret::{validate_gcp_provider_config, GcpProviderConfig, GcpProviderConfigError},
    kubernetes_secret::{
        validate_kubernetes_provider_config, KubernetesProviderConfig,
        KubernetesProviderConfigError,
    },
    local_secret::{
        validate_local_secret_keyring_config, LocalSecretKeyConfig, LocalSecretKeyringConfigError,
    },
    secret::{
        validate_operator_secret_alias_config, OperatorSecretAliasConfig,
        SecretProviderConfigError, SecretRootConfig,
    },
    vault_secret::{validate_vault_provider_config, VaultProviderConfig, VaultProviderConfigError},
};

/// The Connections block's inputs, as the reader returned them.
pub(super) struct ConnectionInputs {
    sqlite_path: RawInput,
    secrets_root: RawInput,
    secret_aliases: RawInput,
    local_secret_keyring: RawInput,
    admin_login_keyring: RawInput,
    rate_limit_keyring: RawInput,
    vault_provider: RawInput,
    gcp_provider: RawInput,
    azure_provider: RawInput,
    aws_provider: RawInput,
    kubernetes_provider: RawInput,
}

impl ConnectionInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            sqlite_path: RawInput::new(CONNECTIONS_SQLITE_PATH, get_var(CONNECTIONS_SQLITE_PATH)),
            secrets_root: RawInput::new(CONNECTION_SECRETS_ROOT, get_var(CONNECTION_SECRETS_ROOT)),
            secret_aliases: RawInput::new(
                CONNECTION_SECRET_ALIASES,
                get_var(CONNECTION_SECRET_ALIASES),
            ),
            local_secret_keyring: RawInput::new(
                CONNECTION_LOCAL_SECRET_KEYRING,
                get_var(CONNECTION_LOCAL_SECRET_KEYRING),
            ),
            admin_login_keyring: RawInput::new(ADMIN_LOGIN_KEYRING, get_var(ADMIN_LOGIN_KEYRING)),
            rate_limit_keyring: RawInput::new(RATE_LIMIT_KEYRING, get_var(RATE_LIMIT_KEYRING)),
            vault_provider: RawInput::new(
                CONNECTION_VAULT_PROVIDER,
                get_var(CONNECTION_VAULT_PROVIDER),
            ),
            gcp_provider: RawInput::new(CONNECTION_GCP_PROVIDER, get_var(CONNECTION_GCP_PROVIDER)),
            azure_provider: RawInput::new(
                CONNECTION_AZURE_PROVIDER,
                get_var(CONNECTION_AZURE_PROVIDER),
            ),
            aws_provider: RawInput::new(CONNECTION_AWS_PROVIDER, get_var(CONNECTION_AWS_PROVIDER)),
            kubernetes_provider: RawInput::new(
                CONNECTION_KUBERNETES_PROVIDER,
                get_var(CONNECTION_KUBERNETES_PROVIDER),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.sqlite_path,
            &self.secrets_root,
            &self.secret_aliases,
            &self.local_secret_keyring,
            &self.admin_login_keyring,
            &self.rate_limit_keyring,
            &self.vault_provider,
            &self.gcp_provider,
            &self.azure_provider,
            &self.aws_provider,
            &self.kubernetes_provider,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// The validated Connections settings.
///
/// The derived `Debug` is safe: the secrets root, every alias's source, every
/// key's ID and file and every provider document print redacted or as counts,
/// by their own `Debug`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConnectionsPlan {
    pub(crate) connections_sqlite_path: Option<String>,
    pub(crate) connection_secrets_root: Option<SecretRootConfig>,
    pub(crate) connection_secret_aliases: Vec<OperatorSecretAliasConfig>,
    pub(crate) connection_local_secret_keyring: Vec<LocalSecretKeyConfig>,
    pub(crate) admin_login_keyring: Vec<LocalSecretKeyConfig>,
    pub(crate) rate_limit_keyring: Vec<LocalSecretKeyConfig>,
    pub(crate) connection_vault_provider: VaultProviderConfig,
    pub(crate) connection_gcp_provider: GcpProviderConfig,
    pub(crate) connection_azure_provider: AzureProviderConfig,
    pub(crate) connection_aws_provider: AwsProviderConfig,
    pub(crate) connection_kubernetes_provider: KubernetesProviderConfig,
    /// Where each of the block's inputs came from, in the order they are read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// Parses the Connections block, then checks the rules between its inputs:
/// file aliases and keyrings need the secrets root, the local keyring needs
/// the Connections store it encrypts, and no provider alias may reuse an
/// operator alias's ID.
///
/// Each validator also refuses an entry on its own terms -- an ID, a label, a
/// key or a profile that is malformed or repeated -- and reports only the
/// first thing it refuses, exactly as before. Such a refusal is the input's
/// own value; only the cross-input refusals carry a rule of their own.
pub(super) fn compile(inputs: ConnectionInputs) -> Checked<ConnectionsPlan> {
    let mut findings = Findings::default();
    let provenance = inputs.provenance();

    let connections_sqlite_path = findings.input(CONNECTIONS_SQLITE_PATH, |problems| {
        parse_optional_string(
            CONNECTIONS_SQLITE_PATH,
            inputs.sqlite_path.value(),
            problems,
        )
    });
    let connection_secrets_root = findings.input(CONNECTION_SECRETS_ROOT, |problems| {
        parse_optional_secret_root(
            CONNECTION_SECRETS_ROOT,
            inputs.secrets_root.value(),
            problems,
        )
    });
    let connection_secret_aliases = findings.input(CONNECTION_SECRET_ALIASES, |problems| {
        parse_operator_secret_aliases(
            CONNECTION_SECRET_ALIASES,
            inputs.secret_aliases.value(),
            problems,
        )
    });
    let connection_local_secret_keyring =
        findings.input(CONNECTION_LOCAL_SECRET_KEYRING, |problems| {
            parse_local_secret_keyring(
                CONNECTION_LOCAL_SECRET_KEYRING,
                inputs.local_secret_keyring.value(),
                problems,
            )
        });
    let admin_login_keyring = findings.input(ADMIN_LOGIN_KEYRING, |problems| {
        parse_local_secret_keyring(
            ADMIN_LOGIN_KEYRING,
            inputs.admin_login_keyring.value(),
            problems,
        )
    });
    let rate_limit_keyring = findings.input(RATE_LIMIT_KEYRING, |problems| {
        parse_local_secret_keyring(
            RATE_LIMIT_KEYRING,
            inputs.rate_limit_keyring.value(),
            problems,
        )
    });
    let connection_vault_provider = findings.input(CONNECTION_VAULT_PROVIDER, |problems| {
        parse_vault_provider_config(
            CONNECTION_VAULT_PROVIDER,
            inputs.vault_provider.value(),
            problems,
        )
    });
    let connection_gcp_provider = findings.input(CONNECTION_GCP_PROVIDER, |problems| {
        parse_gcp_provider_config(
            CONNECTION_GCP_PROVIDER,
            inputs.gcp_provider.value(),
            problems,
        )
    });
    let connection_azure_provider = findings.input(CONNECTION_AZURE_PROVIDER, |problems| {
        parse_azure_provider_config(
            CONNECTION_AZURE_PROVIDER,
            inputs.azure_provider.value(),
            problems,
        )
    });
    let connection_aws_provider = findings.input(CONNECTION_AWS_PROVIDER, |problems| {
        parse_aws_provider_config(
            CONNECTION_AWS_PROVIDER,
            inputs.aws_provider.value(),
            problems,
        )
    });
    let connection_kubernetes_provider =
        findings.input(CONNECTION_KUBERNETES_PROVIDER, |problems| {
            parse_kubernetes_provider_config(
                CONNECTION_KUBERNETES_PROVIDER,
                inputs.kubernetes_provider.value(),
                problems,
            )
        });

    let secrets_root_configured = connection_secrets_root.is_some();
    if let Err(error) =
        validate_operator_secret_alias_config(&connection_secret_aliases, secrets_root_configured)
    {
        let rule = if matches!(error, SecretProviderConfigError::SecretsRootRequired { .. }) {
            ConfigRule::SecretsRootRequired
        } else {
            ConfigRule::Value
        };
        findings.refuse(
            CONNECTION_SECRET_ALIASES,
            rule,
            format!("{CONNECTION_SECRET_ALIASES}: {error}"),
        );
    }
    check_keyring(
        CONNECTION_LOCAL_SECRET_KEYRING,
        &connection_local_secret_keyring,
        secrets_root_configured,
        connections_sqlite_path.is_some(),
        &mut findings,
    );
    // The login keyring seals rows in PostgreSQL, so it needs the secrets
    // root for its key files but no local store.
    check_keyring(
        ADMIN_LOGIN_KEYRING,
        &admin_login_keyring,
        secrets_root_configured,
        true,
        &mut findings,
    );
    // The rate-limit keyring signs bucket keys stored in PostgreSQL, so it
    // needs the secrets root for its key files but no local store.
    check_keyring(
        RATE_LIMIT_KEYRING,
        &rate_limit_keyring,
        secrets_root_configured,
        true,
        &mut findings,
    );

    // The network providers' aliases share one namespace with the operator
    // aliases, so a duplicate ID fails closed at startup rather than letting
    // resolution order decide which provider answers. Duplicates between two
    // network providers are refused by the connection control plane's
    // collision guard instead.
    let reserved_alias_ids = connection_secret_aliases
        .iter()
        .map(|alias| alias.id.clone())
        .collect::<BTreeSet<_>>();
    if let Err(error) =
        validate_vault_provider_config(&connection_vault_provider, &reserved_alias_ids)
    {
        let reserved = matches!(error, VaultProviderConfigError::ReservedAliasId { .. });
        refuse_provider(CONNECTION_VAULT_PROVIDER, reserved, &error, &mut findings);
    }
    if let Err(error) = validate_gcp_provider_config(&connection_gcp_provider, &reserved_alias_ids)
    {
        let reserved = matches!(error, GcpProviderConfigError::ReservedAliasId { .. });
        refuse_provider(CONNECTION_GCP_PROVIDER, reserved, &error, &mut findings);
    }
    if let Err(error) =
        validate_azure_provider_config(&connection_azure_provider, &reserved_alias_ids)
    {
        let reserved = matches!(error, AzureProviderConfigError::ReservedAliasId { .. });
        refuse_provider(CONNECTION_AZURE_PROVIDER, reserved, &error, &mut findings);
    }
    if let Err(error) = validate_aws_provider_config(&connection_aws_provider, &reserved_alias_ids)
    {
        let reserved = matches!(error, AwsProviderConfigError::ReservedAliasId { .. });
        refuse_provider(CONNECTION_AWS_PROVIDER, reserved, &error, &mut findings);
    }
    if let Err(error) =
        validate_kubernetes_provider_config(&connection_kubernetes_provider, &reserved_alias_ids)
    {
        let reserved = matches!(error, KubernetesProviderConfigError::ReservedAliasId { .. });
        refuse_provider(
            CONNECTION_KUBERNETES_PROVIDER,
            reserved,
            &error,
            &mut findings,
        );
    }

    Checked::new(
        ConnectionsPlan {
            connections_sqlite_path,
            connection_secrets_root,
            connection_secret_aliases,
            connection_local_secret_keyring,
            admin_login_keyring,
            rate_limit_keyring,
            connection_vault_provider,
            connection_gcp_provider,
            connection_azure_provider,
            connection_aws_provider,
            connection_kubernetes_provider,
            provenance,
        },
        findings,
    )
}

/// A keyring's key files live beneath the secrets root, and the local keyring
/// also needs the store whose rows it encrypts.
fn check_keyring(
    setting: &'static str,
    keyring: &[LocalSecretKeyConfig],
    secrets_root_configured: bool,
    managed_store_configured: bool,
    findings: &mut Findings,
) {
    if let Err(error) = validate_local_secret_keyring_config(
        keyring,
        secrets_root_configured,
        managed_store_configured,
    ) {
        let rule = match error {
            LocalSecretKeyringConfigError::SecretsRootRequired => ConfigRule::SecretsRootRequired,
            LocalSecretKeyringConfigError::ManagedStoreRequired => {
                ConfigRule::LocalKeyringRequiresConnectionsStore
            }
            _ => ConfigRule::Value,
        };
        findings.refuse(setting, rule, format!("{setting}: {error}"));
    }
}

/// A provider document the validator refused: for reusing an operator
/// alias's ID, or on its own terms.
fn refuse_provider(
    setting: &'static str,
    reserved_alias_id: bool,
    error: &impl std::fmt::Display,
    findings: &mut Findings,
) {
    let rule = if reserved_alias_id {
        ConfigRule::SecretAliasIdReserved
    } else {
        ConfigRule::Value
    };
    findings.refuse(setting, rule, format!("{setting}: {error}"));
}
