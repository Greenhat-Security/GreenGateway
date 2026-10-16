//! Fixtures for tests that need an enabled Connection with a caller assertion.
//!
//! An enabled Connection's caller-assertion keys are resolved and loaded when
//! it is saved or loaded, so a fixture needs a real key behind its alias. Keys
//! are generated per test: no private key material belongs in this tree.

use std::{
    fs,
    path::{Path, PathBuf},
};

use super::secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig};
use crate::config::Config;

/// The alias caller-assertion fixtures bind their signing key under.
pub(crate) const ASSERTION_SIGNING_KEY_ALIAS: &str = "assertion-signing-key";

/// A freshly generated P-256 key as one PKCS#8 PEM block.
pub(crate) fn generated_es256_pem() -> String {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("P-256 key generates")
        .serialize_pem()
}

/// A freshly generated RSA-2048 key as one PKCS#8 PEM block.
///
/// `rcgen` is built on ring here, which cannot generate RSA keys, so aws-lc-rs
/// -- already linked as `jsonwebtoken`'s backend -- generates it and `rcgen`
/// only wraps its DER as PEM.
pub(crate) fn generated_rs256_pem() -> String {
    use aws_lc_rs::encoding::AsDer;

    let generated = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
        .expect("RSA-2048 key generates");
    let pkcs8 = generated
        .as_der()
        .expect("generated RSA key encodes as PKCS#8")
        .as_ref()
        .to_vec();
    rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8),
        &rcgen::PKCS_RSA_SHA256,
    )
    .expect("generated RSA key loads")
    .serialize_pem()
}

/// The base64 lines of a PEM document: each is a fragment of the key, so none
/// may appear in any error, log line or audit event.
pub(crate) fn pem_body_lines(pem: &str) -> Vec<&str> {
    pem.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect()
}

/// Writes `pem` into the secrets root `root` as the file behind
/// [`ASSERTION_SIGNING_KEY_ALIAS`], with the permissions an operator file alias
/// requires, and returns that alias.
pub(crate) fn write_assertion_signing_key(root: &Path, pem: &str) -> OperatorSecretAliasConfig {
    let path = root.join(ASSERTION_SIGNING_KEY_ALIAS);
    fs::write(&path, pem).expect("assertion signing key should write");
    restrict(&path, 0o600);
    OperatorSecretAliasConfig {
        id: ASSERTION_SIGNING_KEY_ALIAS.to_owned(),
        label: "Caller assertion signing key".to_owned(),
        source: OperatorSecretAliasSource::File {
            key: ASSERTION_SIGNING_KEY_ALIAS.to_owned(),
        },
    }
}

/// A secrets root of its own holding a generated signing key, for a test that
/// has no root yet. Removed on drop.
pub(crate) struct AssertionSigningKeyRoot {
    root: PathBuf,
    pem: String,
}

impl AssertionSigningKeyRoot {
    pub(crate) fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-assertion-signing-key-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("assertion signing key root should create");
        restrict(&root, 0o700);
        let pem = generated_es256_pem();
        let path = root.join(ASSERTION_SIGNING_KEY_ALIAS);
        fs::write(&path, &pem).expect("assertion signing key should write");
        restrict(&path, 0o600);
        Self { root, pem }
    }

    /// Points `config` at this root and binds [`ASSERTION_SIGNING_KEY_ALIAS`].
    pub(crate) fn configure(&self, config: &mut Config) {
        config.connection_secrets_root = Some(SecretRootConfig::new(self.root.clone()));
        config
            .connection_secret_aliases
            .push(OperatorSecretAliasConfig {
                id: ASSERTION_SIGNING_KEY_ALIAS.to_owned(),
                label: "Caller assertion signing key".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: ASSERTION_SIGNING_KEY_ALIAS.to_owned(),
                },
            });
    }

    pub(crate) fn pem(&self) -> &str {
        &self.pem
    }
}

impl Drop for AssertionSigningKeyRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("fixture permissions should set");
}

#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) {}
