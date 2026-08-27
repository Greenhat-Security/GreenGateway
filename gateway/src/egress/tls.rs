//! The single outbound TLS configuration the egress boundary hands to every
//! transport it builds.
//!
//! # Why the gateway builds this rather than letting reqwest build it
//!
//! reqwest can assemble a `rustls::ClientConfig` on its own from
//! `add_root_certificate` and `identity`, and until this module existed that is
//! what happened. The problem is not that reqwest's construction is wrong; it
//! is that the construction is not the obvious one, and anything that has to
//! agree with it from the outside is likely to get it wrong in a way that does
//! not show up in testing.
//!
//! Specifically: configured CAs are EXTRA trust anchors layered on top of the
//! platform trust store, via
//! `rustls_platform_verifier::Verifier::new_with_extra_roots`
//! (`reqwest-0.13.4/src/async_impl/client.rs:754-777`). The obvious hand-written
//! equivalent, `ClientConfig::builder().with_root_certificates(roots)`, does
//! something materially different: it NARROWS trust to the configured CA and
//! drops every platform root. Everything the private CA signs keeps working, so
//! a deployment that only ever talks to its own PKI cannot tell the two apart;
//! the difference appears only when a publicly signed upstream is reached by a
//! deployment that also configures a private CA. `tls_tests.rs` demonstrates
//! that: five of its six cases reach the same verdict under both constructions.
//!
//! Issue #257 wants a second outbound transport (h2, for gRPC) that cannot go
//! through `reqwest::ClientBuilder` at all, so it would need a `ClientConfig` of
//! its own. Two independently built configs would then have to keep agreeing
//! forever, guarded by a differential test whose only discriminating case needs
//! a real public trust anchor and therefore cannot run in offline CI.
//!
//! So instead of two configurations that agree, there is one. This module builds
//! it, and reqwest is handed it through `ClientBuilder::tls_backend_preconfigured`
//! (`client.rs:2192`, consumed at `client.rs:642`). A future h2 transport calls
//! [`client_config`] with a different ALPN list and nothing else changes.
//!
//! # What handing reqwest a finished config turns off
//!
//! Once `tls_backend_preconfigured` is called, `config.tls` becomes
//! `TlsBackend::BuiltRustls` and the arm that consumes it
//! (`client.rs:642-685`) passes the config straight to the connector. It never
//! reads `root_certs`, never reads `identity`, and never assigns
//! `alpn_protocols`. That is why `base_client_builder_for_profile` no longer
//! calls `add_root_certificate` or `identity` -- those calls would still
//! compile, still look load-bearing, and do nothing -- and why every profile's
//! ALPN list is set here explicitly instead of being inherited from
//! `.http1_only()`.

use std::sync::Arc;

use tokio_rustls::rustls::{
    self,
    client::danger::ServerCertVerifier,
    crypto::CryptoProvider,
    pki_types::{pem::PemObject, PrivateKeyDer},
    sign::CertifiedKey,
    ClientConfig,
};

/// Re-exported so `EgressConfig` can hold trust anchors in the form the TLS
/// stack consumes, without every caller reaching through `tokio_rustls`.
pub(super) use tokio_rustls::rustls::pki_types::CertificateDer;

use super::client_cache::ProtocolProfile;

/// The ALPN list every profile negotiates in this build.
///
/// Nothing here speaks HTTP/2 yet, and `scripts/check-egress-only.sh` keeps the
/// `http2` feature off `reqwest`, `hyper-util`, and `axum` precisely so that
/// stays true. An h2 transport arrives as a new [`ProtocolProfile`] whose arm in
/// [`alpn_protocols`] returns a different list, not as a silent ALPN change to
/// the profiles that already carry live traffic.
const HTTP1_ALPN: &[&[u8]] = &[b"http/1.1"];

/// Why a TLS configuration could not be built.
///
/// Deliberately coarse: the two kinds of material the caller supplies are the
/// two things a deployment can fix, and `EgressError` already has a variant for
/// each. Nothing here renders the material itself.
#[derive(Debug)]
pub(super) enum TlsConfigError {
    /// The CA bundle could not be turned into trust anchors, or the platform
    /// trust store could not be read.
    TrustAnchors(&'static str),
    /// The client certificate chain and private key were rejected by the TLS
    /// stack -- unparsable, mismatched, or an unsupported key type.
    ClientIdentity,
}

/// A parsed mutual-TLS client identity, in the form the TLS stack consumes.
///
/// Held as DER rather than as the source PEM so that the bytes the gateway
/// validated at configuration time are literally the bytes it later presents;
/// re-parsing at connect time is how a preflight and a transport come to
/// disagree about what is valid.
pub(crate) struct TlsClientIdentity {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl Clone for TlsClientIdentity {
    fn clone(&self) -> Self {
        // `PrivateKeyDer` deliberately withholds `Clone` so that copying key
        // material is always visible at the call site. `EgressConfig` is cloned
        // on every derived client, so it is needed here.
        Self {
            certificates: self.certificates.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl std::fmt::Debug for TlsClientIdentity {
    /// Renders the shape and nothing else. A derived `Debug` would put the
    /// private key into any log line, panic message, or assertion failure that
    /// formats an `EgressConfig`.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsClientIdentity")
            .field("certificate_count", &self.certificates.len())
            .finish_non_exhaustive()
    }
}

impl TlsClientIdentity {
    #[cfg(test)]
    pub(super) fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.certificates
    }

    /// Consumes the identity into its parts.
    ///
    /// Test-only, and deliberately consuming: the private key is not something
    /// production code should be able to borrow out of the configuration, and
    /// only the trust comparison in `tls_tests.rs` needs the parts separately
    /// in order to build the alternative construction it compares against.
    #[cfg(test)]
    pub(super) fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certificates, self.private_key)
    }
}

/// The ALPN list for one protocol profile.
///
/// Exhaustive on purpose: a new profile must state what it negotiates rather
/// than inheriting whatever the last arm happened to return.
fn alpn_protocols(profile: ProtocolProfile) -> &'static [&'static [u8]] {
    match profile {
        ProtocolProfile::Http1AndHttp2 | ProtocolProfile::Sse | ProtocolProfile::UpgradeHttp1 => {
            HTTP1_ALPN
        }
    }
}

/// Resolves the crypto provider this process's outbound TLS uses.
///
/// Mirrors reqwest's own rule exactly (`client.rs:718-720` with
/// `client.rs:2482-2494`): an installed process default wins, and with none
/// installed the choice is aws-lc-rs. Preserving that rule matters more than
/// preferring one provider: this PR is meant to make the existing configuration
/// explicit, not to change which cipher suites production negotiates.
///
/// It has to be stated rather than inherited. This build has BOTH the `ring` and
/// `aws_lc_rs` features on `rustls` -- `tokio-rustls` asks for `ring` and
/// reqwest's `rustls` feature asks for `aws-lc-rs` -- and with both enabled a
/// bare `ClientConfig::builder()` does not pick one, it panics
/// (`rustls-0.23.41/src/crypto/mod.rs:249`).
///
/// The split this closes: production installs no process default, so reqwest
/// fell through to aws-lc-rs, while the test suite installs `ring` process-wide
/// before standing up its TLS fixtures. The suite therefore still exercises a
/// different provider than production does -- that is reqwest's own rule, and
/// changing it belongs in its own change -- but the choice is now made in ONE
/// place, and whichever provider wins is the provider that validates client
/// identities, verifies server certificates, and negotiates suites, on every
/// outbound path.
pub(super) fn crypto_provider() -> Arc<CryptoProvider> {
    resolve_crypto_provider(CryptoProvider::get_default().cloned())
}

/// The provider rule itself, with the process-global input passed in.
///
/// Split out so the fallback branch is reachable from a test: the process
/// default is installed exactly once per process and the suite installs `ring`,
/// so the branch production actually takes cannot otherwise be observed.
fn resolve_crypto_provider(process_default: Option<Arc<CryptoProvider>>) -> Arc<CryptoProvider> {
    process_default.unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

/// Parses a PEM CA bundle into trust anchors.
///
/// Two checks, because the previous path did two. The PEM decode is the parser
/// reqwest uses (`reqwest-0.13.4/src/tls.rs:260-267`), and the trust-anchor
/// check is what `RootCertStore::add` did when reqwest built a client from the
/// bundle -- `Certificate::from_der` itself validates nothing, so a PEM block
/// whose body is well-formed base64 but not a certificate used to be caught at
/// client-build time. Doing it here keeps the rejection where the operator can
/// act on it, and stops a bundle that adds no usable anchor from being accepted
/// as if it had.
pub(super) fn parse_ca_bundle_pem(
    pem_bundle: &[u8],
) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let certificates = CertificateDer::pem_slice_iter(pem_bundle)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsConfigError::TrustAnchors("PEM bundle could not be parsed"))?;

    let mut anchors = rustls::RootCertStore::empty();
    for certificate in &certificates {
        anchors
            .add(certificate.clone())
            .map_err(|_| TlsConfigError::TrustAnchors("PEM bundle is not a usable trust anchor"))?;
    }

    Ok(certificates)
}

/// Parses and validates a combined certificate-chain and private-key PEM.
///
/// The validation is the transport's own: [`CertifiedKey::from_der`] is what
/// `ConfigBuilder::with_client_auth_cert` calls
/// (`rustls-0.23.41/src/client/builder.rs:146-153`), so an identity accepted
/// here is an identity the handshake can present. It is provider-sensitive --
/// key parsing lives in the provider's `KeyProvider` -- which is another reason
/// [`crypto_provider`] has to be the one resolution point.
pub(super) fn parse_client_identity_pem(
    pem_identity: &[u8],
) -> Result<TlsClientIdentity, TlsConfigError> {
    let mut certificates = Vec::new();
    let mut private_key = None;

    let mut cursor = std::io::Cursor::new(pem_identity);
    // Read every section rather than filtering to one kind: a PEM document
    // carrying material this build does not understand is a configuration
    // mistake, and accepting it silently would present a different identity
    // than the operator wrote.
    while let Some((kind, der)) =
        rustls::pki_types::pem::from_buf(&mut cursor).map_err(|_| TlsConfigError::ClientIdentity)?
    {
        use rustls::pki_types::pem::SectionKind;
        match kind {
            SectionKind::Certificate => certificates.push(CertificateDer::from(der)),
            SectionKind::PrivateKey => private_key = Some(PrivateKeyDer::Pkcs8(der.into())),
            SectionKind::RsaPrivateKey => private_key = Some(PrivateKeyDer::Pkcs1(der.into())),
            SectionKind::EcPrivateKey => private_key = Some(PrivateKeyDer::Sec1(der.into())),
            _ => return Err(TlsConfigError::ClientIdentity),
        }
    }

    let private_key = private_key.ok_or(TlsConfigError::ClientIdentity)?;
    if certificates.is_empty() {
        return Err(TlsConfigError::ClientIdentity);
    }

    CertifiedKey::from_der(
        certificates.clone(),
        private_key.clone_key(),
        &crypto_provider(),
    )
    .map_err(|_| TlsConfigError::ClientIdentity)?;

    Ok(TlsClientIdentity {
        certificates,
        private_key,
    })
}

/// Builds the outbound TLS configuration for one protocol profile.
///
/// Every profile gets the same trust decision and the same client identity; the
/// ALPN list is the only thing that varies, and it varies by an exhaustive match
/// rather than by whatever the caller passes in.
pub(super) fn client_config(
    root_certificates: &[CertificateDer<'static>],
    client_identity: Option<&TlsClientIdentity>,
    profile: ProtocolProfile,
) -> Result<ClientConfig, TlsConfigError> {
    let provider = crypto_provider();
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        // reqwest offers everything rustls supports unless a min/max version is
        // configured, and nothing in this crate configures one
        // (`client.rs:659-715`).
        .with_protocol_versions(rustls::ALL_VERSIONS)
        .map_err(|_| TlsConfigError::TrustAnchors("TLS protocol versions are unsupported"))?;

    // The whole point of the module, in three lines: configured CAs are EXTRA
    // roots on top of the platform trust store, never a replacement for it.
    // `with_root_certificates(roots)` here would silently stop trusting every
    // public CA, and no offline test can tell the difference -- see
    // `tls_tests.rs`.
    let verifier: Arc<dyn ServerCertVerifier> = if root_certificates.is_empty() {
        Arc::new(
            rustls_platform_verifier::Verifier::new(Arc::clone(&provider))
                .map_err(|_| TlsConfigError::TrustAnchors("platform trust store is unreadable"))?,
        )
    } else {
        Arc::new(
            rustls_platform_verifier::Verifier::new_with_extra_roots(
                root_certificates.to_vec(),
                Arc::clone(&provider),
            )
            .map_err(|_| TlsConfigError::TrustAnchors("CA bundle is not a usable trust anchor"))?,
        )
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let mut config = match client_identity {
        Some(identity) => builder
            .with_client_auth_cert(
                identity.certificates.clone(),
                identity.private_key.clone_key(),
            )
            .map_err(|_| TlsConfigError::ClientIdentity)?,
        None => builder.with_no_client_auth(),
    };

    // Not decoration, and not inherited: `.http1_only()` pins ALPN only on the
    // backend reqwest builds itself (`client.rs:822-826`), and the
    // `BuiltRustls` arm never touches `alpn_protocols`. Leaving this unset
    // sends no ALPN extension at all; setting it to `h2` in a build without
    // `hyper-util/http2` does not error, it panics inside hyper-util
    // (`hyper-util-0.1.20/src/client/legacy/client.rs:562-563`).
    config.alpn_protocols = alpn_protocols(profile)
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();

    Ok(config)
}

#[cfg(test)]
mod tests {
    use tokio_rustls::rustls::crypto::{aws_lc_rs, ring};

    use super::*;

    /// Names rather than the trait objects themselves: `SupportedKxGroup` is a
    /// `&'static dyn`, and `SupportedCipherSuite`'s `PartialEq` compares suite
    /// identifiers, which the two providers share. The key exchange groups are
    /// what actually differ.
    fn kx_group_names(provider: &CryptoProvider) -> Vec<String> {
        provider
            .kx_groups
            .iter()
            .map(|group| format!("{:?}", group.name()))
            .collect()
    }

    #[test]
    fn both_crypto_providers_are_compiled_in_and_are_distinguishable() {
        // The premise behind naming a provider explicitly. With both features
        // on `rustls`, `ClientConfig::builder()` cannot choose and panics
        // (`rustls-0.23.41/src/crypto/mod.rs:249`) unless something already
        // installed a process default -- which production does not do.
        //
        // This also keeps the two assertions below honest: if the providers
        // ever became indistinguishable by key exchange group, they would stop
        // discriminating and this test says so first.
        let ring_groups = kx_group_names(&ring::default_provider());
        let aws_groups = kx_group_names(&aws_lc_rs::default_provider());
        assert_ne!(
            ring_groups, aws_groups,
            "ring and aws-lc-rs no longer differ by key exchange group; the provider \
             assertions in this module are no longer discriminating"
        );
    }

    #[test]
    fn provider_falls_back_to_the_same_choice_reqwest_makes() {
        // The branch production takes. It cannot be reached through
        // `crypto_provider()` from inside the suite, because the suite installs
        // `ring` process-wide before any TLS fixture starts.
        let resolved = resolve_crypto_provider(None);
        assert_eq!(
            kx_group_names(&resolved),
            kx_group_names(&aws_lc_rs::default_provider()),
            "with no process default installed the shared config must resolve to the same \
             provider reqwest would have (`client.rs:2482-2494`)"
        );
        assert_ne!(
            kx_group_names(&resolved),
            kx_group_names(&ring::default_provider()),
            "the fallback resolved to ring; production would negotiate different suites than \
             it did before this configuration was made explicit"
        );
    }

    #[test]
    fn provider_prefers_an_installed_process_default() {
        let installed: Arc<CryptoProvider> = Arc::new(ring::default_provider());
        let resolved = resolve_crypto_provider(Some(Arc::clone(&installed)));
        assert!(
            Arc::ptr_eq(&resolved, &installed),
            "an installed process default must win, exactly as it does for reqwest"
        );
    }

    #[test]
    fn the_shared_config_carries_the_resolved_provider() {
        let _ = ring::default_provider().install_default();
        let config = client_config(&[], None, ProtocolProfile::Http1AndHttp2)
            .expect("a config with no custom trust material should build");
        let expected = crypto_provider();
        assert!(
            Arc::ptr_eq(config.crypto_provider(), &expected),
            "the config must carry the provider `crypto_provider()` resolved, not one rustls \
             picked implicitly"
        );
        // In this process that is `ring`, because the suite installs it. The
        // assertion worth making is that the config and the resolver agree, not
        // which provider won.
        assert_eq!(
            kx_group_names(config.crypto_provider()),
            kx_group_names(&expected)
        );
    }

    #[test]
    fn every_protocol_profile_negotiates_http1_and_nothing_else() {
        for profile in [
            ProtocolProfile::Http1AndHttp2,
            ProtocolProfile::Sse,
            ProtocolProfile::UpgradeHttp1,
        ] {
            let config = client_config(&[], None, profile)
                .unwrap_or_else(|error| panic!("{profile:?} config should build: {error:?}"));
            assert_eq!(
                config.alpn_protocols,
                vec![b"http/1.1".to_vec()],
                "{profile:?} must offer exactly http/1.1; an empty list sends no ALPN \
                 extension at all, and an h2 entry panics hyper-util in this build"
            );
        }
    }

    /// A PEM block whose body decodes cleanly but is not a certificate. The PEM
    /// parser accepts it; only the trust-anchor check rejects it. Dropping that
    /// check would let a CA bundle be accepted, stored, and published while
    /// contributing no trust at all.
    #[test]
    fn a_well_formed_pem_that_is_not_a_certificate_is_refused() {
        let error = parse_ca_bundle_pem(
            b"-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n",
        )
        .expect_err("a PEM body that is not a certificate must not become a trust anchor");
        assert!(matches!(error, TlsConfigError::TrustAnchors(_)));
    }

    #[test]
    fn a_ca_bundle_of_garbage_is_refused_rather_than_ignored() {
        let error = parse_ca_bundle_pem(b"-----BEGIN CERTIFICATE-----\nnot base64\n")
            .expect_err("a malformed PEM bundle must not parse");
        assert!(matches!(error, TlsConfigError::TrustAnchors(_)));
    }

    #[test]
    fn a_client_identity_whose_key_does_not_match_its_certificate_is_refused() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["identity.example.test".to_owned()])
                .expect("test certificate should generate");
        let unrelated =
            rcgen::generate_simple_self_signed(vec!["unrelated.example.test".to_owned()])
                .expect("unrelated test key should generate");
        let mismatched = format!(
            "{}{}",
            certificate.cert.pem(),
            unrelated.key_pair.serialize_pem()
        );

        let error = parse_client_identity_pem(mismatched.as_bytes())
            .expect_err("a key that does not match the certificate must be refused");
        assert!(matches!(error, TlsConfigError::ClientIdentity));

        let matching = format!(
            "{}{}",
            certificate.cert.pem(),
            certificate.key_pair.serialize_pem()
        );
        let identity = parse_client_identity_pem(matching.as_bytes())
            .expect("a matching certificate and key must be accepted");
        assert_eq!(identity.certificates().len(), 1);
    }
}
