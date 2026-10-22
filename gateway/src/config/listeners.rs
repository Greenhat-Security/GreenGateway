//! The listeners, their inbound TLS and client-certificate authentication,
//! compiled in pure stages (issue #433, PR 2).
//!
//! This is the first block `Config::from_env_vars` reads.
//! [`ListenerInputs::read`] requests its nineteen inputs; [`compile`] parses
//! each one on its own and then checks the rules between them: the listeners
//! must not share an address, a certificate list needs its key list, admin TLS
//! needs an admin listener, and client-certificate authentication needs TLS, a
//! CA bundle and an identity source. The private key files come out as
//! [`SecretLocator`]s. Nothing here opens one, or any certificate, CA or CRL
//! file: loading TLS material is activation's work, and a path that does not
//! exist is accepted here exactly as the legacy parser accepts it.

use std::env::VarError;

use super::{
    compose_inbound_client_auth,
    diagnostic::ConfigRule,
    parse_material_file_list, parse_optional_socket_addr, parse_optional_string, parse_var,
    require_inbound_tls_pair,
    stage::{Checked, Findings, Provenance, RawInput, SecretLocator},
    validate_positive_timeout_ms, validate_positive_usize, validate_range_u32,
    InboundClientAuthConfig, RawInboundClientAuth, SocketAddr, ADMIN_CLIENT_CERT_CA_FILE,
    ADMIN_CLIENT_CERT_CRL_FILE, ADMIN_CLIENT_CERT_MODE, ADMIN_LISTEN_ADDR, ADMIN_TLS_CERT_FILE,
    ADMIN_TLS_KEY_FILE, CLIENT_CERT_CA_FILE, CLIENT_CERT_CRL_FILE, CLIENT_CERT_IDENTITY_SOURCE,
    CLIENT_CERT_MODE, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS, DEFAULT_GRPC_MAX_METADATA_BYTES,
    DEFAULT_LISTEN_SOCKET_ADDR, DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
    DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES, DEFAULT_TLS_MIN_VERSION, GRPC_LISTEN_ADDR,
    GRPC_MAX_CONCURRENT_STREAMS, GRPC_MAX_METADATA_BYTES, LISTEN_ADDR,
    MAX_GRPC_MAX_CONCURRENT_STREAMS, MAX_GRPC_MAX_METADATA_BYTES, MIN_GRPC_MAX_METADATA_BYTES,
    TLS_CERT_FILE, TLS_HANDSHAKE_TIMEOUT_MS, TLS_KEY_FILE, TLS_MAX_CONCURRENT_HANDSHAKES,
    TLS_MIN_VERSION,
};
use crate::{
    auth::ClientCertIdentitySource,
    inbound_tls::{ClientCertMode, TlsMinVersion},
};

/// The listener block's inputs, as the reader returned them.
pub(super) struct ListenerInputs {
    listen_addr: RawInput,
    admin_listen_addr: RawInput,
    grpc_listen_addr: RawInput,
    grpc_max_concurrent_streams: RawInput,
    grpc_max_metadata_bytes: RawInput,
    tls_cert_file: RawInput,
    tls_key_file: RawInput,
    admin_tls_cert_file: RawInput,
    admin_tls_key_file: RawInput,
    tls_min_version: RawInput,
    tls_handshake_timeout_ms: RawInput,
    tls_max_concurrent_handshakes: RawInput,
    client_cert_identity_source: RawInput,
    client_cert_mode: RawInput,
    admin_client_cert_mode: RawInput,
    client_cert_ca_file: RawInput,
    client_cert_crl_file: RawInput,
    admin_client_cert_ca_file: RawInput,
    admin_client_cert_crl_file: RawInput,
}

impl ListenerInputs {
    /// Requests every input of the block once, in the inventory's order.
    pub(super) fn read(mut get_var: impl FnMut(&str) -> Result<String, VarError>) -> Self {
        Self {
            listen_addr: RawInput::new(LISTEN_ADDR, get_var(LISTEN_ADDR)),
            admin_listen_addr: RawInput::new(ADMIN_LISTEN_ADDR, get_var(ADMIN_LISTEN_ADDR)),
            grpc_listen_addr: RawInput::new(GRPC_LISTEN_ADDR, get_var(GRPC_LISTEN_ADDR)),
            grpc_max_concurrent_streams: RawInput::new(
                GRPC_MAX_CONCURRENT_STREAMS,
                get_var(GRPC_MAX_CONCURRENT_STREAMS),
            ),
            grpc_max_metadata_bytes: RawInput::new(
                GRPC_MAX_METADATA_BYTES,
                get_var(GRPC_MAX_METADATA_BYTES),
            ),
            tls_cert_file: RawInput::new(TLS_CERT_FILE, get_var(TLS_CERT_FILE)),
            tls_key_file: RawInput::new(TLS_KEY_FILE, get_var(TLS_KEY_FILE)),
            admin_tls_cert_file: RawInput::new(ADMIN_TLS_CERT_FILE, get_var(ADMIN_TLS_CERT_FILE)),
            admin_tls_key_file: RawInput::new(ADMIN_TLS_KEY_FILE, get_var(ADMIN_TLS_KEY_FILE)),
            tls_min_version: RawInput::new(TLS_MIN_VERSION, get_var(TLS_MIN_VERSION)),
            tls_handshake_timeout_ms: RawInput::new(
                TLS_HANDSHAKE_TIMEOUT_MS,
                get_var(TLS_HANDSHAKE_TIMEOUT_MS),
            ),
            tls_max_concurrent_handshakes: RawInput::new(
                TLS_MAX_CONCURRENT_HANDSHAKES,
                get_var(TLS_MAX_CONCURRENT_HANDSHAKES),
            ),
            client_cert_identity_source: RawInput::new(
                CLIENT_CERT_IDENTITY_SOURCE,
                get_var(CLIENT_CERT_IDENTITY_SOURCE),
            ),
            client_cert_mode: RawInput::new(CLIENT_CERT_MODE, get_var(CLIENT_CERT_MODE)),
            admin_client_cert_mode: RawInput::new(
                ADMIN_CLIENT_CERT_MODE,
                get_var(ADMIN_CLIENT_CERT_MODE),
            ),
            client_cert_ca_file: RawInput::new(CLIENT_CERT_CA_FILE, get_var(CLIENT_CERT_CA_FILE)),
            client_cert_crl_file: RawInput::new(
                CLIENT_CERT_CRL_FILE,
                get_var(CLIENT_CERT_CRL_FILE),
            ),
            admin_client_cert_ca_file: RawInput::new(
                ADMIN_CLIENT_CERT_CA_FILE,
                get_var(ADMIN_CLIENT_CERT_CA_FILE),
            ),
            admin_client_cert_crl_file: RawInput::new(
                ADMIN_CLIENT_CERT_CRL_FILE,
                get_var(ADMIN_CLIENT_CERT_CRL_FILE),
            ),
        }
    }

    fn provenance(&self) -> Vec<Provenance> {
        [
            &self.listen_addr,
            &self.admin_listen_addr,
            &self.grpc_listen_addr,
            &self.grpc_max_concurrent_streams,
            &self.grpc_max_metadata_bytes,
            &self.tls_cert_file,
            &self.tls_key_file,
            &self.admin_tls_cert_file,
            &self.admin_tls_key_file,
            &self.tls_min_version,
            &self.tls_handshake_timeout_ms,
            &self.tls_max_concurrent_handshakes,
            &self.client_cert_identity_source,
            &self.client_cert_mode,
            &self.admin_client_cert_mode,
            &self.client_cert_ca_file,
            &self.client_cert_crl_file,
            &self.admin_client_cert_ca_file,
            &self.admin_client_cert_crl_file,
        ]
        .into_iter()
        .map(RawInput::provenance)
        .collect()
    }
}

/// One listener's certificate chains and their private keys, paired by
/// position: the first pair is the default, and more than one turns on SNI
/// selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsMaterial {
    pub(crate) certificate_files: Vec<String>,
    pub(crate) private_key_files: Vec<SecretLocator>,
}

impl TlsMaterial {
    /// The legacy `Config` fields: the certificate and key file lists.
    pub(super) fn into_files(self) -> (Vec<String>, Vec<String>) {
        let private_key_files = self
            .private_key_files
            .into_iter()
            .map(SecretLocator::into_locator)
            .collect();
        (self.certificate_files, private_key_files)
    }
}

/// The validated listener settings.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ListenerPlan {
    pub(crate) listen_addr: SocketAddr,
    pub(crate) admin_listen_addr: Option<SocketAddr>,
    pub(crate) grpc_listen_addr: Option<SocketAddr>,
    pub(crate) grpc_max_concurrent_streams: u32,
    pub(crate) grpc_max_metadata_bytes: u32,
    /// The data listener's TLS material, or `None` for plaintext.
    pub(crate) data_tls: Option<TlsMaterial>,
    /// The admin listener's TLS material, or `None` for plaintext.
    pub(crate) admin_tls: Option<TlsMaterial>,
    pub(crate) tls_min_version: TlsMinVersion,
    pub(crate) tls_handshake_timeout_ms: u64,
    pub(crate) tls_max_concurrent_handshakes: usize,
    pub(crate) client_cert_auth: Option<InboundClientAuthConfig>,
    pub(crate) admin_client_cert_auth: Option<InboundClientAuthConfig>,
    /// Where each of the block's inputs came from, in the order they are read.
    #[allow(dead_code)] // Read by the stage tests until startup consumes the plan (#433 PR 3).
    pub(crate) provenance: Vec<Provenance>,
}

/// Each listener input parsed on its own, before any rule relates them.
struct ParsedListeners {
    listen_addr: SocketAddr,
    admin_listen_addr: Option<SocketAddr>,
    grpc_listen_addr: Option<SocketAddr>,
    grpc_max_concurrent_streams: u32,
    grpc_max_metadata_bytes: u32,
    tls_cert_files: Option<Vec<String>>,
    tls_key_files: Option<Vec<String>>,
    admin_tls_cert_files: Option<Vec<String>>,
    admin_tls_key_files: Option<Vec<String>>,
    tls_min_version: TlsMinVersion,
    tls_handshake_timeout_ms: u64,
    tls_max_concurrent_handshakes: usize,
    client_cert_identity_source: Option<ClientCertIdentitySource>,
    client_cert_mode: ClientCertMode,
    admin_client_cert_mode: ClientCertMode,
    client_cert_ca_file: Option<String>,
    client_cert_crl_file: Option<String>,
    admin_client_cert_ca_file: Option<String>,
    admin_client_cert_crl_file: Option<String>,
}

/// Parses and validates the listener block.
pub(super) fn compile(inputs: ListenerInputs) -> Checked<ListenerPlan> {
    let mut findings = Findings::default();
    let provenance = inputs.provenance();
    let parsed = parse(&inputs, &mut findings);
    let plan = validate(parsed, provenance, &mut findings);
    Checked::new(plan, findings)
}

/// Parses each input on its own, with the bounds that belong to it alone.
fn parse(inputs: &ListenerInputs, findings: &mut Findings) -> ParsedListeners {
    let listen_addr = findings.input(LISTEN_ADDR, |problems| {
        parse_var(
            LISTEN_ADDR,
            inputs.listen_addr.value(),
            *DEFAULT_LISTEN_SOCKET_ADDR,
            "socket address",
            problems,
        )
    });
    let admin_listen_addr = findings.input(ADMIN_LISTEN_ADDR, |problems| {
        parse_optional_socket_addr(
            ADMIN_LISTEN_ADDR,
            inputs.admin_listen_addr.value(),
            problems,
        )
    });
    let grpc_listen_addr = findings.input(GRPC_LISTEN_ADDR, |problems| {
        parse_optional_socket_addr(GRPC_LISTEN_ADDR, inputs.grpc_listen_addr.value(), problems)
    });
    let grpc_max_concurrent_streams = findings.input(GRPC_MAX_CONCURRENT_STREAMS, |problems| {
        let streams = parse_var(
            GRPC_MAX_CONCURRENT_STREAMS,
            inputs.grpc_max_concurrent_streams.value(),
            DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            "stream count",
            problems,
        );
        validate_range_u32(
            GRPC_MAX_CONCURRENT_STREAMS,
            streams,
            1,
            MAX_GRPC_MAX_CONCURRENT_STREAMS,
            DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            problems,
        )
    });
    let grpc_max_metadata_bytes = findings.input(GRPC_MAX_METADATA_BYTES, |problems| {
        let bytes = parse_var(
            GRPC_MAX_METADATA_BYTES,
            inputs.grpc_max_metadata_bytes.value(),
            DEFAULT_GRPC_MAX_METADATA_BYTES,
            "byte count",
            problems,
        );
        validate_range_u32(
            GRPC_MAX_METADATA_BYTES,
            bytes,
            MIN_GRPC_MAX_METADATA_BYTES,
            MAX_GRPC_MAX_METADATA_BYTES,
            DEFAULT_GRPC_MAX_METADATA_BYTES,
            problems,
        )
    });
    let tls_cert_files = findings.input(TLS_CERT_FILE, |problems| {
        parse_material_file_list(TLS_CERT_FILE, inputs.tls_cert_file.value(), problems)
    });
    let tls_key_files = findings.input(TLS_KEY_FILE, |problems| {
        parse_material_file_list(TLS_KEY_FILE, inputs.tls_key_file.value(), problems)
    });
    let admin_tls_cert_files = findings.input(ADMIN_TLS_CERT_FILE, |problems| {
        parse_material_file_list(
            ADMIN_TLS_CERT_FILE,
            inputs.admin_tls_cert_file.value(),
            problems,
        )
    });
    let admin_tls_key_files = findings.input(ADMIN_TLS_KEY_FILE, |problems| {
        parse_material_file_list(
            ADMIN_TLS_KEY_FILE,
            inputs.admin_tls_key_file.value(),
            problems,
        )
    });
    let tls_min_version = findings.input(TLS_MIN_VERSION, |problems| {
        parse_var(
            TLS_MIN_VERSION,
            inputs.tls_min_version.value(),
            DEFAULT_TLS_MIN_VERSION,
            "TLS version",
            problems,
        )
    });
    let tls_handshake_timeout_ms = findings.input(TLS_HANDSHAKE_TIMEOUT_MS, |problems| {
        let timeout = parse_var(
            TLS_HANDSHAKE_TIMEOUT_MS,
            inputs.tls_handshake_timeout_ms.value(),
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            "millisecond duration",
            problems,
        );
        validate_positive_timeout_ms(
            TLS_HANDSHAKE_TIMEOUT_MS,
            timeout,
            DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            problems,
        )
    });
    let tls_max_concurrent_handshakes = findings.input(TLS_MAX_CONCURRENT_HANDSHAKES, |problems| {
        let handshakes = parse_var(
            TLS_MAX_CONCURRENT_HANDSHAKES,
            inputs.tls_max_concurrent_handshakes.value(),
            DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            "handshake count",
            problems,
        );
        validate_positive_usize(
            TLS_MAX_CONCURRENT_HANDSHAKES,
            handshakes,
            DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            problems,
        )
    });
    let client_cert_identity_source = findings.input(CLIENT_CERT_IDENTITY_SOURCE, |problems| {
        parse_optional_string(
            CLIENT_CERT_IDENTITY_SOURCE,
            inputs.client_cert_identity_source.value(),
            problems,
        )
        .and_then(|value| match value.parse::<ClientCertIdentitySource>() {
            Ok(source) => Some(source),
            Err(expected) => {
                problems.push(format!(
                    "{CLIENT_CERT_IDENTITY_SOURCE} must name a supported identity source, got '{value}': {expected}"
                ));
                None
            }
        })
    });
    let client_cert_mode = findings.input(CLIENT_CERT_MODE, |problems| {
        parse_var(
            CLIENT_CERT_MODE,
            inputs.client_cert_mode.value(),
            ClientCertMode::Off,
            "client certificate mode",
            problems,
        )
    });
    let admin_client_cert_mode = findings.input(ADMIN_CLIENT_CERT_MODE, |problems| {
        parse_var(
            ADMIN_CLIENT_CERT_MODE,
            inputs.admin_client_cert_mode.value(),
            ClientCertMode::Off,
            "client certificate mode",
            problems,
        )
    });
    let client_cert_ca_file = findings.input(CLIENT_CERT_CA_FILE, |problems| {
        parse_optional_string(
            CLIENT_CERT_CA_FILE,
            inputs.client_cert_ca_file.value(),
            problems,
        )
    });
    let client_cert_crl_file = findings.input(CLIENT_CERT_CRL_FILE, |problems| {
        parse_optional_string(
            CLIENT_CERT_CRL_FILE,
            inputs.client_cert_crl_file.value(),
            problems,
        )
    });
    let admin_client_cert_ca_file = findings.input(ADMIN_CLIENT_CERT_CA_FILE, |problems| {
        parse_optional_string(
            ADMIN_CLIENT_CERT_CA_FILE,
            inputs.admin_client_cert_ca_file.value(),
            problems,
        )
    });
    let admin_client_cert_crl_file = findings.input(ADMIN_CLIENT_CERT_CRL_FILE, |problems| {
        parse_optional_string(
            ADMIN_CLIENT_CERT_CRL_FILE,
            inputs.admin_client_cert_crl_file.value(),
            problems,
        )
    });

    ParsedListeners {
        listen_addr,
        admin_listen_addr,
        grpc_listen_addr,
        grpc_max_concurrent_streams,
        grpc_max_metadata_bytes,
        tls_cert_files,
        tls_key_files,
        admin_tls_cert_files,
        admin_tls_key_files,
        tls_min_version,
        tls_handshake_timeout_ms,
        tls_max_concurrent_handshakes,
        client_cert_identity_source,
        client_cert_mode,
        admin_client_cert_mode,
        client_cert_ca_file,
        client_cert_crl_file,
        admin_client_cert_ca_file,
        admin_client_cert_crl_file,
    }
}

/// Checks the rules between the listener inputs and builds the plan.
fn validate(
    parsed: ParsedListeners,
    provenance: Vec<Provenance>,
    findings: &mut Findings,
) -> ListenerPlan {
    let ParsedListeners {
        listen_addr,
        admin_listen_addr,
        grpc_listen_addr,
        grpc_max_concurrent_streams,
        grpc_max_metadata_bytes,
        tls_cert_files,
        tls_key_files,
        admin_tls_cert_files,
        admin_tls_key_files,
        tls_min_version,
        tls_handshake_timeout_ms,
        tls_max_concurrent_handshakes,
        client_cert_identity_source,
        client_cert_mode,
        admin_client_cert_mode,
        client_cert_ca_file,
        client_cert_crl_file,
        admin_client_cert_ca_file,
        admin_client_cert_crl_file,
    } = parsed;

    // An address that did not parse has been replaced by a default, and a
    // default compared with anything says nothing about the operator's
    // configuration, so the collision checks run only while every address
    // read so far parsed. Once one collision is found the gRPC checks are
    // skipped too, as they always have been.
    let mut addresses_clean =
        !findings.refused(LISTEN_ADDR) && !findings.refused(ADMIN_LISTEN_ADDR);
    if addresses_clean && admin_listen_addr == Some(listen_addr) {
        findings.refuse(
            ADMIN_LISTEN_ADDR,
            ConfigRule::AdminListenerCollision,
            format!(
                "{ADMIN_LISTEN_ADDR} must not be the same address as {LISTEN_ADDR} (both resolved to {listen_addr}); choose a different port for the admin listener or leave {ADMIN_LISTEN_ADDR} unset"
            ),
        );
        addresses_clean = false;
    }
    // Sharing a socket with either existing listener is refused rather than
    // resolved. The gRPC listener speaks HTTP/2 and nothing else, and the
    // other two refuse an HTTP/2 preface outright, so a collision is not a
    // preference to reconcile -- one of the two listeners would simply
    // never answer.
    if addresses_clean && !findings.refused(GRPC_LISTEN_ADDR) && grpc_listen_addr.is_some() {
        if grpc_listen_addr == Some(listen_addr) {
            findings.refuse(
                GRPC_LISTEN_ADDR,
                ConfigRule::GrpcListenerCollision,
                format!(
                    "{GRPC_LISTEN_ADDR} must not be the same address as {LISTEN_ADDR} (both resolved to {listen_addr}); the gRPC listener serves HTTP/2 and the data listener refuses it"
                ),
            );
        }
        if admin_listen_addr.is_some() && grpc_listen_addr == admin_listen_addr {
            findings.refuse(
                GRPC_LISTEN_ADDR,
                ConfigRule::GrpcListenerCollision,
                format!(
                    "{GRPC_LISTEN_ADDR} must not be the same address as {ADMIN_LISTEN_ADDR}; the gRPC listener serves HTTP/2 and the admin listener refuses it"
                ),
            );
        }
    }

    // Half a pair is the shape that quietly serves plaintext on a listener
    // an operator believes is protected, so it is a startup failure rather
    // than a warning or an implicit "TLS off".
    findings.rule(
        ADMIN_TLS_KEY_FILE,
        ConfigRule::TlsMaterialUnpaired,
        |problems| {
            require_inbound_tls_pair(
                TLS_CERT_FILE,
                tls_cert_files.as_deref(),
                TLS_KEY_FILE,
                tls_key_files.as_deref(),
                problems,
            );
            require_inbound_tls_pair(
                ADMIN_TLS_CERT_FILE,
                admin_tls_cert_files.as_deref(),
                ADMIN_TLS_KEY_FILE,
                admin_tls_key_files.as_deref(),
                problems,
            );
        },
    );
    // Admin TLS only has a listener to terminate on when the admin surface
    // has its own listener. Accepting the settings without one would leave
    // the admin surface on the data listener's scheme while its own
    // settings say otherwise.
    if admin_listen_addr.is_none()
        && (admin_tls_cert_files.is_some() || admin_tls_key_files.is_some())
    {
        findings.refuse(
            ADMIN_TLS_KEY_FILE,
            ConfigRule::AdminTlsWithoutAdminListener,
            format!(
                "{ADMIN_TLS_CERT_FILE} and {ADMIN_TLS_KEY_FILE} require {ADMIN_LISTEN_ADDR} to be set; without a separate admin listener there is nothing for them to terminate"
            ),
        );
    }

    // Client-certificate authentication, per listener. It depends on the
    // certificate/key pair: a listener that terminates no TLS cannot ask for
    // a client certificate, and a mode that says otherwise is a
    // configuration an operator would reasonably read as "mutual TLS is on".
    let data_tls_configured = tls_cert_files.is_some();
    let admin_tls_configured = admin_tls_cert_files.is_some();
    let client_cert_auth = findings.rule(
        CLIENT_CERT_CRL_FILE,
        ConfigRule::ClientCertificateAuth,
        |problems| {
            compose_inbound_client_auth(
                RawInboundClientAuth {
                    mode_setting: CLIENT_CERT_MODE,
                    mode: client_cert_mode,
                    ca_setting: CLIENT_CERT_CA_FILE,
                    ca_file: client_cert_ca_file,
                    crl_setting: CLIENT_CERT_CRL_FILE,
                    crl_file: client_cert_crl_file,
                    identity_source: client_cert_identity_source,
                    tls_certificate_setting: TLS_CERT_FILE,
                    tls_configured: data_tls_configured,
                },
                problems,
            )
        },
    );
    let admin_client_cert_auth = findings.rule(
        ADMIN_CLIENT_CERT_CRL_FILE,
        ConfigRule::ClientCertificateAuth,
        |problems| {
            compose_inbound_client_auth(
                RawInboundClientAuth {
                    mode_setting: ADMIN_CLIENT_CERT_MODE,
                    mode: admin_client_cert_mode,
                    ca_setting: ADMIN_CLIENT_CERT_CA_FILE,
                    ca_file: admin_client_cert_ca_file,
                    crl_setting: ADMIN_CLIENT_CERT_CRL_FILE,
                    crl_file: admin_client_cert_crl_file,
                    identity_source: client_cert_identity_source,
                    tls_certificate_setting: ADMIN_TLS_CERT_FILE,
                    tls_configured: admin_tls_configured,
                },
                problems,
            )
        },
    );
    // An identity source with nothing to apply it to is a setting that
    // reads as "client certificates are configured" and does nothing. Say
    // so rather than ignoring it.
    if client_cert_identity_source.is_some()
        && client_cert_mode == ClientCertMode::Off
        && admin_client_cert_mode == ClientCertMode::Off
    {
        findings.refuse(
            ADMIN_CLIENT_CERT_CRL_FILE,
            ConfigRule::ClientCertIdentitySourceUnused,
            format!(
                "{CLIENT_CERT_IDENTITY_SOURCE} is set while {CLIENT_CERT_MODE} and {ADMIN_CLIENT_CERT_MODE} are both off; set one of them to `optional` or `required`, or unset the identity source"
            ),
        );
    }

    ListenerPlan {
        listen_addr,
        admin_listen_addr,
        grpc_listen_addr,
        grpc_max_concurrent_streams,
        grpc_max_metadata_bytes,
        data_tls: tls_material(tls_cert_files, tls_key_files),
        admin_tls: tls_material(admin_tls_cert_files, admin_tls_key_files),
        tls_min_version,
        tls_handshake_timeout_ms,
        tls_max_concurrent_handshakes,
        client_cert_auth,
        admin_client_cert_auth,
        provenance,
    }
}

/// A listener's TLS material, when its certificate and key lists are paired.
/// Any other shape has already been refused above.
fn tls_material(
    certificate_files: Option<Vec<String>>,
    private_key_files: Option<Vec<String>>,
) -> Option<TlsMaterial> {
    match (certificate_files, private_key_files) {
        (Some(certificate_files), Some(private_key_files))
            if certificate_files.len() == private_key_files.len() =>
        {
            Some(TlsMaterial {
                certificate_files,
                private_key_files: private_key_files
                    .into_iter()
                    .map(SecretLocator::new)
                    .collect(),
            })
        }
        _ => None,
    }
}
