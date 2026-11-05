//! Listener material at startup (`load_server_config`, `read_material`,
//! `open_material_directory`): a missing, malformed, mismatched or
//! oversized certificate or key fails startup and names its setting, never
//! its contents, and on Unix the private key's permission rules and
//! projected (kubelet-style) material. Shared fixtures stay in
//! `inbound_tls_tests.rs`.
use super::*;

// --- failing closed --------------------------------------------------------

#[test]
fn a_missing_certificate_fails_startup_and_names_the_setting() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.key", &identity.private_key_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a missing certificate must not start the gateway in plaintext");

    assert_eq!(
        error,
        InboundTlsError::MaterialUnavailable {
            setting: "TLS_CERT_FILE"
        }
    );
    assert!(error.to_string().contains("TLS_CERT_FILE"), "{error}");
}

#[test]
fn a_missing_private_key_fails_startup_and_names_the_setting() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a missing key must not start the gateway in plaintext");

    assert_eq!(
        error,
        InboundTlsError::MaterialUnavailable {
            setting: "TLS_KEY_FILE"
        }
    );
}

#[test]
fn malformed_pem_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", "-----BEGIN CERTIFICATE-----\nnot base64\n");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a malformed certificate must fail startup"),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_certificate_file_that_is_not_a_certificate_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", "no PEM here at all\n");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a certificate file with no certificate in it must fail startup"),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_key_that_does_not_match_the_certificate_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    let other = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &other.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a mismatched key must fail startup rather than serve a broken listener"),
        InboundTlsError::KeyDoesNotMatchCertificate {
            certificate_setting: "TLS_CERT_FILE",
            private_key_setting: "TLS_KEY_FILE",
        }
    );
}

/// A key concatenated into the certificate file inherits the certificate's
/// permissions, and a certificate is the one half of the pair an operator
/// reasonably mounts world-readable.
#[test]
fn a_certificate_file_containing_a_private_key_is_refused() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write(
        "tls.crt",
        &format!("{}{}", identity.certificate_pem, identity.private_key_pem),
    );
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a certificate file carrying a key must be refused"),
        InboundTlsError::CertificateContainsPrivateKey {
            setting: "TLS_CERT_FILE"
        }
    );
}

/// The key file here is a perfectly good key with a great deal of leading
/// filler, which the PEM reader would happily skip. Only the read bound refuses
/// it, so this fails if the bound is widened or dropped rather than passing for
/// the unrelated reason that the material was malformed.
#[test]
fn an_oversized_private_key_is_refused_by_the_bounded_read() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    let filler = "# padding
"
    .repeat(crate::connections::secret::MAX_TLS_PRIVATE_KEY_BYTES / 10);
    material.write("tls.key", &format!("{filler}{}", identity.private_key_pem));

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material)).expect_err(
            "a key file larger than the purpose's bound must be refused before parsing"
        ),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_KEY_FILE"
        }
    );

    // Non-vacuity: the very same key, without the filler, loads.
    material.write("tls.key", &identity.private_key_pem);
    InboundTlsBindings::load(&tls_config(&material))
        .expect("the same key under the bound must load");
}

#[test]
fn a_path_with_no_file_component_fails_startup() {
    let mut config = Config::test_defaults();
    config.tls_cert_files = Some(vec!["/".to_owned()]);
    config.tls_key_files = Some(vec!["/run/tls/tls.key".to_owned()]);

    assert_eq!(
        InboundTlsBindings::load(&config)
            .expect_err("a path that names no file is not certificate material"),
        InboundTlsError::MaterialPathInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_directory_named_as_certificate_material_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    fs::create_dir_all(material.root.join("tls.crt")).expect("directory fixture should create");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a directory is not certificate material"),
        InboundTlsError::MaterialUnsafe {
            setting: "TLS_CERT_FILE"
        }
    );
}

/// Every startup failure is printed to stderr and routinely scraped into a log
/// aggregator, so no error may carry the material that produced it.
#[test]
fn startup_errors_never_carry_key_material() {
    let material = MaterialDir::new();
    let identity = server_identity();
    let other = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &other.private_key_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a mismatched key must fail startup");
    let rendered = format!("{error} {error:?}");

    for line in other
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "a startup error must never render private key material: {rendered}"
        );
    }
    assert!(
        !rendered.contains(&material.path("tls.key")),
        "a startup error must name the setting, not the path it points at: {rendered}"
    );
}

/// `InboundTlsBindings` holds resolved `ServerConfig`s, whose signing keys a
/// derived `Debug` would happily walk into.
#[test]
fn bindings_debug_output_reports_state_without_material() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");

    let rendered = format!("{bindings:?}");

    assert!(rendered.contains("data: true"), "{rendered}");
    assert!(rendered.contains("admin: false"), "{rendered}");
    for line in identity
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "Debug output must never render private key material: {rendered}"
        );
    }
}

// --- permission rules (unix only) ------------------------------------------

/// The private key inherits the connection-secret discipline: group or other
/// *write* on the leaf means another account could swap the key underneath the
/// gateway, so the read fails closed.
#[cfg(unix)]
#[test]
fn a_group_writable_private_key_fails_startup() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let _ = identity;
    set_file_permissions(&material.root.join("tls.key"), 0o620);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a group-writable key must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Constraint: a server private key readable by another account on the host is
/// refused, not warned about.
///
/// Reading this key is the whole compromise -- every session it ever protected,
/// retroactively -- so *read* is as disqualifying as *write*, which is the rule
/// every other private key in this codebase is already held to. Kubernetes
/// publishes Secret volume files `0644`, so this is the mode a default TLS
/// Secret mount arrives with, and refusing it is the point rather than an
/// accident: the operator sets `defaultMode: 0400`.
#[cfg(unix)]
#[test]
fn a_world_readable_private_key_fails_startup() {
    let material = MaterialDir::new();
    write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.key"), 0o644);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a world-readable private key must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Constraint: the refusal has to be actionable and still say nothing it
/// should not.
///
/// The operator whose Secret mount just stopped the gateway needs the setting
/// and the remedy in the line they are looking at; what they must not get is
/// the path the key was read from or a byte of the key itself.
#[cfg(unix)]
#[test]
fn the_world_readable_key_error_names_the_remedy_without_naming_the_file() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.key"), 0o644);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a world-readable private key must not start the gateway");
    let rendered = format!("{error} {error:?}");

    assert!(
        rendered.contains("TLS_KEY_FILE"),
        "the error must name the setting to fix: {rendered}"
    );
    assert!(
        rendered.contains("defaultMode: 0400"),
        "the error must name the remedy, because the default Kubernetes mount is what trips it:          {rendered}"
    );
    assert!(
        !rendered.contains(&material.path("tls.key")),
        "the error must not name the path it read: {rendered}"
    );
    for line in identity
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "the error must never render key material: {rendered}"
        );
    }
}

/// Constraint: the certificate is public material and keeps the looser policy.
///
/// A certificate is served to every client that connects, so world-readable is
/// its normal condition; tightening it in step with the key would refuse a
/// perfectly ordinary mount for no gain.
#[cfg(unix)]
#[test]
fn a_world_readable_certificate_still_loads() {
    let material = MaterialDir::new();
    write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.crt"), 0o644);
    set_file_permissions(&material.root.join("tls.key"), 0o400);

    InboundTlsBindings::load(&tls_config(&material))
        .expect("a world-readable certificate is public material and must load");
}

/// The kubelet publishes projected volume roots as `drwxrwxrwt`, so a
/// world-writable root with the sticky bit has to stay acceptable; the same
/// mode without the sticky bit does not.
#[cfg(unix)]
#[test]
fn a_world_writable_material_directory_is_accepted_only_with_the_sticky_bit() {
    let material = MaterialDir::new();
    write_default_identity(&material);

    set_directory_permissions(&material.root, 0o1777);
    InboundTlsBindings::load(&tls_config(&material))
        .expect("a sticky world-writable root is what every Kubernetes secret mount looks like");

    set_directory_permissions(&material.root, 0o777);
    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("without the sticky bit, any account could swap the mounted key"),
        InboundTlsError::MaterialDirectoryPermissions {
            setting: "TLS_CERT_FILE"
        }
    );

    set_directory_permissions(&material.root, 0o700);
}

/// Builds the shape a Kubernetes Secret volume actually publishes: the kubelet's
/// atomic writer never exposes the leaf directly, it writes
/// `tls.key -> ..data/tls.key`.
#[cfg(unix)]
fn write_projected_identity(material: &MaterialDir, key_mode: u32) {
    let identity = server_identity();
    let data = material.root.join("..data");
    fs::create_dir_all(&data).expect("projected data directory should create");
    fs::write(data.join("tls.crt"), &identity.certificate_pem)
        .expect("projected cert should write");
    fs::write(data.join("tls.key"), &identity.private_key_pem).expect("projected key should write");
    set_file_permissions(&data.join("tls.crt"), 0o644);
    set_file_permissions(&data.join("tls.key"), key_mode);
    std::os::unix::fs::symlink("..data/tls.crt", material.root.join("tls.crt"))
        .expect("projected cert symlink should create");
    std::os::unix::fs::symlink("..data/tls.key", material.root.join("tls.key"))
        .expect("projected key symlink should create");
}

/// Constraint: the symlinked leaf and the permission mask are separate rules,
/// and tightening the second must not quietly re-introduce a refusal of the
/// first.
///
/// Refusing a symlinked leaf would make the most common way to mount this
/// material unusable, so the projected shape loads -- with the key mounted as
/// `defaultMode: 0400` and the certificate left world-readable, which is
/// exactly the split the two policies encode.
#[cfg(unix)]
#[test]
fn a_kubelet_style_symlinked_leaf_still_loads() {
    let material = MaterialDir::new();
    write_projected_identity(&material, 0o400);

    InboundTlsBindings::load(&tls_config(&material))
        .expect("a kubelet-style projected TLS secret with a 0400 key must load");
}

/// Constraint: tolerating the projection does not mean tolerating its default
/// mode.
///
/// This is the same shape as the test above with the key left at the `0644`
/// Kubernetes publishes by default, and it must fail. The two axes -- may the
/// leaf be a symlink, and who may read it -- are independent, and a policy that
/// answered only the first is what let a world-readable key through.
#[cfg(unix)]
#[test]
fn a_kubelet_style_symlinked_leaf_is_still_refused_at_the_default_mode() {
    let material = MaterialDir::new();
    write_projected_identity(&material, 0o644);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a projected key at the default 0644 must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Symlink resolution is confined beneath the capability root, so material
/// pointed outside the mounted directory fails rather than being followed.
///
/// The escape surfaces as a denial rather than as `MaterialUnsafe`, because
/// cap-std refuses to traverse out of the root with `PermissionDenied` and the
/// shared reader maps that to `SourceDenied` before its unsafe-source fallback.
/// The assertion names that outcome rather than "some error", so a future
/// change that started *following* the link would have to fail here.
#[cfg(unix)]
#[test]
fn a_symlink_escaping_the_material_directory_fails_startup() {
    let material = MaterialDir::new();
    let outside = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    let escaped = outside.write("tls.key", &identity.private_key_pem);
    std::os::unix::fs::symlink(&escaped, material.root.join("tls.key"))
        .expect("escaping symlink should create");

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("material reached through an escaping symlink must fail closed"),
        InboundTlsError::MaterialDenied {
            setting: "TLS_KEY_FILE"
        }
    );
}
