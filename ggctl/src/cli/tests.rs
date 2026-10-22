use super::*;

fn arguments(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

fn parsed(words: &[&str]) -> Result<Parsed, Diagnostic> {
    parse(&arguments(words))
}

fn refused(words: &[&str]) -> Diagnostic {
    match parsed(words) {
        Err(diagnostic) => diagnostic,
        Ok(parsed) => panic!("{words:?} should be refused, got {parsed:?}"),
    }
}

fn runnable(words: &[&str]) -> Invocation {
    match parsed(words) {
        Ok(Parsed::Run(invocation)) => invocation,
        other => panic!("{words:?} should run, got {other:?}"),
    }
}

#[test]
fn the_table_is_consistent() {
    let names: Vec<_> = COMMANDS.iter().map(|command| command.name).collect();
    assert_eq!(names, COMMAND_NAMES);
    for command in COMMANDS {
        let mut options: Vec<_> = command.options.iter().map(|option| option.name).collect();
        options.sort_unstable();
        options.dedup();
        assert_eq!(options.len(), command.options.len(), "{}", command.name);
        for option in command.options {
            assert!(option.name.starts_with("--") && option.name != "--help");
            assert!(
                !SECRET_OPTIONS.contains(&&option.name[2..]),
                "{}",
                option.name
            );
            assert!(
                !INSECURE_OPTIONS.contains(&&option.name[2..]),
                "{}",
                option.name
            );
        }
        assert!(
            command
                .arguments
                .windows(2)
                .all(|pair| pair[0].required || !pair[1].required),
            "a required argument cannot follow an optional one in {}",
            command.name
        );
    }
    for (reserved, _) in RESERVED {
        assert!(!names.contains(reserved));
    }
}

#[test]
fn commands_options_and_values_parse_in_every_spelling() {
    let invocation = runnable(&[
        "version",
        "--server",
        "https://gateway.example.test/v1/admin",
        "--format=json",
        "--token-stdin",
        "--timeout",
        "5",
    ]);
    assert_eq!(invocation.command.name, "version");
    assert_eq!(
        invocation.text("--server"),
        Some((2, "https://gateway.example.test/v1/admin"))
    );
    assert_eq!(invocation.text("--format"), Some((4, "json")));
    assert_eq!(invocation.flag("--token-stdin"), Some(5));
    assert_eq!(invocation.text("--timeout"), Some((6, "5")));
    assert_eq!(invocation.flag("--ca-file"), None);

    let invocation = runnable(&[
        "schema",
        "GatewayBundle",
        "--api-version",
        "greengateway.dev/v1alpha1",
    ]);
    assert_eq!(invocation.positional(0), Some((2, "GatewayBundle")));
    assert_eq!(
        invocation.text("--api-version"),
        Some((3, "greengateway.dev/v1alpha1"))
    );

    let invocation = runnable(&["schema", "--", "GatewayBundle"]);
    assert_eq!(invocation.positional(0), Some((3, "GatewayBundle")));
}

#[test]
fn help_and_version_are_recognized_everywhere() {
    assert!(matches!(parsed(&["--help"]), Ok(Parsed::Help(None))));
    assert!(matches!(parsed(&["-h"]), Ok(Parsed::Help(None))));
    assert!(matches!(parsed(&["help"]), Ok(Parsed::Help(None))));
    assert!(matches!(parsed(&["--version"]), Ok(Parsed::Version)));
    for words in [
        &["help", "version"][..],
        &["version", "--help"],
        &[
            "version",
            "--server",
            "https://h.example.test/v1/admin",
            "-h",
        ],
    ] {
        match parsed(words) {
            Ok(Parsed::Help(Some(command))) => assert_eq!(command.name, "version"),
            other => panic!("{words:?}: {other:?}"),
        }
    }
}

#[test]
fn usage_errors_name_the_position_and_never_the_argument() {
    for (words, code, position) in [
        (&[][..], Code::MissingCommand, None),
        (&["frobnicate"], Code::UnknownCommand, Some(1)),
        (&["--verbose"], Code::UnknownOption, Some(1)),
        (&["version", "--verbose"], Code::UnknownOption, Some(2)),
        (&["version", "-v"], Code::UnknownOption, Some(2)),
        (&["version", "--server"], Code::MissingValue, Some(2)),
        (
            &["version", "--format", "yaml"],
            Code::InvalidValue,
            Some(3),
        ),
        (&["version", "--format="], Code::InvalidValue, Some(2)),
        (
            &["version", "--format", "sarif"],
            Code::InvalidValue,
            Some(3),
        ),
        (
            &["version", "--format", "json", "--format", "json"],
            Code::DuplicateOption,
            Some(4),
        ),
        (
            &["version", "--token-stdin=yes"],
            Code::UnexpectedValue,
            Some(2),
        ),
        (&["version", "extra"], Code::UnexpectedArgument, Some(2)),
        (
            &["schema", "GatewayBundle", "extra"],
            Code::UnexpectedArgument,
            Some(3),
        ),
        (&["schema", "gatewaybundle"], Code::InvalidValue, Some(2)),
        (&["completion"], Code::MissingArgument, None),
        (&["completion", "tcsh"], Code::InvalidValue, Some(2)),
        (&["help", "frobnicate"], Code::InvalidValue, Some(2)),
    ] {
        let diagnostic = refused(words);
        assert_eq!(diagnostic.code, code, "{words:?}");
        assert_eq!(diagnostic.argument, position, "{words:?}");
        assert!(!diagnostic.to_string().contains("frobnicate"));
        assert!(!diagnostic.to_string().contains("verbose"));
    }
}

#[test]
fn reserved_commands_name_the_gateway_command_instead() {
    let database = refused(&["db", "migrate"]);
    assert_eq!(database.code, Code::ReservedCommand);
    assert!(database
        .hint
        .is_some_and(|hint| hint.contains("gateway migrate")));
    let cluster = refused(&["cluster"]);
    assert_eq!(cluster.code, Code::ReservedCommand);
    assert!(cluster
        .hint
        .is_some_and(|hint| hint.contains("gateway cluster-members")));
}

#[test]
fn a_secret_or_insecure_option_is_refused_anywhere_before_parsing() {
    let canary = "gg-canary-7f3a9c";
    for words in [
        vec!["version".to_owned(), format!("--token={canary}")],
        vec![
            "version".to_owned(),
            "--token".to_owned(),
            canary.to_owned(),
        ],
        vec![format!("--TOKEN={canary}"), "version".to_owned()],
        vec!["frobnicate".to_owned(), format!("--password={canary}")],
        vec!["version".to_owned(), format!("-api-key={canary}")],
        vec![
            "version".to_owned(),
            "--bearer".to_owned(),
            canary.to_owned(),
        ],
        vec!["schema".to_owned(), format!("--client-secret={canary}")],
    ] {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let diagnostic = refused(&words);
        assert_eq!(diagnostic.code, Code::SecretOnCommandLine, "{words:?}");
        assert!(!format!("{diagnostic}{diagnostic:?}").contains(canary));
    }
    for words in [
        &["version", "--insecure"][..],
        &["version", "-k"],
        &["version", "--insecure-skip-tls-verify=true"],
        &["--no-verify", "version"],
    ] {
        assert_eq!(
            refused(words).code,
            Code::InsecureOptionRefused,
            "{words:?}"
        );
    }
    // Legitimate options that share a prefix are not refused.
    assert!(matches!(
        parsed(&[
            "version",
            "--server",
            "https://h.example.test/v1/admin",
            "--token-stdin"
        ]),
        Ok(Parsed::Run(_))
    ));
    // After `--`, a positional is data, not an option.
    assert_eq!(
        refused(&["schema", "--", "--token"]).code,
        Code::InvalidValue
    );
}

/// `prefix` followed by what this platform cannot represent as Unicode: a
/// byte that is not UTF-8 on Unix, an unpaired surrogate on Windows.
#[cfg(any(unix, windows))]
fn non_utf8(prefix: &str) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.push(0xff);
        OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut wide: Vec<u16> = prefix.encode_utf16().collect();
        wide.push(0xd800);
        OsString::from_wide(&wide)
    }
}

#[cfg(any(unix, windows))]
#[test]
fn only_a_path_value_may_be_non_utf8() {
    let path = non_utf8("/t");
    let parsed = parse(&[
        OsString::from("version"),
        OsString::from("--server"),
        OsString::from("https://h.example.test/v1/admin"),
        OsString::from("--token-file"),
        path.clone(),
    ]);
    match parsed {
        Ok(Parsed::Run(invocation)) => {
            assert_eq!(
                invocation
                    .value("--token-file")
                    .map(|(_, value)| value.to_owned()),
                Some(path.clone())
            );
        }
        other => panic!("{other:?}"),
    }
    let refused = parse(&[OsString::from("version"), OsString::from("--server"), path])
        .expect_err("a URL must be UTF-8");
    assert_eq!(refused.code, Code::ArgumentNotUtf8);
    assert_eq!(refused.argument, Some(3));
    // Nor may a command, an option name or a positional argument.
    for (arguments, position) in [
        (vec![non_utf8("version")], 1),
        (vec![OsString::from("version"), non_utf8("--server")], 2),
        (vec![OsString::from("schema"), non_utf8("GatewayBundle")], 2),
    ] {
        let refused = parse(&arguments).expect_err("non-UTF-8 argument");
        assert_eq!(refused.code, Code::ArgumentNotUtf8);
        assert_eq!(refused.argument, Some(position));
    }
}
