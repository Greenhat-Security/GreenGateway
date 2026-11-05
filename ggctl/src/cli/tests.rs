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
    // Help names every command outside a family and every family, in table
    // order; a family lists its commands' second words in table order.
    let mut topics: Vec<&str> = Vec::new();
    for command in COMMANDS {
        let topic = command.family().map_or(command.name, |family| family.name);
        if !topics.contains(&topic) {
            topics.push(topic);
        }
    }
    assert_eq!(topics, HELP_TOPICS);
    for family in FAMILIES {
        let words: Vec<_> = family
            .members()
            .map(|command| member_word(family, command).expect("a member"))
            .collect();
        assert_eq!(words, family.commands);
        assert!(COMMANDS.iter().all(|command| command.name != family.name));
    }
    // Only an acknowledgement can be given more than once.
    for command in COMMANDS {
        for option in command.options {
            assert_eq!(
                option.repeatable,
                option.name == "--acknowledge",
                "{}",
                option.name
            );
        }
    }
}

#[test]
fn the_acknowledgeable_risk_codes_are_the_diff_engines() {
    let codes: Vec<_> = gateway_config::semantic_diff::RiskCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect();
    assert_eq!(codes, RISK_CODES);
}

#[test]
fn a_family_command_is_its_family_and_a_second_word() {
    let invocation = runnable(&[
        "ledger",
        "rollback",
        "rev-00000000000000000000000000000000",
        "--acknowledge",
        "risk.policy_broadened",
        "--state-dir",
        "/state",
        "--acknowledge=risk.unknown_impact",
    ]);
    assert_eq!(invocation.command.name, "ledger rollback");
    assert_eq!(
        invocation.positional(0),
        Some((3, "rev-00000000000000000000000000000000"))
    );
    assert_eq!(
        invocation.texts("--acknowledge"),
        [(4, "risk.policy_broadened"), (8, "risk.unknown_impact")]
    );
    assert_eq!(invocation.text("--state-dir"), Some((6, "/state")));
    assert!(invocation.texts("--format").is_empty());

    for (words, code, position) in [
        (&["ledger"][..], Code::MissingCommand, None),
        (&["ledger", "frobnicate"], Code::UnknownCommand, Some(2)),
        (&["ledger", "--state-dir"], Code::UnknownCommand, Some(2)),
        (&["ledger seed", "/bundle"], Code::UnknownCommand, Some(1)),
        (
            &["ledger", "verify", "extra"],
            Code::UnexpectedArgument,
            Some(3),
        ),
        (
            &["ledger", "verify", "--state-dir", "/a", "--state-dir", "/b"],
            Code::DuplicateOption,
            Some(5),
        ),
        (
            &[
                "ledger",
                "rollback",
                "rev-x",
                "--acknowledge",
                "risk.everything",
            ],
            Code::InvalidValue,
            Some(5),
        ),
        (
            &["help", "ledger", "frobnicate"],
            Code::InvalidValue,
            Some(3),
        ),
        (
            &["help", "version", "seed"],
            Code::UnexpectedArgument,
            Some(3),
        ),
    ] {
        let diagnostic = refused(words);
        assert_eq!(diagnostic.code, code, "{words:?}");
        assert_eq!(diagnostic.argument, position, "{words:?}");
    }
    let alone = refused(&["ledger"]);
    assert!(alone
        .hint
        .is_some_and(|hint| hint.contains("ggctl help ledger")));
}

#[test]
fn a_family_and_its_commands_have_help() {
    for words in [
        &["ledger", "--help"][..],
        &["ledger", "-h"],
        &["help", "ledger"],
    ] {
        match parsed(words) {
            Ok(Parsed::Help(HelpTopic::Family(family))) => assert_eq!(family.name, "ledger"),
            other => panic!("{words:?}: {other:?}"),
        }
    }
    for words in [
        &["ledger", "seed", "--help"][..],
        &["help", "ledger", "seed"],
        &["ledger", "seed", "/bundle", "--state-dir", "/state", "-h"],
    ] {
        match parsed(words) {
            Ok(Parsed::Help(HelpTopic::Spec(command))) => {
                assert_eq!(command.name, "ledger seed")
            }
            other => panic!("{words:?}: {other:?}"),
        }
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
    for words in [&["--help"][..], &["-h"], &["help"]] {
        assert!(
            matches!(parsed(words), Ok(Parsed::Help(HelpTopic::Overview))),
            "{words:?}"
        );
    }
    assert!(matches!(parsed(&["--version"]), Ok(Parsed::Version)));
    assert!(matches!(
        parsed(&["help", "--man"]),
        Ok(Parsed::Manual(HelpTopic::Overview))
    ));
    for words in [
        &["help", "--man", "validate"][..],
        &["help", "validate", "--man"],
    ] {
        match parsed(words) {
            Ok(Parsed::Manual(HelpTopic::Spec(command))) => assert_eq!(command.name, "validate"),
            other => panic!("{words:?}: {other:?}"),
        }
    }
    match parsed(&["help", "--man", "ledger"]) {
        Ok(Parsed::Manual(HelpTopic::Family(family))) => assert_eq!(family.name, "ledger"),
        other => panic!("{other:?}"),
    }
    match parsed(&["help", "ledger", "seed", "--man"]) {
        Ok(Parsed::Manual(HelpTopic::Spec(command))) => assert_eq!(command.name, "ledger seed"),
        other => panic!("{other:?}"),
    }
    // `--help` wins over `--man`, as it does over every other option.
    assert!(matches!(
        parsed(&["help", "--man", "--help"]),
        Ok(Parsed::Help(HelpTopic::Spec(command))) if command.name == "help"
    ));
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
            Ok(Parsed::Help(HelpTopic::Spec(command))) => assert_eq!(command.name, "version"),
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
        (&["help", "--man", "--man"], Code::DuplicateOption, Some(3)),
        (&["help", "--man=yes"], Code::UnexpectedValue, Some(2)),
        (&["version", "--man"], Code::UnknownOption, Some(2)),
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
    // Nor may a command, a family's command, an option name or a positional
    // argument.
    for (arguments, position) in [
        (vec![non_utf8("version")], 1),
        (vec![OsString::from("ledger"), non_utf8("seed")], 2),
        (vec![OsString::from("version"), non_utf8("--server")], 2),
        (vec![OsString::from("schema"), non_utf8("GatewayBundle")], 2),
    ] {
        let refused = parse(&arguments).expect_err("non-UTF-8 argument");
        assert_eq!(refused.code, Code::ArgumentNotUtf8);
        assert_eq!(refused.argument, Some(position));
    }
}
