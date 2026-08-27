use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[test]
fn env_example_matches_gateway_env_reads() {
    let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = gateway_root
        .parent()
        .expect("gateway crate should live directly under the repo root");

    let documented = documented_env_vars(&repo_root.join(".env.example"));
    let code_reads = code_env_vars(&gateway_root.join("src"));

    let missing_from_example: Vec<_> = code_reads.difference(&documented).cloned().collect();
    let missing_from_code: Vec<_> = documented.difference(&code_reads).cloned().collect();

    assert!(
        missing_from_example.is_empty() && missing_from_code.is_empty(),
        ".env.example drift detected.\n\
         Read in gateway/src but missing from .env.example: {}\n\
         Documented in .env.example but not read in gateway/src: {}",
        format_vars(&missing_from_example),
        format_vars(&missing_from_code)
    );
}

#[test]
fn env_example_exempt_paths_are_not_hardcoded() {
    let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = gateway_root
        .parent()
        .expect("gateway crate should live directly under the repo root");
    let path = repo_root.join(".env.example");
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    for key in ["AUTH_EXEMPT_PATHS", "RBAC_EXEMPT_PATHS"] {
        let assignment_prefix = format!("{key}=");
        let active = contents
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(&assignment_prefix));
        assert!(
            active.is_none(),
            "{key} must remain unset in .env.example so its dynamic ADMIN_PREFIX-aware default applies; found {active:?}"
        );

        let documented = contents.lines().map(str::trim).find_map(|line| {
            line.strip_prefix('#')
                .map(str::trim_start)
                .filter(|line| line.starts_with(&assignment_prefix))
        });
        let documented =
            documented.unwrap_or_else(|| panic!("{key} should retain a commented shape example"));
        assert!(
            !documented.split(',').any(|entry| entry.trim() == "/admin"),
            "{key} shape example must not hardcode /admin: {documented}"
        );
    }
}

/// Every published claim that an explicit `AUTH_EXEMPT_PATHS` /
/// `RBAC_EXEMPT_PATHS` value replaces the whole default must also disclose the
/// one pair the code appends anyway.
///
/// `append_admin_login_exempt_paths` in gateway/src/config.rs runs
/// unconditionally after the parse whenever `ADMIN_LOGIN_PROVIDER` is set, so
/// `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` stay
/// exempt even for an operator who supplied an explicit list. Both routes have
/// to be anonymous for the OIDC authorization-code flow to complete, so the
/// behavior is deliberate; leaving it out of the documented contract is what
/// made an operator's own configuration audit come to a false conclusion about
/// their exempt surface.
#[test]
fn exempt_path_replacement_claims_disclose_the_forced_admin_login_pair() {
    const DISCLOSURE: &str = "remain exempt even when";

    let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = gateway_root
        .parent()
        .expect("gateway crate should live directly under the repo root");

    for (path, claim) in [
        (
            repo_root.join("docs/configuration.md"),
            "replaces its entire dynamic default",
        ),
        (
            repo_root.join("docs/configuration.md"),
            "replaces the entire default",
        ),
        (
            repo_root.join(".env.example"),
            "REPLACES the default entirely",
        ),
    ] {
        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
            .replace("\r\n", "\n");
        let blocks: Vec<&str> = contents
            .split("\n\n")
            .filter(|block| block.contains(claim))
            .collect();

        assert!(
            !blocks.is_empty(),
            "{} no longer contains the {claim:?} contract this test guards; update the test with the new wording",
            path.display()
        );

        for block in blocks {
            assert!(
                block.contains(DISCLOSURE),
                "{} claims {claim:?} without disclosing that \
                 /v1{{ADMIN_PREFIX}}/auth/login and /v1{{ADMIN_PREFIX}}/auth/callback stay exempt \
                 while ADMIN_LOGIN_PROVIDER is set. Say so with the phrase {DISCLOSURE:?} or change \
                 append_admin_login_exempt_paths in gateway/src/config.rs to match the claim.\n\n{block}",
                path.display()
            );
            assert!(
                block.contains("/auth/login") && block.contains("/auth/callback"),
                "{} should name both always-appended routes:\n\n{block}",
                path.display()
            );
        }
    }
}

#[test]
fn configuration_doc_matches_gateway_env_reads() {
    let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = gateway_root
        .parent()
        .expect("gateway crate should live directly under the repo root");

    let documented = configuration_doc_env_vars(&repo_root.join("docs/configuration.md"));
    let code_reads = code_env_vars(&gateway_root.join("src"));

    let missing_from_doc: Vec<_> = code_reads.difference(&documented).cloned().collect();
    let missing_from_code: Vec<_> = documented.difference(&code_reads).cloned().collect();

    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/configuration.md drift detected.\n\
         Read in gateway/src but missing from docs/configuration.md: {}\n\
         Documented in docs/configuration.md but not read in gateway/src: {}",
        format_vars(&missing_from_doc),
        format_vars(&missing_from_code)
    );
}

#[test]
fn cloudflare_forwarding_matches_supported_gateway_env_vars() {
    let gateway_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = gateway_root
        .parent()
        .expect("gateway crate should live directly under the repo root");

    let mut expected = code_env_vars(&gateway_root.join("src"));
    expected.remove("LISTEN_ADDR");
    expected.remove("ADMIN_LISTEN_ADDR");
    // Inbound TLS settings are deliberately not forwardable.
    //
    // The Worker terminates TLS at Cloudflare's edge and reaches the container
    // over plain HTTP/1.1 on `CONTAINER_PORT`. Forwarding these would make the
    // container demand a TLS ClientHello on a connection the Worker will never
    // start one on, so every request would fail while the deployment looked
    // correctly configured. There is also nowhere for an operator to mount a
    // certificate and key in that deployment shape.
    //
    // Excluded here rather than added to the allowlist because a forwarding
    // entry that cannot work is worse than an absent one: it invites the
    // configuration it silently breaks.
    for excluded in [
        "TLS_CERT_FILE",
        "TLS_KEY_FILE",
        "ADMIN_TLS_CERT_FILE",
        "ADMIN_TLS_KEY_FILE",
        "TLS_MIN_VERSION",
        "TLS_HANDSHAKE_TIMEOUT_MS",
        "TLS_MAX_CONCURRENT_HANDSHAKES",
    ] {
        assert!(
            expected.remove(excluded),
            "{excluded} is excluded from Cloudflare forwarding but is no longer read in \
             gateway/src; drop the exclusion so it cannot outlive the setting"
        );
    }
    let forwarded = cloudflare_forwarded_env_vars(&repo_root.join("cloudflare/src/config.ts"));

    let missing_from_cloudflare: Vec<_> = expected.difference(&forwarded).cloned().collect();
    let unsupported_in_cloudflare: Vec<_> = forwarded.difference(&expected).cloned().collect();

    assert!(
        missing_from_cloudflare.is_empty() && unsupported_in_cloudflare.is_empty(),
        "Cloudflare environment forwarding drift detected.\n\
         Gateway variables missing from Cloudflare: {}\n\
         Unsupported variables forwarded by Cloudflare: {}",
        format_vars(&missing_from_cloudflare),
        format_vars(&unsupported_in_cloudflare)
    );
}

fn documented_env_vars(path: &Path) -> BTreeSet<String> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();

            if line.is_empty() {
                return None;
            }

            // A commented `#KEY=value` assignment still documents a supported
            // variable while keeping it unset so runtime defaults apply.
            let line = line.strip_prefix('#').unwrap_or(line).trim_start();

            let (key, _) = line.split_once('=')?;
            let key = key.trim();
            is_env_key(key).then(|| key.to_owned())
        })
        .collect()
}

fn configuration_doc_env_vars(path: &Path) -> BTreeSet<String> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    contents
        .lines()
        .filter_map(|line| {
            let heading = line.strip_prefix("### ")?;

            is_env_key(heading).then(|| heading.to_owned())
        })
        .collect()
}

fn cloudflare_forwarded_env_vars(path: &Path) -> BTreeSet<String> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let start_marker = "export const GREEN_GATEWAY_ENV_KEYS = [";
    let start = contents
        .find(start_marker)
        .unwrap_or_else(|| panic!("{} is missing {start_marker}", path.display()))
        + start_marker.len();
    let remaining = &contents[start..];
    let end = remaining.find("] as const;").unwrap_or_else(|| {
        panic!(
            "{} has an unterminated environment key list",
            path.display()
        )
    });

    remaining[..end]
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_suffix(',')
                .and_then(|line| line.strip_prefix('"'))
                .and_then(|line| line.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

fn code_env_vars(src_dir: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    collect_rs_files(src_dir, &mut files);
    files.sort();

    let sources: Vec<(PathBuf, String)> = files
        .into_iter()
        .map(|file| {
            let source = fs::read_to_string(&file)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.display()));
            (file, source)
        })
        .collect();

    env_vars_in_sources(&sources)
}

/// Resolve the variable name behind every environment read in `gateway/src`.
///
/// The drift tests above are only worth their assertions if this walk sees
/// every read, so it does two things a narrower scan would not. A name that the
/// reading file does not declare itself is resolved against the whole crate,
/// because a `&str` constant declared in one module and read from another is a
/// perfectly ordinary shape that used to be invisible here. And an argument the
/// walk cannot follow to a name -- a macro, a call, a name declared with two
/// different values in two modules -- fails the test rather than being skipped,
/// so the only reads left out of the comparison are the ones whose key
/// genuinely is not known until runtime.
///
/// The walk does not track modules, so `a::KEY` and `b::KEY` are the same name
/// to it. That only costs precision when the reading file declares the name
/// itself and means a different one, which no module in `gateway/src` does.
fn env_vars_in_sources(sources: &[(PathBuf, String)]) -> BTreeSet<String> {
    let crate_consts = crate_string_consts(sources);
    let mut vars = BTreeSet::new();

    for (path, source) in sources {
        let file_consts = string_consts(source);

        for argument in env_read_arguments(source) {
            match argument {
                EnvReadArgument::Name(name) => {
                    vars.insert(name);
                }
                EnvReadArgument::Runtime => {}
                EnvReadArgument::Const(name) => {
                    let resolved = file_consts
                        .get(&name)
                        .cloned()
                        .or_else(|| crate_consts.get(&name).cloned().flatten());
                    let value = resolved.unwrap_or_else(|| {
                        panic!(
                            "{} reads the environment as `{name}`, which does not resolve to a \
                             single `&str` constant anywhere in gateway/src. Name the variable \
                             with a string literal or one unambiguous `&str` constant so it \
                             cannot be omitted from .env.example, docs/configuration.md, or \
                             the Cloudflare forwarding list.",
                            path.display()
                        )
                    });
                    vars.insert(value);
                }
                EnvReadArgument::Opaque(snippet) => panic!(
                    "{} reads the environment as `{snippet}`, a form this parity check cannot \
                     follow to a variable name. Name the variable with a string literal or a \
                     `&str` constant so it cannot be omitted from .env.example, \
                     docs/configuration.md, or the Cloudflare forwarding list.",
                    path.display()
                ),
            }
        }
    }

    vars
}

/// A name declared with two different values anywhere in the crate resolves to
/// neither, so an ambiguous read fails loudly instead of binding to whichever
/// declaration the directory walk happened to reach last.
fn crate_string_consts(sources: &[(PathBuf, String)]) -> BTreeMap<String, Option<String>> {
    let mut consts: BTreeMap<String, Option<String>> = BTreeMap::new();

    for (_, source) in sources {
        for (name, value) in string_consts(source) {
            match consts.entry(name) {
                Entry::Vacant(entry) => {
                    entry.insert(Some(value));
                }
                Entry::Occupied(mut entry) => {
                    if entry.get().as_deref() != Some(value.as_str()) {
                        entry.insert(None);
                    }
                }
            }
        }
    }

    consts
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in
        fs::read_dir(dir).unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
    {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read entry in {}: {err}", dir.display()))
            .path();

        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

fn string_consts(source: &str) -> BTreeMap<String, String> {
    let mut consts = BTreeMap::new();

    for keyword in ["const", "static"] {
        let mut index = 0;

        while let Some(offset) = source[index..].find(keyword) {
            let start = index + offset;
            index = start + keyword.len();

            if !has_word_boundary(source, start, keyword.len()) {
                continue;
            }

            let mut cursor = skip_whitespace(source, index);
            let Some((name, next)) = parse_identifier(source, cursor) else {
                continue;
            };

            cursor = skip_whitespace(source, next);
            if source.as_bytes().get(cursor) != Some(&b':') {
                continue;
            }

            let Some(equal_offset) = source[cursor..].find('=') else {
                break;
            };
            let equal = cursor + equal_offset;

            if !is_string_ref_type(source[cursor + 1..equal].trim()) {
                continue;
            }

            cursor = skip_whitespace(source, equal + 1);
            if let Some((value, _)) = parse_string_literal(source, cursor) {
                consts.insert(name.to_owned(), value);
            }
        }
    }

    consts
}

fn is_string_ref_type(type_text: &str) -> bool {
    if type_text == "&str" {
        return true;
    }

    let Some(lifetime_start) = type_text.strip_prefix("&'") else {
        return false;
    };
    let Some((_, lifetime_end)) = parse_identifier(lifetime_start, 0) else {
        return false;
    };

    let cursor = skip_whitespace(lifetime_start, lifetime_end);
    cursor > lifetime_end && &lifetime_start[cursor..] == "str"
}

/// What an environment read names, as written at the call site.
#[derive(Debug, PartialEq, Eq)]
enum EnvReadArgument {
    /// A string literal: the variable name is right there.
    Name(String),
    /// A reference to a `&str` constant, by the final segment of its path.
    Const(String),
    /// A lower-case binding. `Config::from_env` and the operator secret-alias
    /// resolver both take the key as a parameter, and no static walk can know
    /// what a caller will pass.
    Runtime,
    /// A shape the walk cannot follow, kept verbatim for the failure message.
    Opaque(String),
}

fn env_read_arguments(source: &str) -> Vec<EnvReadArgument> {
    let mut arguments = Vec::new();

    for callee in ["env::var", "env::var_os", "get_var"] {
        let mut index = 0;

        while let Some(offset) = source[index..].find(callee) {
            let start = index + offset;
            index = start + callee.len();

            if !has_word_boundary(source, start, callee.len()) {
                continue;
            }

            let cursor = skip_whitespace(source, index);
            if source.as_bytes().get(cursor) != Some(&b'(') {
                continue;
            }

            arguments.push(parse_env_read_argument(source, cursor + 1));
        }
    }

    arguments
}

fn parse_env_read_argument(source: &str, start: usize) -> EnvReadArgument {
    let cursor = skip_whitespace(source, start);
    let cursor = if source.as_bytes().get(cursor) == Some(&b'&') {
        skip_whitespace(source, cursor + 1)
    } else {
        cursor
    };

    if let Some((value, _)) = parse_string_literal(source, cursor) {
        return EnvReadArgument::Name(value);
    }

    let Some((segment, end)) = parse_path(source, cursor) else {
        return EnvReadArgument::Opaque(argument_snippet(source, cursor));
    };

    // A macro expansion or a nested call builds its string somewhere this walk
    // cannot see, so neither counts as naming a variable.
    let next = skip_whitespace(source, end);
    if matches!(source.as_bytes().get(next), Some(b'!' | b'(')) {
        return EnvReadArgument::Opaque(argument_snippet(source, cursor));
    }

    if segment
        .chars()
        .any(|character| character.is_ascii_lowercase())
    {
        EnvReadArgument::Runtime
    } else {
        EnvReadArgument::Const(segment.to_owned())
    }
}

fn parse_path(source: &str, start: usize) -> Option<(&str, usize)> {
    let (mut segment, mut end) = parse_identifier(source, start)?;

    loop {
        let cursor = skip_whitespace(source, end);
        if !source[cursor..].starts_with("::") {
            return Some((segment, end));
        }

        let cursor = skip_whitespace(source, cursor + 2);
        let Some((next_segment, next_end)) = parse_identifier(source, cursor) else {
            return Some((segment, end));
        };

        segment = next_segment;
        end = next_end;
    }
}

fn argument_snippet(source: &str, start: usize) -> String {
    source[start..]
        .chars()
        .take_while(|character| !matches!(character, ')' | ',' | '\n'))
        .take(48)
        .collect::<String>()
        .trim_end()
        .to_owned()
}

fn parse_string_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();

    match bytes.get(start) {
        Some(b'"') => parse_quoted_string_literal(source, start),
        Some(b'r') => parse_raw_string_literal(source, start),
        _ => None,
    }
}

fn parse_quoted_string_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let content_start = start + 1;
    let mut cursor = content_start;
    let mut escaped = false;

    while cursor < bytes.len() {
        match (bytes[cursor], escaped) {
            (_, true) => escaped = false,
            (b'\\', false) => escaped = true,
            (b'"', false) => return Some((source[content_start..cursor].to_owned(), cursor + 1)),
            _ => {}
        }

        cursor += 1;
    }

    None
}

fn parse_raw_string_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let mut cursor = start + 1;

    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }

    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }

    let content_start = cursor + 1;
    let hashes = cursor - start - 1;
    let terminator = format!("\"{}", "#".repeat(hashes));
    let end_offset = source[content_start..].find(&terminator)?;
    let content_end = content_start + end_offset;

    Some((
        source[content_start..content_end].to_owned(),
        content_end + terminator.len(),
    ))
}

fn parse_identifier(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;

    if !is_identifier_start(first) {
        return None;
    }

    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|byte| is_identifier_continue(*byte))
    {
        end += 1;
    }

    Some((&source[start..end], end))
}

fn skip_whitespace(source: &str, start: usize) -> usize {
    let bytes = source.as_bytes();
    let mut cursor = start;

    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }

    cursor
}

fn has_word_boundary(source: &str, start: usize, len: usize) -> bool {
    let bytes = source.as_bytes();
    let before = start
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .is_none_or(|byte| !is_identifier_continue(*byte));
    let after = bytes
        .get(start + len)
        .is_none_or(|byte| !is_identifier_continue(*byte));

    before && after
}

fn is_env_key(key: &str) -> bool {
    let bytes = key.as_bytes();

    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_uppercase() || *byte == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_identifier_continue(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

fn format_vars(vars: &[String]) -> String {
    if vars.is_empty() {
        "none".to_owned()
    } else {
        vars.join(", ")
    }
}

#[test]
fn lifetime_annotated_string_consts_resolve_in_env_reads() {
    let source = r#"
        const STATIC_KEY: &'static str = "STATIC_KEY";
        const SHORT_KEY: &'a str = "SHORT_KEY";
        const BARE_KEY: &str = "BARE_KEY";
        static STATIC_ITEM_KEY: &str = "STATIC_ITEM_KEY";

        fn read(get_var: impl Fn(&str)) {
            let _ = env::var(STATIC_KEY);
            get_var(SHORT_KEY);
            let _ = env::var(BARE_KEY);
            let _ = env::var_os(STATIC_ITEM_KEY);
            let _ = env::var("LITERAL_KEY");
        }
    "#;
    let consts = string_consts(source);

    assert_eq!(consts.get("STATIC_KEY"), Some(&"STATIC_KEY".to_owned()));
    assert_eq!(consts.get("SHORT_KEY"), Some(&"SHORT_KEY".to_owned()));
    assert_eq!(consts.get("BARE_KEY"), Some(&"BARE_KEY".to_owned()));
    assert_eq!(
        consts.get("STATIC_ITEM_KEY"),
        Some(&"STATIC_ITEM_KEY".to_owned())
    );

    assert_eq!(
        env_vars_in_sources(&[(PathBuf::from("read.rs"), source.to_owned())]),
        BTreeSet::from([
            "BARE_KEY".to_owned(),
            "LITERAL_KEY".to_owned(),
            "SHORT_KEY".to_owned(),
            "STATIC_ITEM_KEY".to_owned(),
            "STATIC_KEY".to_owned(),
        ])
    );
}

/// A `&str` constant declared in one module and read from another is the shape
/// that made this test's "cannot silently be omitted" promise untrue: the walk
/// used to resolve names only against the file it was reading, so the read
/// resolved to nothing and the variable never entered the comparison.
#[test]
fn cross_module_string_consts_resolve_in_env_reads() {
    let declaring = r#"
        pub const CROSS_MODULE_KEY: &str = "CROSS_MODULE_KEY";
    "#;
    let reading = r#"
        fn load(get_var: impl Fn(&str)) {
            get_var(config::CROSS_MODULE_KEY);
        }
    "#;

    assert_eq!(
        env_vars_in_sources(&[
            (PathBuf::from("config.rs"), declaring.to_owned()),
            (PathBuf::from("load.rs"), reading.to_owned()),
        ]),
        BTreeSet::from(["CROSS_MODULE_KEY".to_owned()])
    );
}

/// Reads whose key is a runtime parameter are the one gap the walk accepts, so
/// they must stay distinguishable from a name it merely failed to follow.
#[test]
fn runtime_named_env_reads_are_not_mistaken_for_variables() {
    let source = r#"
        fn read_one(key: &str) {
            let _ = env::var(key);
        }
    "#;

    assert!(env_vars_in_sources(&[(PathBuf::from("read.rs"), source.to_owned())]).is_empty());
}

#[test]
#[should_panic(expected = "cannot follow to a variable name")]
fn macro_named_env_reads_fail_instead_of_disappearing() {
    let source = r#"
        fn read() {
            let _ = env::var(concat!("PREFIX", "_SUFFIX"));
        }
    "#;

    let _ = env_vars_in_sources(&[(PathBuf::from("read.rs"), source.to_owned())]);
}

#[test]
#[should_panic(expected = "does not resolve to a single `&str` constant")]
fn ambiguously_declared_env_names_fail_instead_of_binding_to_one_declaration() {
    let first = r#"
        const SHARED_NAME: &str = "FIRST_KEY";
    "#;
    let second = r#"
        const SHARED_NAME: &str = "SECOND_KEY";
    "#;
    let reading = r#"
        fn read(get_var: impl Fn(&str)) {
            get_var(other::SHARED_NAME);
        }
    "#;

    let _ = env_vars_in_sources(&[
        (PathBuf::from("first.rs"), first.to_owned()),
        (PathBuf::from("second.rs"), second.to_owned()),
        (PathBuf::from("read.rs"), reading.to_owned()),
    ]);
}
