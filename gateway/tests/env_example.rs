use std::{
    collections::{BTreeMap, BTreeSet},
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

fn documented_env_vars(path: &Path) -> BTreeSet<String> {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));

    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let (key, _) = line.split_once('=')?;
            let key = key.trim();
            is_env_key(key).then(|| key.to_owned())
        })
        .collect()
}

fn code_env_vars(src_dir: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    collect_rs_files(src_dir, &mut files);
    files.sort();

    let mut vars = BTreeSet::new();

    for file in files {
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", file.display()));
        let consts = string_consts(&source);

        vars.extend(env_var_calls(&source, &consts));
        vars.extend(get_var_calls(&source, &consts));
    }

    vars
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
    let mut index = 0;

    while let Some(offset) = source[index..].find("const") {
        let start = index + offset;
        index = start + "const".len();

        if !has_word_boundary(source, start, "const".len()) {
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

        if !source[cursor..equal].contains("&str") {
            continue;
        }

        cursor = skip_whitespace(source, equal + 1);
        if let Some((value, _)) = parse_string_literal(source, cursor) {
            consts.insert(name.to_owned(), value);
        }
    }

    consts
}

fn env_var_calls(source: &str, consts: &BTreeMap<String, String>) -> BTreeSet<String> {
    scan_calls(source, consts, &["env::var", "env::var_os"])
}

fn get_var_calls(source: &str, consts: &BTreeMap<String, String>) -> BTreeSet<String> {
    scan_calls(source, consts, &["get_var"])
}

fn scan_calls(
    source: &str,
    consts: &BTreeMap<String, String>,
    callees: &[&str],
) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    for callee in callees {
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

            let cursor = skip_whitespace(source, cursor + 1);
            if let Some((value, _)) = parse_string_literal(source, cursor) {
                vars.insert(value);
            } else if let Some((identifier, _)) = parse_identifier(source, cursor) {
                if let Some(value) = consts.get(identifier) {
                    vars.insert(value.clone());
                }
            }
        }
    }

    vars
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
