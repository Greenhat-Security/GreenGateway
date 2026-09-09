//! Syntax facts for the transport ownership gate. No source is executed.
use quote::ToTokens;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};
use syn::{
    visit::{self, Visit},
    Attribute, Item, Meta, UseTree,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn hash(tokens: impl ToTokens) -> String {
    hex::encode(Sha256::digest(
        tokens.to_token_stream().to_string().as_bytes(),
    ))
}

// Possible truth values with test=false; every other cfg atom remains unknown.
fn cfg_values(meta: &Meta) -> (bool, bool) {
    match meta {
        Meta::Path(p) if p.is_ident("test") => (true, false),
        Meta::List(list) => {
            let nested = list.parse_args_with(
                syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
            );
            let Ok(nested) = nested else {
                return (true, true);
            };
            let vals: Vec<_> = nested.iter().map(cfg_values).collect();
            if list.path.is_ident("all") {
                (vals.iter().any(|v| v.0), vals.iter().all(|v| v.1))
            } else if list.path.is_ident("any") {
                (vals.iter().all(|v| v.0), vals.iter().any(|v| v.1))
            } else if list.path.is_ident("not") && vals.len() == 1 {
                (vals[0].1, vals[0].0)
            } else {
                (true, true)
            }
        }
        _ => (true, true),
    }
}
fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg") && a.parse_args::<Meta>().is_ok_and(|m| !cfg_values(&m).1)
    })
}
fn attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

#[derive(Serialize)]
struct Scope {
    file: String,
    scope: String,
    sha256: String,
    reasons: BTreeSet<String>,
}
struct Unit {
    file: String,
    scope: String,
    item: Item,
}
#[derive(Default)]
struct Tree {
    units: Vec<Unit>,
    files: BTreeMap<String, String>,
    names: BTreeMap<String, usize>,
}
impl Tree {
    fn unit(&mut self, file: &str, scope: String, item: Item) {
        let count = self.names.entry(format!("{file}::{scope}")).or_default();
        *count += 1;
        self.units.push(Unit {
            file: file.into(),
            scope: format!("{scope}#{count}"),
            item,
        });
    }
    fn file(&mut self, root: &Path, file: &Path, scope: &str, test: bool) -> Result<()> {
        let absolute = file.canonicalize()?;
        if !absolute.starts_with(root) {
            return Err(format!("module escapes workspace: {}", file.display()).into());
        }
        let relative = absolute
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let role = if test { "nonproduction" } else { "production" };
        if let Some(previous) = self.files.insert(relative.clone(), role.into()) {
            if previous != role {
                return Err(
                    format!("module has mixed test/production ownership: {relative}").into(),
                );
            }
            if test {
                return Ok(());
            }
            return Err(format!(
                "production module reached twice; review path attributes: {relative}"
            )
            .into());
        }
        let source = syn::parse_file(&fs::read_to_string(&absolute)?.replace("\r\n", "\n"))?;
        let test = test || test_only(&source.attrs);
        self.files.insert(
            relative.clone(),
            if test { "nonproduction" } else { "production" }.into(),
        );
        // Inner attributes can generate or conditionally include code too.
        if !test && !source.attrs.is_empty() {
            let mut attrs = source.attrs.clone();
            for a in &mut attrs {
                a.style = syn::AttrStyle::Outer;
            }
            let item: Item =
                syn::parse2(quote::quote!(#(#attrs)* const __FILE_ATTRIBUTES: () = ();))?;
            self.unit(&relative, format!("{scope}::file_attributes"), item);
        }
        let parent = absolute.parent().ok_or("module has no parent")?;
        let directory = if !scope.contains("::")
            || matches!(
                absolute.file_stem().and_then(|x| x.to_str()),
                Some("main" | "lib" | "mod")
            ) {
            parent.to_path_buf()
        } else {
            parent.join(absolute.file_stem().ok_or("module has no stem")?)
        };
        self.items(
            root,
            &relative,
            &directory,
            parent,
            scope,
            test,
            source.items,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn items(
        &mut self,
        root: &Path,
        file: &str,
        directory: &Path,
        path_base: &Path,
        scope: &str,
        test: bool,
        items: Vec<Item>,
    ) -> Result<()> {
        for item in items {
            let test = test || test_only(attrs(&item));
            match item {
                Item::Mod(module) => {
                    let child = format!("{scope}::{}", module.ident);
                    if !test && !module.attrs.is_empty() {
                        let attrs = &module.attrs;
                        self.unit(
                            file,
                            format!("{child}::attributes"),
                            syn::parse2(
                                quote::quote!(#(#attrs)* const __MODULE_ATTRIBUTES: () = ();),
                            )?,
                        );
                    }
                    if let Some((_, items)) = module.content {
                        self.items(
                            root,
                            file,
                            &directory.join(module.ident.to_string()),
                            &directory.join(module.ident.to_string()),
                            &child,
                            test,
                            items,
                        )?;
                    } else {
                        let mut paths = Vec::new();
                        for attr in &module.attrs {
                            if attr.path().is_ident("path") {
                                if let Meta::NameValue(v) = &attr.meta {
                                    if let syn::Expr::Lit(l) = &v.value {
                                        if let syn::Lit::Str(s) = &l.lit {
                                            paths.push(path_base.join(s.value()));
                                        }
                                    }
                                }
                            }
                            if attr.path().is_ident("cfg_attr")
                                && attr.to_token_stream().to_string().contains("path")
                            {
                                return Err(format!("conditional module path needs explicit support: {file}:{child}").into());
                            }
                        }
                        if paths.is_empty() {
                            paths = [
                                directory.join(format!("{}.rs", module.ident)),
                                directory.join(module.ident.to_string()).join("mod.rs"),
                            ]
                            .into_iter()
                            .filter(|p| p.is_file())
                            .collect();
                        }
                        if paths.len() != 1 {
                            return Err(format!("ambiguous/missing module: {file}:{child}").into());
                        }
                        self.file(root, &paths[0], &child, test)?;
                    }
                }
                Item::Impl(mut i) if !test => {
                    let name = format!(
                        "{scope}::impl {} {}",
                        i.trait_
                            .as_ref()
                            .map(|(_, p, _)| p.to_token_stream().to_string())
                            .unwrap_or_default(),
                        i.self_ty.to_token_stream()
                    );
                    let members = std::mem::take(&mut i.items);
                    // Keep impl attributes and type/trait paths in a separate exact scope.
                    self.unit(file, format!("{name}::header"), Item::Impl(i.clone()));
                    for member in members {
                        let (a, member_name) = match &member {
                            syn::ImplItem::Fn(m) => (&m.attrs, m.sig.ident.to_string()),
                            syn::ImplItem::Const(m) => (&m.attrs, m.ident.to_string()),
                            syn::ImplItem::Type(m) => (&m.attrs, m.ident.to_string()),
                            syn::ImplItem::Macro(m) => {
                                (&m.attrs, m.mac.path.to_token_stream().to_string())
                            }
                            _ => return Err("unexamined impl member".into()),
                        };
                        if test_only(a) {
                            continue;
                        }
                        let mut single = i.clone();
                        single.items = vec![member];
                        self.unit(file, format!("{name}::{member_name}"), Item::Impl(single));
                    }
                }
                i if !test => {
                    let name = match &i {
                        Item::Fn(v) => v.sig.ident.to_string(),
                        Item::Use(v) => format!("use {}", v.tree.to_token_stream()),
                        Item::Struct(v) => v.ident.to_string(),
                        Item::Enum(v) => v.ident.to_string(),
                        Item::Type(v) => v.ident.to_string(),
                        Item::Const(v) => v.ident.to_string(),
                        Item::Static(v) => v.ident.to_string(),
                        Item::Trait(v) => v.ident.to_string(),
                        Item::Macro(v) => format!(
                            "macro {}",
                            v.ident
                                .as_ref()
                                .map(ToString::to_string)
                                .unwrap_or_else(|| v.mac.path.to_token_stream().to_string())
                        ),
                        _ => "opaque_item".into(),
                    };
                    self.unit(file, format!("{scope}::{name}"), i);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn capability(path: &[String], aliases: &BTreeSet<String>) -> bool {
    const RAW: &[&str] = &[
        "reqwest",
        "rmcp",
        "rmcp_http",
        "hyper",
        "h2",
        "hyper_util",
        "socket2",
        "mio",
        "libc",
        "windows_sys",
        "winapi",
        "rustix",
        "tokio_postgres",
        "deadpool_postgres",
        "tokio_postgres_rustls",
        "tokio_tungstenite",
        "tungstenite",
    ];
    const SYMBOLS: &[&str] = &[
        "TcpStream",
        "TcpListener",
        "TcpSocket",
        "UdpSocket",
        "UnixStream",
        "UnixListener",
        "UnixDatagram",
        "lookup_host",
        "ToSocketAddrs",
        "connect_async",
        "client_async",
        "Command",
        "Client",
        "ClientBuilder",
        // These checked factories expose a concrete client to protocol adapters.
        // New callers still require review even when their local type is inferred.
        "mcp_http_client",
        "mcp_reqwest_client_at_checked_destination",
        "TlsConnector",
    ];
    path.iter()
        .any(|p| RAW.contains(&p.as_str()) || SYMBOLS.contains(&p.as_str()) || aliases.contains(p))
        || (path.first().is_some_and(|p| p == "std" || p == "tokio")
            && (path.len() == 1
                || path
                    .iter()
                    .any(|p| p == "process" || p == "net" || p == "os")))
}
// These imported names carry values, not the ability to construct a transport.
// Direct crate-qualified occurrences still receive normal capability scanning.
fn data_name(name: &str) -> bool {
    [
        "IpAddr",
        "Ipv4Addr",
        "Ipv6Addr",
        "SocketAddr",
        "SocketAddrV4",
        "SocketAddrV6",
        "Method",
        "StatusCode",
        "Url",
        "HeaderMap",
        "HeaderName",
        "HeaderValue",
        "Version",
        "Error",
        "Response",
        "Body",
        "Bytes",
        "Incoming",
        "Frame",
        "SizeHint",
        "RoleClient",
        "RoleServer",
        "ErrorData",
        "CallToolRequestParams",
        "CallToolResult",
        "Tool",
        "Content",
        "Resource",
        "Prompt",
        "ServerInfo",
        "ClientInfo",
        "ProtocolVersion",
        "RequestId",
    ]
    .contains(&name)
}
fn use_paths(tree: &UseTree, prefix: Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    match tree {
        UseTree::Path(p) => {
            let mut next = prefix;
            next.push(p.ident.to_string());
            use_paths(&p.tree, next, out);
        }
        UseTree::Name(n) => {
            let mut p = prefix;
            if n.ident != "self" {
                p.push(n.ident.to_string());
            }
            let alias = p.last().cloned().unwrap_or_default();
            out.push((p, alias));
        }
        UseTree::Rename(n) => {
            let mut p = prefix;
            if n.ident != "self" {
                p.push(n.ident.to_string());
            }
            out.push((p, n.rename.to_string()));
        }
        UseTree::Group(g) => {
            for t in &g.items {
                use_paths(t, prefix.clone(), out)
            }
        }
        UseTree::Glob(_) => out.push((prefix, "*".into())),
    }
}
#[derive(Default)]
struct Imports {
    paths: Vec<(Vec<String>, String)>,
}
impl<'ast> Visit<'ast> for Imports {
    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        use_paths(&i.tree, vec![], &mut self.paths);
    }
    fn visit_item_type(&mut self, i: &'ast syn::ItemType) {
        if let syn::Type::Path(p) = i.ty.as_ref() {
            self.paths.push((
                p.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                i.ident.to_string(),
            ));
        }
        visit::visit_item_type(self, i);
    }
    fn visit_impl_item_type(&mut self, i: &'ast syn::ImplItemType) {
        if let syn::Type::Path(p) = &i.ty {
            self.paths.push((
                p.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                i.ident.to_string(),
            ));
        }
        visit::visit_impl_item_type(self, i);
    }
    fn visit_item_extern_crate(&mut self, i: &'ast syn::ItemExternCrate) {
        self.paths.push((
            vec![i.ident.to_string()],
            i.rename
                .as_ref()
                .map(|(_, a)| a.to_string())
                .unwrap_or_else(|| i.ident.to_string()),
        ));
    }
}
struct Scan<'a> {
    aliases: &'a BTreeSet<String>,
    reasons: BTreeSet<String>,
}
impl Scan<'_> {
    fn reason(&mut self, r: &str) {
        self.reasons.insert(r.into());
    }
}
impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        if capability(
            &p.segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>(),
            self.aliases,
        ) {
            self.reason("network-or-process-reference");
        }
        visit::visit_path(self, p);
    }
    fn visit_item_use(&mut self, i: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        use_paths(&i.tree, vec![], &mut paths);
        if paths.iter().any(|(p, a)| {
            a == "*" || p.last().is_some_and(|last| last != a) || capability(p, self.aliases)
        }) {
            self.reason("capability-import-or-glob");
        }
    }
    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        if e.method == "mcp_reqwest_client_at_checked_destination" {
            self.reason("network-or-process-reference");
        }
        if [
            "connect",
            "connect_raw",
            "bind",
            "handshake",
            "to_socket_addrs",
            "from_std",
            "from_raw_fd",
            "from_raw_handle",
        ]
        .contains(&e.method.to_string().as_str())
        {
            self.reason("unresolved-transport-method");
        }
        visit::visit_expr_method_call(self, e);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        let path = m.path.to_token_stream().to_string().replace(' ', "");
        // Reviewed syntax containers. Their expression tokens are inspected below;
        // custom/code-generating macros are never accepted just by their suffix.
        let trusted = [
            "format",
            "format_args",
            "vec",
            "matches",
            "write",
            "writeln",
            "assert",
            "assert_eq",
            "assert_ne",
            "debug_assert",
            "debug_assert_eq",
            "debug_assert_ne",
            "panic",
            "unreachable",
            "unimplemented",
            "todo",
            "println",
            "eprintln",
            "concat",
            "env",
            "option_env",
            "stringify",
            "include_str",
            "include_bytes",
            "cfg",
            "serde_json::json",
            "json",
            "tokio::select",
            "tokio::pin",
            "tokio::join",
            "tokio::try_join",
            "tracing::error",
            "tracing::warn",
            "tracing::info",
            "tracing::debug",
            "tracing::trace",
            "metrics::counter",
            "metrics::gauge",
            "metrics::histogram",
            "metrics::describe_counter",
            "metrics::describe_gauge",
            "metrics::describe_histogram",
            "rusqlite::params",
            "params",
        ];
        if !trusted.contains(&path.as_str()) {
            self.reason("unexpanded-macro");
        }
        fn inspect(tokens: proc_macro2::TokenStream, aliases: &BTreeSet<String>) -> bool {
            tokens.into_iter().any(|t| match t {
                proc_macro2::TokenTree::Ident(i) => {
                    capability(&[i.to_string()], aliases)
                        || [
                            "connect",
                            "bind",
                            "handshake",
                            "connect_raw",
                            "from_std",
                            "from_raw_fd",
                            "from_raw_handle",
                            "to_socket_addrs",
                        ]
                        .contains(&i.to_string().as_str())
                }
                proc_macro2::TokenTree::Group(g) => inspect(g.stream(), aliases),
                _ => false,
            })
        }
        if inspect(m.tokens.clone(), self.aliases) {
            self.reason("capability-in-macro-input");
        }
        visit::visit_macro(self, m);
    }
    fn visit_attribute(&mut self, a: &'ast Attribute) {
        if a.path().is_ident("doc") {
            return;
        }
        let name = a.path().to_token_stream().to_string();
        if name == "derive" {
            if let Ok(paths) = a.parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            ) {
                let trusted = [
                    "Debug",
                    "Clone",
                    "Copy",
                    "Default",
                    "Eq",
                    "PartialEq",
                    "Ord",
                    "PartialOrd",
                    "Hash",
                    "Serialize",
                    "Deserialize",
                    "serde::Serialize",
                    "serde::Deserialize",
                ];
                if paths.iter().all(|p| {
                    trusted.contains(&p.to_token_stream().to_string().replace(' ', "").as_str())
                }) {
                    return;
                }
            }
        }
        if ![
            "cfg",
            "allow",
            "warn",
            "deny",
            "forbid",
            "inline",
            "cold",
            "must_use",
            "repr",
            "path",
            "non_exhaustive",
            "serde",
            "async_trait",
            "async_trait :: async_trait",
        ]
        .contains(&name.as_str())
        {
            self.reason("unexpanded-attribute");
        }
    }
    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if signature.unsafety.is_some() {
            self.reason("unsafe-code");
        }
        if signature.abi.is_some() {
            self.reason("foreign-code");
        }
        visit::visit_signature(self, signature);
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.unsafety.is_some() {
            self.reason("unsafe-code");
        }
        visit::visit_item_impl(self, item);
    }
    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if matches!(expression, syn::Expr::Verbatim(_)) {
            self.reason("unexamined-syntax");
        }
        visit::visit_expr(self, expression);
    }
    fn visit_type(&mut self, ty: &'ast syn::Type) {
        if matches!(ty, syn::Type::Verbatim(_)) {
            self.reason("unexamined-syntax");
        }
        visit::visit_type(self, ty);
    }
    fn visit_pat(&mut self, pattern: &'ast syn::Pat) {
        if matches!(pattern, syn::Pat::Verbatim(_)) {
            self.reason("unexamined-syntax");
        }
        visit::visit_pat(self, pattern);
    }
    fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
        self.reason("unsafe-code");
        visit::visit_expr_unsafe(self, e);
    }
    fn visit_item_extern_crate(&mut self, i: &'ast syn::ItemExternCrate) {
        self.reason("external-crate-alias");
        visit::visit_item_extern_crate(self, i);
    }
    fn visit_item_foreign_mod(&mut self, i: &'ast syn::ItemForeignMod) {
        self.reason("foreign-code");
        visit::visit_item_foreign_mod(self, i);
    }
    fn visit_item(&mut self, i: &'ast Item) {
        if test_only(attrs(i)) {
            return;
        }
        if matches!(i, Item::Verbatim(_)) {
            self.reason("unexamined-syntax");
        }
        visit::visit_item(self, i);
    }
}
fn facts(tree: &Tree) -> Vec<Scope> {
    let mut imports = Imports::default();
    for unit in &tree.units {
        imports.visit_item(&unit.item);
    }
    // Global union is conservative: same-spelled local names are also reviewed.
    // Fixed point covers chained renames/reexports/type aliases without pretending
    // to implement Rust's lexical/type resolution.
    let mut aliases = BTreeSet::new();
    loop {
        let previous = aliases.len();
        for (path, alias) in &imports.paths {
            if alias != "*"
                && !path.last().is_some_and(|n| data_name(n))
                && capability(path, &aliases)
            {
                aliases.insert(alias.clone());
            }
        }
        if aliases.len() == previous {
            break;
        }
    }
    tree.units
        .iter()
        .filter_map(|u| {
            let mut scan = Scan {
                aliases: &aliases,
                reasons: BTreeSet::new(),
            };
            scan.visit_item(&u.item);
            (!scan.reasons.is_empty()).then(|| Scope {
                file: u.file.clone(),
                scope: u.scope.clone(),
                sha256: hash(&u.item),
                reasons: scan.reasons,
            })
        })
        .collect()
}
fn run() -> Result<()> {
    let root = env::args().nth(1).ok_or("usage: transport_guard ROOT")?;
    let root = PathBuf::from(root).canonicalize()?;
    let manifest = env::args().nth(2).ok_or("missing enumeration manifest")?;
    let manifest: serde_json::Value = serde_json::from_str(&fs::read_to_string(manifest)?)?;
    for file in manifest["files"].as_array().ok_or("missing files")? {
        let file = root.join(file.as_str().ok_or("file must be a string")?);
        if !file.canonicalize()?.starts_with(&root) {
            return Err("enumerated source escapes workspace".into());
        }
        syn::parse_file(&fs::read_to_string(file)?)?;
    }
    let mut tree = Tree::default();
    for target in manifest["roots"].as_array().ok_or("missing roots")? {
        let file = target["file"].as_str().ok_or("missing root file")?;
        let name = target["name"].as_str().ok_or("missing root name")?;
        let test = target["test"].as_bool().ok_or("missing root role")?;
        tree.file(&root, &root.join(file), name, test)?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"schema":1,"files":tree.files,"scopes":facts(&tree)})
        )?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("transport syntax guard: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(source: &str) -> Vec<Scope> {
        let parsed = syn::parse_file(source).expect("fixture parses");
        let mut tree = Tree::default();
        tree.items(
            Path::new("."),
            "fixture.rs",
            Path::new("."),
            Path::new("."),
            "fixture",
            false,
            parsed.items,
        )
        .expect("fixture module graph");
        facts(&tree)
    }
    fn has(scopes: &[Scope], reason: &str) -> bool {
        scopes.iter().any(|s| s.reasons.contains(reason))
    }
    #[test]
    fn ordinary_checked_api_consumer_does_not_claim_raw_authority() {
        assert!(scan(
            "fn call(client: &EgressClient) { client.checked_destination(PLACEHOLDER); }"
        )
        .is_empty());
    }
    #[test]
    fn direct_socket_is_reviewed_without_executing_it() {
        assert!(has(
            &scan("fn new_path() { std::net::TcpStream::connect(PLACEHOLDER); }"),
            "network-or-process-reference"
        ));
    }
    #[test]
    fn renamed_crate_and_chained_reexport_reach_constructor() {
        let s=scan("use reqwest as first; pub use first as second; use second::Client as Quiet; fn new_path() { Quiet::new(); }");
        assert!(s
            .iter()
            .any(|s| s.scope.contains("new_path")
                && s.reasons.contains("network-or-process-reference")));
    }
    #[test]
    fn renamed_std_module_reaches_socket() {
        let s=scan("use std::net as channel; use channel::TcpStream as Pipe; fn new_path() { Pipe::connect(PLACEHOLDER); }");
        assert!(s
            .iter()
            .any(|s| s.scope.contains("new_path")
                && s.reasons.contains("network-or-process-reference")));
    }
    #[test]
    fn type_alias_and_function_pointer_are_reviewed() {
        let s = scan("type Quiet = reqwest::Client; fn new_path() { let factory = Quiet::new; }");
        assert!(s
            .iter()
            .any(|s| s.scope.contains("new_path")
                && s.reasons.contains("network-or-process-reference")));
    }
    #[test]
    fn foreign_alias_requires_review() {
        assert!(has(
            &scan("extern crate reqwest as quiet; fn new_path() { quiet::Client::new(); }"),
            "external-crate-alias"
        ));
    }
    #[test]
    fn glob_is_not_a_construction_bypass() {
        assert!(has(
            &scan("use crate::unknown::*;"),
            "capability-import-or-glob"
        ));
    }
    #[test]
    fn unresolved_receiver_connect_requires_review() {
        assert!(has(
            &scan("fn new_path(receiver: Thing) { receiver.connect(PLACEHOLDER); }"),
            "unresolved-transport-method"
        ));
    }
    #[test]
    fn macro_input_containing_network_alias_requires_review() {
        let s=scan("use reqwest::Client as Quiet; fn new_path() { serde_json::json!({\"value\": Quiet::new()}); }");
        assert!(has(&s, "capability-in-macro-input"));
    }
    #[test]
    fn trusted_macro_still_checks_nested_tokens() {
        assert!(has(&scan("fn new_path() { tokio::select! { x = async { std::net::TcpStream::connect(PLACEHOLDER) } => {} } }"),"capability-in-macro-input"));
    }
    #[test]
    fn unknown_macro_and_generated_include_are_not_assumed_safe() {
        for source in [
            "fn f() { custom!(); }",
            "include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"));",
            "fn f() { external::json!({}); }",
        ] {
            assert!(has(&scan(source), "unexpanded-macro"));
        }
    }
    #[test]
    fn custom_macro_definition_requires_exact_review() {
        assert!(has(
            &scan("macro_rules! hidden { () => { something() } }"),
            "unexpanded-macro"
        ));
    }
    #[test]
    fn unknown_attribute_requires_exact_review() {
        assert!(has(&scan("#[custom] fn f() {}"), "unexpanded-attribute"));
    }
    #[test]
    fn expression_macro_and_standard_derive_control_passes() {
        assert!(scan(
            "#[derive(Clone, Debug)] struct Data { value: u8 } fn f() { format!(\"{}\", 1); }"
        )
        .is_empty());
    }
    #[test]
    fn test_only_modules_are_excluded_by_cfg_not_name() {
        assert!(
            scan("#[cfg(test)] mod fixtures { fn f() { reqwest::Client::new(); } }").is_empty()
        );
        assert!(has(
            &scan("mod tests { fn f() { reqwest::Client::new(); } }"),
            "network-or-process-reference"
        ));
    }
    #[test]
    fn feature_and_platform_alternatives_remain_in_scope() {
        for cfg in [
            "any(test, feature = \"optional\")",
            "not(test)",
            "windows",
            "unix",
            "all(feature = \"one\", feature = \"two\")",
        ] {
            let s = scan(&format!(
                "#[cfg({cfg})] fn f() {{ reqwest::Client::new(); }}"
            ));
            assert!(has(&s, "network-or-process-reference"), "{cfg}");
        }
        assert!(scan(
            "#[cfg(all(test, feature = \"optional\"))] fn f() { reqwest::Client::new(); }"
        )
        .is_empty());
    }
    #[test]
    fn changed_constructor_settings_change_review_fingerprint() {
        let a = scan("fn f() { reqwest::Client::builder().no_proxy().build(); }");
        let b = scan("fn f() { reqwest::Client::builder().build(); }");
        assert_ne!(a[0].sha256, b[0].sha256);
        let whitespace = scan("fn f(){reqwest::Client::builder().no_proxy().build();}");
        assert_eq!(a[0].sha256, whitespace[0].sha256);
    }
    #[test]
    fn unsafe_and_ffi_have_explicit_review() {
        assert!(has(
            &scan("fn f() { unsafe { operation(); } }"),
            "unsafe-code"
        ));
        assert!(has(&scan("extern \"C\" { fn opaque(); }"), "foreign-code"));
    }
    #[test]
    fn malformed_source_never_yields_empty_success() {
        assert!(syn::parse_file("fn incomplete(").is_err());
    }
    struct FixtureDirectory(PathBuf);
    impl FixtureDirectory {
        fn new(files: &[(&str, &str)]) -> Self {
            let path = env::temp_dir().join(format!(
                "greengateway-transport-fixture-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&path).expect("isolated fixture directory");
            for (name, source) in files {
                let file = path.join(name);
                fs::create_dir_all(file.parent().expect("fixture parent"))
                    .expect("fixture parents");
                fs::write(file, source).expect("write inert fixture source");
            }
            Self(path.canonicalize().expect("fixture root"))
        }
        fn tree(&self) -> Result<Tree> {
            let mut tree = Tree::default();
            tree.file(&self.0, &self.0.join("main.rs"), "fixture", false)?;
            Ok(tree)
        }
    }
    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn file_name_does_not_exclude_a_production_module() {
        let dir = FixtureDirectory::new(&[
            ("main.rs", "mod innocuous_tests;"),
            ("innocuous_tests.rs", "fn f() { reqwest::Client::new(); }"),
        ]);
        let tree = dir.tree().expect("module graph");
        assert_eq!(tree.files["innocuous_tests.rs"], "production");
        assert!(has(&facts(&tree), "network-or-process-reference"));
    }
    #[test]
    fn test_cfg_propagates_into_external_module() {
        let dir = FixtureDirectory::new(&[
            ("main.rs", "#[cfg(test)] mod fixtures;"),
            ("fixtures.rs", "fn f() { reqwest::Client::new(); }"),
        ]);
        let tree = dir.tree().expect("module graph");
        assert_eq!(tree.files["fixtures.rs"], "nonproduction");
        assert!(facts(&tree).is_empty());
    }
    #[test]
    fn missing_module_and_conditional_path_fail() {
        for source in [
            "mod missing;",
            "#[cfg_attr(windows,path=\"alternate.rs\")] mod missing;",
        ] {
            let dir = FixtureDirectory::new(&[("main.rs", source)]);
            assert!(dir.tree().is_err());
        }
    }
    #[test]
    fn explicit_path_is_scanned_and_ambiguous_paths_fail() {
        let dir = FixtureDirectory::new(&[
            ("main.rs", "#[path=\"alternate.rs\"] mod hidden;"),
            ("alternate.rs", "fn f() { reqwest::Client::new(); }"),
        ]);
        assert!(has(
            &facts(&dir.tree().expect("explicit module")),
            "network-or-process-reference"
        ));
        let dir = FixtureDirectory::new(&[
            ("main.rs", "mod ambiguous;"),
            ("ambiguous.rs", ""),
            ("ambiguous/mod.rs", ""),
        ]);
        assert!(dir.tree().is_err());
    }
    #[test]
    fn checkout_line_endings_do_not_change_syntax_fingerprint() {
        let source = "fn f() { let query = \"first\nsecond\"; reqwest::Client::new(); }\n";
        let unix = FixtureDirectory::new(&[("main.rs", source)]);
        let windows = FixtureDirectory::new(&[("main.rs", &source.replace('\n', "\r\n"))]);
        assert_eq!(
            facts(&unix.tree().expect("LF source"))[0].sha256,
            facts(&windows.tree().expect("CRLF source"))[0].sha256
        );
    }
    #[test]
    fn unsafe_signatures_and_impls_require_review_without_an_explicit_block() {
        assert!(has(&scan("unsafe fn f() { operation(); }"), "unsafe-code"));
        assert!(has(
            &scan("unsafe impl Contract for Thing {}"),
            "unsafe-code"
        ));
    }
    #[test]
    fn verbatim_syntax_is_unexamined_instead_of_empty() {
        let aliases = BTreeSet::new();
        let mut scanner = Scan {
            aliases: &aliases,
            reasons: BTreeSet::new(),
        };
        scanner.visit_expr(&syn::Expr::Verbatim(quote::quote!(future_syntax)));
        assert!(scanner.reasons.contains("unexamined-syntax"));
        scanner.reasons.clear();
        scanner.visit_type(&syn::Type::Verbatim(quote::quote!(FutureType)));
        assert!(scanner.reasons.contains("unexamined-syntax"));
    }
    #[test]
    fn aliased_raw_client_factory_call_requires_review_without_a_type_annotation() {
        let scopes=scan("use crate::egress::mcp_http_client as prepared; fn f() { let client = prepared(PLACEHOLDER); }");
        assert!(scopes.iter().any(
            |s| s.scope.contains("::f#") && s.reasons.contains("network-or-process-reference")
        ));
    }
    #[test]
    fn raw_client_factory_method_requires_review_beyond_checked_wrapper_usage() {
        for source in [
            "fn f(egress: &EgressClient) { let client = egress.mcp_reqwest_client_at_checked_destination(PLACEHOLDER); }",
            "fn f(egress: &EgressClient) { let client = EgressClient::mcp_reqwest_client_at_checked_destination(egress, PLACEHOLDER); }",
        ] {
            assert!(has(&scan(source), "network-or-process-reference"));
        }
    }
}
