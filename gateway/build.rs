use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("gateway crate should live directly under the repo root");
    let admin_ui = repo_root.join("admin-ui");

    for path in [
        "index.html",
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "vite.config.ts",
        "src",
    ] {
        println!("cargo:rerun-if-changed={}", admin_ui.join(path).display());
    }

    run_npm(&admin_ui, &["ci"]);
    run_npm(&admin_ui, &["run", "build"]);
}

fn run_npm(admin_ui: &Path, args: &[&str]) {
    let status = Command::new(npm_command())
        .args(args)
        .current_dir(admin_ui)
        .status()
        .unwrap_or_else(|err| panic!("failed to run npm {}: {err}", args.join(" ")));

    assert!(
        status.success(),
        "npm {} failed with status {status}",
        args.join(" ")
    );
}

fn npm_command() -> &'static str {
    if cfg!(windows) {
        "npm.cmd"
    } else {
        "npm"
    }
}
