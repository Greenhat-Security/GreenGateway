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
        ".npmrc",
        "tsconfig.json",
        "vite.config.ts",
        "src",
    ] {
        println!("cargo:rerun-if-changed={}", admin_ui.join(path).display());
    }

    for (command, file) in [("node", ".node-version"), (npm_command(), ".npm-version")] {
        let pin = repo_root.join(file);
        println!("cargo:rerun-if-changed={}", pin.display());
        let expected = std::fs::read_to_string(pin).expect("read declared build-tool version");
        let actual = Command::new(command)
            .arg("--version")
            .output()
            .expect("run declared build tool");
        assert!(actual.status.success(), "build-tool version check failed");
        let actual = String::from_utf8(actual.stdout).expect("build-tool version is UTF-8");
        assert_eq!(
            actual.trim().trim_start_matches('v'),
            expected.trim(),
            "build tool differs from repository version contract"
        );
    }
    for file in [
        "build-tools.json",
        "npm-script-policy.json",
        "scripts/npm-script-policy.mjs",
    ] {
        println!("cargo:rerun-if-changed={}", repo_root.join(file).display());
    }
    let status = Command::new("node")
        .arg(repo_root.join("scripts/npm-script-policy.mjs"))
        .args(["install", "admin-ui"])
        .current_dir(repo_root)
        .status()
        .expect("run reviewed npm installer");
    assert!(status.success(), "reviewed npm install failed");
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
