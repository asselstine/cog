use std::{env, path::Path, process::Command};

fn main() {
    let frontend = Path::new("frontend");
    println!("cargo:rerun-if-changed=frontend/src");
    println!("cargo:rerun-if-changed=frontend/index.html");
    println!("cargo:rerun-if-changed=frontend/package.json");
    println!("cargo:rerun-if-changed=frontend/package-lock.json");
    println!("cargo:rerun-if-changed=frontend/vite.config.js");

    if env::var_os("DOCS_RS").is_some() {
        std::fs::create_dir_all("frontend/dist").expect("create documentation asset directory");
        std::fs::write(
            "frontend/dist/index.html",
            "<!doctype html><title>Clanker Operations Gateway</title>",
        )
        .expect("create documentation placeholder asset");
        return;
    }

    if env::var_os("COG_FRONTEND_PREBUILT").is_some() {
        assert!(
            frontend.join("dist/index.html").is_file(),
            "prebuilt frontend assets are missing"
        );
        return;
    }

    let install = Command::new("npm")
        .args(["ci", "--no-audit", "--no-fund"])
        .current_dir(frontend)
        .status()
        .expect("npm is required to build the cog frontend");
    assert!(install.success(), "npm ci failed");

    let build = Command::new("npm")
        .args(["run", "build"])
        .current_dir(frontend)
        .status()
        .expect("failed to run the frontend build");
    assert!(build.success(), "frontend build failed");
}
