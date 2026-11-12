//! Builds the web UI in `ui/` (Vite) and embeds `ui/dist` in the binary.
//!
//! The UI is rebuilt when its sources change. Set `BISONBASE_SKIP_UI_BUILD=1` to embed whatever
//! is in `ui/dist` as is (e.g. when building without Node, from a prebuilt `ui/dist`).

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const UI_INPUTS: &[&str] = &[
    "ui/src",
    "ui/index.html",
    "ui/package.json",
    "ui/package-lock.json",
    "ui/vite.config.ts",
    "ui/tsconfig.json",
];

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let ui = root.join("ui");
    let dist = ui.join("dist");
    println!("cargo:rerun-if-env-changed=BISONBASE_SKIP_UI_BUILD");

    if env::var_os("BISONBASE_SKIP_UI_BUILD").is_some() {
        // Not building it ourselves, so pick up changes to the prebuilt files.
        println!("cargo:rerun-if-changed=ui/dist");
    } else {
        for p in UI_INPUTS {
            println!("cargo:rerun-if-changed={p}");
        }
        match build_ui(&ui) {
            Ok(()) => {}
            // No npm here, but a build from elsewhere: use it.
            Err(Build::NoNpm(e)) if dist.join("index.html").exists() => {
                println!("cargo:warning=npm not found ({e}); embedding the existing ui/dist");
            }
            Err(Build::NoNpm(e)) => panic!(
                "building the web UI needs npm ({e}).\n\
                 Install Node.js, or build ui/dist elsewhere and set BISONBASE_SKIP_UI_BUILD=1."
            ),
            Err(Build::Failed(e)) => panic!("building the web UI failed: {e}"),
        }
    }

    assert!(
        dist.join("index.html").exists(),
        "ui/dist/index.html is missing; run `npm run build` in ui/"
    );
    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    files.sort();
    let mut out = String::from("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (url, path) in files {
        writeln!(out, "    ({url:?}, include_bytes!({path:?})),").unwrap();
    }
    out.push_str("];\n");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("ui_files.rs"), out).unwrap();
}

fn npm() -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "npm"]);
        c
    } else {
        Command::new("npm")
    }
}

enum Build {
    NoNpm(std::io::Error),
    Failed(String),
}

fn build_ui(ui: &Path) -> Result<(), Build> {
    let run = |args: &[&str]| -> Result<(), Build> {
        let status = npm()
            .args(args)
            .current_dir(ui)
            .status()
            .map_err(Build::NoNpm)?;
        if status.success() {
            Ok(())
        } else {
            Err(Build::Failed(format!(
                "`npm {}` exited with {status}",
                args.join(" ")
            )))
        }
    };
    if !ui.join("node_modules").exists() {
        run(&["ci", "--no-audit", "--no-fund"])?;
    }
    run(&["run", "build"])
}

/// Every file under `dir`, as (URL path, absolute file path).
fn collect(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for e in fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        if path.is_dir() {
            collect(base, &path, out);
        } else {
            let rel = path.strip_prefix(base).unwrap();
            let url = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            out.push((format!("/{url}"), path.to_string_lossy().into_owned()));
        }
    }
}
