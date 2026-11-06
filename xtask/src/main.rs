//! Repository commands. Run them as `cargo xtask <command>`.
//!
//! Each Cargo command runs Cargo from the toolchain that `rust-toolchain.toml`
//! pins, in the workspace root, without ambient compiler overrides. The model
//! command runs the TLA+ checkers that `machine update all` installs. Local work
//! and CI use the same commands. This package has no dependencies.

#![expect(
    clippy::print_stderr,
    reason = "xtask is a command-line tool, and standard error is its report channel"
)]

use core::iter;
use std::{
    env,
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Instant,
};

const USAGE: &str = "\
Usage: cargo xtask <command> [arguments]

Commands
  fix [Cargo args]     Apply Clippy fixes, format, then fail on the lints that remain (local only)
  check [Cargo args]   Check formatting, lints, and rustdoc, and change no file (the CI gate)
  test [Nextest args]  Run the tests; with no arguments, also run the doctests
  model [model[/file]] Check the TLA+ models in models/; with no argument, every profile

With no Cargo arguments, fix and check select the whole workspace.

A model is a directory in models/. In it, each <M>.cfg beside <M>.tla is a TLC
profile, and each <M>.apalache beside <M>.tla is an Apalache profile that holds
the apalache-mc arguments, one a line. A profile whose name ends in `_bad` is a
known-bad variant: it passes only when the checker finds a violation. The
checkers are the ones that `machine update all` installs under ~/.local/opt,
and their output goes to target/model/.
";

/// Environment variables that change compilation without notice. Each command
/// removes them, so only the checked-in configuration applies. Each variable
/// that starts with `CARGO_BUILD_`, `CARGO_PROFILE_`, or `CARGO_TARGET_` is
/// also removed.
const SCRUBBED: &[&str] = &[
    "CARGO",
    "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_INCREMENTAL",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTDOC",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
    "RUSTUP_TOOLCHAIN",
];

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::SUCCESS;
    };
    let result = match command.as_str() {
        "-h" | "--help" => {
            eprint!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        "fix" => Repo::open().and_then(|repo| repo.fix(rest)),
        "check" => Repo::open().and_then(|repo| repo.check(rest)),
        "test" => Repo::open().and_then(|repo| repo.test(rest)),
        "model" => Repo::open().and_then(|repo| repo.model(rest)),
        other => Err(Failure::new(format!("unknown command `{other}`\n\n{USAGE}"))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("error: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

/// The workspace root and the toolchain channel that it pins.
struct Repo {
    root: PathBuf,
    channel: String,
}

impl Repo {
    fn open() -> Result<Self, Failure> {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.parent().unwrap_or(manifest).to_path_buf();
        let path = root.join("rust-toolchain.toml");
        let text = fs::read_to_string(&path).map_err(|error| Failure::new(format!("{}: {error}", path.display())))?;
        let channel = text
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
            })
            .filter(|channel| !channel.is_empty())
            .ok_or_else(|| Failure::new(format!("{} pins no channel", path.display())))?;
        Ok(Self { root, channel })
    }

    /// A Cargo command from the pinned toolchain. It runs in the workspace
    /// root, with no compiler wrapper and no ambient compiler overrides. A
    /// missing toolchain or component fails; nothing is installed.
    fn cargo(&self, args: &[&str]) -> Command {
        let mut command = Command::new("rustup");
        command
            .args(["run", &self.channel, "cargo"])
            .args(args)
            .current_dir(&self.root);
        for (name, _) in env::vars_os() {
            if scrubbed(&name) {
                command.env_remove(name);
            }
        }
        command
            .env("RUSTUP_AUTO_INSTALL", "0")
            .env("RUSTC_WRAPPER", "")
            .env("RUSTC_WORKSPACE_WRAPPER", "");
        command
    }

    /// Applies the machine-applicable Clippy fixes, then formats the code.
    /// `clippy --fix` reports each lint that it cannot fix as a warning and
    /// still succeeds. Thus a last pass that changes nothing fails on them.
    fn fix(&self, args: &[String]) -> Result<(), Failure> {
        let scope = scope(args);
        step(
            "clippy --fix",
            self.cargo(&[
                "clippy",
                "--fix",
                "--locked",
                "--allow-dirty",
                "--all-targets",
                "--quiet",
            ])
            .args(&scope),
        )?;
        step("fmt", &mut self.cargo(&["fmt", "--all"]))?;
        step(
            "clippy",
            self.cargo(&["clippy", "--locked", "--all-targets", "--quiet"])
                .args(&scope),
        )
    }

    /// Checks formatting, lints, and rustdoc. It changes no file.
    fn check(&self, args: &[String]) -> Result<(), Failure> {
        let scope = scope(args);
        step("fmt --check", &mut self.cargo(&["fmt", "--all", "--check"]))?;
        step(
            "clippy",
            self.cargo(&["clippy", "--locked", "--all-targets", "--quiet"])
                .args(&scope),
        )?;
        step(
            "rustdoc",
            self.cargo(&["doc", "--locked", "--no-deps", "--quiet"]).args(&scope),
        )
    }

    /// Runs the tests with Nextest. With no arguments, it runs every test in
    /// the workspace, then the doctests, which Nextest does not run.
    fn test(&self, args: &[String]) -> Result<(), Failure> {
        if !args.is_empty() {
            return step("nextest", self.cargo(&["nextest", "run", "--locked"]).args(args));
        }
        step(
            "nextest",
            &mut self.cargo(&["nextest", "run", "--locked", "--workspace"]),
        )?;
        step(
            "doctest",
            &mut self.cargo(&["test", "--locked", "--doc", "--workspace", "--quiet"]),
        )
    }

    /// Runs each selected model profile with its checker. A selection with no
    /// profile fails, because an empty selection is not a pass.
    fn model(&self, args: &[String]) -> Result<(), Failure> {
        let selection = match args {
            [] => None,
            [one] => Some(one.as_str()),
            _ => return Err(Failure::new(format!("model takes at most one argument\n\n{USAGE}"))),
        };
        let profiles = profiles(&self.root.join("models"), selection)?;
        if profiles.is_empty() {
            return Err(Failure::new(format!(
                "no model profile matches `{}`; an empty selection is not a pass",
                selection.unwrap_or("models/")
            )));
        }
        let checkers = Checkers::find()?;
        eprintln!("checkers: {}", checkers.versions);
        for profile in &profiles {
            checkers.run(profile, &self.root.join("target/model").join(&profile.name))?;
        }
        Ok(())
    }
}

/// A checker run: a model module and the file that configures the run.
struct Profile {
    /// `<model>/<file name>`, for example `operation-ownership/MC.cfg`.
    name: String,
    dir: PathBuf,
    module: String,
    file: PathBuf,
    apalache: bool,
    known_bad: bool,
}

/// The profiles in `models/` that `selection` names, in name order: all of them,
/// those of one model, or one file.
fn profiles(models: &Path, selection: Option<&str>) -> Result<Vec<Profile>, Failure> {
    let (model, file) = match selection.map(|text| text.split_once('/')) {
        None => (None, None),
        Some(None) => (selection, None),
        Some(Some((model, file))) => (Some(model), Some(file)),
    };
    let mut found = Vec::new();
    for dir in sorted_entries(models)? {
        let Some(model_name) = dir.file_name().map(|name| name.to_string_lossy().into_owned()) else {
            continue;
        };
        if !dir.is_dir() || model.is_some_and(|model| model != model_name) {
            continue;
        }
        for path in sorted_entries(&dir)? {
            let (Some(stem), Some(extension), Some(file_name)) = (
                path.file_stem().map(|stem| stem.to_string_lossy().into_owned()),
                path.extension(),
                path.file_name().map(|name| name.to_string_lossy().into_owned()),
            ) else {
                continue;
            };
            let apalache = match extension.to_str() {
                Some("cfg") => false,
                Some("apalache") => true,
                _ => continue,
            };
            let module = format!("{stem}.tla");
            if !dir.join(&module).is_file() || file.is_some_and(|file| file != file_name) {
                continue;
            }
            found.push(Profile {
                name: format!("{model_name}/{file_name}"),
                dir: dir.clone(),
                known_bad: stem.ends_with("_bad"),
                module,
                file: path,
                apalache,
            });
        }
    }
    Ok(found)
}

/// The entries of `dir` in name order; none when `dir` does not exist.
fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>, Failure> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Failure::new(format!("{}: {error}", dir.display()))),
    };
    let mut paths = entries
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Failure::new(format!("{}: {error}", dir.display())))?;
    paths.sort();
    Ok(paths)
}

/// The model checkers that `machine update all` installs, one version of each,
/// under `~/.local/opt/<name>/<version>`.
struct Checkers {
    java_bin: PathBuf,
    tla2tools: PathBuf,
    apalache: PathBuf,
    versions: String,
}

impl Checkers {
    fn find() -> Result<Self, Failure> {
        let home = env::var_os("HOME").ok_or_else(|| Failure::new("HOME is not set".to_owned()))?;
        let opt = Path::new(&home).join(".local/opt");
        let (jre, jre_version) = installed(&opt, "temurin-jre")?;
        let (tla2tools, tla2tools_version) = installed(&opt, "tla2tools")?;
        let (apalache, apalache_version) = installed(&opt, "apalache")?;
        // A macOS JRE keeps its home in a bundle; a Linux JRE is the home.
        let bundle = jre.join("Contents/Home");
        let java_home = if bundle.is_dir() { bundle } else { jre };
        Ok(Self {
            java_bin: java_home.join("bin"),
            tla2tools: tla2tools.join("tla2tools.jar"),
            apalache: apalache.join("bin/apalache-mc"),
            versions: format!("temurin-jre {jre_version}, tla2tools {tla2tools_version}, apalache {apalache_version}"),
        })
    }

    /// Runs `profile` with its output in `out`, which starts empty. TLC reports
    /// a violation with an exit code from 10 to 14, and Apalache with 12. TLC
    /// runs with no search limit, so a pass is a completed search.
    fn run(&self, profile: &Profile, out: &Path) -> Result<(), Failure> {
        let output_error = |error: io::Error| Failure::new(format!("{}: {error}", out.display()));
        match fs::remove_dir_all(out) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(output_error(error)),
            _ => fs::create_dir_all(out).map_err(output_error)?,
        }
        let mut command = if profile.apalache {
            let text = fs::read_to_string(&profile.file)
                .map_err(|error| Failure::new(format!("{}: {error}", profile.file.display())))?;
            // apalache-mc runs the first `java` on the path.
            let path = env::var_os("PATH").unwrap_or_default();
            let path = env::join_paths(iter::once(self.java_bin.clone()).chain(env::split_paths(&path)))
                .map_err(|error| Failure::new(format!("PATH: {error}")))?;
            let mut command = Command::new(&self.apalache);
            command
                .args(text.lines().map(str::trim).filter(|line| !line.is_empty()))
                .arg(format!("--out-dir={}", out.display()))
                .env("PATH", path);
            command
        } else {
            let mut command = Command::new(self.java_bin.join("java"));
            command
                .args(["-XX:+UseParallelGC", "-cp"])
                .arg(&self.tla2tools)
                .args(["tlc2.TLC", "-workers", "auto", "-noGenerateSpecTE", "-metadir"])
                .arg(out.join("states"))
                .args(["-dumpTrace", "json"])
                .arg(out.join("trace.json"))
                .arg("-config")
                .arg(&profile.file);
            command
        };
        command.arg(&profile.module).current_dir(&profile.dir);

        let checker = if profile.apalache { "apalache" } else { "tlc" };
        eprintln!("── {checker} {}", profile.name);
        let started = Instant::now();
        let status = command
            .status()
            .map_err(|error| Failure::new(format!("{}: cannot start {checker}: {error}", profile.name)))?;
        let code = status.code();
        let violation = if profile.apalache {
            code == Some(12)
        } else {
            matches!(code, Some(10..=14))
        };
        let seconds = started.elapsed().as_secs_f64();
        match (profile.known_bad, violation) {
            (true, true) => {
                eprintln!("   violation found, as the known-bad variant requires, in {seconds:.2}s");
                Ok(())
            }
            (true, false) if status.success() => Err(Failure::new(format!(
                "{}: the known-bad variant found no violation",
                profile.name
            ))),
            (false, _) if status.success() => {
                eprintln!("   ok in {seconds:.2}s");
                Ok(())
            }
            _ => Err(Failure {
                message: format!("{} failed ({status}); the output is in {}", profile.name, out.display()),
                code: code
                    .and_then(|code| u8::try_from(code).ok())
                    .filter(|code| *code != 0)
                    .unwrap_or(1),
            }),
        }
    }
}

/// The one installed version of `name` under `opt`: its directory and version.
fn installed(opt: &Path, name: &str) -> Result<(PathBuf, String), Failure> {
    let dir = opt.join(name);
    let mut versions = sorted_entries(&dir)?;
    versions.retain(|path| path.is_dir());
    match (versions.pop(), versions.is_empty()) {
        (Some(path), true) => {
            let version = path
                .file_name()
                .map(|version| version.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok((path, version))
        }
        _ => Err(Failure::new(format!(
            "{}: expected one installed version; run `machine update all`",
            dir.display()
        ))),
    }
}

/// Whether the environment variable `name` changes compilation without notice.
fn scrubbed(name: &OsStr) -> bool {
    let name = name.to_string_lossy().to_ascii_uppercase();
    SCRUBBED.contains(&name.as_str())
        || ["CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// The Cargo arguments of the caller, or the whole workspace when there are none.
fn scope(args: &[String]) -> Vec<&str> {
    if args.is_empty() {
        vec!["--workspace"]
    } else {
        args.iter().map(String::as_str).collect()
    }
}

/// Runs `command` as the step `name`. A failure keeps the exit code of the command.
fn step(name: &str, command: &mut Command) -> Result<(), Failure> {
    eprintln!("── {name}");
    let started = Instant::now();
    let status = command.status().map_err(|error| {
        Failure::new(format!(
            "{name}: cannot start {}: {error}",
            command.get_program().to_string_lossy()
        ))
    })?;
    if status.success() {
        eprintln!("   ok in {:.2}s", started.elapsed().as_secs_f64());
        return Ok(());
    }
    let code = status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .filter(|code| *code != 0)
        .unwrap_or(1);
    Err(Failure {
        message: format!("{name} failed ({status})"),
        code,
    })
}

/// A failed command: the message to report and the exit code of the process.
struct Failure {
    message: String,
    code: u8,
}

impl Failure {
    fn new(message: String) -> Self {
        Self { message, code: 1 }
    }
}
