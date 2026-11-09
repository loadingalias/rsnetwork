//! Repository commands. Run them as `cargo xtask <command>`.
//!
//! Each Cargo command runs Cargo from the toolchain that `rust-toolchain.toml`
//! pins, in the workspace root, without ambient compiler overrides. The model
//! command runs the pinned TLA+ checkers under `~/.local/opt`. Local work
//! and CI use the same commands. Its one dependency is rscrypto, which gives
//! the SHA-256 of the evidence digest.

#![expect(
    clippy::print_stderr,
    reason = "xtask is a command-line tool, and standard error is its report channel"
)]

use core::iter;

use rscrypto::Sha256;
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufRead as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::Instant,
};

const USAGE: &str = "\
Usage: cargo xtask <command> [arguments]

Commands
  fix [Cargo args]     Apply Clippy fixes, format, then fail on the lints that remain (local only)
  check [Cargo args]   Check formatting, lints, and rustdoc, and change no file (the CI gate)
  test [Nextest args]  Run the tests; with no arguments, also run the doctests
  model [model[/file]]...
                       Check the TLA+ models in models/; with no argument, every profile

With no Cargo arguments, fix and check select the whole workspace.

A model is a directory in models/. The first part of a profile's file name
names its module: <M>.cfg and <M>.<name>.cfg are TLC profiles of <M>.tla, and
<M>.apalache and <M>.<name>.apalache are Apalache profiles of <M>.tla that hold
the apalache-mc arguments, one a line. A profile whose name ends in `_bad` is a
known-bad variant, and one whose name ends in `_reach` is a reachability
witness. Each of them checks exactly one property, and it passes only when the
checker reports a violation of that property. Every other profile passes only
on a complete check with no violation. TLC checks liveness once, after the
search. One model run at a time holds the host lock; another run waits for it.
The checkers are the pinned JRE, TLC, and Apalache under ~/.local/opt, one
version of each (docs/content/design-models.md), and their output goes to
target/model/.
";

/// The keywords of a TLC configuration file.
const TLC_KEYWORDS: &[&str] = &[
    "ACTION_CONSTRAINT",
    "ACTION_CONSTRAINTS",
    "ALIAS",
    "CHECK_DEADLOCK",
    "CONSTANT",
    "CONSTANTS",
    "CONSTRAINT",
    "CONSTRAINTS",
    "INIT",
    "INVARIANT",
    "INVARIANTS",
    "NEXT",
    "POSTCONDITION",
    "PROPERTIES",
    "PROPERTY",
    "SPECIFICATION",
    "SYMMETRY",
    "VIEW",
];

/// Environment variables that pass options to a checker's JVM without notice,
/// such as `-Dtlc2.TLC.stopAfter`, which stops a search and still exits with 0.
/// Each checker run removes them. `JVM_ARGS` is the one that `apalache-mc` reads.
const JVM_SCRUBBED: &[&str] = &["JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "JVM_ARGS", "_JAVA_OPTIONS"];

/// The name that a deadlock report gets. It is not a TLA+ identifier, so no
/// property can have it.
const DEADLOCK: &str = "(deadlock)";

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

    /// Runs each selected model profile with its checker, in the order of the
    /// selections. A selection with no profile fails, because an empty
    /// selection is not a pass. Each profile is checked before the first run,
    /// and the runs hold the host lock together.
    fn model(&self, args: &[String]) -> Result<(), Failure> {
        let models = self.root.join("models");
        let selections: Vec<Option<&str>> = if args.is_empty() {
            vec![None]
        } else {
            args.iter().map(|arg| Some(arg.as_str())).collect()
        };
        let mut selected: Vec<Profile> = Vec::new();
        for selection in selections {
            let found = profiles(&models, selection)?;
            if found.is_empty() {
                return Err(Failure::new(format!(
                    "no model profile matches `{}`; an empty selection is not a pass",
                    selection.unwrap_or("models/")
                )));
            }
            for profile in found {
                if !selected.iter().any(|known| known.name == profile.name) {
                    selected.push(profile);
                }
            }
        }
        let profiles = selected;
        let checkers = Checkers::find()?;
        let _lock = host_lock()?;
        eprintln!("checkers: {}", checkers.versions);
        let mut dirs: Vec<&Path> = profiles.iter().map(|profile| profile.dir.as_path()).collect();
        dirs.sort();
        dirs.dedup();
        for dir in dirs {
            eprintln!("files of {}: {}", dir.display(), digest(dir)?);
        }
        for profile in &profiles {
            checkers.run(profile, &self.root.join("target/model").join(&profile.name))?;
        }
        Ok(())
    }
}

/// What a profile must show.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A complete check with no violation.
    Holds,
    /// A known-bad variant (`_bad`): a violation of its one property.
    Bad,
    /// A reachability witness (`_reach`): a violation of its one property,
    /// which is the negation of its target.
    Reach,
}

/// A checker run: a model module and the file that configures the run.
struct Profile {
    /// `<model>/<file name>`, for example `operation-ownership/MC.Uring.cfg`.
    name: String,
    dir: PathBuf,
    module: String,
    file: PathBuf,
    apalache: bool,
    kind: Kind,
    /// The one property whose violation a `_bad` or `_reach` profile requires.
    expected: Option<String>,
}

/// The profiles in `models/` that `selection` names, in name order: all of them,
/// those of one model, or one file. A profile with no module, and a `_bad` or
/// `_reach` profile that does not check exactly one property, fail here, before
/// any checker runs.
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
            let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            let Some((stem, extension)) = file_name.rsplit_once('.') else {
                continue;
            };
            let apalache = match extension {
                "cfg" => false,
                "apalache" => true,
                _ => continue,
            };
            let module_stem = stem.split_once('.').map_or(stem, |(module, _)| module);
            let module = format!("{module_stem}.tla");
            if file.is_some_and(|file| file != file_name) {
                continue;
            }
            let name = format!("{model_name}/{file_name}");
            // A profile with no module would be left out of "every profile",
            // while the digest still counts it.
            if !dir.join(&module).is_file() {
                return Err(Failure::new(format!("{name}: the model has no module {module}")));
            }
            let kind = if stem.ends_with("_bad") {
                Kind::Bad
            } else if stem.ends_with("_reach") {
                Kind::Reach
            } else {
                Kind::Holds
            };
            let expected = if kind == Kind::Holds {
                None
            } else {
                let text =
                    fs::read_to_string(&path).map_err(|error| Failure::new(format!("{}: {error}", path.display())))?;
                match properties(&text, apalache).as_slice() {
                    [one] => Some(one.clone()),
                    names => {
                        return Err(Failure::new(format!(
                            "{name}: a `_bad` or `_reach` profile checks exactly one property, and it names {}",
                            names.len()
                        )));
                    }
                }
            };
            found.push(Profile {
                name,
                dir: dir.clone(),
                module,
                file: path,
                apalache,
                kind,
                expected,
            });
        }
    }
    Ok(found)
}

/// The properties that a profile checks: the names after `INVARIANT` and
/// `PROPERTY` in a TLC configuration, or the `--inv` and `--temporal`
/// arguments of an Apalache profile.
fn properties(text: &str, apalache: bool) -> Vec<String> {
    if apalache {
        return text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                line.strip_prefix("--inv=").or_else(|| line.strip_prefix("--temporal="))
            })
            .flat_map(|names| names.split(','))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect();
    }
    let mut names = Vec::new();
    let mut listing = false;
    for line in text.lines() {
        let code = line.split_once("\\*").map_or(line, |(code, _)| code);
        for word in code.split_whitespace() {
            if TLC_KEYWORDS.contains(&word) {
                listing = matches!(word, "INVARIANT" | "INVARIANTS" | "PROPERTY" | "PROPERTIES");
            } else if listing {
                names.push(word.to_owned());
            }
        }
    }
    names
}

/// What a checker's output reports about a run.
#[derive(Default)]
struct Report {
    /// The named properties that the output reports as violated.
    violated: Vec<String>,
    /// TLC printed "Model checking completed. No error has been found.".
    completed: bool,
    /// The count of TLC's last summary line "... N states left on queue.".
    left: Option<u64>,
    /// The first word of Apalache's last "The outcome is: ..." line.
    outcome: Option<String>,
    /// An Apalache line that says that it ignores a part of the profile.
    ignored: Option<String>,
    /// Apalache reported an SMT timeout. It then takes the query's property
    /// as true and goes on, so no outcome line shows that the property was
    /// checked.
    timeout: bool,
}

impl Report {
    fn read(&mut self, line: &str, apalache: bool, expected: Option<&str>) {
        if let Some(name) = violation(line, apalache, expected) {
            self.violated.push(name.to_owned());
        }
        if apalache {
            if let Some(rest) = line.strip_prefix("The outcome is: ") {
                self.outcome = rest.split_whitespace().next().map(str::to_owned);
            }
            if line.contains("will be ignored") {
                self.ignored = Some(line.trim().to_owned());
            }
            if line.contains("=> TIMEOUT") {
                self.timeout = true;
            }
            return;
        }
        if line.starts_with("Model checking completed. No error has been found.") {
            self.completed = true;
        }
        if !line.starts_with("Progress")
            && let Some(rest) = line.strip_suffix(" states left on queue.")
        {
            self.left = rest
                .rsplit(' ')
                .next()
                .and_then(|count| count.replace(',', "").parse().ok());
        }
    }

    /// Whether the run is a complete check with no violation. TLC also exits
    /// with 0, and prints its completion line, after a stopped search, as after
    /// `TLCSet("exit", TRUE)` or `-Dtlc2.TLC.stopAfter`: only a final count of
    /// 0 states left on the queue shows a complete search. Apalache exits with 0
    /// after `SmtTimeout` and `ExecutionsTooShort`, so its outcome decides.
    fn holds(&self, apalache: bool, code: Option<i32>) -> Result<(), String> {
        if apalache {
            if let Some(line) = &self.ignored {
                return Err(format!("Apalache ignores a part of the profile: {line}"));
            }
            if self.timeout {
                return Err(
                    "the check is inconclusive: an SMT query timed out, and Apalache took it as true".to_owned(),
                );
            }
            return match (code, self.outcome.as_deref()) {
                (Some(0), Some("NoError")) => Ok(()),
                (_, Some(outcome @ ("SmtTimeout" | "ExecutionsTooShort" | "Interrupted"))) => {
                    Err(format!("the check is inconclusive: the outcome is {outcome}"))
                }
                (_, Some(outcome)) => Err(format!("the outcome is {outcome}")),
                (_, None) => Err("Apalache reported no outcome".to_owned()),
            };
        }
        match (code, self.completed, self.left) {
            (Some(0), true, Some(0)) => Ok(()),
            (Some(0), _, Some(left)) => Err(format!(
                "the search is inconclusive: it stopped with {left} states left on the queue"
            )),
            (Some(0), _, None) => Err("the search is inconclusive: TLC reported no final queue".to_owned()),
            (None, _, _) => Err("the search is inconclusive: TLC was stopped by a signal".to_owned()),
            (Some(_), _, _) => Err("TLC failed".to_owned()),
        }
    }

    /// Whether the checker's own exit status and outcome are those of a
    /// violation: TLC exits with 10 to 14, and Apalache with 12 after the
    /// outcome `Error`.
    fn violation_status(&self, apalache: bool, code: Option<i32>) -> bool {
        if apalache {
            code == Some(12) && self.outcome.as_deref() == Some("Error")
        } else {
            matches!(code, Some(10..=14))
        }
    }
}

/// The violation that one line of checker output reports, if any. Apalache
/// numbers its properties, so a must-fail Apalache profile names one, and its
/// violation is property 0.
fn violation<'a>(line: &'a str, apalache: bool, expected: Option<&'a str>) -> Option<&'a str> {
    if apalache {
        let reported = line.contains("invariant 0 violated") || line.contains("property 0 violated");
        return if reported { expected } else { None };
    }
    if line.starts_with("Error: Deadlock reached") {
        return Some(DEADLOCK);
    }
    let rest = line
        .strip_prefix("Error: Invariant ")
        .or_else(|| line.strip_prefix("Error: Action property "))
        .or_else(|| line.strip_prefix("Error: Temporal property "))?;
    rest.split_once(" is violated")
        .or_else(|| rest.split_once(" was violated"))
        .map(|(name, _)| name)
}

/// Takes the host lock that lets one model run at a time use the host. It
/// waits while another run holds the lock.
fn host_lock() -> Result<fs::File, Failure> {
    let path = env::temp_dir().join("xtask-model.lock");
    let lock_error = |error: io::Error| Failure::new(format!("{}: {error}", path.display()));
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(lock_error)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            eprintln!("waiting for the model run that holds {}", path.display());
            file.lock().map_err(lock_error)?;
        }
        Err(fs::TryLockError::Error(error)) => return Err(lock_error(error)),
    }
    Ok(file)
}

/// One digest over the checked files of a model (its `.tla`, `.cfg`, and
/// `.apalache` files): the SHA-256 of a list that has, in name order, one
/// line for each file with the SHA-256 of its bytes and its name. An evidence
/// record names this digest, not each file.
fn digest(dir: &Path) -> Result<String, Failure> {
    let names: Vec<String> = sorted_entries(dir)?
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| matches!(extension, "tla" | "cfg" | "apalache"))
        })
        .filter_map(|path| path.file_name().and_then(OsStr::to_str).map(str::to_owned))
        .collect();
    let mut list = String::new();
    for name in &names {
        let path = dir.join(name);
        let bytes = fs::read(&path).map_err(|error| Failure::new(format!("{}: {error}", path.display())))?;
        list.push_str(&hex(&Sha256::digest(&bytes)));
        list.push(' ');
        list.push_str(name);
        list.push('\n');
    }
    Ok(format!(
        "sha256:{} ({} files)",
        hex(&Sha256::digest(list.as_bytes())),
        names.len()
    ))
}

/// The bytes in lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
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

/// The pinned model checkers, one version of each,
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

    /// Runs `profile` with its output in `out`, which starts empty. The checker
    /// output also goes to `out/checker.log`. TLC runs with no search limit,
    /// so a pass is a completed search. A `_bad` or `_reach` profile passes
    /// only when the output reports a violation of its one property.
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
                .args([
                    "tlc2.TLC",
                    "-workers",
                    "auto",
                    "-lncheck",
                    "final",
                    "-noGenerateSpecTE",
                    "-metadir",
                ])
                .arg(out.join("states"))
                .args(["-dumpTrace", "json"])
                .arg(out.join("trace.json"))
                .arg("-config")
                .arg(&profile.file);
            command
        };
        command.arg(&profile.module).current_dir(&profile.dir);
        for name in JVM_SCRUBBED {
            command.env_remove(name);
        }

        let checker = if profile.apalache { "apalache" } else { "tlc" };
        eprintln!("── {checker} {}", profile.name);
        let started = Instant::now();
        let start_error = |error: io::Error| Failure::new(format!("{}: cannot start {checker}: {error}", profile.name));
        let mut child = command.stdout(Stdio::piped()).spawn().map_err(start_error)?;
        let log_path = out.join("checker.log");
        let log_error = |error: io::Error| Failure::new(format!("{}: {error}", log_path.display()));
        let mut log = fs::File::create(&log_path).map_err(log_error)?;
        let mut report = Report::default();
        let mut copy = || -> io::Result<()> {
            if let Some(stdout) = child.stdout.take() {
                for line in io::BufReader::new(stdout).lines() {
                    let line = line?;
                    eprintln!("{line}");
                    writeln!(log, "{line}")?;
                    report.read(&line, profile.apalache, profile.expected.as_deref());
                }
            }
            Ok(())
        };
        if let Err(error) = copy() {
            // A checker that runs on unattended after this run releases the
            // host lock would share the host with the next run, so stop it.
            child.kill().map_err(start_error)?;
            child.wait().map_err(start_error)?;
            return Err(log_error(error));
        }
        let status = child.wait().map_err(start_error)?;
        let seconds = started.elapsed().as_secs_f64();
        let Some(expected) = profile.expected.as_deref() else {
            return match report.holds(profile.apalache, status.code()) {
                Ok(()) => {
                    eprintln!("   ok in {seconds:.2}s ({status})");
                    Ok(())
                }
                Err(reason) => Err(Failure {
                    message: format!(
                        "{}: {reason} ({status}); the output is in {}",
                        profile.name,
                        out.display()
                    ),
                    code: status
                        .code()
                        .and_then(|code| u8::try_from(code).ok())
                        .filter(|code| *code != 0)
                        .unwrap_or(1),
                }),
            };
        };
        let violated = &report.violated;
        if report.violation_status(profile.apalache, status.code())
            && !violated.is_empty()
            && violated.iter().all(|name| name == expected)
        {
            let shows = if profile.kind == Kind::Reach {
                "the target is reached"
            } else {
                "as the known-bad variant requires"
            };
            eprintln!("   `{expected}` is violated: {shows}, in {seconds:.2}s ({status})");
            return Ok(());
        }
        let found = if violated.is_empty() {
            "no violation".to_owned()
        } else {
            format!("a violation of `{}`", violated.join("`, `"))
        };
        Err(Failure::new(format!(
            "{}: it must violate `{expected}`, and the checker reports {found} ({status}); the output is in {}",
            profile.name,
            out.display()
        )))
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
            "{}: expected one installed version; docs/content/design-models.md says how to install it",
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

#[cfg(test)]
mod tests {
    //! The verdicts from checker output, and profile discovery. Each checker
    //! input is lines that the pinned checkers printed (TLC 1.8.0 rev 3ec1cc4,
    //! Apalache 0.62.4).

    use std::fs;
    use std::path::PathBuf;

    use super::{Report, profiles};

    fn report(apalache: bool, lines: &[&str]) -> Report {
        let mut report = Report::default();
        for line in lines {
            report.read(line, apalache, None);
        }
        report
    }

    /// TLC stopped by `-Dtlc2.TLC.stopAfter=5` exits with 0 and prints its
    /// completion line, but its queue is not empty: not a pass.
    #[test]
    fn tlc_stopped_search_is_inconclusive() {
        let report = report(
            false,
            &[
                "Progress(9) at 2026-11-08 11:52:59: 157,492 states generated, 39,960 distinct states found, 23,794 states left on queue.",
                "Model checking completed. No error has been found.",
                "157492 states generated, 39960 distinct states found, 23794 states left on queue.",
            ],
        );
        assert!(matches!(report.holds(false, Some(0)), Err(reason) if reason.contains("23794 states left")));
    }

    /// A complete TLC search ends with 0 states left on the queue.
    #[test]
    fn tlc_complete_search_holds() {
        let report = report(
            false,
            &[
                "Model checking completed. No error has been found.",
                "35811633 states generated, 12415204 distinct states found, 0 states left on queue.",
            ],
        );
        assert_eq!(report.holds(false, Some(0)), Ok(()));
    }

    /// A progress line with an empty queue is not the final summary.
    #[test]
    fn tlc_progress_line_is_not_the_summary() {
        let report = report(
            false,
            &[
                "Model checking completed. No error has been found.",
                "Progress(29) at 2026-11-08 08:17:23: 35,811,633 states generated, 12,415,204 distinct states found, 0 states left on queue.",
            ],
        );
        assert!(
            report
                .holds(false, Some(0))
                .is_err_and(|reason| reason.contains("no final queue"))
        );
    }

    /// Apalache's outcome line has a log stamp after it.
    #[test]
    fn apalache_no_error_holds() {
        let report = report(
            true,
            &["The outcome is: NoError                                           I@10:33:32.335"],
        );
        assert_eq!(report.holds(true, Some(0)), Ok(()));
    }

    /// Apalache exits with 0 after an SMT timeout outcome.
    #[test]
    fn apalache_smt_timeout_is_inconclusive() {
        let report = report(true, &["The outcome is: SmtTimeout                    I@10:33:32.335"]);
        assert!(
            report
                .holds(true, Some(0))
                .is_err_and(|reason| reason.contains("inconclusive"))
        );
    }

    /// With `--timeout-smt`, Apalache takes a timed-out invariant as true and
    /// goes on. The runs seen so far ended with `RuntimeError` or `SmtTimeout`;
    /// the rule does not depend on the outcome, so a `NoError` ending also
    /// fails.
    #[test]
    fn apalache_timed_out_query_is_inconclusive() {
        let report = report(
            true,
            &[
                "State 0: state invariant 13 => TIMEOUT. Assuming it holds true.   I@11:58:01.120",
                "The outcome is: NoError                                           I@11:58:20.004",
            ],
        );
        assert!(
            report
                .holds(true, Some(0))
                .is_err_and(|reason| reason.contains("timed out"))
        );
    }

    /// Only the outcome `Error` with exit 12 is a violation; a runtime error
    /// with the same exit is not.
    #[test]
    fn apalache_violation_needs_the_error_outcome() {
        let error = report(true, &["The outcome is: Error                      I@10:33:32.335"]);
        let runtime = report(true, &["The outcome is: RuntimeError               I@10:33:32.335"]);
        assert!(error.violation_status(true, Some(12)));
        assert!(!runtime.violation_status(true, Some(12)));
    }

    /// A profile whose module is missing fails the selection of every
    /// profile; it is not left out.
    #[test]
    fn profile_with_no_module_fails() {
        let models: PathBuf = std::env::temp_dir().join(format!("xtask-test-models-{}", std::process::id()));
        let model = models.join("m");
        fs::create_dir_all(&model).expect("create the scratch model");
        fs::write(model.join("M.tla"), "").expect("write the module");
        fs::write(model.join("M.cfg"), "").expect("write a profile");
        fs::write(model.join("Missing.cfg"), "").expect("write a profile with no module");
        let result = profiles(&models, None);
        fs::remove_dir_all(&models).expect("remove the scratch model");
        assert!(matches!(result, Err(failure) if failure.message.contains("m/Missing.cfg")));
    }
}
