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

mod evidence;

use core::{iter, num::NonZeroU32};

use rscrypto::Sha256;
use std::{
    env,
    ffi::OsStr,
    fs,
    io::{self, BufRead as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::Instant,
};

const USAGE: &str = "\
Usage: cargo xtask <command> [arguments]

Commands
  fix [Cargo args]     Apply Clippy fixes, format, then fail on the lints that remain (local only)
  check [Cargo args]   Check formatting, lints, rustdoc, and the protocol-only closure, and
                       change no file (the CI gate)
  test [Nextest args]  Run the tests; with no arguments, also run the doctests
  model [--tlc-heap-mib=N --tlc-fp-mib=N] [model[/file]]...
                       Check the TLA+ models in models/; with no argument, every profile

fix, check, and test select the whole workspace unless their arguments select
packages with -p or --package.

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
target/model/. The two TLC memory options must be given together as positive
whole MiB values. They select a separate off-heap fingerprint set and retain
gc.log with each TLC run. Without them, TLC uses its default memory settings.
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

/// The name that a deadlock report gets. It is not a TLA+ identifier, so no
/// property can have it.
const DEADLOCK: &str = "(deadlock)";

/// The crates that a protocol-only build of `rsnetwork` can hold: the core, and the shared types
/// of the runtime family, which have no scheduler and no driver. A binding adds its runtime in its
/// own package (`rsnetwork-tokio`, `rsnetwork-rsasync`), never in this closure.
const PROTOCOL_CLOSURE: &[&str] = &["rsnetwork", "rstypes"];

/// The crates that the default `tls` feature adds: rustls, the rscrypto provider, and their
/// dependencies. None builds C, and only rscrypto does cryptography (N101). A new crate here needs
/// the approval of the user.
const TLS_CLOSURE: &[&str] = &[
    "cfg-if",
    "getrandom",
    "libc",
    "r-efi",
    "rscrypto",
    "rscrypto-rustls",
    "rustls",
    "rustls-pki-types",
    "rustls-webpki",
    "subtle",
    "untrusted",
    "zeroize",
];

/// The crates that the Tokio binding adds to the core with all its features: Tokio with `rt`,
/// `net`, `sync`, and `time`, socket2, and their dependencies (N107). None builds C. A new crate
/// here needs the approval of the user.
const TOKIO_CLOSURE: &[&str] = &[
    "mio",
    "pin-project-lite",
    "rsnetwork-tokio",
    "socket2",
    "tokio",
    "wasi",
    "windows-link",
    "windows-sys",
];

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
        self.tool("cargo", args)
    }

    /// `rustfmt` with the root `rustfmt.toml` on the sources of `fuzz/`: the
    /// harness and each target. `fuzz/` is a workspace of its own, so
    /// `cargo fmt --all` does not reach it. `rustfmt` on the files resolves no
    /// dependency of the fuzz workspace.
    fn fuzz_fmt(&self, args: &[&str]) -> Result<Command, Failure> {
        let targets = self.root.join("fuzz/fuzz_targets");
        let unreadable =
            |error: io::Error| Failure::new(format!("fmt fuzz: cannot read {}: {error}", targets.display()));
        let mut files = vec![self.root.join("fuzz/src/lib.rs")];
        for entry in fs::read_dir(&targets).map_err(unreadable)? {
            let path = entry.map_err(unreadable)?.path();
            if path.extension() == Some(OsStr::new("rs")) {
                files.push(path);
            }
        }
        files.sort();
        let mut command = self.tool("rustfmt", &["--config-path", "rustfmt.toml"]);
        command.args(args).args(files);
        Ok(command)
    }

    /// A command of `tool` from the pinned toolchain, as [`cargo`](Self::cargo)
    /// runs it.
    fn tool(&self, tool: &str, args: &[&str]) -> Command {
        let mut command = Command::new("rustup");
        command
            .args(["run", &self.channel, tool])
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

    /// Applies the machine-applicable Clippy fixes, then formats the code and the
    /// sources of `fuzz/`.
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
        step("fmt fuzz", &mut self.fuzz_fmt(&[])?)?;
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
        step("fmt --check fuzz", &mut self.fuzz_fmt(&["--check"])?)?;
        step(
            "clippy",
            self.cargo(&["clippy", "--locked", "--all-targets", "--quiet"])
                .args(&scope),
        )?;
        step(
            "rustdoc",
            self.cargo(&["doc", "--locked", "--no-deps", "--quiet"]).args(&scope),
        )?;
        self.closure()
    }

    /// Fails when a build of a package holds a crate outside its list. The protocol-only build
    /// of `rsnetwork` (no default features) holds only [`PROTOCOL_CLOSURE`]: no executor, socket
    /// driver, or Tokio. The default build, and a build with all features, add only
    /// [`TLS_CLOSURE`]: the `tcp` feature adds no crate. `rsnetwork-tokio` adds only
    /// [`TOKIO_CLOSURE`]. It reads the normal and build dependencies on every target.
    fn closure(&self) -> Result<(), Failure> {
        eprintln!("── closure");
        let started = Instant::now();
        for (package, build, features, lists) in [
            (
                "rsnetwork",
                "a protocol-only build",
                Some("--no-default-features"),
                &[][..],
            ),
            ("rsnetwork", "the default build", None, &[TLS_CLOSURE][..]),
            (
                "rsnetwork",
                "a build with all features",
                Some("--all-features"),
                &[TLS_CLOSURE][..],
            ),
            (
                "rsnetwork-tokio",
                "a build with all features",
                Some("--all-features"),
                &[TLS_CLOSURE, TOKIO_CLOSURE][..],
            ),
        ] {
            let mut args = vec![
                "tree",
                "--locked",
                "--quiet",
                "-p",
                package,
                "-e",
                "normal,build",
                "--target",
                "all",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ];
            args.extend(features);
            let output = self
                .cargo(&args)
                .output()
                .map_err(|error| Failure::new(format!("closure: cannot start cargo tree: {error}")))?;
            if !output.status.success() {
                return Err(Failure::new(format!(
                    "closure: cargo tree failed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            let tree = String::from_utf8_lossy(&output.stdout);
            let mut outside: Vec<&str> = tree
                .lines()
                .filter_map(|line| line.split_whitespace().next())
                .filter(|name| !PROTOCOL_CLOSURE.contains(name) && !lists.iter().any(|list| list.contains(name)))
                .collect();
            outside.sort_unstable();
            outside.dedup();
            if !outside.is_empty() {
                return Err(Failure::new(format!(
                    "closure: {build} of {package} holds {}; a binding takes its runtime in its own package, and a new crate needs approval",
                    outside.join(", ")
                )));
            }
        }
        eprintln!("   ok in {:.2}s", started.elapsed().as_secs_f64());
        Ok(())
    }

    /// Runs the tests with Nextest, in the whole workspace unless the
    /// arguments select packages. With no arguments, it then runs the
    /// doctests, which Nextest does not run.
    fn test(&self, args: &[String]) -> Result<(), Failure> {
        step("nextest", self.cargo(&["nextest", "run", "--locked"]).args(scope(args)))?;
        if !args.is_empty() {
            return Ok(());
        }
        step(
            "doctest",
            &mut self.cargo(&["test", "--locked", "--doc", "--workspace", "--all-features", "--quiet"]),
        )
    }

    /// Runs each selected model profile with its checker, in the order of the
    /// selections. A selection with no profile fails, because an empty
    /// selection is not a pass. Each profile is checked before the first run,
    /// and the runs hold the host lock together.
    fn model(&self, args: &[String]) -> Result<(), Failure> {
        let (args, memory) = model_args(args)?;
        let live_models = self.root.join("models");
        let _lock = host_lock()?;
        let models = evidence::directory(&self.root.join("target/model/inputs"))?;
        for dir in sorted_entries(&live_models)? {
            let Some(name) = dir.file_name().and_then(OsStr::to_str) else {
                continue;
            };
            if dir.is_dir() && (args.is_empty() || args.iter().any(|arg| arg.split('/').next() == Some(name))) {
                evidence::freeze(&dir, &models.join(name))?;
            }
        }
        let selections: Vec<Option<&str>> = if args.is_empty() {
            vec![None]
        } else {
            args.iter().copied().map(Some).collect()
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
        if memory.is_some() && profiles.iter().all(|profile| profile.apalache) {
            return Err(Failure::new("TLC memory options require a TLC profile".to_owned()));
        }
        let checkers = Checkers::find()?;
        eprintln!("checkers: {}", checkers.versions);
        if let Some(memory) = memory {
            eprintln!(
                "TLC memory: heap={} MiB, fingerprints={} MiB (OffHeapDiskFPSet); GC log: gc.log",
                memory.heap_mib, memory.fp_mib
            );
        }
        let mut dirs: Vec<&Path> = profiles.iter().map(|profile| profile.dir.as_path()).collect();
        dirs.sort();
        dirs.dedup();
        for dir in &dirs {
            eprintln!("files of {}: {}", dir.display(), digest(dir)?);
        }
        for profile in &profiles {
            checkers.run(profile, &self.root.join("target/model").join(&profile.name), memory)?;
        }
        for dir in dirs {
            let name = dir
                .file_name()
                .ok_or_else(|| Failure::new("model has no directory name".to_owned()))?;
            if digest(dir)? != digest(&live_models.join(name))? {
                return Err(Failure::new(
                    "model files changed after the inputs were retained; results apply to the retained revision"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Explicit JVM heap and off-heap fingerprint limits. MiB values fit Java's
/// signed byte count after conversion; zero cannot select a default by mistake.
#[derive(Clone, Copy)]
struct TlcMemory {
    heap_mib: NonZeroU32,
    fp_mib: NonZeroU32,
}

/// Separate model selections from the paired TLC memory options before any run.
fn model_args(args: &[String]) -> Result<(Vec<&str>, Option<TlcMemory>), Failure> {
    let mut selections = Vec::new();
    let mut heap_mib = None;
    let mut fp_mib = None;
    for arg in args {
        if !arg.starts_with('-') {
            selections.push(arg.as_str());
            continue;
        }
        let (name, value) = arg.split_once('=').unwrap_or((arg, ""));
        let slot = match name {
            "--tlc-heap-mib" => &mut heap_mib,
            "--tlc-fp-mib" => &mut fp_mib,
            _ => return Err(Failure::new(format!("unknown model option `{name}`"))),
        };
        if slot.is_some() {
            return Err(Failure::new(format!("duplicate model option `{name}`")));
        }
        *slot = Some(value.parse::<NonZeroU32>().map_err(|_| {
            Failure::new(format!(
                "{name} requires a positive whole MiB value no larger than 4294967295"
            ))
        })?);
    }
    let memory = match (heap_mib, fp_mib) {
        (None, None) => None,
        (Some(heap_mib), Some(fp_mib)) => Some(TlcMemory { heap_mib, fp_mib }),
        _ => {
            return Err(Failure::new(
                "give both --tlc-heap-mib=N and --tlc-fp-mib=N, or neither".to_owned(),
            ));
        }
    };
    Ok((selections, memory))
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

fn profile_kind(stem: &str) -> Kind {
    if stem.ends_with("_bad") {
        Kind::Bad
    } else if stem.ends_with("_reach") {
        Kind::Reach
    } else {
        Kind::Holds
    }
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
            let kind = profile_kind(stem);
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
    let mut names = std::collections::BTreeSet::new();
    for path in sorted_entries(dir)? {
        let extension = path.extension().and_then(OsStr::to_str);
        if extension.is_some_and(|extension| matches!(extension, "tla" | "cfg" | "apalache"))
            && let Some(name) = path.file_name().and_then(OsStr::to_str)
        {
            names.insert(name.to_owned());
        }
        if extension == Some("apalache") {
            let text = fs::read_to_string(&path).map_err(|error| Failure::new(error.to_string()))?;
            names.extend(evidence::auxiliaries(&text)?);
        }
    }
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
        let identities = format!(
            "jre-sha256={}\ntlc-sha256={}\napalache-sha256={}\nrunner-sha256={}",
            evidence::tool_identity(&jre)?,
            evidence::tool_identity(&tla2tools)?,
            evidence::tool_identity(&apalache)?,
            hex(&Sha256::digest(
                &fs::read(env::current_exe().map_err(|error| Failure::new(error.to_string()))?)
                    .map_err(|error| Failure::new(error.to_string()))?
            ))
        );
        // A macOS JRE keeps its home in a bundle; a Linux JRE is the home.
        let bundle = jre.join("Contents/Home");
        let java_home = if bundle.is_dir() { bundle } else { jre };
        Ok(Self {
            java_bin: java_home.join("bin"),
            tla2tools: tla2tools.join("tla2tools.jar"),
            apalache: apalache.join("bin/apalache-mc"),
            versions: format!(
                "temurin-jre {jre_version}, tla2tools {tla2tools_version}, apalache {apalache_version}\n{identities}"
            ),
        })
    }

    /// Runs `profile` in a new child of `out`, with its inputs and both logs.
    /// Existing run directories stay unchanged. TLC runs with no search limit,
    /// so a pass is a completed search. A `_bad` or `_reach` profile passes
    /// only when the output reports a violation of its one property.
    fn run(&self, profile: &Profile, out: &Path, memory: Option<TlcMemory>) -> Result<(), Failure> {
        let out = evidence::directory(out)?;
        let output_error = |error: io::Error| Failure::new(format!("{}: {error}", out.display()));
        let source_digest = digest(&profile.dir)?;
        let closure = evidence::snapshot(&out, profile)?;
        let source = out.join("source");
        let file_name = profile
            .file
            .file_name()
            .ok_or_else(|| Failure::new("profile has no file name".to_owned()))?;
        let retained_profile = source.join(file_name);
        let mut command = if profile.apalache {
            let text = fs::read_to_string(&retained_profile)
                .map_err(|error| Failure::new(format!("{}: {error}", retained_profile.display())))?;
            // apalache-mc runs the first `java` on the path.
            let path = env::join_paths(
                iter::once(self.java_bin.clone()).chain(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from)),
            )
            .map_err(|error| Failure::new(format!("PATH: {error}")))?;
            let settings = out.join("apalache.json");
            fs::write(&settings, "{}\n").map_err(output_error)?;
            let mut command = Command::new(&self.apalache);
            command
                .env_clear()
                .args(text.lines().map(str::trim).filter(|line| !line.is_empty()))
                .arg(format!("--out-dir={}", out.display()))
                .arg(format!("--config-file={}", settings.display()))
                .env("PATH", path)
                .arg(&profile.module)
                .current_dir(&source);
            command
        } else {
            self.tlc_command(&out, &retained_profile, &profile.module, memory)
        };

        let checker = if profile.apalache { "apalache" } else { "tlc" };
        eprintln!("── {checker} {}", profile.name);
        let started = Instant::now();
        let start_error = |error: io::Error| Failure::new(format!("{}: cannot start {checker}: {error}", profile.name));
        let mut manifest = evidence::start(&out, profile, &command, &self.versions, &closure)?;
        eprintln!("   evidence: {}", out.display());
        let stdout = fs::File::create(out.join("checker.log")).map_err(output_error)?;
        let stderr = fs::File::create(out.join("stderr.log")).map_err(output_error)?;
        let status = command.stdout(stdout).stderr(stderr).status().map_err(start_error)?;
        let seconds = started.elapsed().as_secs_f64();
        writeln!(manifest, "state=finished\nstatus={status}\nseconds={seconds:.6}").map_err(output_error)?;
        manifest.sync_all().map_err(output_error)?;
        if digest(&profile.dir)? != source_digest {
            writeln!(manifest, "verdict=fail\nreason=model files changed during the check").map_err(output_error)?;
            manifest.sync_all().map_err(output_error)?;
            return Err(Failure::new(
                "model files changed during the check; evidence is invalid".to_owned(),
            ));
        }
        let mut report = Report::default();
        for name in ["checker.log", "stderr.log"] {
            let log = fs::File::open(out.join(name)).map_err(output_error)?;
            for line in io::BufReader::new(log).lines() {
                report.read(
                    &line.map_err(output_error)?,
                    profile.apalache,
                    profile.expected.as_deref(),
                );
            }
        }
        let Some(expected) = profile.expected.as_deref() else {
            return match report.holds(profile.apalache, status.code()) {
                Ok(()) => {
                    writeln!(manifest, "verdict=pass").map_err(output_error)?;
                    manifest.sync_all().map_err(output_error)?;
                    eprintln!("   ok in {seconds:.2}s ({status})");
                    Ok(())
                }
                Err(reason) => {
                    writeln!(manifest, "verdict=fail\nreason={reason}").map_err(output_error)?;
                    manifest.sync_all().map_err(output_error)?;
                    Err(Failure {
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
                    })
                }
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
            writeln!(manifest, "verdict=pass\nviolated={expected}").map_err(output_error)?;
            manifest.sync_all().map_err(output_error)?;
            eprintln!("   `{expected}` is violated: {shows}, in {seconds:.2}s ({status})");
            return Ok(());
        }
        let found = if violated.is_empty() {
            "no violation".to_owned()
        } else {
            format!("a violation of `{}`", violated.join("`, `"))
        };
        writeln!(manifest, "verdict=fail\nreason=expected {expected}; found {found}").map_err(output_error)?;
        manifest.sync_all().map_err(output_error)?;
        Err(Failure::new(format!(
            "{}: it must violate `{expected}`, and the checker reports {found} ({status}); the output is in {}",
            profile.name,
            out.display()
        )))
    }

    /// Build the native TLC command that is retained in the run manifest.
    fn tlc_command(&self, out: &Path, profile: &Path, module: &str, memory: Option<TlcMemory>) -> Command {
        let mut command = Command::new(self.java_bin.join("java"));
        command
            .env_clear()
            .args(["-XX:+UseParallelGC", "-XX:+ExitOnOutOfMemoryError"]);
        if let Some(memory) = memory {
            command
                .arg(format!("-Xmx{}m", memory.heap_mib))
                .arg(format!("-XX:MaxDirectMemorySize={}m", memory.fp_mib))
                .arg("-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet")
                // The checker runs in source/. A fixed relative path also
                // keeps path separators out of Java's logging-option syntax.
                .arg("-Xlog:gc*:file=../gc.log:time,uptime,level,tags:filecount=0");
        }
        command
            .arg("-cp")
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
            .arg(profile)
            .arg(module)
            .current_dir(out.join("source"));
        command
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

/// The Cargo or Nextest arguments of the caller, after `--workspace` unless
/// they select packages, and after `--all-features` unless they select
/// features. With no selection, Cargo takes only the root package, and only
/// its default features: the `tcp` feature adds code that no other build
/// checks. With `--workspace`, Cargo ignores `-p`, and a second `--workspace`
/// is an error.
fn scope(args: &[String]) -> Vec<&str> {
    let packages = args
        .iter()
        .any(|arg| arg == "--workspace" || arg.starts_with("--package") || arg.starts_with("-p"));
    let features = args.iter().any(|arg| {
        ["--all-features", "--no-default-features"].contains(&arg.as_str())
            || arg.starts_with("--features")
            || arg.starts_with("-F")
    });
    (!packages)
        .then_some("--workspace")
        .into_iter()
        .chain((!features).then_some("--all-features"))
        .chain(args.iter().map(String::as_str))
        .collect()
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
    //! The verdicts from checker output, profile discovery, and the package
    //! selection of the Cargo commands. Each checker input is lines that the
    //! pinned checkers printed (TLC 1.8.0 rev 3ec1cc4, Apalache 0.62.4).

    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{Checkers, Report, model_args, profiles, scope};

    /// A partial, malformed, or repeated memory option must not silently use
    /// the small-profile defaults or admit arbitrary JVM arguments.
    #[test]
    fn tlc_memory_requires_one_valid_pair() {
        for args in [
            ["--tlc-heap-mib=8192"].as_slice(),
            ["--tlc-fp-mib=8192"].as_slice(),
            ["--tlc-heap-mib=8192", "--tlc-fp-mib=0"].as_slice(),
            ["--tlc-heap-mib=-1", "--tlc-fp-mib=8192"].as_slice(),
            ["--tlc-heap-mib=8192m", "--tlc-fp-mib=8192"].as_slice(),
            ["--tlc-heap-mib", "--tlc-fp-mib=8192"].as_slice(),
            ["--tlc-heap-mib=8192", "--tlc-fp-mib=4294967296"].as_slice(),
            ["--tlc-heap-mib=8192", "--tlc-heap-mib=4096", "--tlc-fp-mib=8192"].as_slice(),
            ["--tlc-heap-mib=8192", "--tlc-fp-mib=8192", "--tlc-fp-mib=4096"].as_slice(),
            ["--jvm-option=-Xmx8g"].as_slice(),
        ] {
            let owned: Vec<_> = args.iter().map(|arg| (*arg).to_owned()).collect();
            assert!(
                model_args(&owned).is_err(),
                "invalid model arguments accepted: {args:?}"
            );
        }
    }

    /// The requested limits must reach Java before its main class, select
    /// the matching off-heap set, and keep the complete GC log in evidence.
    /// Omitting the pair must keep the defaults for small local profiles.
    #[test]
    fn tlc_memory_configures_the_native_command_only_when_requested() {
        let checkers = Checkers {
            java_bin: PathBuf::from("jre/bin"),
            tla2tools: PathBuf::from("tla2tools.jar"),
            apalache: PathBuf::from("apalache-mc"),
            versions: String::new(),
        };
        let args: Vec<_> = ["m/M.cfg", "--tlc-fp-mib=8192", "other/N.cfg", "--tlc-heap-mib=8192"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let (selected, memory) = model_args(&args).map_err(|error| error.message).expect("valid pair");
        assert_eq!(selected, ["m/M.cfg", "other/N.cfg"]);
        let out = Path::new("evidence with spaces/run");
        let config = out.join("source/M.cfg");
        let command = checkers.tlc_command(out, &config, "M.tla", memory);
        let args: Vec<_> = command.get_args().collect();
        let entry = args.iter().position(|arg| *arg == "tlc2.TLC").expect("TLC entry point");
        for flag in [
            "-Xmx8192m",
            "-XX:MaxDirectMemorySize=8192m",
            "-Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet",
            "-Xlog:gc*:file=../gc.log:time,uptime,level,tags:filecount=0",
        ] {
            assert!(
                args[..entry].iter().any(|arg| *arg == flag),
                "missing JVM argument: {flag}"
            );
        }
        assert_eq!(command.get_current_dir(), Some(out.join("source").as_path()));
        assert_eq!(args.last().copied(), Some(std::ffi::OsStr::new("M.tla")));
        let (_, default) = model_args(&[])
            .map_err(|error| error.message)
            .expect("default settings");
        let command = checkers.tlc_command(out, &config, "M.tla", default);
        assert!(command.get_args().all(|arg| {
            let arg = arg.to_string_lossy();
            !arg.starts_with("-Xmx")
                && !arg.starts_with("-XX:MaxDirectMemorySize")
                && !arg.starts_with("-Dtlc2.tool.fp.FPSet.impl")
                && !arg.starts_with("-Xlog")
        }));
    }

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

    /// A target or filter argument keeps the whole workspace and each feature:
    /// without them, the musl step of CI and a named test cover only the root
    /// package and its default features. Each package flag keeps its own
    /// package selection, and each feature flag its own feature selection, so
    /// `cargo xtask check --no-default-features` checks the protocol-only build.
    #[test]
    fn only_package_and_feature_flags_narrow_the_scope() {
        let joined = |args: &[&str]| scope(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()).join(" ");
        for args in [
            &[][..],
            &["--target", "x86_64-unknown-linux-musl"],
            &["-E", "test(tlc_complete_search_holds)"],
            &["--exclude", "xtask"],
        ] {
            assert_eq!(
                joined(args),
                [&["--workspace", "--all-features"][..], args].concat().join(" ")
            );
        }
        for args in [
            &["-p", "rsnetwork"][..],
            &["-prsnetwork"],
            &["--package", "rsnetwork"],
            &["--package=rsnetwork"],
            &["--workspace"],
        ] {
            assert_eq!(joined(args), [&["--all-features"][..], args].concat().join(" "));
        }
        for args in [
            &["--all-features"][..],
            &["--no-default-features"],
            &["--features", "tcp"],
            &["--features=tcp"],
            &["-Ftcp"],
        ] {
            assert_eq!(joined(args), [&["--workspace"][..], args].concat().join(" "));
        }
    }
}
