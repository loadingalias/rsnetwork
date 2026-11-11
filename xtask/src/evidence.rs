//! Retained inputs and results of one model check.

use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use rscrypto::Sha256;

use crate::{Failure, Profile, digest, hex};

/// Create a new run directory. An existing run is never replaced.
pub(crate) fn directory(parent: &Path) -> Result<PathBuf, Failure> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Failure::new(error.to_string()))?
        .as_nanos();
    fs::create_dir_all(parent).map_err(|error| Failure::new(error.to_string()))?;
    let out = parent.join(format!("{stamp}-{}", std::process::id()));
    fs::create_dir(&out).map_err(|error| Failure::new(error.to_string()))?;
    Ok(out)
}

/// Retain one model before profile selection and matrix validation.
pub(crate) fn freeze(from: &Path, to: &Path) -> Result<(), Failure> {
    fs::create_dir(to).map_err(failure)?;
    for path in crate::sorted_entries(from)? {
        if path.is_file() {
            let name = path
                .file_name()
                .ok_or_else(|| Failure::new("model input has no file name".to_owned()))?;
            fs::copy(&path, to.join(name)).map_err(failure)?;
        }
    }
    Ok(())
}

/// Hash all installed checker files, including libraries and launch scripts.
pub(crate) fn tool_identity(root: &Path) -> Result<String, Failure> {
    let mut pending = vec![root.to_owned()];
    let mut files = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            pending.extend(crate::sorted_entries(&path)?);
        } else {
            files.insert(path);
        }
    }
    let mut list = String::new();
    for path in files {
        let name = path
            .strip_prefix(root)
            .map_err(|error| Failure::new(error.to_string()))?;
        let bytes = fs::read(&path).map_err(failure)?;
        list.push_str(&format!("{} {}\n", hex(&Sha256::digest(&bytes)), name.display()));
    }
    Ok(hex(&Sha256::digest(list.as_bytes())))
}

/// Copy the exact profile and each local module for the checker to read.
/// Checker libraries belong to the installed checker identity.
pub(crate) fn snapshot(out: &Path, profile: &Profile) -> Result<String, Failure> {
    let mut names = BTreeSet::new();
    let mut pending = vec![profile.module.clone()];
    while let Some(name) = pending.pop() {
        if !names.insert(name.clone()) {
            continue;
        }
        let text = fs::read_to_string(profile.dir.join(&name)).map_err(failure)?;
        for module in imports(&text) {
            let file = format!("{module}.tla");
            if profile.dir.join(&file).is_file() {
                pending.push(file);
            }
        }
    }
    let file_name = profile
        .file
        .file_name()
        .ok_or_else(|| Failure::new("profile has no file name".to_owned()))?;
    names.insert(file_name.to_string_lossy().into_owned());
    if profile.apalache {
        let text = fs::read_to_string(&profile.file).map_err(failure)?;
        names.extend(auxiliaries(&text)?);
    }
    if profile.dir.join("induction.matrix").is_file() {
        names.insert("induction.matrix".to_owned());
    }
    let source = out.join("source");
    fs::create_dir(&source).map_err(failure)?;
    let mut closure = String::new();
    for name in names {
        let bytes = fs::read(profile.dir.join(&name)).map_err(failure)?;
        closure.push_str(&format!("{} {name}\n", hex(&Sha256::digest(&bytes))));
        fs::write(source.join(name), bytes).map_err(failure)?;
    }
    Ok(closure)
}

/// File arguments are local model inputs; the runner owns the ambient JSON settings.
pub(crate) fn auxiliaries(text: &str) -> Result<BTreeSet<String>, Failure> {
    let mut names = BTreeSet::new();
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    while let Some(line) = lines.next() {
        if line.starts_with("--config-file") {
            return Err(Failure::new("the runner owns --config-file; use --config for model constants and --tuning-options-file for solver options".to_owned()));
        }
        for key in ["--config", "--tuning-options-file"] {
            let input = if line == key {
                lines.next()
            } else {
                line.strip_prefix(&format!("{key}="))
            };
            if let Some(name) = input {
                let mut parts = Path::new(name).components();
                if !matches!(parts.next(), Some(std::path::Component::Normal(_))) || parts.next().is_some() {
                    return Err(Failure::new(format!(
                        "input {name} must be a file in the model directory"
                    )));
                }
                names.insert(name.to_owned());
                break;
            }
        }
    }
    Ok(names)
}

/// Record the command that reads the retained source copy.
pub(crate) fn start(
    out: &Path,
    profile: &Profile,
    command: &Command,
    versions: &str,
    closure: &str,
) -> Result<fs::File, Failure> {
    let record = || -> Result<fs::File, Failure> {
        let mut manifest = fs::File::create(out.join("run.txt")).map_err(failure)?;
        writeln!(
            manifest,
            "state=started\nprofile={}\ncheckers={versions}\nmodel={}\nclosure=sha256:{}",
            profile.name,
            digest(&profile.dir)?,
            hex(&Sha256::digest(closure.as_bytes()))
        )
        .map_err(failure)?;
        writeln!(
            manifest,
            "cwd={:?}\nprogram={:?}",
            command.get_current_dir(),
            command.get_program()
        )
        .map_err(failure)?;
        for args in [
            ["rev-parse", "HEAD"].as_slice(),
            ["status", "--porcelain=v1"].as_slice(),
        ] {
            let output = Command::new("git")
                .args(args)
                .current_dir(&profile.dir)
                .output()
                .map_err(failure)?;
            if !output.status.success() {
                return Err(Failure::new(
                    "cannot record the repository revision and status".to_owned(),
                ));
            }
            writeln!(manifest, "git {args:?}:\n{}", String::from_utf8_lossy(&output.stdout)).map_err(failure)?;
        }
        writeln!(
            manifest,
            "environment=cleared\nplatform={}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
        .map_err(failure)?;
        for (name, value) in command.get_envs() {
            writeln!(manifest, "env={name:?}={value:?}").map_err(failure)?;
        }
        if profile.apalache {
            let settings = fs::read(out.join("apalache.json")).map_err(failure)?;
            writeln!(manifest, "apalache-config-sha256={}", hex(&Sha256::digest(&settings))).map_err(failure)?;
        }
        for argument in command.get_args() {
            writeln!(manifest, "arg={argument:?}").map_err(failure)?;
        }
        writeln!(manifest, "expected={:?}\n{closure}", profile.expected).map_err(failure)?;
        manifest.sync_all().map_err(failure)?;
        Ok(manifest)
    };
    record().map_err(|error| Failure::new(format!("{}: {}", out.display(), error.message)))
}

fn failure(error: std::io::Error) -> Failure {
    Failure::new(error.to_string())
}

/// Require the whole initialization, step, and safety obligations for each domain.
/// The checker expands Next and IndInv; this gate does not parse TLA+ definitions.
pub(crate) fn matrix(dir: &Path) -> Result<(), Failure> {
    let path = dir.join("induction.matrix");
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&path).map_err(failure)?;
    for row in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = row.split_whitespace().collect();
        let [module, cinit, ind_init] = fields.as_slice() else {
            return Err(Failure::new(format!(
                "{}: a row needs module, constant initializer, and invariant initializer",
                path.display()
            )));
        };
        for (role, init, invariant, length) in [
            ("Init", "Init", "IndInv", "0"),
            ("Step", *ind_init, "IndInv", "1"),
            ("Safety", *ind_init, "Safety", "0"),
        ] {
            let name = format!("{module}.{role}.apalache");
            let profile =
                fs::read_to_string(dir.join(&name)).map_err(|error| Failure::new(format!("{name}: {error}")))?;
            let mut lines = profile.lines().map(str::trim).filter(|line| !line.is_empty());
            if lines.next() != Some("check") {
                return Err(Failure::new(format!("{name}: an induction obligation must use check")));
            }
            let mut options = std::collections::BTreeMap::new();
            for line in lines {
                let Some((key, value)) = line.split_once('=') else {
                    return Err(Failure::new(format!("{name}: unsupported induction argument {line}")));
                };
                if options.insert(key, value).is_some() {
                    return Err(Failure::new(format!("{name}: duplicate induction argument {key}")));
                }
            }
            let expected = std::collections::BTreeMap::from([
                ("--cinit", *cinit),
                ("--init", init),
                ("--next", "Next"),
                ("--inv", invariant),
                ("--length", length),
            ]);
            match (options.remove("--discard-disabled"), options.remove("--no-deadlock")) {
                (None, None) | (Some("false"), Some("true")) => {}
                _ => {
                    return Err(Failure::new(format!(
                        "{name}: use --discard-disabled=false and --no-deadlock=true together"
                    )));
                }
            }
            if role == "Step" && options.get("--tuning-options") == Some(&"search.invariantFilter=1->.*") {
                options.remove("--tuning-options");
            }
            if options != expected {
                return Err(Failure::new(format!(
                    "{name}: must check the complete {role} obligation"
                )));
            }
        }
    }
    Ok(())
}

/// Exclude comments and strings while keeping token and line boundaries.
fn without_comments(source: &str) -> String {
    let mut chars = source.chars().peekable();
    let mut clean = String::new();
    let mut depth = 0_u32;
    while let Some(ch) = chars.next() {
        match (ch, chars.peek().copied(), depth) {
            ('(', Some('*'), _) => {
                depth = depth.saturating_add(1);
                chars.next();
                clean.push(' ');
            }
            ('*', Some(')'), 1..) => {
                depth = depth.saturating_sub(1);
                chars.next();
            }
            ('\n', _, 1..) => clean.push('\n'),
            (_, _, 1..) => {}
            ('\\', Some('*'), 0) => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
                clean.push('\n');
            }
            ('"', _, 0) => {
                while let Some(next) = chars.next() {
                    if next == '\\' {
                        chars.next();
                    } else if next == '"' {
                        break;
                    }
                }
                clean.push(' ');
            }
            _ => clean.push(ch),
        }
    }
    clean
}

/// Module names after EXTENDS and INSTANCE, excluding comments and strings.
fn imports(source: &str) -> BTreeSet<String> {
    let spaced = without_comments(source).replace(',', " , ");
    let tokens: Vec<&str> = spaced
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != ',')
        .filter(|part| !part.is_empty())
        .collect();
    let mut names = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let mut next = index.saturating_add(1);
        if matches!(*token, "INSTANCE" | "EXTENDS") {
            while let Some(name) = tokens.get(next) {
                names.insert((*name).to_owned());
                next = next.saturating_add(1);
                if *token == "INSTANCE" || tokens.get(next) != Some(&",") {
                    break;
                }
                next = next.saturating_add(1);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::imports;

    /// Comments and strings do not add dependencies; multiline imports and instances do.
    #[test]
    fn module_imports_follow_the_source() {
        let source = "(* EXTENDS Fake (* nested *) *)\nEXTENDS Naturals,\n Local\nX == INSTANCE Other\nY == \"INSTANCE Hidden\"\n\\* INSTANCE Comment";
        assert_eq!(
            imports(source).into_iter().collect::<Vec<_>>(),
            ["Local", "Naturals", "Other"]
        );
    }

    /// The checker retains referenced inputs from the same revision as its validated profiles.
    #[test]
    fn retained_inputs_survive_checkout_changes() {
        let dir = super::directory(&std::env::temp_dir().join("xtask-input-test"))
            .map_err(|error| error.message)
            .expect("scratch directory");
        let live = dir.join("live");
        let frozen = dir.join("frozen");
        std::fs::create_dir(&live).expect("live directory");
        for (name, text) in [
            ("Core.tla", "EXTENDS Shared\n"),
            ("Shared.tla", "Value == 1\n"),
            (
                "Core.apalache",
                "check\n--config=values.cfg\n--tuning-options-file=solver.options\n",
            ),
            ("values.cfg", "CONSTANT N = 1\n"),
            ("solver.options", "search.outputTraces=false\n"),
        ] {
            std::fs::write(live.join(name), text).expect("write input");
        }
        super::freeze(&live, &frozen)
            .map_err(|error| error.message)
            .expect("freeze inputs");
        std::fs::write(live.join("Shared.tla"), "Value == 2\n").expect("edit checkout");
        std::fs::write(live.join("solver.options"), "changed\n").expect("edit solver options");
        let out = super::directory(&dir)
            .map_err(|error| error.message)
            .expect("run directory");
        let profile = crate::Profile {
            name: "test/Core.apalache".to_owned(),
            dir: frozen.clone(),
            module: "Core.tla".to_owned(),
            file: frozen.join("Core.apalache"),
            apalache: true,
            kind: crate::Kind::Holds,
            expected: None,
        };
        super::snapshot(&out, &profile)
            .map_err(|error| error.message)
            .expect("retain closure");
        for (name, expected) in [
            ("Shared.tla", "Value == 1\n"),
            ("values.cfg", "CONSTANT N = 1\n"),
            ("solver.options", "search.outputTraces=false\n"),
        ] {
            assert_eq!(
                std::fs::read_to_string(out.join("source").join(name)).expect("retained input"),
                expected
            );
        }
        super::auxiliaries("check\n--config=/tmp/external.cfg\n").unwrap_err();
        super::auxiliaries("check\n--config-file=ambient.json\n").unwrap_err();
        std::fs::remove_dir_all(dir).expect("remove owned inputs");
    }
    /// Missing or partial proofs cannot replace a whole induction obligation.
    #[test]
    fn induction_matrix_requires_whole_obligations() {
        let dir = super::directory(&std::env::temp_dir().join("xtask-matrix-test"))
            .map_err(|error| error.message)
            .expect("scratch directory");
        let write = |name: &str, text: &str| std::fs::write(dir.join(name), text).expect("write matrix input");
        write("induction.matrix", "Proof CInit IndInit\n");
        for (role, init, inv, length) in [
            ("Init", "Init", "IndInv", 0),
            ("Step", "IndInit", "IndInv", 1),
            ("Safety", "IndInit", "Safety", 0),
        ] {
            write(
                &format!("Proof.{role}.apalache"),
                &format!("check\n--cinit=CInit\n--init={init}\n--next=Next\n--inv={inv}\n--length={length}\n"),
            );
        }
        assert!(super::matrix(&dir).is_ok());
        let step = "check\n--cinit=CInit\n--init=IndInit\n--next=Next\n--inv=IndInv\n--length=1\n";
        write(
            "Proof.Step.apalache",
            &format!("{step}--discard-disabled=false\n--no-deadlock=true\n"),
        );
        assert!(super::matrix(&dir).is_ok());
        write(
            "Proof.Step.apalache",
            &format!("{step}--tuning-options=search.invariantFilter=1->.*\n"),
        );
        assert!(super::matrix(&dir).is_ok());
        for options in [
            "--discard-disabled=false\n",
            "--no-deadlock=true\n",
            "--discard-disabled=true\n--no-deadlock=true\n",
            "--discard-disabled=false\n--no-deadlock=false\n",
            "--tuning-options=search.invariantFilter=0->.*\n",
            "--tuning-options=search.invariantFilter=1->0\n",
            "--tuning-options=search.invariantFilter=1->.*:search.transitionFilter=0->0\n",
        ] {
            write("Proof.Step.apalache", &format!("{step}{options}"));
            assert!(super::matrix(&dir).is_err());
        }
        write("Proof.Step.apalache", step);
        for role in ["Init", "Safety"] {
            let name = format!("Proof.{role}.apalache");
            let text = std::fs::read_to_string(dir.join(&name)).expect("read complete obligation");
            write(&name, &format!("{text}--tuning-options=search.invariantFilter=1->.*\n"));
            assert!(super::matrix(&dir).is_err());
            write(&name, &text);
        }
        let original = dir.join("Proof.Step.apalache");
        for suffix in ["bad", "reach"] {
            let must_fail = dir.join(format!("Proof.Step_{suffix}.apalache"));
            std::fs::rename(&original, &must_fail).expect("select a must-fail profile");
            assert!(super::matrix(&dir).is_err());
            std::fs::rename(&must_fail, &original).expect("restore the proof profile");
        }
        for args in [
            "--next=Take\n--inv=IndInv\n",
            "--next=Next\n--inv=OnePart\n",
            "--next=Next\n--inv=IndInv\n--inv=OnePart\n",
        ] {
            write(
                "Proof.Step.apalache",
                &format!("check\n--cinit=CInit\n--init=IndInit\n--length=1\n{args}"),
            );
            assert!(super::matrix(&dir).is_err());
        }
        std::fs::remove_dir_all(dir).expect("remove owned matrix input");
    }
}
