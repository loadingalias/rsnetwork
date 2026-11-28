"""Check, measure, or profile the native HTTP and QUIC kernels."""

import argparse
import json
import os
import platform
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEST = "quic::recovery::tests::kernels::protocol_kernels"


def executable(env):
    command = [
        "cargo", "test", "--locked", "-p", "rsnetwork", "--profile", "bench",
        "--lib", "--no-run", "--message-format=json-render-diagnostics",
    ]
    build = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
    if build.returncode:
        raise SystemExit(build.stderr)
    for record in map(json.loads, build.stdout.splitlines()):
        if record.get("executable") and record["target"]["name"] == "rsnetwork":
            return record["executable"]
    raise SystemExit("Cargo did not report the library test executable.")


def results(directory):
    rows = {}
    for file in sorted(directory.glob("*/*/new/estimates.json")):
        case = json.loads(file.with_name("benchmark.json").read_text())
        count = case["throughput"]["Elements"]
        median = json.loads(file.read_text())["median"]
        interval = median["confidence_interval"]
        rows[case["full_id"]] = [
            value / count for value in (median["point_estimate"], interval["lower_bound"], interval["upper_bound"])
        ]
    if not rows:
        raise SystemExit("Criterion did not measure a matching kernel.")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "measure", "profile"))
    parser.add_argument("filter", nargs="?", default="", help="Criterion case filter (regular expression)")
    parser.add_argument("--sudo-perf", action="store_true", help="Run only the Linux sampler with sudo")
    args = parser.parse_args()
    if args.mode == "profile" and not args.filter:
        parser.error("Select a kernel to profile.")
    if args.mode == "check" and args.filter:
        parser.error("The fixture check runs every case.")

    work = ROOT / "target" / "kernels"
    work.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix="corpus-") as corpus:
        with tarfile.open(Path(__file__).with_name("corpus.tar.gz")) as archive:
            archive.extractall(corpus, filter="data")
        env = os.environ.copy()
        env.update(RUSTUP_AUTO_INSTALL="0", RSNETWORK_KERNEL_CORPUS=corpus, RSNETWORK_KERNEL_MODE=args.mode,
                   RSNETWORK_KERNEL_FILTER=args.filter)
        if args.mode == "check":
            subprocess.run(["cargo", "xtask", "test", "-p", "rsnetwork", "--lib", "--run-ignored", "only",
                            "-E", f"test(={TEST})"], cwd=ROOT, env=env, check=True)
            return
        env["CARGO_PROFILE_BENCH_DEBUG"] = "1"
        env["RUSTFLAGS"] = " ".join(filter(None, [env.get("RUSTFLAGS"), "-Ctarget-cpu=native", "-Cforce-frame-pointers=yes"]))
        binary = executable(env)
        output = Path(tempfile.mkdtemp(dir=work, prefix=args.mode + "-"))
        env["CRITERION_HOME"] = str(output)
        command = [binary, "--ignored", "--exact", TEST, "--nocapture"]
        if args.mode == "profile":
            if platform.system() == "Darwin":
                command = ["samply", "record", "--save-only", "--unstable-presymbolicate",
                           "-o", str(output / "profile.json.gz"), *command]
            else:
                perf = ["perf", "record", "-e", "cpu-clock:u", "-F", "999", "-g",
                        "-o", str(output / "perf.data")]
                if args.sudo_perf:
                    # Let perf own the recording lifetime. Drop privileges before the benchmark starts.
                    (output / "perf.data").touch()
                    settings = ["CRITERION_HOME", "RSNETWORK_KERNEL_MODE", "RSNETWORK_KERNEL_FILTER", "RSNETWORK_KERNEL_CORPUS"]
                    command = ["setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()),
                               "--init-groups", "--no-new-privs", "--", "env",
                               *(f"{key}={env[key]}" for key in settings), *command]
                    perf = ["sudo", "-n", *perf]
                command = [*perf, "--", *command]
        print("Kernel output", output, flush=True)
        if args.mode == "profile":
            run = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True)
            print(run.stdout, end="")
            run.check_returncode()
            if "Complete (Analysis Disabled)" not in run.stdout:
                raise SystemExit("Criterion did not profile a matching kernel.")
        else:
            subprocess.run(command, cwd=ROOT, env=env, check=True)
            print("MEDIANS_NS", json.dumps(results(output)), flush=True)


if __name__ == "__main__":
    main()
