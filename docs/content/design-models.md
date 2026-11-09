# Check the design models

rsnetwork has a TLA+ model of the datagram form of attached channels:
[`models/attached-datagram/`](../../models/attached-datagram/README.md). It checks that the
consumer reads only the bytes that the sender sent, that an acknowledgement means that the
receiver holds the bytes, that the receiver's replay state stays bounded, and that the channel
ends when loss is fair and the consumer reads. The network loses, duplicates, and reorders
datagrams, the parent migrates, and an on-path attacker reads and injects datagrams. The model
checks the design, not the Rust code. Change the model when you change one of these rules or the
wire format that they constrain.

## Install the checkers

The model command uses the Rust toolchain that `rust-toolchain.toml` pins and three checkers. Put
one version of each checker under `~/.local/opt/<name>/<version>/`:

| Name | Version of the recorded evidence | Source | Path that the command uses |
| --- | --- | --- | --- |
| `temurin-jre` | 21.0.13+9 | [Eclipse Temurin](https://adoptium.net/temurin/releases/?version=21) JRE 21 | `bin/java` (on macOS, `Contents/Home/bin/java`) |
| `tla2tools` | 1.8.0 (TLC2 Version 2026.11.06.005304, rev 3ec1cc4) | [TLA+ release v1.8.0](https://github.com/tlaplus/tlaplus/releases/tag/v1.8.0) | `tla2tools.jar` |
| `apalache` | 0.62.4 | [Apalache release v0.62.4](https://github.com/apalache-mc/apalache/releases/tag/v0.62.4), `apalache-0.62.4.tgz` without its top directory | `bin/apalache-mc` |

Compare each download with the SHA-256 that its release publishes. The TLA+ project builds the
v1.8.0 release again from its main branch, so its `tla2tools.jar` changes in place. A newer build
can give other state counts, but it must give the same verdicts. Each evidence record names the
`TLC2 Version` line of its build. This model uses only TLC, but the command needs all three.

The command does not install anything. If a checker is missing, or two versions of one are
present, it stops and names the directory.

## Run the model

From the repository root:

```sh
cargo xtask model attached-datagram                                  # every profile
cargo xtask model attached-datagram/AttachedDatagram.NoTagSquat_bad.cfg # one profile
```

You can give several selections to one command. One model run at a time holds the host lock;
another run waits for it.

The command prints the digest of the model files, then one result for each profile:

```text
files of .../models/attached-datagram: sha256:<digest> (<count> files)
── tlc attached-datagram/AttachedDatagram.NoTagSquat_bad.cfg
   `AckMeansHeld` is violated: as the known-bad variant requires, in 0.63s (exit status: 12)
```

- A main profile passes with `ok` and exit status 0: a complete search with no violation. The
  command reads the checker's own summary: TLC must report 0 states left on the queue, and
  Apalache the outcome `NoError` with no timed-out query. A search that stopped early fails as
  inconclusive, also when the checker exits with 0. The command removes the JVM option variables
  (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JVM_ARGS`) from each checker run.
- A `_bad` profile is a known-bad variant. It passes only when the checker reports a violation
  of its one property.
- A `_reach` profile is a reachability witness. It passes only when the checker reaches its
  target.

The command exits 0 when every selected profile passes. The output of each profile goes to
`target/model/attached-datagram/<profile>/`: `checker.log`, and `trace.json` for a violation.

## Large profiles

The whole model takes about 25 minutes on a 16-core host. The main profile takes about 30
seconds. These profiles take more time (measured on 16 vCPUs, 64 GiB, 2026-11-08):

| Profile | Distinct states | Time |
| --- | --- | --- |
| `AttachedDatagram.MaxPN7.cfg` | 45.0 million | 10 minutes |
| `AttachedDatagram.FaultySender.cfg` | 23.3 million | 4.5 minutes |
| `AttachedDatagram.Cap3Range3Window3.cfg` | 12.4 million | 4 minutes on 10 cores |
| `AttachedDatagram.Paths3.cfg`, `Cap3.cfg`, `Bytes5.cfg` | 7.8 to 9.5 million | 2 minutes |

Each profile must finish within one hour on a 16-vCPU host. Before you run a new large profile in
full, run it for 10 minutes, and estimate its full size from the growth of the distinct states and
the queue. A profile that cannot finish in that time needs a smaller model, not a larger host.

On a smaller host, select the profiles that your change touches, and run the whole model before
you record evidence.

## When a profile fails

- A main profile reports a violation. The trace in `trace.json` is a counterexample to a design
  rule. The design changes first, and then the model.
- A `_bad` profile reports "no violation". The variant no longer breaks its property, so the
  property or the module changed. Find which one changed before you change the profile.
- A profile reports a violation of a property other than its own. The variant fails for another
  reason, so it shows nothing about its own property.

After a change, run every profile and update the evidence record in the model's README with the
digest that the command prints.
