# Contributing

## The most useful things you can send

This project's weakest points are not in the code, they are in the evidence.
Three of them can only be closed by people running it somewhere that is not the
author's laptop:

**Does it run on your distribution?** `docs/COMPATIBILITY.md` has exactly one
verified row. Every other entry is inferred from shipped kernel versions and
default configs. Paste the output of `sudo kernelsentinel doctor` into a
[compatibility report](../../issues/new?template=compatibility.yml) and that
becomes a fact.

**Did it cry wolf?** The false-positive rate has never been measured over a long
period on a busy host. A [false positive report](../../issues/new?template=false_positive.yml)
with the incident it produced is more valuable than a feature request, because
a detection that fires on ordinary work gets the whole tool muted.

**Did it miss something?** A [missed detection](../../issues/new?template=missed_detection.yml)
is the most serious kind of report here. A container escape detection once
passed 113 tests and failed against the real attack; only running the attack
found it.

## Building

```bash
sudo apt install -y clang llvm libelf-dev zlib1g-dev libbpf-dev bpftool pkg-config
./scripts/gen-vmlinux.sh
cargo build --release
```

The server alone needs none of that: `cargo build --release --no-default-features`
skips the eBPF toolchain entirely.

## What has to pass

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo fmt --check
```

Both feature configurations, because the server-only build is a supported
artifact and breaks independently.

## If you add a detection

Three things are enforced by `tests/docs_consistency.rs`, and a PR that skips
them fails before review:

1. An entry in **`docs/DETECTIONS.md`** — including its known **false positives
   and known evasions**. A detection whose weaknesses are undocumented is one
   nobody can tune or trust.
2. A scenario in **`tests/scenarios/`** that runs the real attack and asserts the
   signal fires. Replay tests feed the detector events you chose; they cannot
   tell you a live attack still produces the signal.
3. The signal id must appear in incidents exactly as documented, so someone
   looking up the id in front of them finds it.

Then run it for real:

```bash
sudo tests/attack/verify.sh
```

## Principles worth knowing before you propose something

**Behaviour over names.** `comm` is attacker-controlled. Where a detection keys
on a name — and two still do — it is documented as an evasion. Ancestry,
credentials, and object identity (`dev`, `inode`) survive an attacker renaming
things; paths and process names do not.

**A false positive is a bug.** Severity bands exist so single signals stay quiet
until they chain. If a detection fires on ordinary work, the fix is the
detection or the baseline, not a note telling operators to ignore it.

**Say what is not known.** Every limitation in the README and `DETECTIONS.md` is
there deliberately. A patch that removes a caveat without removing the
limitation will not be merged.

**Enforcement fails open.** `--enforce` can make syscalls fail. Every uncertain
path in that code allows the operation; an agent that blocks something because
it could not read a pointer is worse than one that misses a detection.

## Commits

Explain why, not what — the diff already says what. If you found the problem by
running something, say what you ran and what it printed.
