# Axon

Axon is a native **C++23** transactional source-control system, built with
**Catalyst**. See [implementation status](docs/axon_status.md) for what is
implemented and what is not.

## Build

The supported build environment is Linux x86-64 with Catalyst 2.1.0,
Clang/libc++/LLVM 21.1.8, mold 2.42.0, ccache and vcpkg (`VCPKG_ROOT`).
OpenSSL, curl and nlohmann-json come from vcpkg (`x64-linux`, linked
statically) at the versions pinned in `catalyst.lock`; `catalyst fetch -p debug`
installs them. `llvm-config-21` locates LLVM's BLAKE3 C API. Git and GNU diff
are used for Git interoperability and text merge/diff.

```sh
catalyst build -p debug
./build/common-debug/axon help

catalyst build -p release
./build/common-release/axon help
```

`debug`, `sanitized-debug`, `relwithdebinfo`, `release`, and `test` are separate
Catalyst profiles. Compiler and linker flags live in `toolchains/`.
Dependencies are declared in `CATALYST.yaml`; run `catalyst lock` after changing
them.

## Quickstart

```sh
AXON="$PWD/build/common-debug/axon"
"$AXON" init --data ./axon-data --admin "human:$USER"
"$AXON" serve --data ./axon-data &

WS=$("$AXON" fork -q)
printf 'hello\n' | "$AXON" write "$WS" docs/hello.txt -
"$AXON" stack "$WS" --title 'Add greeting' --intent feature --wait
"$AXON" get trunk docs/hello.txt
"$AXON" log
```

Structured output is JSON. `fork -q` returns only an ID; `cat`, `get` (files),
and `diff` return bytes/text. `diff --json` returns file-entry changes.
Flags can appear before or after positional arguments. `--` ends flag parsing.

Configuration lives in `$AXON_HOME/config.json`, defaulting to
`$XDG_CONFIG_HOME/axon/config.json` or `~/.config/axon/config.json`.
`AXON_SERVER`, `AXON_PRINCIPAL`, and `AXON_KEY` override configuration.
Private Ed25519 seeds are hex-encoded files with mode 0600.

Axon uses its own versioned storage and RPC format (`axon-1`). Git
import/export is the interchange path with other systems.

## Agents and review

```sh
eval "$("$AXON" agent-key bot1 --ttl 24h)"
WS=$("$AXON" fork -q)
printf 'implementation\n' | "$AXON" write "$WS" src/example.txt -
"$AXON" stack "$WS" --title 'Agent change' --intent feature --land
# The default policy blocks an agent change outside tests/ and docs/ for review.
unset AXON_PRINCIPAL AXON_KEY
"$AXON" diff STACK_ID
"$AXON" review STACK_ID
```

`--land` queues a stack and returns its current state. `--wait` polls until it
lands or reaches a terminal state; `--timeout SECONDS` bounds the wait (default
1,800). A blocked stack retains its candidate and requirements. Review binds to
the candidate content, so a merge that changes that content requires a new review.

Workspace reads, including absent-file reads, feed optimistic concurrency control.
Directory reads track names; content changes alone do not invalidate a listing.
Writes are included in the read set. Disjoint work lands directly, stale reads
trigger rebase, overlapping writes use three-way text merge, and conflicting
stacks can be reopened with `resolve` and replaced using `--supersedes`.

## Build inputs and CI

A package's `BUILD.axon` contains JSON:

```json
{
  "targets": [
    {
      "name": "test",
      "kind": "test",
      "srcs": ["src/**", "tests/**"],
      "deps": ["//library:core"],
      "cmd": "./tests/run.sh",
      "env": {"MODE": "test"}
    }
  ]
}
```

Target labels are `//package:name` (`//:name` for the root). Source globs are
relative to their package, commands run from the materialized repository root,
and `:dependency` is package-relative. Closures include transitive dependencies,
build files, file content, file modes, definitions, commands, and environment.
Dependency cycles and missing targets are errors. Optional `ttl` values use
`s`, `m`, `h`, or `d` suffixes.

```sh
"$AXON" targets
"$AXON" affected src/example.cpp
"$AXON" closure //package:test
"$AXON" materialize //package:test /tmp/empty-destination
"$AXON" green --request
```

The default server leases affected jobs to a background local executor with a
60-second timeout. Commands run outside transaction and domain locks; completion
records evidence and resumes the merge queue. Results are reused by input hash. Commands run
as the server user, without a sandbox. Use a trusted repository and an appropriate
execution account. For a separate executor:

```sh
"$AXON" serve --data ./axon-data --no-executors
# In another terminal, using a configured human/service identity:
"$AXON" executor --work /tmp/axon-executor
```

Remote jobs use authenticated claims, expiring leases, verified content hashes,
and standalone signed completion claims. `executor --once` processes at most one job.
Disagreeing CI results are flaky until three consecutive results agree. The queue
prepares up to eight speculative candidates (set `limits.speculative_window` in
policy to 0 to disable, maximum 64). Exact input hashes bind all speculative evidence.

`admin workflows FILE` accepts a JSON array of objects with `name`,
`on`, `kind`, and optional `gate`. `on` accepts `head_moved`, `workspace_changed`,
or `stack_submitted`. Only head-moved workflows may gate landing; non-gated
head-moved workflows run afterward. Workspace/submission triggers schedule targets
from that source root. The `tests`
workflow kind selects `test` targets (also targets with an omitted kind); other
kinds select targets with that exact kind. `green` includes configured workflow
kinds. Failed line-head checks trigger asynchronous historical bisection;
this diagnostic assumes a passing-to-failing transition in the history.

`axon subscribe --from OFFSET` streams authenticated SSE events and reconnects
with the next cursor. Streams renew authentication every 30 seconds; identity
changes and expiry close them. The HTTP endpoint is `POST /v1/subscribe` with a
signed subscribe request body. Unknown partitions return no events. At most eight
streams run per server and two per principal; excess subscriptions receive HTTP 429.

For HTTPS, start the server with `--tls-cert CERT.pem --tls-key KEY.pem` and
configure an `https://` server URL. Clients validate certificates; set
`AXON_CA_BUNDLE` to a PEM trust bundle for a private CA. The client retries
connection-establishment failures only, avoiding uncertain mutation replay.

`get` and `cat` cache verified blobs under `$AXON_HOME/client-cache` (or the
usual config directory). Metadata and workspace read tracking still go through
an authenticated RPC on every call. Explicit offline editing uses the spool and
replay commands described below.

`axon admin compact` replaces the metadata journal with an atomic, checksummed
checkpoint. It preserves all state and history; it does not prune retention.
Agent bindings, human reviews, and external attestations carry independently
verifiable Ed25519 signatures. The CLI supplies these statements automatically.

## Git

```sh
"$AXON" git import --repo /path/to/git --ref HEAD
"$AXON" git export --repo /path/to/git --branch axon/trunk
"$AXON" git push --repo /path/to/git --ref HEAD
```

Import requires an administrator, follows first-parent history, and retains Git
commit IDs for repeat-import detection. Push submits the selected tree with a
whole-tree read set. Export creates a **new** branch with one commit per landing
and Axon provenance trailers. Existing branches are refused. Files, symlinks,
executable modes, and binary contents round-trip; submodules are rejected.

## Verification

```sh
catalyst test -r
```

This builds and runs both suites. The `test` profile builds `axon_tests` from
`test/unit.cpp` plus the library sources (`src/.catalystignore` drops the CLI's
`axon.cpp`). Its `pre-test` hook builds the `sanitized-debug` CLI and its
`post-test` hook runs `test/integration.py` against it. Both use
AddressSanitizer and UndefinedBehaviorSanitizer. The integration suite starts
loopback HTTP servers and requires local socket access.
If a ptrace-based container prevents LeakSanitizer from running, use
`ASAN_OPTIONS=detect_leaks=0 catalyst test -r`; ASan and UBSan stay enabled.

`catalyst fmt` formats with clang-format 22.1.8 and `.clang-format`. See the
[status document](docs/axon_status.md) for toolchain/style exceptions and current
scaling limits.

## Mounted workspaces, symbols and offline edits

```sh
mkdir /tmp/axon-mount
"$AXON" mount "$WS" /tmp/axon-mount   # foreground; requires /dev/fuse and fusermount3
# In another terminal, edit files under /tmp/axon-mount.
# Unmount with fusermount3 -u /tmp/axon-mount, or stop the foreground client.

"$AXON" symbol "$WS" src/self_contained.cpp 'namespace_name::function_name'
printf 'queued content\n' | "$AXON" write "$WS" docs/offline.txt - --offline
"$AXON" replay

"$AXON" admin prune --age 30d --keep 100 --dry-run
"$AXON" admin prune --age 30d --keep 100
"$AXON" admin gc --dry-run
"$AXON" admin compact
```

Offline replay is ordered and idempotent, including when a response is lost after
commit. It retains failed edits for retry and does not automatically merge against
changed workspace content. Retention preserves live bases and snapshot numbering,
but deletes old provenance payloads. Symbol reads and declaration merges currently
support self-contained C++23 without preprocessor directives; other merges use the
existing text merge. See the status document for FUSE and retention limitations.
