# Axon implementation status

This document describes implemented behavior only. Features that exist in code
but are not wired up are listed as not functional. The remaining feature pass is
wired into the CLI/server. The scope and validation limits below are part of the
implementation status, especially for FUSE and C++ symbols.

| Area | Implemented | Limitations / notes |
| --- | --- | --- |
| Storage | BLAKE3 CAS, FastCDC chunks, verified reads, canonical Merkle directories, 16-way BLAKE3 nibble directory sharding above 1,024 entries, O(1) workspace fork, shared object/node LRU (4,096 entries, 32 MiB weighted budget) with disk-fingerprint invalidation | None |
| Durability | Checksummed append-only JSON-patch transactions, background group commit fsync batching, torn-tail recovery, failed-append truncation, exclusive process lock, atomic journal checkpoint via `admin compact` | None (checkpointing is manual; startup replays patches since the last checkpoint) |
| Workspaces | Fork, reads/listings/absence, put/delete/move, status, stale reads, rebase, drop, TTL checks, session read union | Linux FUSE `mount` and tracked C++ declaration reads are implemented; see limitations below |
| Landing | Read-set/write-set invariant, fast/rebase/three-way text merge/conflict, atomic cross-path landing, resolve/supersede, merge queue, abandon | Concurrent preparation with domain locks through durable commit, record/table version validation, atomic cross-domain journal commit, and C++ declaration merge are implemented; no distributed coordinator |
| Provenance | Ed25519 authenticated RPC, persisted nonces, timestamp skew checks, expiring agent identities with a recorded owner, signed immutable submissions and landings, stored signed request proofs, owner-signed agent bindings, standalone signatures for human reviews and external attestations, signed local-executor receipts | None (remote completion signatures bind job, lease, result, and evidence digest) |
| Policy | Principal/path/read/intent/label/class/affected/import/narrowing conditions, deny, reviews/groups, CI requirements, rate and blast limits, strict policy schema validation on updates | None |
| Build graph | BUILD.axon, source globs, transitive closures, affected paths, cycle checks, closure materialization, repository-scoped graph LRU (64 entries, 64 MiB serialized-weight budget), external `--build-query` adapter | None |
| CI | Background local and remote executors, durable leases, cancellable local command timeout, evidence, input-hash reuse/job coalescing, flaky result handling, TTLs, green query, blame/ejection, bounded speculative queue candidates, asynchronous historical bisection | None (historical bisection assumes a passing-to-failing transition) |
| Events | Durable ordered events, partitioned line streams, cursor reads, consumer group offsets, path/line filters, polling, authenticated SSE via `POST /v1/subscribe` and CLI reconnect cursors | 8 simultaneous subscriptions per server, 2 per principal; excess requests receive HTTP 429 |
| Workflows | Validated `head_moved` workflows schedule matching target kinds; `gate: true` gates candidates, other workflows run after landing; `green` includes workflow kinds | `workspace_changed` and `stack_submitted` also schedule matching target kinds; only `head_moved` may gate landing |
| Lifecycle | Conservative mark/sweep with 24-hour grace; `admin prune` retains live bases and configurable recent history, with dry-run | Physical event/history slots retain small tombstones to preserve cursors and snapshot numbers |
| Git | First-parent import, export, push, repeated-import detection, modes/symlinks/binary fidelity, incremental fast-import chaining, original author identity/timestamp/timezone retained on import/export | None |
| Transport | Versioned HTTP JSON RPC, Concurrent `ThreadPool` HTTP workers, libcurl client, IPv4 listener, direct CAS `/cas/<hash>`, Prometheus `/metrics`, regional CAS `cache` proxy tier with verified misses, verified client blob disk cache, connection-establishment retries, native TLS | Durable `--offline` edit spool and `replay` with server-side operation IDs; automatic retries after ambiguous failures remain disabled |
| Web view | `axon web`: local read-only browser UI for files at any snapshot, history, stacks/diffs and queue; proxies allowlisted reads signed with the CLI identity; loopback-only, Host check, per-launch token | No write actions (review/land/abandon); no live event updates; file views are truncated at 1 MiB |
| Tooling | Catalyst debug/release/sanitized/relwithdebinfo/test profiles, C++ unit tests, CLI integration suite, in-process multi-agent `bench` load model | None |

`Line` (`src/line.cpp`) is unused apart from `DomainLockManager`.

Commands that have not been implemented are absent from `axon help` and fail;
there are no success-returning stubs.

## Transaction architecture and performance

`StateSnapshot` shares immutable tables and records. `StateTable` gives repository
code typed table identifiers; individual record payloads retain their JSON wire
representation. `StateTransaction` lazily reads tables or individual records,
validates their versions against the journal tip, and retries conflicting requests.
Ordinary workspace operations copy their workspace record rather than all metadata.
Event offsets are allocated during commit, allowing independent transactions to
append events without invalidating one another.

Domain locks cover preparation through durable commit. Cross-domain changes use
one journal transaction, so recovery publishes all changed paths or none. This is
a single-process prepare/commit protocol, not distributed two-phase commit.
A shared maintenance lock permits concurrent requests; initialization, retention,
checkpointing and garbage collection take it exclusively. Executor commands run
outside transaction and domain locks. Group commit publishes immutable snapshots
only after fsync succeeds and rolls back queued dependent commits on failure.

Queue scans and line history still materialize the tables they inspect. Concurrent
landings to one line can retry on its head version even when their paths differ.
Partition histories and changed-table pointer maps also grow with retained history;
this is not a constant-time database for arbitrary workloads.

Release (full LTO), 64 agents, 5-second requested workload, fsync enabled:

| Domains | Landings | Measured elapsed, including drain | Landings/s | p50 / p99 landing latency |
| --- | --- | --- | --- | --- |
| 1 | 46 | 9.2 s | 5 | 3,549 / 4,106 ms |
| 16 | 103 | 8.7 s | 11 | 3,562 / 8,207 ms |

Commands: `axon bench --agents 64 --domains 1 --duration 5 --sync` and the
same command with `--domains 16`. No build or test suite ran alongside these
measurements. The workload had 105 and 12 conflicted submissions respectively;
short adjacent-line files and one shared line create substantial contention.
The benchmark joins in-flight requests after the requested duration, so throughput
uses the longer measured interval. This is a correctness-oriented architecture
change, not a claim of high-throughput line landing.
The old 64-agent, fsync-disabled baseline was 5 landings/s on one domain and
13 landings/s on 16 domains. These are not comparable to a synchronized run.

## Implemented follow-up checklist

- [x] Replace the global request mutex/full-state copy with immutable table/record
      snapshots, validated transactions, domain ownership and group commit.
- [x] Move build execution onto leased, cancellable executors.
- [x] Resume historical diagnosis asynchronously and prepare speculative candidates.
- [x] Implement authenticated SSE with admission limits.
- [x] Drive CI from workflows, including workspace and submission events.
- [x] Verify cache misses and bound shared caches.
- [x] Sign agent bindings, standalone reviews/attestations and remote completions;
      preserve Git authors.
- [x] Add Linux FUSE mounting, C++ symbol reads and declaration merging within the
      supported scope below.
- [x] Add retention pruning, dry-run, durable offline editing and replay IDs.

## Supported scope and remaining limitations

- `mount WS DIRECTORY` is a foreground Linux FUSE client using the kernel protocol
  and `fusermount3`. It supports lookup/listing, regular file read/write/create,
  truncate, executable-bit changes, explicit workspace directories, symlinks,
  unlink/rmdir and atomic rename. Writes return after journal fsync. Kernel data
  caching is disabled so reads enter the workspace read set. Files are limited to
  32 MiB in this adapter. This is a source workspace view: hard links, xattrs,
  general ownership/permission metadata, persistent timestamps and POSIX open-after-unlink
  semantics are not implemented. Mount-session timestamps update when content changes
  and honor touch/utimens, so build tools can detect edits; remounting resets them.
  Empty directories are workspace conveniences;
  file-based submissions do not version empty directories. Protocol tests run
  without a device; **a live kernel mount has not been tested here** because
  `/dev/fuse` is absent.
- `symbol WS PATH QUALIFIED_NAME` tracks the selected C++ declaration or overload
  set, including absence. Clang 21 parses self-contained C++23 files up to 1 MiB.
  Preprocessor directives and external headers are rejected rather than silently
  omitted. Declaration merging handles independent edits with unchanged declaration
  identities, order and surrounding text; unsupported source and overlapping edits
  fall back to the existing three-way text merge. Arbitrary language-aware merging
  and compile-database/header-aware symbol indexing are not implemented.
- `admin prune --age 30d --keep 100 [--dry-run]` preserves line heads, recent
  snapshots and bases of live workspaces/nonterminal stacks. It prunes expired
  workspaces/evidence, old terminal stacks/completed jobs and old event payloads.
  Pruned history positions remain addressable tombstones and return an explicit
  error for content access. Bisection does not cross a pruned history gap. Run
  `admin gc` after the 24-hour grace period to reclaim unreachable CAS data and
  `admin compact` to reclaim journal history. Retention deliberately removes old
  provenance payloads; preview the counts before choosing a retention policy.
- `write`, `rm` and `mv` accept `--offline`; `replay` sends edits in durable spool
  order with fresh authentication envelopes. The spool is locked and bound to its
  server/principal. A failed replay keeps that entry and its successors. Repeating
  an acknowledged operation returns its original result, including after server
  restart. Replay does not resolve expired/dropped workspaces or merge offline
  edits against a local replica. Operation IDs are retained indefinitely to keep
  retries safe.
- Record payload fields remain JSON and are validated at request boundaries;
  fully generated typed record schemas are not present. Large RPC transfers still
  hex-encode bytes and have a 64 MiB limit. Arbitrary transfer streaming and
  pagination, replacing external `git merge-file`, and portable toolchain packaging
  remain engineering work, not implemented features.

## Data and trust boundaries

- Axon refuses an uninitialized data directory when serving, and refuses
  reinitializing an Axon repository.
- Immutable submissions carry a signature under `submission`; mutable planning
  and status fields are outside that signature. The append-only event stream
  retains the authenticated request and registered public key for reviews,
  external attestations, and submissions. These are signed request proofs,
  separate from the new standalone signatures stored on human reviews and
  external attestations. New agent-key, review, attest and remote job-complete requests must include
  the corresponding signed statement; the CLI constructs it automatically.
- `review` fetches and binds the candidate subject before signing its request;
  the server rejects a changed subject. CI attestations bind target, kind, and
  input hash. Human/service accounts are trusted to attest CI results.
- Workspace operations enforce owner/admin access. Snapshot content, stack
  metadata, history, and events are readable by registered identities.
- Remote jobs are leased for 120 seconds and commands time out after 60 seconds.
  Local builds run outside transaction/domain locks and are cancelled at server shutdown.
  A terminated or disconnected worker can leave work to be reclaimed after
  lease expiry. Completion must match both identity and lease token.
- RPC requests and client responses are bounded at 64 MiB. Writes and closure
  transfers hex-encode binary bytes, so their practical limits are smaller.
  Cached file reads download raw CAS bytes. Large-transfer streaming
  and pagination remain work to do.
- Materialization requires an empty destination and rejects escaping symlinks.
  It is not an OS-level sandbox for build commands.

## C++ prescription application and exceptions

The code uses C++23, Clang/libc++ 21.1.8, Catalyst-owned build profiles, private
self-contained `.hpp` headers, RAII descriptors, project namespaces, explicit
request locking, hidden visibility, and automated formatting. No public SDK is
exported. `main` and the CLI driver live in `src/axon.cpp`.

The installed formatter, clangd, and clang-tidy are LLVM 22.1.8, rather than the
prescription's LLVM 21 tooling family. Formatting is pinned to the available
formatter. The private request boundary returns `std::expected<Json, string>`;
private implementation and third-party JSON/I/O operations use exceptions that
are caught at that boundary. The prescribed `pq::expected` implementation and
Jocasta are not available in this project. No full prescription-compliance claim
is made. The concurrency companion guides were not present locally.

Dependency versions used for validation: OpenSSL 3.5.1, curl 8.15.0 and
nlohmann-json 3.12.0 from vcpkg (pinned in `catalyst.lock`, linked statically),
plus system LLVM/libc++ 21.1.8, mold 2.42.0 and Catalyst 2.1.0. The
compiler/stdlib baseline is checked; LLVM's BLAKE3 C API remains a system
dependency located by `scripts/find-llvm.sh`.

## Validation for this implementation pass

Final validation results are recorded here after the complete build/test pass.
The earlier feature pass passed 12 native groups and 20 integration tests under
ASan/UBSan; the expanded suite now exercises transactions, FUSE packets, retention,
offline replay, standalone remote signatures, workflow triggers and C++ declarations.

The skill's `-=j=32` clangd option is unsupported; `-j=32` is used. Full interactive
tweak testing reports ExtractFunction limitations on break/continue statements;
`--check-lines=1-1` avoids those tool-only failures while retaining full translation
unit parsing and diagnostics. LeakSanitizer is disabled in the ptrace environment;
ASan and UBSan remain enabled. No full prescription-compliance claim is made.

## Prior baseline validation

The following results describe the earlier implementation, not the current diff.

- Catalyst debug, release (full LTO), sanitized-debug, common, and test builds passed with zero `-Werror` warnings.
- Thirteen end-to-end integration tests passed against release and debug binaries:
  workspace and binary round trips, journal restart recovery, all landing paths,
  conflict resolution, policy/review/auth checks, local and remote CI, flaky
  attestations, Git tree fidelity, path safety, disjoint concurrent writers,
  regional CAS cache tier, log limits and admin workflows, merge queue and agent
  ejection, and Prometheus metrics with partitioned event offsets.
- Sanitized native unit checks (8 test groups) passed under AddressSanitizer and
  UndefinedBehaviorSanitizer for BLAKE3 vectors, Ed25519 tampering, FastCDC edit
  locality, Merkle canonicality, directory sharding, CAS corruption, torn/corrupt
  journals, failed-append truncation, concurrent group commit, RPC replay/timestamp/signature rejection, and workflow/queue operations.
- All private headers compiled independently; formatting and whitespace checks
  passed with zero diffs using `clang-format-22`.
- LeakSanitizer was disabled because the execution container uses ptrace;
  AddressSanitizer and UndefinedBehaviorSanitizer remained enabled.
