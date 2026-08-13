# Repo2OKF architecture

Repo2OKF is a local-first, evidence-bound compiler from a source repository to
Open Knowledge Format (OKF) v0.2. `repo2okf` is a working product name.

## Pipeline

```text
repository
  -> deterministic scanner
  -> RepositoryIr + evidence graph
  -> coverage planner
  -> optional isolated Codex or Claude Code enrichment
  -> claim validator and bounded repair loop
  -> deterministic OKF v0.2 emitter
  -> verifier and incremental build state
```

## Workspace boundaries

- `repo2okf-core` owns repository discovery, language-aware scanning,
  `RepositoryIr`, evidence, coverage and incremental fingerprints.
- `repo2okf-agent` owns process launch, capability probes, JSON/JSONL decoding,
  prompts and the bounded enrichment/repair loop. It may depend on core.
- `repo2okf-format` owns OKF v0.2 documents, deterministic emission and
  verification. It may depend on core.
- `repo2okf-cli` owns configuration, commands, orchestration and user-facing
  diagnostics. It may depend on every library crate.

## Required invariants

1. Facts-only output is deterministic for the same repository bytes and config.
2. An agent never writes repository or OKF files. Claude receives only bounded,
   hash-verified source excerpts with tools disabled. Codex repository reads
   require explicit user opt-in. Both return structured claim candidates
   through stdout; the host validates and writes them.
3. Every accepted semantic claim contains at least one resolvable evidence ID.
4. Every scanned coverage item is classified as included, excluded with a
   reason, or unresolved.
5. A facts-only unchanged-build skip must be byte-equivalent to a clean
   facts-only build over the same repository bytes and configuration. Agent
   output is non-deterministic and is outside this byte-equivalence guarantee.
6. Prompts are sent through stdin. Repository paths and prompts are never joined
   into a shell command string.
7. Codex and Claude authentication files are never read by Repo2OKF. Only the
   vendor CLIs are invoked.
8. Compilation stages and publishes `.okf` and the whole `.repo2okf` cache as
   two repository-root directory entries. Scan publishes the whole cache as a
   single entry. Concurrent Repo2OKF commands for one repository are not
   supported.

## Incremental behavior

`repo2okf update` currently performs a full deterministic rescan. It compares
the resulting build state with persisted fingerprints and may skip publication
when inputs are unchanged and the existing bundle still verifies against a
fresh emission. Facts-only builds reuse deterministic local state. Agent claims
are reused only with the explicit `--reuse-agent-cache` trust opt-in; otherwise
the agent runs again. Changed inputs trigger a full rebuild; per-file
parse-result reuse is not implemented yet.

`.okf` and `.repo2okf` are compiler-owned generated caches, not source inputs.
They should remain uncommitted and must not be trusted or reused when supplied
by an untrusted checkout.

## Dependency resolution scope

The scanner resolves JavaScript and TypeScript relative imports when exactly one
scanned source file matches the normalized path, a supported source extension,
or an `index` file with a supported source extension. Resolved imports link the
two repository source concepts. Missing, root-escaping, case-mismatched, and
ambiguous relative imports remain explicit unresolved coverage items and do not
become misleading external-module concepts.

The Python scanner extracts classes, functions (including nested functions),
and direct class-body methods as evidence-backed entities. It also accounts for
each `import` and `from ... import ...` statement as an evidence-backed import
record. Relative imports and absolute package/module imports that uniquely
match a scanned repository source file resolve to that source concept. Missing,
ambiguous, root-escaping, and case-mismatched local imports remain explicit
unresolved coverage items. Standard-library and third-party Python imports stay
external references. A dots-only form such as `from . import util` records a
dependency on the current package initializer; it does not guess whether
`util` is a package attribute or a same-named submodule. `from __future__`
remains a compiler directive and never resolves to a shadowing repository file.

For Python classes, functions, and methods, a leading docstring expression is
captured as its own exact `EvidenceRef`. Facts-only scanning emits a claim that
the declaration has a docstring, but does not copy the docstring body into an
unprocessed deterministic claim. When semantic enrichment is enabled, the
agent can see that text only through the same content-hash validation and
bounded excerpt path used for other source evidence.

Bare JavaScript/TypeScript specifiers and the syntax-level import records found
by the initial Go and Rust scanners are currently represented as external
references. Resolving them reliably requires package/module manifests and
language-specific module graphs, which the scanner deliberately does not infer
in this release.

## Initial public contracts

The core crate exposes `scan_repository`, `RepositoryIr`, `Claim`,
`EvidenceRef`, `CoverageReport`, `BuildState` and `compute_changes`.

The agent crate exposes `AgentDriver`, `CodexDriver`, `ClaudeDriver`,
`AgentKind`, `AgentCapabilities`, `EnrichmentRequest`, `EnrichmentResponse` and
`enrich_with_repair`.

The format crate exposes `emit_okf`, `verify_okf`, `OkfDocument`,
`VerificationReport` and `VerifyOptions`.
