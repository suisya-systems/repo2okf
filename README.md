# Repo2OKF

Repo2OKF is a local-first, evidence-bound compiler that turns a source
repository into [Open Knowledge Format (OKF) v0.2][okf]. It combines a
deterministic source scanner with optional semantic enrichment through an
already-installed Codex or Claude Code CLI.

The project is an early implementation. The command and Rust APIs may change
before the first stable release.

## Why another OKF tool?

Repo2OKF treats AI output as an untrusted claim, not as the source of truth.

- Static scanning creates a reproducible repository inventory and evidence
  graph.
- Coverage accounting classifies every discovered item as included, excluded,
  or unresolved.
- Codex and Claude Code only return structured claim candidates; they do not
  write the repository or generated OKF.
- Claims without resolvable file, line, symbol and content-hash evidence are
  rejected.
- `verify` rescans the repository and byte-compares the compiler-owned bundle
  with a fresh deterministic emission, detecting source drift and manual OKF
  edits.
- Relative TypeScript/JavaScript imports are resolved to source concepts;
  ambiguous or missing local targets remain visibly unresolved.
- Python files contribute evidence-backed function, method and class entities.
  Local imports resolve to source concepts when unambiguous; unresolved local
  targets stay visible, while standard-library and third-party imports remain
  external references.
- Leading Python class/function/method docstrings are captured as exact source
  evidence. Facts-only output records their presence without copying prose into
  claims; agents receive docstring text only through hash-verified excerpts.
- `update` performs a full repository rescan, then uses persisted fingerprints
  to skip regeneration when the inputs and verified bundle are unchanged.

```text
Repository -> scanner -> Repository IR -> coverage planner
                                      -> optional CLI agent
                                      -> evidence validator
                                      -> OKF v0.2 -> verifier
```

## Intended UX

```console
repo2okf init
repo2okf doctor
repo2okf compile --facts-only
repo2okf compile --agent claude
repo2okf compile --agent codex --allow-agent-filesystem
repo2okf update --agent auto --reuse-agent-cache
repo2okf verify --strict
repo2okf coverage
```

AI is opt-in per invocation: without `--agent`, compilation is facts-only even
if a repository configuration asks for an agent. Agent modes use the user's
existing vendor CLI installation and login; Repo2OKF does not read or copy
vendor OAuth tokens. Model-generated prose is inherently non-deterministic;
byte-for-byte reproducibility is guaranteed only for facts-only builds over the
same repository bytes and configuration.

Claude runs from an isolated temporary directory with all local tools disabled;
the host supplies only hash-verified, size-bounded evidence excerpts. Codex's
current read-only sandbox still permits repository reads, so Codex runs require
the additional, explicit `--allow-agent-filesystem` opt-in. Agent cache reuse is
also explicit (`--reuse-agent-cache`) because persisted agent prose is not a
trust anchor.

Claude Code 2.1.227 or newer is required. That release fixes a headless startup
feature-gating bug that could incorrectly block Max subscribers; see the
[Claude Code changelog](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md#21227).

The `.okf` bundle and `.repo2okf` persisted state are compiler-owned generated
caches. They are ignored by Git by default, should not be committed, and must
not be reused from an untrusted checkout. The standard CI path is a clean
`repo2okf compile --facts-only` build with both directories initially absent.

## Build from source

Rust 1.88 or newer is required to build the project. End users of release
binaries do not need Rust, Node.js, or a Python interpreter: Python source is
parsed directly by the native Repo2OKF binary.

```console
cargo install --path crates/repo2okf-cli --locked
repo2okf doctor
```

For development builds:

```console
cargo build --release --locked
cargo test --workspace --all-targets
```

The release configuration produces native archives for Windows x64, macOS x64
and arm64, and Linux x64 and arm64. Shell and PowerShell installers are thin
wrappers around those archives. See [the distribution guide](docs/distribution.md)
for the target matrix and release prerequisites.

## Workspace

- `repo2okf-core`: repository scanning, IR, evidence, coverage and incremental
  fingerprints
- `repo2okf-agent`: isolated Codex and Claude Code process adapters and bounded
  repair loop
- `repo2okf-format`: OKF v0.2 emission and verification
- `repo2okf-cli`: configuration and end-user commands

See the [architecture](docs/architecture.md),
[security model](docs/security.md), [configuration](docs/configuration.md), and
[distribution](docs/distribution.md) guides.

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The project is licensed under the MIT License.

[okf]: https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf
