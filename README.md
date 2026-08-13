# Repo2OKF

Repo2OKF scans a source repository and emits [Open Knowledge Format (OKF)
v0.2][okf] documents whose claims can be traced back to source evidence.
Codex or Claude Code can optionally enrich the result through their installed
CLI and existing login.

> Repo2OKF is pre-1.0. Commands and Rust APIs may still change.

## Quick start

Until the first binary release, install from source with Rust 1.88 or newer:

```console
git clone https://github.com/suisya-systems/repo2okf.git
cd repo2okf
cargo install --path crates/repo2okf-cli --locked
```

Run it in the repository you want to document:

```console
repo2okf init
repo2okf doctor
repo2okf compile --facts-only
repo2okf verify --strict
repo2okf coverage
```

See the [CLI reference](docs/cli-reference.md) for every command, option, and
agent flag combination.

Generated OKF is written to `.okf`; scanner state is stored in `.repo2okf`.
Both directories are generated and should be added to `.gitignore`, not
committed.

## Verification model

Repo2OKF treats AI output as an untrusted claim, not as source truth.

- The scanner produces a deterministic repository inventory, evidence records,
  source/semantic graphs, and coverage accounting.
- Evidence binds claims to a path, source range, symbol, and content hash.
- Optional agents return structured claim and architecture candidates. The host
  validates their graph/evidence references and emits architecture as `draft`;
  agents do not write the repository or generated OKF.
- `verify` rescans the repository and compares the bundle with a fresh
  deterministic emission, detecting source drift and manual edits.

```text
repository -> scanner -> IR + evidence -> OKF
                            ^              |
                            |              v
                      optional agent    verifier
```

Facts-only builds are byte-for-byte reproducible for the same repository bytes
and configuration. Agent-written prose is not deterministic.

## Agent enrichment

AI is optional and selected per invocation:

```console
repo2okf compile --agent claude
repo2okf compile --agent codex --allow-agent-filesystem
```

Claude runs with local tools disabled and receives bounded, hash-verified
evidence excerpts. Codex currently requires explicit permission to read the
repository. Repo2OKF uses the vendor CLI's existing authentication and does not
copy its OAuth tokens. See the [security model](docs/security.md) and
[configuration guide](docs/configuration.md) for the full trust boundary and
version requirements.

## Language support

The scanner currently parses Rust, Go, JavaScript, TypeScript, Python, and
Markdown. Local import resolution is implemented for relative JavaScript and
TypeScript imports and for unambiguous Python modules. Python also records
conservative import bindings, direct calls, class bases, annotation type uses,
and decorators as resolved, external, ambiguous, or unresolved references.
OKF rolls these references up into Python module or package concepts; it does
not create a document for every symbol or call. Unsupported or ambiguous
behavior remains visible rather than being guessed. See
[architecture](docs/architecture.md) for current limits.

## Development

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
```

The workspace contains four crates:

- `repo2okf-core`: scanning, IR, evidence, and coverage
- `repo2okf-agent`: Codex and Claude Code adapters
- `repo2okf-format`: OKF emission and verification
- `repo2okf-cli`: configuration and commands

See the [distribution guide](docs/distribution.md) for supported release
targets. Contributions are described in [CONTRIBUTING.md](CONTRIBUTING.md).

Repo2OKF is licensed under the MIT License.

[okf]: https://github.com/GoogleCloudPlatform/knowledge-catalog/tree/main/okf
