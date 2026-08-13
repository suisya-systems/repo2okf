# CLI reference

Repo2OKF uses the following command shape:

```console
repo2okf [GLOBAL OPTIONS] <COMMAND> [COMMAND OPTIONS]
```

Global options may appear before or after the command. Run `repo2okf help
<COMMAND>` or `repo2okf <COMMAND> --help` for the help built into the installed
version.

## Commands at a glance

| Command | Purpose | Writes generated files |
| --- | --- | --- |
| `init` | Create a starter `repo2okf.toml`. | `repo2okf.toml` |
| `doctor` | Check the repository, Git, Codex, and Claude Code setup. | No |
| `scan` | Build deterministic repository IR without AI. | `.repo2okf/` unless `--stdout` is used |
| `compile` | Scan and emit an OKF v0.2 bundle. | `.okf/` and `.repo2okf/` |
| `update` | Rescan, then skip or rebuild an existing bundle. | `.okf/` and `.repo2okf/` when rebuilding |
| `verify` | Rescan and verify an OKF bundle against source evidence. | No |
| `coverage` | Show coverage recorded by the last scan or compile. | No |
| `help` | Show top-level or command-specific help. | No |

## Global options

| Option | Meaning |
| --- | --- |
| `--repository <PATH>` | Repository root to process. Defaults to the current directory. Relative paths are resolved from the process working directory. |
| `--config <FILE>` | Use an explicit configuration file. A relative path is resolved from the repository root; an absolute path is preserved. This option is not used by `init`. |
| `-v`, `--verbose` | Enable informational diagnostics. Repeat as `-vv` for debug diagnostics. `RUST_LOG` takes precedence when set. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print the Repo2OKF version. |

If `repo2okf.toml` is absent and `--config` is not supplied, commands other
than `init` use the built-in defaults. See the [configuration guide] for all
configuration fields.

## Common workflows

Create deterministic OKF without invoking an agent:

```console
repo2okf init
repo2okf compile --facts-only
repo2okf verify --strict
```

`init` is optional: when `repo2okf.toml` is absent, the other commands use
built-in defaults.

Inspect the scanner IR without writing compiler state:

```console
repo2okf scan --stdout
```

Use an existing Claude Code login for optional enrichment:

```console
repo2okf doctor
repo2okf compile --agent claude
```

Generate human-readable OKF prose in Japanese by setting the repository
configuration (the CLI itself remains English):

```toml
[output]
locale = "ja"
```

The locale applies to generated descriptions, claims, and safe presentation
labels. Machine-readable keys, IDs, paths, symbols, OKF types/statuses/kinds,
and code are never translated.

Use Codex after explicitly allowing its CLI to read the repository:

```console
repo2okf compile --agent codex --allow-agent-filesystem
```

Rebuild only when the rescan or verified output requires it:

```console
repo2okf update --facts-only
```

Get machine-readable reports:

```console
repo2okf doctor --json
repo2okf verify --json
repo2okf coverage --json
```

## `init`

```console
repo2okf init [--force]
```

Creates `repo2okf.toml` at the repository root. It refuses to replace an
existing file unless `--force` is supplied.

| Option | Meaning |
| --- | --- |
| `--force` | Replace an existing `repo2okf.toml`. |

`init` always writes the standard file name at the repository root, so the
global `--config` option has no effect on this command.

## `doctor`

```console
repo2okf doctor [--json]
```

Reports the repository path, Git availability, Codex and Claude Code probe
results, authentication readiness, and facts-only readiness. It probes local
tools but does not ask an AI model to analyze the repository.

Git status is informational. The default deterministic scanner does not invoke
Git or repository-controlled hooks.

| Option | Meaning |
| --- | --- |
| `--json` | Emit the report as stable JSON instead of human-readable text. |

Run this before using `--agent` to diagnose missing, unauthenticated, or
unsupported vendor CLIs.

## `scan`

```console
repo2okf scan [--stdout]
```

Runs the deterministic scanner and builds repository IR. No AI agent is
invoked.

Without `--stdout`, the command writes the configured IR and build state under
the reserved `.repo2okf/` directory. With `--stdout`, it prints pretty JSON and
does not update the saved IR or state.

| Option | Meaning |
| --- | --- |
| `--stdout` | Print IR JSON to standard output instead of saving compiler state. |

## `compile`

```console
repo2okf compile [OPTIONS]
```

Performs a full deterministic scan, optionally enriches the IR with an agent,
emits OKF v0.2, verifies the staged result, and publishes `.okf/` together with
`.repo2okf/`. Publication fails rather than replacing directories that do not
carry Repo2OKF's ownership marker.

No agent is used by default. `--facts-only` makes that choice explicit and is
recommended for reproducible builds and CI.

## `update`

```console
repo2okf update [OPTIONS]
```

Accepts the same options as `compile`. It performs a full deterministic rescan,
compares the new state with the saved state, and verifies the existing bundle.
If the inputs and bundle are unchanged, it skips publication; otherwise it
rebuilds the bundle.

Changing `output.locale` is an output-contract change, so `update` renders and
verifies a new bundle instead of accepting the previous language as current.

`update` does not yet reuse individual parse results. Its current optimization
is skipping an unchanged, verified build after the rescan.

## Compile and update options

| Option | Meaning |
| --- | --- |
| `--agent <off\|auto\|codex\|claude>` | Select optional semantic enrichment. The default is `off`. |
| `--facts-only` | Disable all agent calls. Conflicts with `--agent`, `--review-with`, and both agent trust options. |
| `--review-with <off\|auto\|codex\|claude>` | Run a second agent over the enriched IR. Requires `--agent` and must resolve to a different agent from the primary. |
| `--allow-agent-filesystem` | Permit an agent CLI that cannot prevent repository reads. Requires `--agent`; Codex currently requires this opt-in. |
| `--reuse-agent-cache` | Trust and reuse locally persisted agent claims during `update`. Requires `--agent`. A clean `compile` has no existing result to reuse. |
| `--output <DIRECTORY>` | Select the generated bundle directory. The current safety policy only accepts `.okf`; other values fail. |
| `--strict` | Fail if verification has warnings or non-excluded coverage is below 100%. Broken links and stale documents are errors. |

`--agent off` cannot be combined with `--allow-agent-filesystem` or
`--reuse-agent-cache`. Passing `--review-with off` explicitly disables the
reviewer.

Agent selection behaves as follows:

| Value | Behavior |
| --- | --- |
| `off` | Do not invoke an agent. This is the default. |
| `auto` | Prefer a ready Claude Code CLI. Codex is eligible only when `--allow-agent-filesystem` is also supplied. |
| `claude` | Require a supported and authenticated Claude Code CLI. Repository tools are disabled; bounded evidence excerpts are sent through standard input. |
| `codex` | Require a supported Codex CLI and `--allow-agent-filesystem`. The installed CLI's existing login is reused. |

Agent output is validated against known evidence before publication, but its
prose is not deterministic. With `update --agent ...`, the agent runs again
even when source bytes are unchanged unless `--reuse-agent-cache` is supplied.
That flag is an explicit trust decision: never reuse generated state from an
untrusted checkout. See the [security model] for the complete boundary.

When a reviewer runs, deterministic scanner claims are retained, primary-agent
claims and architecture drafts are replaced, and only the reviewer's accepted
claims and always-draft architecture interpretation are published.

## `verify`

```console
repo2okf verify [PATH] [--strict] [--json]
```

Loads the saved IR and state, rescans the current repository, verifies evidence
hashes and OKF structure, and compares the target bundle with a fresh emission.
It detects source drift and manual changes to generated output.

`PATH` defaults to the configured output directory, `.okf/`. It must name a
bundle directory inside the repository. Run `compile` first so the bundle, IR,
and state exist.

| Argument or option | Meaning |
| --- | --- |
| `[PATH]` | Bundle directory to verify. Defaults to `.okf/`. |
| `--strict` | Treat warnings as failures, require 100% non-excluded coverage, and make broken links and stale documents errors. |
| `--json` | Emit a stable JSON report. An invalid report still produces a nonzero exit status. |

## `coverage`

```console
repo2okf coverage [--json]
```

Reports included, excluded, and unresolved inventory from the saved IR. It does
not rescan the repository, so it describes the last successful `scan`,
`compile`, or `update` rather than necessarily describing current source.

The text report also shows semantic-reference totals split into resolved,
external, ambiguous, and unresolved. JSON retains the source-coverage fields at
the top level and adds a `semantic` object with those totals. Semantic coverage
accounts for conservative resolution; unresolved dynamic behavior is visible
but does not by itself make strict verification fail.

After agent enrichment, the report also includes `architecture_scope`: the
host-computed supplied/total evidence and semantic-graph counts plus whether the
agent saw the complete bounded input. This prevents a partial draft from being
mistaken for a repository-wide interpretation.

| Option | Meaning |
| --- | --- |
| `--json` | Emit the saved coverage object as stable JSON. |

## `help`

```console
repo2okf help [COMMAND]
```

Prints top-level help or the help for one command. `repo2okf <COMMAND> --help`
is equivalent for command-specific help.

## Generated files

| Path | Produced by | Contents |
| --- | --- | --- |
| `repo2okf.toml` | `init` | Repository configuration. |
| `.repo2okf/ir.json` | `scan`, `compile`, `update` | Repository IR, semantic graph and any accepted agent claims/draft architecture concepts. |
| `.repo2okf/state.json` | `scan`, `compile`, `update` | Fingerprints used by verification and update decisions. |
| `.okf/index.md` and concept documents | `compile`, `update` | Generated OKF v0.2 index and concepts. |
| `.okf/.repo2okf-owned` and `.repo2okf/.repo2okf-owned` | `compile`, `update`; cache marker also by `scan` | Ownership markers used to guard whole-directory replacement. |

`.okf/` and `.repo2okf/` are compiler-owned generated directories. Add both to
the target repository's `.gitignore`, do not commit them, and do not reuse them
from an untrusted checkout. Each directory is replaced as a whole: do not store
user files inside it, and do not run concurrent Repo2OKF writers for the same
repository. See the [security model] for publication and recovery details.

Every generated index and concept records `repo2okf.output_locale` as `en` or
`ja`. Verification rejects a missing or mixed locale when checking a bundle
against the configured output locale.

## Exit status and output

Successful commands, `--help`, and `--version` return status `0`. Command-line
usage errors return status `2`. Runtime failures, missing prerequisites, unsafe
output paths, invalid bundles, and strict verification failures return status
`1`. Human-readable progress goes to standard output and errors go to standard
error.

The machine-readable surfaces are:

- `doctor --json` for environment readiness;
- `scan --stdout` for repository IR;
- `verify --json` for a verification report; and
- `coverage --json` for saved coverage.

[configuration guide]: configuration.md
[security model]: security.md
