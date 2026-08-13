# Configuration

`repo2okf init` creates `repo2okf.toml` at the repository root.

```toml
schema = 1

[scan]
include_hidden = false
max_file_bytes = 2097152
languages = ["typescript", "javascript", "python", "go", "rust", "markdown"]

[output]
directory = ".okf"
ir_file = ".repo2okf/ir.json"
state_file = ".repo2okf/state.json"
locale = "en"

[agent]
max_repair_attempts = 2
timeout_seconds = 600

[verify]
minimum_coverage = 0.0
```

Agent selection and strictness are invocation-level CLI choices rather than
repository settings. The generated bundle directory is currently fixed to
`.okf`; both `output.directory` and `--output` must use that value. Relative
configuration paths are resolved from the repository root, not the current
working directory after startup. See the [CLI reference](cli-reference.md) for
command options and their conflict rules.

`output.locale` controls only human-readable prose in generated OKF. Supported
values are `en` (the default) and `ja`. Japanese output localizes deterministic
descriptions, claims, and safe presentation labels; optional agent prose is
also requested in Japanese. Schema keys, IDs, paths, symbols, code, OKF types,
statuses, tags, and relationship kinds remain canonical and untranslated. The
CLI, diagnostics, source code, and developer documentation remain English.

Changing the locale does not change the scanned repository IR or its source
and semantic IDs. It does invalidate the output build contract, so `update`
renders the bundle again and does not reuse agent prose created for another
locale.

Generated output and internal state use the reserved `.okf` and `.repo2okf`
directories. Both are compiler-owned generated caches. Add them to the target
repository's `.gitignore`; `repo2okf init` does not edit `.gitignore`. They
should not be committed or reused from an untrusted checkout. Existing `.okf`
and `.repo2okf` content is replaced only when its fixed ownership marker
matches; the marker is an accidental-deletion guard, not an authentication
proof.

CI should start with both cache directories absent and run a clean
`repo2okf compile --facts-only` build. Agent-enriched prose is non-deterministic,
so byte-for-byte clean-build equivalence applies only to facts-only output.

Repository configuration never authorizes an AI process by itself. Pass
`--agent auto`, `--agent codex`, or `--agent claude` explicitly for each
compile/update invocation. Without an explicit flag the CLI is facts-only.
Claude receives bounded evidence excerpts with tools disabled. Codex requires
`--allow-agent-filesystem` because its CLI sandbox cannot currently disable all
repository reads. `update --agent ... --reuse-agent-cache` is the only mode that
trusts and retains locally persisted agent claims; without it, an agent run is
performed again even when source bytes are unchanged.

Claude Code 2.1.227 or newer is required because that release fixes a headless
feature-gating bug affecting subscription detection. Older or unparseable
versions are reported as unsupported by `repo2okf doctor` and fail closed at
invocation time; see the [upstream changelog][claude-2-1-227].

The default minimum coverage is zero so partially supported repositories still
produce a useful bundle. Set a project quality gate explicitly, or use
`--strict` to require complete non-excluded coverage.

Configuration rejects unknown fields and supports only `schema = 1`.
`output.locale` must be `en` or `ja`.
`scan.languages` must not be empty. `scan.max_file_bytes` must be between 1 and
67108864, `agent.max_repair_attempts` between 0 and 5,
`agent.timeout_seconds` between 1 and 3600, and `verify.minimum_coverage`
between 0 and 1. The IR and state paths must be distinct, non-nested files
inside `.repo2okf/`.

Language names are case-insensitive and accept the aliases `js`, `ts`, `py`,
`golang`, `rs`, and `md`. Python is enabled in the starter configuration.

[claude-2-1-227]: https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md#21227
