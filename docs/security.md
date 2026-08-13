# Security model

Repo2OKF processes repositories that may be untrusted. A repository can contain
prompt injection, misleading documentation, unusual paths, large files and
language constructs designed to confuse a parser or an agent.

## Trust boundaries

The deterministic scanner treats repository bytes as data and never executes
build scripts, package lifecycle hooks or source code. It follows ignore rules,
enforces file-size limits and does not traverse symbolic links outside the scan
root.

Repository-root and source-file identities are rechecked before and after the
scanner's discovery and read checkpoints. The implementation deliberately uses
safe standard-library path APIs for portability; those APIs are not fully
handle-relative, so they cannot exclude a swap-away-and-back performed entirely
between two checks. Run Repo2OKF against a repository tree that is not
concurrently writable by an adversary.

The CLI also disables Git-backed discovery because repository-local Git
configuration can invoke programs such as filesystem-monitor hooks. Discovery
uses a native ignore-aware filesystem walk and does not start Git.

Agent enrichment is optional. The host sends prompts through stdin and accepts
only structured claim candidates through stdout. Claude runs with all built-in
and MCP tools disabled in an isolated temporary working directory; it receives
only BLAKE3-verified evidence spans selected by the host, with fixed per-span,
count and aggregate bounds. Codex's current CLI does not expose an equivalent
tool-free/read-allowlist mode, so it fails closed unless the user explicitly
passes `--allow-agent-filesystem`. Repo2OKF validates every accepted evidence ID
against its own previously-built IR before writing OKF.

Repo2OKF never reads Codex or Claude authentication files. Authentication and
refresh remain entirely inside the vendor CLI.

## Hermetic mode

Hermetic mode asks supported vendor CLIs to ignore user configuration, project
rules, hooks and optional tool integrations. Availability depends on the
installed CLI version and is detected by the adapter capability probe. A run
must fail closed when a requested isolation property is unsupported.

Hermetic mode improves reproducibility but does not make model output
deterministic. Agent-generated prose is always identified as generated and is
never marked verified solely because a second model approved it.

Agent execution is always hermetic in the current release; repository
configuration cannot disable that boundary. Evidence excerpts are sent to the
selected model. A Codex run additionally permits its CLI to read repository
files after the explicit filesystem opt-in. Use facts-only mode when repository
contents must not be disclosed to a model.

## Process safety

- Executables and arguments are passed separately; no shell command string is
  constructed.
- Dynamic prompts are sent over stdin, never interpolated into an argument.
- Timeouts and cancellation terminate the entire child process tree.
- Windows PowerShell and command shims are launched through fixed interpreters
  with the script path and each argument kept separate.
- stdout and stderr have bounded capture limits.

## Output safety

- Output paths are resolved beneath the configured output root.
- Document and concept identifiers are checked for duplicates.
- Evidence paths must be normalized repository-relative paths.
- Evidence line ranges and source hashes are revalidated at verification time.
- Generated bundles are verified in a staging directory before replacement.
  Compilation publishes the two repository-root directories `.okf` and
  `.repo2okf` through a rollback journal. Directory replacement is not
  universally atomic or safe for concurrent Repo2OKF writers/readers; run only
  one Repo2OKF command per repository. Ordinary failures restore both old
  directories, and an uncertain or failed rollback preserves a recovery path.
- Publication repeatedly checks repository, staging and published directory
  identities and refuses link/reparse trees. These are best-effort path-based
  race defenses; standard Rust filesystem APIs do not provide portable
  handle-relative renames. Do not run Repo2OKF while another process can rename
  the repository root or generated directories.

The `.okf` bundle and `.repo2okf` IR/build state are compiler-owned generated
caches. Keep them uncommitted and do not reuse copies supplied by an untrusted
checkout. The fixed ownership marker prevents accidental replacement of an
unrelated directory; it is not an authentication or integrity proof.

## CI guidance

Local CLI subscriptions are intended for interactive, trusted machines. CI
should use the vendor's documented automation authentication and isolate the
agent job from untrusted repository-controlled code. The standard CI workflow
starts without `.okf` or `.repo2okf` and runs a clean facts-only build.
Facts-only compilation requires no credentials and is the recommended default
for public pull requests; do not restore persisted Repo2OKF state from an
untrusted checkout or cache source.
