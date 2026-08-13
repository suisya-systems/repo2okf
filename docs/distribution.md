# Distribution

Repo2OKF is a single Rust executable. Facts-only operation has no runtime
dependency on Rust, Node.js, Python, Git, Codex or Claude Code. Agent enrichment
only requires the selected vendor CLI and its existing authenticated session.

## Supported release artifacts

The cargo-dist configuration builds these native targets:

| Platform | Architecture | Rust target |
| --- | --- | --- |
| Windows | x64 | `x86_64-pc-windows-msvc` |
| macOS | x64 | `x86_64-apple-darwin` |
| macOS | arm64 | `aarch64-apple-darwin` |
| Linux (glibc) | x64 | `x86_64-unknown-linux-gnu` |
| Linux (glibc) | arm64 | `aarch64-unknown-linux-gnu` |

Shell and PowerShell installers are generated from the same versioned release
archives. GitHub artifact attestations are enabled in `dist-workspace.toml`.

## Install the pre-release

The current dogfood release is `v0.1.0-alpha.2`. Install it without a Rust
toolchain:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/suisya-systems/repo2okf/releases/download/v0.1.0-alpha.2/repo2okf-installer.sh | sh
```

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/suisya-systems/repo2okf/releases/download/v0.1.0-alpha.2/repo2okf-installer.ps1 | iex"
```

The release page also provides archives, SHA-256 checksums, and GitHub artifact
attestations for all supported targets. This alpha is not code-signed or
notarized. The installer is provided for convenience; when provenance matters,
verify a downloaded artifact with
`gh attestation verify <file> --repo suisya-systems/repo2okf` and its checksum.

To build from a checkout instead, use Rust 1.88 or newer:

```console
cargo install --path crates/repo2okf-cli --locked
repo2okf doctor
```

`repo2okf compile --facts-only` is always available without an AI subscription
or API key.

## Publishing checklist

For each hosted release:

1. Confirm private vulnerability reporting and the issue-template contact URL.
2. Run `dist generate --check` with cargo-dist 0.32.
3. Run formatting, Clippy, all workspace tests, documentation and cargo-deny.
4. Inspect `dist plan` for all five targets and both installers.
5. Push the single matching version tag only after the release workflow is on
   the default branch.

The canonical source repository is
[`suisya-systems/repo2okf`](https://github.com/suisya-systems/repo2okf).
Generated release workflows are committed only after their release plan has
been reviewed.
