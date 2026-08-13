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

## Install from a checkout

Until the first hosted release is published, install directly from a checkout
with Rust 1.85 or newer:

```console
cargo install --path crates/repo2okf-cli --locked
repo2okf doctor
```

`repo2okf compile --facts-only` is always available without an AI subscription
or API key.

## Publishing checklist

Before the first hosted release:

1. Enable private vulnerability reporting and verify its URL in the issue-template
   contact links.
2. Install cargo-dist 0.32 and run `dist init --yes` to generate its GitHub
   release workflow from the checked-in `dist-workspace.toml`.
3. Run formatting, Clippy, all workspace tests, documentation and cargo-deny.
4. Inspect the generated release plan for all five targets and both installers.

The canonical source repository is
[`suisya-systems/repo2okf`](https://github.com/suisya-systems/repo2okf).
Generated release workflows are committed only after their release plan has
been reviewed.
