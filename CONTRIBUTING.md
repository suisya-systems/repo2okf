# Contributing

Repo2OKF is currently stabilizing its first public contracts. Before proposing
a large change, describe the user-facing problem and which pipeline invariant
it affects.

Run these checks before submitting a change:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --locked
cargo doc --workspace --no-deps --locked
```

The cross-platform CLI integration test is credential-free: it invokes the
compiled binary with `compile --facts-only`, then exercises verification,
coverage reporting and both incremental update paths. It is part of the normal
workspace test command and must remain independent of Git, Codex and Claude.

Changes to scanners should include a minimal source fixture. Changes to an
agent adapter should include recorded, credential-free JSONL fixtures. Changes
to incremental behavior must compare incremental output with a clean build.

Never commit repository samples containing secrets, vendor authentication
state, or private code.
