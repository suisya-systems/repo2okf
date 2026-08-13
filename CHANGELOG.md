# Changelog

All notable changes to this project will be documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Rust workspace and cross-platform CI.
- Deterministic repository IR, evidence and coverage pipeline.
- Isolated Codex and Claude Code enrichment adapters with bounded,
  hash-verified evidence excerpts and strict structured output.
- TypeScript/JavaScript relative-import resolution and unresolved ambiguity
  accounting.
- Python class, function, method and syntax-level import extraction with
  evidence and coverage accounting.
- Exact Python declaration-docstring evidence, facts-only presence claims, and
  hash-verified agent excerpts without raw docstring-to-claim copying.
- Direct verification of compiler-owned bundle bytes against a fresh
  deterministic emission, including manual body edits.
- Compiler-owned bundle/IR/state integrity checks and staged publication.
- Root/file identity revalidation and rollback-safe bundle/cache publication.
- OKF v0.2 emission and verification.

### Changed

- Updated Tree-sitter, language grammars, TOML parsing and repository walking
  dependencies to their current compatible releases.
- Raised the source-build MSRV to Rust 1.88 and grouped routine Dependabot
  updates by ecosystem to avoid one pull request per dependency.
