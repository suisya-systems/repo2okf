# Changelog

All notable changes to this project will be documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-08-13

First dogfood pre-release. Commands, output details, and Rust APIs may change.
Release artifacts include checksums and GitHub attestations, but are not yet
code-signed or notarized.

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
- Evidence-backed Python semantic references for import bindings, direct calls,
  class bases, annotation type uses and decorators, with explicit conservative
  resolution and semantic coverage.
- Deterministic Python module/package OKF concepts that aggregate semantic
  relationships without generating a document per symbol or reference.
- Evidence-preserving semantic relationships and always-draft, host-validated
  architecture concept proposals from optional agents.
- Configurable English or Japanese human-readable OKF prose while preserving
  canonical machine fields, source facts, and semantic IDs.

### Changed

- Updated Tree-sitter, language grammars, TOML parsing and repository walking
  dependencies to their current compatible releases.
- Raised the source-build MSRV to Rust 1.88 and grouped routine Dependabot
  updates by ecosystem to avoid one pull request per dependency.

[Unreleased]: https://github.com/suisya-systems/repo2okf/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/suisya-systems/repo2okf/releases/tag/v0.1.0-alpha.1
