//! Deterministic repository scanning and evidence-bound intermediate model.
//!
//! This crate never executes repository code. It inventories repository files,
//! extracts language-aware symbols and imports, builds stable evidence IDs and
//! accounts for every discovered item through the coverage model.

mod incremental;
mod model;
mod python_resolver;
mod scanner;

pub use incremental::{BuildState, ChangeSet, compute_changes};
pub use model::{
    Claim, ClaimProvenance, CoverageDisposition, CoverageItem, CoverageKind, CoverageReport,
    Entity, EntityKind, EvidenceRef, FileRecord, ImportRecord, Language, Relationship,
    RelationshipKind, RepositoryIr, RepositoryMetadata, ScanStatus,
};
pub use scanner::{ScanError, ScanOptions, scan_repository};

/// Version of the serialized repository intermediate representation.
pub const IR_SCHEMA_VERSION: u32 = 1;

/// Version identifier included in evidence extractor metadata.
///
/// Increment the algorithm revision whenever scan or fingerprint semantics
/// change, even before the next package release.
pub const EXTRACTOR_VERSION: &str = concat!("repo2okf-core/", env!("CARGO_PKG_VERSION"), "+scan.4");
