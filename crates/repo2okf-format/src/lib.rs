//! Deterministic Open Knowledge Format v0.2 emission and verification.
//!
//! `repo2okf-format` deliberately keeps LLM generation separate from trust.
//! Resolving a claim's evidence is required for acceptance, but does not add an
//! OKF `verified` event; only an explicit human or deterministic process may do
//! that.

mod core_adapter;
mod emit;
mod model;
mod verify;

pub use emit::{EmissionReport, EmitError, emit_okf};
pub use model::{
    CoverageClassification, CoverageItem, DocumentPathError, EvidenceRecord, Generated,
    OKF_VERSION, OkfBundle, OkfClaim, OkfDocument, OkfMetadata, OkfRelationship, OkfSource,
    OkfStatus, Repo2OkfMetadata, RepositoryIrView, RepositorySnapshot, UsageWindow, Verification,
    concept_path,
};
pub use verify::{
    FreshnessMismatch, Severity, VerificationIssue, VerificationReport, VerifyOptions, verify_okf,
};
