//! Read-only semantic enrichment through installed vendor coding-agent CLIs.
//!
//! `Repo2OKF` never reads vendor authentication state and never gives an agent
//! write tools. Prompts are written to stdin, final output is schema constrained
//! and all returned claims are independently checked against the core IR.

mod driver;
mod excerpts;
mod loop_engine;
mod model;
mod process;

pub use driver::{AgentDriver, ClaudeDriver, CodexDriver};
pub use loop_engine::{RepairOptions, enrich_with_repair, validate_response};
pub use model::{
    AcceptedConceptCandidate, AcceptedRelationshipCandidate, AgentCapabilities, AgentKind,
    AgentProbe, CandidateRelationshipKind, ConceptCandidate, EnrichmentRequest, EnrichmentResponse,
    EnrichmentStats, EvidenceExcerpt, RelationshipCandidate, SemanticGraphScope,
    SuppliedSemanticGraph, ValidationIssue,
};
pub use process::{AgentError, ProcessConfig};

/// Revision of the vendor prompt, schema, and process-isolation contract.
///
/// Incremental consumers should include this value in build fingerprints.
pub const AGENT_CONTRACT_VERSION: &str = "10";
