//! Serializable agent requests, responses and capability reports.

use std::path::PathBuf;

use repo2okf_core::{
    ArchitectureConcept, ArchitectureRelationship, ArchitectureRelationshipKind, ArchitectureScope,
    ArchitectureStatus, Claim, ClaimProvenance, CoverageItem, Entity, EvidenceRef, Relationship,
    SemanticReference,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Supported vendor agent driver.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// `OpenAI Codex` CLI.
    Codex,
    /// Anthropic `Claude Code` CLI.
    Claude,
}

impl AgentKind {
    /// Expected command name.
    pub const fn command_name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

/// CLI features required or detected by an adapter.
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent booleans mirror vendor CLI capability probes"
)]
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AgentCapabilities {
    /// Non-interactive execution is available.
    pub non_interactive: bool,
    /// JSONL event output is available.
    pub jsonl: bool,
    /// Final response JSON Schema enforcement is available.
    pub output_schema: bool,
    /// Read-only tool/sandbox restriction is available.
    pub read_only: bool,
    /// User/project customization can be suppressed.
    pub hermetic: bool,
    /// Authentication status can be probed without reading token files.
    pub auth_status: bool,
}

/// Read-only result of probing an installed vendor CLI.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AgentProbe {
    /// Vendor kind.
    pub kind: AgentKind,
    /// Resolved executable or script path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<PathBuf>,
    /// Reported version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// True only when the vendor CLI positively confirms authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    /// Detected capabilities.
    pub capabilities: AgentCapabilities,
    /// Non-secret diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

impl AgentProbe {
    /// Whether this CLI can satisfy `Repo2OKF`'s safe enrichment contract.
    pub fn ready(&self, hermetic: bool) -> bool {
        self.executable.is_some()
            && self.authenticated.unwrap_or(false)
            && self.capabilities.non_interactive
            && self.capabilities.output_schema
            && self.capabilities.read_only
            && (!hermetic || self.capabilities.hermetic)
    }
}

/// Bounded semantic-enrichment task sent to a vendor CLI.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct EnrichmentRequest {
    /// Repository display name.
    pub repository: String,
    /// Deterministic IR fingerprint.
    pub ir_fingerprint: String,
    /// Complete evidence catalog available to claims.
    pub evidence: Vec<EvidenceRef>,
    /// Host-verified, bounded source text corresponding to evidence records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_excerpts: Vec<EvidenceExcerpt>,
    /// Items that still benefit from semantic explanation.
    pub coverage: Vec<CoverageItem>,
    /// Closed, bounded view of the deterministic semantic graph supplied to the agent.
    pub semantic_graph: SuppliedSemanticGraph,
    /// Agent-generated claims supplied to an optional review pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existing_agent_claims: Vec<Claim>,
    /// Previously accepted, always-draft concepts supplied to an optional reviewer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existing_architecture_concepts: Vec<ArchitectureConcept>,
    /// Previously accepted, always-draft relationships supplied to an optional reviewer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existing_architecture_relationships: Vec<ArchitectureRelationship>,
    /// Previously rejected output diagnostics during a repair attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_issues: Vec<ValidationIssue>,
}

/// Host-computed accounting for the bounded semantic graph in an agent request.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticGraphScope {
    /// Number of evidence records in the complete deterministic IR.
    pub total_evidence: usize,
    /// Number of evidence records with verified excerpts in this request.
    pub supplied_evidence: usize,
    /// Number of coverage items in the complete deterministic IR.
    pub total_coverage_items: usize,
    /// Number of coverage items actually included in this request.
    pub supplied_coverage_items: usize,
    /// Number of semantic entities in the complete deterministic IR.
    pub total_entities: usize,
    /// Number of entities actually included in this request.
    pub supplied_entities: usize,
    /// Number of semantic references in the complete deterministic IR.
    pub total_references: usize,
    /// Number of references actually included in this request.
    pub supplied_references: usize,
    /// Number of resolved semantic relationships in the complete deterministic IR.
    pub total_relationships: usize,
    /// Number of resolved semantic relationships actually included in this request.
    pub supplied_relationships: usize,
    /// Whether the request contains the complete evidence and semantic inventory.
    pub complete: bool,
}

impl SemanticGraphScope {
    /// Convert bounded request accounting into the persisted core contract.
    #[must_use]
    pub fn architecture_scope(&self) -> ArchitectureScope {
        ArchitectureScope {
            evidence_total: self.total_evidence,
            evidence_supplied: self.supplied_evidence,
            coverage_items_total: self.total_coverage_items,
            coverage_items_supplied: self.supplied_coverage_items,
            entities_total: self.total_entities,
            entities_supplied: self.supplied_entities,
            semantic_references_total: self.total_references,
            semantic_references_supplied: self.supplied_references,
            semantic_relationships_total: self.total_relationships,
            semantic_relationships_supplied: self.supplied_relationships,
            complete: self.complete,
        }
    }
}

/// A bounded semantic graph copied from deterministic host analysis.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuppliedSemanticGraph {
    /// Host-computed completeness and inventory totals.
    pub scope: SemanticGraphScope,
    /// Entities whose declaration evidence was supplied to the agent.
    pub entities: Vec<Entity>,
    /// References whose source evidence and graph endpoints were supplied.
    pub references: Vec<SemanticReference>,
    /// Resolved semantic relationships closed over the supplied entities and references.
    pub relationships: Vec<Relationship>,
}

/// A bounded excerpt read and verified by the host before agent invocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExcerpt {
    /// Evidence record this text was derived from.
    pub evidence_id: String,
    /// Normalized repository-relative source path.
    pub path: String,
    /// One-based inclusive starting line of the original evidence span.
    pub start_line: u32,
    /// One-based inclusive ending line of the original evidence span.
    pub end_line: u32,
    /// UTF-8 source text, capped by the host policy.
    pub text: String,
    /// Whether the evidence span exceeded the per-excerpt byte limit.
    pub truncated: bool,
}

/// Schema-constrained result returned by a vendor CLI.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichmentResponse {
    /// Evidence-bound semantic claims.
    #[serde(default)]
    pub claims: Vec<Claim>,
    /// Evidence-backed summary suitable for an OKF bundle index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_summary: Option<String>,
    /// Evidence IDs supporting the repository summary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summary_evidence_ids: Vec<String>,
    /// Untrusted architecture groupings proposed by the vendor model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub concept_candidates: Vec<ConceptCandidate>,
    /// Untrusted relationships between model-local concept candidates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationship_candidates: Vec<RelationshipCandidate>,
    /// Host-validated concepts with stable IDs and canonical evidence citations.
    #[serde(default, skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    pub accepted_concepts: Vec<AcceptedConceptCandidate>,
    /// Host-validated relationships with host-derived endpoints and evidence.
    #[serde(default, skip_deserializing, skip_serializing_if = "Vec::is_empty")]
    pub accepted_relationships: Vec<AcceptedRelationshipCandidate>,
}

impl EnrichmentResponse {
    /// Project host-validated candidates into persisted core records.
    ///
    /// IDs and support edges were derived by host validation, while concept
    /// evidence citations were checked against the exact member/support set.
    /// The caller only identifies the driver that produced the untrusted
    /// proposal; persisted interpretations always remain `draft` with agent
    /// provenance.
    pub fn accepted_architecture(
        &self,
        provider: AgentKind,
    ) -> (Vec<ArchitectureConcept>, Vec<ArchitectureRelationship>) {
        let provenance = ClaimProvenance::Agent {
            provider: provider.command_name().to_owned(),
            model: None,
        };
        let concepts = self
            .accepted_concepts
            .iter()
            .map(|candidate| ArchitectureConcept {
                id: candidate.id.clone(),
                title: candidate.title.clone(),
                responsibility: candidate.responsibility.clone(),
                member_entity_ids: candidate.member_entity_ids.clone(),
                supporting_relationship_ids: candidate.supporting_edge_ids.clone(),
                evidence_ids: candidate.evidence_ids.clone(),
                status: ArchitectureStatus::Draft,
                provenance: provenance.clone(),
            })
            .collect();
        let relationships = self
            .accepted_relationships
            .iter()
            .map(|candidate| ArchitectureRelationship {
                id: candidate.id.clone(),
                source_concept_id: candidate.source_concept_id.clone(),
                target_concept_id: candidate.target_concept_id.clone(),
                kind: match candidate.kind {
                    CandidateRelationshipKind::DependsOn => ArchitectureRelationshipKind::DependsOn,
                },
                supporting_relationship_ids: candidate.supporting_edge_ids.clone(),
                evidence_ids: candidate.evidence_ids.clone(),
                status: ArchitectureStatus::Draft,
                provenance: provenance.clone(),
            })
            .collect();
        (concepts, relationships)
    }
}

/// A model-authored grouping over supplied deterministic semantic entities.
///
/// `candidate_key` is only a response-local reference. It is never used as a
/// persisted concept ID.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConceptCandidate {
    /// Response-local key used by relationship candidates.
    pub candidate_key: String,
    /// Concise architecture-level concept title.
    pub title: String,
    /// Evidence-backed responsibility shared by the member entities.
    pub responsibility: String,
    /// Supplied deterministic entity IDs grouped by this concept.
    pub member_entity_ids: Vec<String>,
    /// Supplied semantic relationship or reference IDs establishing cohesion.
    pub supporting_edge_ids: Vec<String>,
    /// Supplied evidence IDs supporting this grouping.
    ///
    /// Every cited support edge's evidence must be included. Additional
    /// citations are limited to evidence attached to the proposed members.
    pub evidence_ids: Vec<String>,
}

/// Architecture relationship kinds the MVP allows a model to propose.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRelationshipKind {
    /// The source concept depends on the target concept.
    DependsOn,
}

/// A model-authored relationship between two response-local concepts.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipCandidate {
    /// Response-local source concept key.
    pub source_candidate_key: String,
    /// Response-local target concept key.
    pub target_candidate_key: String,
    /// Proposed architecture relationship kind.
    pub kind: CandidateRelationshipKind,
    /// Supplied semantic relationship or reference IDs supporting this direction.
    pub supporting_edge_ids: Vec<String>,
}

/// A concept accepted atomically by host validation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedConceptCandidate {
    /// Stable concept ID derived by the host from canonical validated content.
    pub id: String,
    /// Validated display title.
    pub title: String,
    /// Validated responsibility statement.
    pub responsibility: String,
    /// Canonical deterministic member entity IDs.
    pub member_entity_ids: Vec<String>,
    /// Canonical deterministic semantic relationship IDs supporting cohesion.
    pub supporting_edge_ids: Vec<String>,
    /// Canonical, host-validated evidence IDs cited by the model.
    pub evidence_ids: Vec<String>,
}

/// A relationship accepted atomically by host validation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRelationshipCandidate {
    /// Stable relationship ID derived by the host.
    pub id: String,
    /// Host-derived source concept ID.
    pub source_concept_id: String,
    /// Host-derived target concept ID.
    pub target_concept_id: String,
    /// Validated relationship kind.
    pub kind: CandidateRelationshipKind,
    /// Canonical semantic relationship IDs proving this direction.
    pub supporting_edge_ids: Vec<String>,
    /// Evidence IDs derived by the host from the supporting edges.
    pub evidence_ids: Vec<String>,
}

/// A machine-readable response validation issue.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ValidationIssue {
    /// Stable issue code.
    pub code: String,
    /// Owning claim or response field.
    pub subject: String,
    /// Human-readable repair guidance.
    pub message: String,
}

/// Usage and repair metadata from an enrichment run.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EnrichmentStats {
    /// Number of vendor CLI invocations.
    pub attempts: usize,
    /// Number of validation issues returned to the agent.
    pub repaired_issues: usize,
    /// Reported input token count when present in vendor output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Reported output token count when present in vendor output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// Host-computed bounds of the graph that produced the accepted response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture_scope: Option<ArchitectureScope>,
}
