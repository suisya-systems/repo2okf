//! Evidence validation and bounded repair orchestration.

use std::collections::{BTreeMap, BTreeSet};

use repo2okf_core::{
    ClaimProvenance, OutputLocale, Relationship, RelationshipOrigin, RepositoryIr,
    SemanticResolution,
};

use crate::excerpts::verified_excerpts;
use crate::{
    AcceptedConceptCandidate, AcceptedRelationshipCandidate, AgentDriver, AgentError,
    CandidateRelationshipKind, EnrichmentRequest, EnrichmentResponse, EnrichmentStats,
    ProcessConfig, SemanticGraphScope, SuppliedSemanticGraph, ValidationIssue,
};

const MAX_CLAIM_ID_CHARS: usize = 256;
const MAX_CLAIM_TEXT_CHARS: usize = 4096;
const MAX_SUMMARY_CHARS: usize = 8192;
const MAX_RESPONSE_CLAIMS: usize = 512;
const MAX_EVIDENCE_IDS_PER_CLAIM: usize = 32;
const MAX_SEMANTIC_ENTITIES: usize = 2_048;
const MAX_SEMANTIC_REFERENCES: usize = 4_096;
const MAX_SEMANTIC_RELATIONSHIPS: usize = 4_096;
const MAX_CONCEPT_CANDIDATES: usize = 64;
const MAX_RELATIONSHIP_CANDIDATES: usize = 128;
const MAX_MEMBERS_PER_CONCEPT: usize = 64;
const MAX_SUPPORT_EDGES: usize = 128;
const MAX_EVIDENCE_IDS_PER_CONCEPT: usize = 256;
const MAX_CANDIDATE_KEY_CHARS: usize = 128;
const MAX_CANDIDATE_TITLE_CHARS: usize = 256;
const MAX_CANDIDATE_RESPONSIBILITY_CHARS: usize = 4_096;
const MAX_SEMANTIC_ID_CHARS: usize = 512;

/// Bounds for the deterministic repair loop.
#[derive(Clone, Copy, Debug)]
pub struct RepairOptions {
    /// Maximum additional attempts after the first run.
    pub max_repair_attempts: usize,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            max_repair_attempts: 2,
        }
    }
}

/// Validate every agent claim against the deterministic IR evidence graph.
#[allow(
    clippy::too_many_lines,
    reason = "claim and summary checks remain together so repair diagnostics are audited as one contract"
)]
pub fn validate_response(ir: &RepositoryIr, response: &EnrichmentResponse) -> Vec<ValidationIssue> {
    let evidence_ids = ir.evidence_ids();
    let mut claim_ids = BTreeSet::new();
    let mut issues = Vec::new();
    if response.claims.len() > MAX_RESPONSE_CLAIMS {
        issues.push(issue(
            "too_many_claims",
            "claims",
            &format!("response must not contain more than {MAX_RESPONSE_CLAIMS} claims"),
        ));
    }
    for claim in &response.claims {
        if claim.id.trim().is_empty() {
            issues.push(issue(
                "empty_claim_id",
                "claims",
                "claim ID must not be empty",
            ));
        } else if !claim_ids.insert(claim.id.as_str()) {
            issues.push(issue(
                "duplicate_claim_id",
                &claim.id,
                "claim ID is duplicated",
            ));
        }
        validate_single_line(
            &claim.id,
            MAX_CLAIM_ID_CHARS,
            "invalid_claim_id_text",
            &claim.id,
            "claim ID",
            &mut issues,
        );
        if claim.text.trim().is_empty() {
            issues.push(issue(
                "empty_claim",
                &claim.id,
                "claim text must not be empty",
            ));
        }
        validate_single_line(
            &claim.text,
            MAX_CLAIM_TEXT_CHARS,
            "invalid_claim_text",
            &claim.id,
            "claim text",
            &mut issues,
        );
        if claim.evidence_ids.is_empty() {
            issues.push(issue(
                "missing_evidence",
                &claim.id,
                "claim must cite at least one supplied evidence ID",
            ));
        }
        if claim.evidence_ids.len() > MAX_EVIDENCE_IDS_PER_CLAIM {
            issues.push(issue(
                "too_many_claim_evidence_ids",
                &claim.id,
                &format!("claim must not cite more than {MAX_EVIDENCE_IDS_PER_CLAIM} evidence IDs"),
            ));
        }
        for evidence_id in &claim.evidence_ids {
            if !evidence_ids.contains(evidence_id.as_str()) {
                issues.push(issue(
                    "unknown_evidence",
                    &claim.id,
                    &format!("evidence ID {evidence_id} does not exist in the supplied IR"),
                ));
            }
        }
        if !matches!(claim.provenance, ClaimProvenance::Agent { .. }) {
            issues.push(issue(
                "invalid_provenance",
                &claim.id,
                "agent-generated claim provenance must use kind=agent",
            ));
        }
        if claim.confidence.is_some_and(|value| value > 100) {
            issues.push(issue(
                "invalid_confidence",
                &claim.id,
                "confidence must not exceed 100",
            ));
        }
    }

    if let Some(summary) = &response.repository_summary {
        if summary.trim().is_empty() {
            issues.push(issue(
                "empty_summary",
                "repository_summary",
                "repository summary must not be empty",
            ));
        }
        validate_single_line(
            summary,
            MAX_SUMMARY_CHARS,
            "invalid_summary_text",
            "repository_summary",
            "repository summary",
            &mut issues,
        );
    }
    if response.repository_summary.is_some() && response.summary_evidence_ids.is_empty() {
        issues.push(issue(
            "summary_missing_evidence",
            "repository_summary",
            "repository summary must cite at least one supplied evidence ID",
        ));
    }
    for evidence_id in &response.summary_evidence_ids {
        if !evidence_ids.contains(evidence_id.as_str()) {
            issues.push(issue(
                "summary_unknown_evidence",
                "repository_summary",
                &format!("evidence ID {evidence_id} does not exist in the supplied IR"),
            ));
        }
    }
    if response.summary_evidence_ids.len() > MAX_EVIDENCE_IDS_PER_CLAIM {
        issues.push(issue(
            "too_many_summary_evidence_ids",
            "repository_summary",
            &format!("summary must not cite more than {MAX_EVIDENCE_IDS_PER_CLAIM} evidence IDs"),
        ));
    }
    let complete_graph = complete_semantic_graph(ir);
    validate_architecture_candidates(response, &complete_graph, &evidence_ids, &mut issues);
    issues
}

fn validate_single_line(
    value: &str,
    maximum_chars: usize,
    code: &str,
    subject: &str,
    label: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if value
        .chars()
        .any(|character| character == '\n' || character == '\r' || character.is_control())
    {
        issues.push(issue(
            code,
            subject,
            &format!("{label} must not contain line breaks or control characters"),
        ));
    }
    if value.chars().count() > maximum_chars {
        issues.push(issue(
            code,
            subject,
            &format!("{label} must not exceed {maximum_chars} characters"),
        ));
    }
}

fn complete_semantic_graph(ir: &RepositoryIr) -> SuppliedSemanticGraph {
    let relationships = ir
        .relationships
        .iter()
        .filter(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { .. }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    SuppliedSemanticGraph {
        scope: SemanticGraphScope {
            total_evidence: ir.evidence.len(),
            supplied_evidence: ir.evidence.len(),
            total_coverage_items: ir.coverage.items.len(),
            supplied_coverage_items: ir.coverage.items.len(),
            total_entities: ir.entities.len(),
            supplied_entities: ir.entities.len(),
            total_references: ir.semantic_references.len(),
            supplied_references: ir.semantic_references.len(),
            total_relationships: relationships.len(),
            supplied_relationships: relationships.len(),
            complete: true,
        },
        entities: ir.entities.clone(),
        references: ir.semantic_references.clone(),
        relationships,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "graph closure, deterministic bounds and completeness accounting form one request contract"
)]
fn bounded_semantic_graph(
    ir: &RepositoryIr,
    supplied_evidence_ids: &BTreeSet<String>,
    excerpts_complete: bool,
    supplied_coverage_items: usize,
) -> SuppliedSemanticGraph {
    let mut entities = ir
        .entities
        .iter()
        .filter(|entity| supplied_evidence_ids.contains(&entity.evidence_id))
        .take(MAX_SEMANTIC_ENTITIES)
        .cloned()
        .collect::<Vec<_>>();
    loop {
        let entity_ids = entities
            .iter()
            .map(|entity| entity.id.clone())
            .collect::<BTreeSet<_>>();
        let previous_len = entities.len();
        entities.retain(|entity| {
            entity
                .owner_id
                .as_ref()
                .is_none_or(|owner_id| entity_ids.contains(owner_id))
        });
        if entities.len() == previous_len {
            break;
        }
    }
    let entity_ids = entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    let references = ir
        .semantic_references
        .iter()
        .filter(|reference| supplied_evidence_ids.contains(&reference.evidence_id))
        .filter(|reference| {
            entity_ids.contains(reference.scope_id.as_str())
                && reference
                    .source_entity_id
                    .as_deref()
                    .is_none_or(|id| entity_ids.contains(id))
        })
        .filter(|reference| match &reference.resolution {
            SemanticResolution::Resolved { target_entity_id } => {
                entity_ids.contains(target_entity_id.as_str())
            }
            SemanticResolution::Ambiguous {
                candidate_entity_ids,
                ..
            } => candidate_entity_ids
                .iter()
                .all(|id| entity_ids.contains(id.as_str())),
            SemanticResolution::External { .. } | SemanticResolution::Unresolved { .. } => true,
        })
        .take(MAX_SEMANTIC_REFERENCES)
        .cloned()
        .collect::<Vec<_>>();
    let reference_ids = references
        .iter()
        .map(|reference| reference.id.as_str())
        .collect::<BTreeSet<_>>();
    let total_relationships = ir
        .relationships
        .iter()
        .filter(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { .. }
            )
        })
        .count();
    let relationships = ir
        .relationships
        .iter()
        .filter(|relationship| {
            let RelationshipOrigin::SemanticReference { reference_id } = &relationship.origin
            else {
                return false;
            };
            reference_ids.contains(reference_id.as_str())
                && entity_ids.contains(relationship.source.as_str())
                && entity_ids.contains(relationship.target.as_str())
                && relationship
                    .evidence_ids
                    .iter()
                    .all(|id| supplied_evidence_ids.contains(id))
        })
        .take(MAX_SEMANTIC_RELATIONSHIPS)
        .cloned()
        .collect::<Vec<_>>();
    let complete = excerpts_complete
        && supplied_evidence_ids.len() == ir.evidence.len()
        && supplied_coverage_items == ir.coverage.items.len()
        && entities.len() == ir.entities.len()
        && references.len() == ir.semantic_references.len()
        && relationships.len() == total_relationships;
    SuppliedSemanticGraph {
        scope: SemanticGraphScope {
            total_evidence: ir.evidence.len(),
            supplied_evidence: supplied_evidence_ids.len(),
            total_coverage_items: ir.coverage.items.len(),
            supplied_coverage_items,
            total_entities: ir.entities.len(),
            supplied_entities: entities.len(),
            total_references: ir.semantic_references.len(),
            supplied_references: references.len(),
            total_relationships,
            supplied_relationships: relationships.len(),
            complete,
        },
        entities,
        references,
        relationships,
    }
}

#[derive(Clone, Copy)]
enum EdgeLookupError {
    Unknown,
    NotSemantic,
    External,
    Ambiguous,
    Unresolved,
    MissingRelationship,
}

struct SemanticGraphIndex<'a> {
    entity_ids: BTreeSet<&'a str>,
    entities: BTreeMap<&'a str, &'a repo2okf_core::Entity>,
    references: BTreeMap<&'a str, &'a repo2okf_core::SemanticReference>,
    relationships: BTreeMap<&'a str, &'a Relationship>,
    relationships_by_reference: BTreeMap<&'a str, &'a Relationship>,
}

impl<'a> SemanticGraphIndex<'a> {
    fn new(graph: &'a SuppliedSemanticGraph) -> Self {
        let entities = graph
            .entities
            .iter()
            .map(|entity| (entity.id.as_str(), entity))
            .collect::<BTreeMap<_, _>>();
        let entity_ids = entities.keys().copied().collect();
        let references = graph
            .references
            .iter()
            .map(|reference| (reference.id.as_str(), reference))
            .collect();
        let relationships = graph
            .relationships
            .iter()
            .map(|relationship| (relationship.id.as_str(), relationship))
            .collect();
        let relationships_by_reference = graph
            .relationships
            .iter()
            .filter_map(|relationship| {
                let RelationshipOrigin::SemanticReference { reference_id } = &relationship.origin
                else {
                    return None;
                };
                Some((reference_id.as_str(), relationship))
            })
            .collect();
        Self {
            entity_ids,
            entities,
            references,
            relationships,
            relationships_by_reference,
        }
    }

    fn edge(&self, id: &str) -> Result<&'a Relationship, EdgeLookupError> {
        if let Some(relationship) = self.relationships.get(id) {
            return if matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { .. }
            ) {
                Ok(*relationship)
            } else {
                Err(EdgeLookupError::NotSemantic)
            };
        }
        let Some(reference) = self.references.get(id) else {
            return Err(EdgeLookupError::Unknown);
        };
        match &reference.resolution {
            SemanticResolution::Resolved { .. } => self
                .relationships_by_reference
                .get(id)
                .copied()
                .ok_or(EdgeLookupError::MissingRelationship),
            SemanticResolution::External { .. } => Err(EdgeLookupError::External),
            SemanticResolution::Ambiguous { .. } => Err(EdgeLookupError::Ambiguous),
            SemanticResolution::Unresolved { .. } => Err(EdgeLookupError::Unresolved),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate membership, cohesion, evidence and directed-edge checks are one atomic validation contract"
)]
fn validate_architecture_candidates(
    response: &EnrichmentResponse,
    graph: &SuppliedSemanticGraph,
    known_evidence_ids: &BTreeSet<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    let index = SemanticGraphIndex::new(graph);
    if response.concept_candidates.len() > MAX_CONCEPT_CANDIDATES {
        issues.push(issue(
            "too_many_concept_candidates",
            "concept_candidates",
            &format!("response must not contain more than {MAX_CONCEPT_CANDIDATES} concepts"),
        ));
    }
    if response.relationship_candidates.len() > MAX_RELATIONSHIP_CANDIDATES {
        issues.push(issue(
            "too_many_relationship_candidates",
            "relationship_candidates",
            &format!(
                "response must not contain more than {MAX_RELATIONSHIP_CANDIDATES} relationships"
            ),
        ));
    }

    let mut candidate_keys = BTreeSet::new();
    let mut candidate_members = BTreeMap::<&str, BTreeSet<&str>>::new();
    let mut assigned_members = BTreeMap::<&str, &str>::new();
    for candidate in &response.concept_candidates {
        let subject = candidate.candidate_key.as_str();
        validate_single_line(
            subject,
            MAX_CANDIDATE_KEY_CHARS,
            "invalid_candidate_key",
            subject,
            "candidate key",
            issues,
        );
        validate_single_line(
            &candidate.title,
            MAX_CANDIDATE_TITLE_CHARS,
            "invalid_candidate_title",
            subject,
            "candidate title",
            issues,
        );
        validate_single_line(
            &candidate.responsibility,
            MAX_CANDIDATE_RESPONSIBILITY_CHARS,
            "invalid_candidate_responsibility",
            subject,
            "candidate responsibility",
            issues,
        );
        if subject.trim().is_empty() {
            issues.push(issue(
                "empty_candidate_key",
                "concept_candidates",
                "candidate key must not be empty",
            ));
        } else if !candidate_keys.insert(subject) {
            issues.push(issue(
                "duplicate_candidate_key",
                subject,
                "candidate key is duplicated",
            ));
        }
        if candidate.title.trim().is_empty() || candidate.responsibility.trim().is_empty() {
            issues.push(issue(
                "empty_candidate_text",
                subject,
                "candidate title and responsibility must not be empty",
            ));
        }
        if candidate.member_entity_ids.len() < 2 {
            issues.push(issue(
                "too_few_concept_members",
                subject,
                "architecture concepts must contain at least two semantic entities",
            ));
        }
        if candidate.member_entity_ids.len() > MAX_MEMBERS_PER_CONCEPT {
            issues.push(issue(
                "too_many_concept_members",
                subject,
                &format!("a concept must not contain more than {MAX_MEMBERS_PER_CONCEPT} members"),
            ));
        }
        let mut members = BTreeSet::new();
        for member_id in &candidate.member_entity_ids {
            validate_single_line(
                member_id,
                MAX_SEMANTIC_ID_CHARS,
                "invalid_semantic_id",
                subject,
                "member entity ID",
                issues,
            );
            if !members.insert(member_id.as_str()) {
                issues.push(issue(
                    "duplicate_concept_member",
                    subject,
                    &format!("member entity {member_id} is duplicated"),
                ));
            }
            if !index.entity_ids.contains(member_id.as_str()) {
                issues.push(issue(
                    "unknown_concept_member",
                    subject,
                    &format!("member entity {member_id} does not exist in the deterministic IR"),
                ));
            }
            if let Some(owner) = assigned_members.insert(member_id.as_str(), subject) {
                issues.push(issue(
                    "overlapping_concept_member",
                    subject,
                    &format!("member entity {member_id} is already assigned to {owner}"),
                ));
            }
        }
        let required_member_evidence_ids = members
            .iter()
            .filter_map(|member_id| index.entities.get(member_id).copied())
            .map(|entity| entity.evidence_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut related_evidence_ids = required_member_evidence_ids.clone();
        let mut required_support_evidence_ids = BTreeSet::new();
        if candidate.supporting_edge_ids.is_empty() {
            issues.push(issue(
                "missing_concept_support",
                subject,
                "a concept must cite resolved semantic edges connecting its members",
            ));
        }
        if candidate.supporting_edge_ids.len() > MAX_SUPPORT_EDGES {
            issues.push(issue(
                "too_many_support_edges",
                subject,
                &format!("a candidate must not cite more than {MAX_SUPPORT_EDGES} edges"),
            ));
        }
        let mut support_ids = BTreeSet::new();
        let mut adjacency = BTreeMap::<&str, BTreeSet<&str>>::new();
        for edge_id in &candidate.supporting_edge_ids {
            validate_single_line(
                edge_id,
                MAX_SEMANTIC_ID_CHARS,
                "invalid_semantic_id",
                subject,
                "supporting edge ID",
                issues,
            );
            if !support_ids.insert(edge_id.as_str()) {
                issues.push(issue(
                    "duplicate_support_edge",
                    subject,
                    &format!("supporting edge {edge_id} is duplicated"),
                ));
            }
            match index.edge(edge_id) {
                Ok(edge)
                    if members.contains(edge.source.as_str())
                        && members.contains(edge.target.as_str()) =>
                {
                    required_support_evidence_ids
                        .extend(edge.evidence_ids.iter().map(String::as_str));
                    related_evidence_ids.extend(edge.evidence_ids.iter().map(String::as_str));
                    adjacency
                        .entry(edge.source.as_str())
                        .or_default()
                        .insert(edge.target.as_str());
                    adjacency
                        .entry(edge.target.as_str())
                        .or_default()
                        .insert(edge.source.as_str());
                }
                Ok(_) => issues.push(issue(
                    "semantic_edge_unrelated",
                    subject,
                    &format!("edge {edge_id} does not connect two members of this concept"),
                )),
                Err(error) => push_edge_lookup_issue(error, edge_id, subject, issues),
            }
        }
        if candidate.evidence_ids.is_empty() {
            issues.push(issue(
                "missing_concept_evidence",
                subject,
                "an architecture concept must cite supplied evidence",
            ));
        }
        if candidate.evidence_ids.len() > MAX_EVIDENCE_IDS_PER_CONCEPT {
            issues.push(issue(
                "too_many_concept_evidence_ids",
                subject,
                &format!(
                    "a concept must not cite more than {MAX_EVIDENCE_IDS_PER_CONCEPT} evidence IDs"
                ),
            ));
        }
        let mut cited_evidence_ids = BTreeSet::new();
        for evidence_id in &candidate.evidence_ids {
            validate_single_line(
                evidence_id,
                MAX_SEMANTIC_ID_CHARS,
                "invalid_semantic_id",
                subject,
                "evidence ID",
                issues,
            );
            if !cited_evidence_ids.insert(evidence_id.as_str()) {
                issues.push(issue(
                    "duplicate_concept_evidence",
                    subject,
                    &format!("evidence ID {evidence_id} is duplicated"),
                ));
            }
            if !known_evidence_ids.contains(evidence_id.as_str()) {
                issues.push(issue(
                    "unknown_concept_evidence",
                    subject,
                    &format!("evidence ID {evidence_id} does not exist in the deterministic IR"),
                ));
            } else if !related_evidence_ids.contains(evidence_id.as_str()) {
                issues.push(issue(
                    "concept_evidence_unrelated",
                    subject,
                    &format!(
                        "evidence ID {evidence_id} is unrelated to the candidate members and support edges"
                    ),
                ));
            }
        }
        for evidence_id in required_support_evidence_ids.difference(&cited_evidence_ids) {
            issues.push(issue(
                "missing_support_edge_evidence",
                subject,
                &format!("candidate omits support-edge evidence ID {evidence_id}"),
            ));
        }
        for evidence_id in required_member_evidence_ids.difference(&cited_evidence_ids) {
            issues.push(issue(
                "missing_member_evidence",
                subject,
                &format!("candidate omits member declaration evidence ID {evidence_id}"),
            ));
        }
        if members.len() >= 2 && !is_connected(&members, &adjacency) {
            issues.push(issue(
                "concept_not_cohesive",
                subject,
                "supporting resolved edges do not connect every concept member",
            ));
        }
        candidate_members.entry(subject).or_insert(members);
    }

    let mut relationship_keys = BTreeSet::new();
    for candidate in &response.relationship_candidates {
        let subject = format!(
            "{}->{:?}->{}",
            candidate.source_candidate_key, candidate.kind, candidate.target_candidate_key
        );
        validate_single_line(
            &candidate.source_candidate_key,
            MAX_CANDIDATE_KEY_CHARS,
            "invalid_candidate_key",
            &subject,
            "source candidate key",
            issues,
        );
        validate_single_line(
            &candidate.target_candidate_key,
            MAX_CANDIDATE_KEY_CHARS,
            "invalid_candidate_key",
            &subject,
            "target candidate key",
            issues,
        );
        if candidate.source_candidate_key == candidate.target_candidate_key {
            issues.push(issue(
                "self_architecture_relationship",
                &subject,
                "an architecture relationship must connect two different concepts",
            ));
        }
        if !relationship_keys.insert((
            candidate.source_candidate_key.as_str(),
            candidate.target_candidate_key.as_str(),
        )) {
            issues.push(issue(
                "duplicate_architecture_relationship",
                &subject,
                "the architecture relationship is duplicated",
            ));
        }
        let source_members = candidate_members.get(candidate.source_candidate_key.as_str());
        let target_members = candidate_members.get(candidate.target_candidate_key.as_str());
        if source_members.is_none() {
            issues.push(issue(
                "unknown_source_candidate",
                &subject,
                "source candidate key does not exist in this response",
            ));
        }
        if target_members.is_none() {
            issues.push(issue(
                "unknown_target_candidate",
                &subject,
                "target candidate key does not exist in this response",
            ));
        }
        if candidate.supporting_edge_ids.is_empty() {
            issues.push(issue(
                "missing_relationship_support",
                &subject,
                "a depends_on relationship must cite at least one resolved semantic edge",
            ));
        }
        if candidate.supporting_edge_ids.len() > MAX_SUPPORT_EDGES {
            issues.push(issue(
                "too_many_support_edges",
                &subject,
                &format!("a candidate must not cite more than {MAX_SUPPORT_EDGES} edges"),
            ));
        }
        let mut support_ids = BTreeSet::new();
        for edge_id in &candidate.supporting_edge_ids {
            validate_single_line(
                edge_id,
                MAX_SEMANTIC_ID_CHARS,
                "invalid_semantic_id",
                &subject,
                "supporting edge ID",
                issues,
            );
            if !support_ids.insert(edge_id.as_str()) {
                issues.push(issue(
                    "duplicate_support_edge",
                    &subject,
                    &format!("supporting edge {edge_id} is duplicated"),
                ));
            }
            let edge = match index.edge(edge_id) {
                Ok(edge) => edge,
                Err(error) => {
                    push_edge_lookup_issue(error, edge_id, &subject, issues);
                    continue;
                }
            };
            let (Some(source_members), Some(target_members)) = (source_members, target_members)
            else {
                continue;
            };
            if source_members.contains(edge.source.as_str())
                && target_members.contains(edge.target.as_str())
            {
                continue;
            }
            if target_members.contains(edge.source.as_str())
                && source_members.contains(edge.target.as_str())
            {
                issues.push(issue(
                    "semantic_edge_reversed",
                    &subject,
                    &format!("edge {edge_id} proves the reverse dependency direction"),
                ));
            } else {
                issues.push(issue(
                    "semantic_edge_unrelated",
                    &subject,
                    &format!("edge {edge_id} does not connect the proposed concepts"),
                ));
            }
        }
    }
}

fn push_edge_lookup_issue(
    error: EdgeLookupError,
    edge_id: &str,
    subject: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    let (code, message) = match error {
        EdgeLookupError::Unknown => (
            "unknown_semantic_edge",
            format!("semantic edge or reference {edge_id} does not exist"),
        ),
        EdgeLookupError::NotSemantic => (
            "semantic_edge_not_resolved",
            format!("relationship {edge_id} is observed syntax, not a resolved semantic edge"),
        ),
        EdgeLookupError::External => (
            "semantic_edge_external",
            format!("reference {edge_id} resolves outside the repository"),
        ),
        EdgeLookupError::Ambiguous => (
            "semantic_edge_ambiguous",
            format!("reference {edge_id} has more than one possible target"),
        ),
        EdgeLookupError::Unresolved => (
            "semantic_edge_unresolved",
            format!("reference {edge_id} has no mechanically established target"),
        ),
        EdgeLookupError::MissingRelationship => (
            "semantic_edge_missing_relationship",
            format!("resolved reference {edge_id} has no corresponding semantic relationship"),
        ),
    };
    issues.push(issue(code, subject, &message));
}

fn is_connected(members: &BTreeSet<&str>, adjacency: &BTreeMap<&str, BTreeSet<&str>>) -> bool {
    let Some(first) = members.first().copied() else {
        return true;
    };
    let mut seen = BTreeSet::from([first]);
    let mut pending = vec![first];
    while let Some(current) = pending.pop() {
        if let Some(neighbors) = adjacency.get(current) {
            for neighbor in neighbors {
                if seen.insert(*neighbor) {
                    pending.push(neighbor);
                }
            }
        }
    }
    seen.len() == members.len()
}

/// Run the vendor driver and return only after evidence validation succeeds.
///
/// # Errors
///
/// Returns an error when the vendor process fails or when every bounded repair
/// attempt still contains invalid or ungrounded claims.
#[allow(
    clippy::too_many_lines,
    reason = "bounded request construction and repair attempts share one auditable orchestration path"
)]
pub fn enrich_with_repair(
    driver: &dyn AgentDriver,
    ir: &RepositoryIr,
    config: &ProcessConfig,
    output_locale: OutputLocale,
    options: RepairOptions,
) -> Result<(EnrichmentResponse, EnrichmentStats), AgentError> {
    let mut request = EnrichmentRequest {
        evidence: Vec::new(),
        evidence_excerpts: verified_excerpts(&config.repository, &ir.evidence),
        repository: ir.repository.name.clone(),
        ir_fingerprint: ir.fingerprint.clone(),
        output_locale,
        coverage: Vec::new(),
        semantic_graph: SuppliedSemanticGraph::default(),
        existing_agent_claims: Vec::new(),
        existing_architecture_concepts: Vec::new(),
        existing_architecture_relationships: Vec::new(),
        repair_issues: vec![],
    };
    let supplied_evidence_ids = request
        .evidence_excerpts
        .iter()
        .map(|excerpt| excerpt.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    request.evidence = ir
        .evidence
        .iter()
        .filter(|evidence| supplied_evidence_ids.contains(&evidence.id))
        .cloned()
        .collect();
    request.coverage = ir
        .coverage
        .items
        .iter()
        .filter(|item| {
            item.evidence_ids
                .iter()
                .any(|id| supplied_evidence_ids.contains(id))
        })
        .take(1024)
        .cloned()
        .collect();
    let excerpts_complete = request
        .evidence_excerpts
        .iter()
        .all(|excerpt| !excerpt.truncated);
    request.semantic_graph = bounded_semantic_graph(
        ir,
        &supplied_evidence_ids,
        excerpts_complete,
        request.coverage.len(),
    );
    request.existing_agent_claims = ir
        .claims
        .iter()
        .filter(|claim| matches!(claim.provenance, ClaimProvenance::Agent { .. }))
        .filter(|claim| {
            claim
                .evidence_ids
                .iter()
                .all(|id| supplied_evidence_ids.contains(id))
        })
        .take(MAX_RESPONSE_CLAIMS)
        .cloned()
        .collect();
    let supplied_entity_ids = request
        .semantic_graph
        .entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    let supplied_relationship_ids = request
        .semantic_graph
        .relationships
        .iter()
        .map(|relationship| relationship.id.as_str())
        .collect::<BTreeSet<_>>();
    request.existing_architecture_concepts = ir
        .architecture_concepts
        .iter()
        .filter(|concept| {
            concept
                .member_entity_ids
                .iter()
                .all(|id| supplied_entity_ids.contains(id.as_str()))
                && concept
                    .supporting_relationship_ids
                    .iter()
                    .all(|id| supplied_relationship_ids.contains(id.as_str()))
        })
        .take(MAX_CONCEPT_CANDIDATES)
        .cloned()
        .collect();
    let supplied_concept_ids = request
        .existing_architecture_concepts
        .iter()
        .map(|concept| concept.id.as_str())
        .collect::<BTreeSet<_>>();
    request.existing_architecture_relationships = ir
        .architecture_relationships
        .iter()
        .filter(|relationship| {
            supplied_concept_ids.contains(relationship.source_concept_id.as_str())
                && supplied_concept_ids.contains(relationship.target_concept_id.as_str())
                && relationship
                    .supporting_relationship_ids
                    .iter()
                    .all(|id| supplied_relationship_ids.contains(id.as_str()))
        })
        .take(MAX_RELATIONSHIP_CANDIDATES)
        .cloned()
        .collect();
    let maximum_attempts = options.max_repair_attempts.saturating_add(1).min(6);
    let mut repaired_issues = 0;
    for attempt in 1..=maximum_attempts {
        let mut response = driver.run(&request, config)?;
        stamp_agent_provenance(driver, &mut response);
        let mut issues = validate_response(ir, &response);
        validate_supplied_evidence(&response, &supplied_evidence_ids, &mut issues);
        validate_supplied_semantics(&request, &response, &mut issues);
        if issues.is_empty() {
            materialize_architecture(&request, &mut response);
            return Ok((
                response,
                EnrichmentStats {
                    attempts: attempt,
                    repaired_issues,
                    architecture_scope: Some(request.semantic_graph.scope.architecture_scope()),
                    ..EnrichmentStats::default()
                },
            ));
        }
        repaired_issues += issues.len();
        if attempt == maximum_attempts {
            return Err(AgentError::InvalidClaims {
                attempts: attempt,
                issues,
            });
        }
        request.repair_issues = issues;
    }
    unreachable!("maximum_attempts is always at least one")
}

fn validate_supplied_evidence(
    response: &EnrichmentResponse,
    supplied: &BTreeSet<String>,
    issues: &mut Vec<ValidationIssue>,
) {
    for claim in &response.claims {
        for evidence_id in &claim.evidence_ids {
            if !supplied.contains(evidence_id) {
                issues.push(issue(
                    "evidence_not_supplied",
                    &claim.id,
                    &format!(
                        "evidence ID {evidence_id} was not included in the bounded agent request"
                    ),
                ));
            }
        }
    }
    for evidence_id in &response.summary_evidence_ids {
        if !supplied.contains(evidence_id) {
            issues.push(issue(
                "summary_evidence_not_supplied",
                "repository_summary",
                &format!("evidence ID {evidence_id} was not included in the bounded agent request"),
            ));
        }
    }
    for candidate in &response.concept_candidates {
        for evidence_id in &candidate.evidence_ids {
            if !supplied.contains(evidence_id) {
                issues.push(issue(
                    "concept_evidence_not_supplied",
                    &candidate.candidate_key,
                    &format!(
                        "evidence ID {evidence_id} was not included in the bounded agent request"
                    ),
                ));
            }
        }
    }
}

fn validate_supplied_semantics(
    request: &EnrichmentRequest,
    response: &EnrichmentResponse,
    issues: &mut Vec<ValidationIssue>,
) {
    let graph = &request.semantic_graph;
    let entity_ids = graph
        .entities
        .iter()
        .map(|entity| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    let reference_ids = graph
        .references
        .iter()
        .map(|reference| reference.id.as_str())
        .collect::<BTreeSet<_>>();
    let relationship_ids = graph
        .relationships
        .iter()
        .map(|relationship| relationship.id.as_str())
        .collect::<BTreeSet<_>>();
    let resolved_reference_ids = graph
        .relationships
        .iter()
        .filter_map(|relationship| {
            let RelationshipOrigin::SemanticReference { reference_id } = &relationship.origin
            else {
                return None;
            };
            Some(reference_id.as_str())
        })
        .collect::<BTreeSet<_>>();

    if response.repository_summary.is_some() && !graph.scope.complete {
        issues.push(issue(
            "incomplete_scope_summary",
            "repository_summary",
            "repository summary is forbidden because the bounded semantic/evidence scope is incomplete",
        ));
    }
    for candidate in &response.concept_candidates {
        for member_id in &candidate.member_entity_ids {
            if !entity_ids.contains(member_id.as_str()) {
                issues.push(issue(
                    "semantic_entity_not_supplied",
                    &candidate.candidate_key,
                    &format!("entity {member_id} was not included in the bounded agent request"),
                ));
            }
        }
        for edge_id in &candidate.supporting_edge_ids {
            if !(relationship_ids.contains(edge_id.as_str())
                || reference_ids.contains(edge_id.as_str())
                    && resolved_reference_ids.contains(edge_id.as_str()))
            {
                issues.push(issue(
                    "semantic_edge_not_supplied",
                    &candidate.candidate_key,
                    &format!(
                        "edge {edge_id} was not included as a resolved edge in the bounded request"
                    ),
                ));
            }
        }
    }
    for candidate in &response.relationship_candidates {
        let subject = format!(
            "{}->{:?}->{}",
            candidate.source_candidate_key, candidate.kind, candidate.target_candidate_key
        );
        for edge_id in &candidate.supporting_edge_ids {
            if !(relationship_ids.contains(edge_id.as_str())
                || reference_ids.contains(edge_id.as_str())
                    && resolved_reference_ids.contains(edge_id.as_str()))
            {
                issues.push(issue(
                    "semantic_edge_not_supplied",
                    &subject,
                    &format!(
                        "edge {edge_id} was not included as a resolved edge in the bounded request"
                    ),
                ));
            }
        }
    }
}

fn materialize_architecture(request: &EnrichmentRequest, response: &mut EnrichmentResponse) {
    response.accepted_concepts.clear();
    response.accepted_relationships.clear();
    let index = SemanticGraphIndex::new(&request.semantic_graph);
    let mut accepted_concepts = Vec::with_capacity(response.concept_candidates.len());
    let mut candidate_ids = BTreeMap::new();
    for candidate in &response.concept_candidates {
        let mut members = candidate.member_entity_ids.clone();
        members.sort();
        members.dedup();
        let mut relationships = candidate
            .supporting_edge_ids
            .iter()
            .filter_map(|id| index.edge(id).ok())
            .map(|relationship| relationship.id.clone())
            .collect::<Vec<_>>();
        relationships.sort();
        relationships.dedup();
        let mut evidence_ids = candidate.evidence_ids.clone();
        evidence_ids.sort();
        evidence_ids.dedup();
        let id = concept_id(
            &candidate.title,
            &candidate.responsibility,
            &members,
            &relationships,
        );
        candidate_ids.insert(candidate.candidate_key.as_str(), id.clone());
        accepted_concepts.push(AcceptedConceptCandidate {
            id,
            title: candidate.title.trim().to_owned(),
            responsibility: candidate.responsibility.trim().to_owned(),
            member_entity_ids: members,
            supporting_edge_ids: relationships,
            evidence_ids,
        });
    }
    let mut accepted_relationships = Vec::with_capacity(response.relationship_candidates.len());
    for candidate in &response.relationship_candidates {
        let (Some(source_concept_id), Some(target_concept_id)) = (
            candidate_ids.get(candidate.source_candidate_key.as_str()),
            candidate_ids.get(candidate.target_candidate_key.as_str()),
        ) else {
            continue;
        };
        let mut relationships = candidate
            .supporting_edge_ids
            .iter()
            .filter_map(|id| index.edge(id).ok())
            .map(|relationship| relationship.id.clone())
            .collect::<Vec<_>>();
        relationships.sort();
        relationships.dedup();
        let evidence_ids = relationships
            .iter()
            .filter_map(|id| index.relationships.get(id.as_str()))
            .flat_map(|relationship| relationship.evidence_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        accepted_relationships.push(AcceptedRelationshipCandidate {
            id: relationship_id(
                source_concept_id,
                target_concept_id,
                candidate.kind,
                &relationships,
            ),
            source_concept_id: source_concept_id.clone(),
            target_concept_id: target_concept_id.clone(),
            kind: candidate.kind,
            supporting_edge_ids: relationships,
            evidence_ids,
        });
    }
    accepted_concepts.sort_by(|left, right| left.id.cmp(&right.id));
    accepted_relationships.sort_by(|left, right| left.id.cmp(&right.id));
    response.accepted_concepts = accepted_concepts;
    response.accepted_relationships = accepted_relationships;
}

fn concept_id(
    title: &str,
    responsibility: &str,
    members: &[String],
    relationships: &[String],
) -> String {
    let mut fields = vec![title.trim(), responsibility.trim()];
    fields.extend(members.iter().map(String::as_str));
    fields.extend(relationships.iter().map(String::as_str));
    host_id("architecture:concept", &fields)
}

fn relationship_id(
    source: &str,
    target: &str,
    kind: CandidateRelationshipKind,
    relationships: &[String],
) -> String {
    let kind = match kind {
        CandidateRelationshipKind::DependsOn => "depends_on",
    };
    let mut fields = vec![source, target, kind];
    fields.extend(relationships.iter().map(String::as_str));
    host_id("architecture:relationship", &fields)
}

fn host_id(prefix: &str, fields: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for field in fields {
        hasher.update(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{prefix}:{}", hasher.finalize().to_hex())
}

fn stamp_agent_provenance(driver: &dyn AgentDriver, response: &mut EnrichmentResponse) {
    let provider = driver.kind().command_name().to_owned();
    for claim in &mut response.claims {
        claim.provenance = ClaimProvenance::Agent {
            provider: provider.clone(),
            // The response schema is model-authored; without vendor event
            // metadata, any model name here would be self-asserted.
            model: None,
        };
    }

    if let Some(summary) = response.repository_summary.as_deref().map(str::trim)
        && !summary.is_empty()
        && !response.summary_evidence_ids.is_empty()
        && !response
            .claims
            .iter()
            .any(|claim| claim.id == "claim:agent:repository-summary")
    {
        response.claims.push(repo2okf_core::Claim {
            id: "claim:agent:repository-summary".into(),
            text: summary.to_owned(),
            fact: None,
            evidence_ids: response.summary_evidence_ids.clone(),
            provenance: ClaimProvenance::Agent {
                provider,
                model: None,
            },
            confidence: None,
        });
    }
}

fn issue(code: &str, subject: &str, message: &str) -> ValidationIssue {
    ValidationIssue {
        code: code.into(),
        subject: subject.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use repo2okf_core::{
        Claim, ClaimProvenance, OutputLocale, RelationshipKind, RelationshipOrigin, ScanOptions,
        SemanticReferenceKind, SemanticResolution, scan_repository,
    };

    use crate::{
        AgentCapabilities, AgentDriver, AgentKind, AgentProbe, CandidateRelationshipKind,
        ConceptCandidate, EnrichmentRequest, EnrichmentResponse, ProcessConfig,
        RelationshipCandidate, SuppliedSemanticGraph, ValidationIssue, validate_response,
    };

    use super::{
        RepairOptions, bounded_semantic_graph, enrich_with_repair, materialize_architecture,
        validate_architecture_candidates, validate_supplied_evidence, validate_supplied_semantics,
    };

    #[test]
    fn rejects_fabricated_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("README.md"), "# Project\n").expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let response = EnrichmentResponse {
            claims: vec![Claim {
                id: "claim:agent".into(),
                text: "Fabricated claim".into(),
                fact: None,
                evidence_ids: vec!["evidence:not-real".into()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: Some(50),
            }],
            repository_summary: None,
            summary_evidence_ids: vec![],
            ..EnrichmentResponse::default()
        };
        let issues = validate_response(&ir, &response);
        assert!(issues.iter().any(|issue| issue.code == "unknown_evidence"));
    }

    #[test]
    fn rejects_multiline_control_and_oversized_agent_text_before_emission() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("README.md"), "# Project\n").expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let evidence_id = ir.evidence[0].id.clone();
        let response = EnrichmentResponse {
            claims: vec![Claim {
                id: "claim:\u{7}bad".into(),
                text: format!("first line\n{}", "x".repeat(4097)),
                fact: None,
                evidence_ids: vec![evidence_id.clone()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: Some(50),
            }],
            repository_summary: Some("unsafe\rsummary".into()),
            summary_evidence_ids: vec![evidence_id],
            ..EnrichmentResponse::default()
        };
        let issues = validate_response(&ir, &response);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "invalid_claim_id_text")
        );
        assert!(
            issues
                .iter()
                .filter(|issue| issue.code == "invalid_claim_text")
                .count()
                >= 2
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "invalid_summary_text")
        );
    }

    #[test]
    fn rejects_valid_ir_evidence_that_was_not_supplied_to_the_agent() {
        let response = EnrichmentResponse {
            claims: vec![Claim {
                id: "claim:agent".into(),
                text: "Unsupported because its excerpt was omitted".into(),
                fact: None,
                evidence_ids: vec!["ev:omitted".into()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: None,
            }],
            repository_summary: None,
            summary_evidence_ids: vec![],
            ..EnrichmentResponse::default()
        };
        let mut issues = Vec::<ValidationIssue>::new();
        validate_supplied_evidence(&response, &BTreeSet::new(), &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "evidence_not_supplied")
        );
    }

    #[test]
    fn accepts_cohesive_candidates_and_derives_stable_ids_and_evidence() {
        let graph = semantic_graph_fixture();
        let request = request_for_graph(graph.clone());
        let mut response = candidate_response(
            vec![ConceptCandidate {
                candidate_key: "service".into(),
                title: "Service".into(),
                responsibility: "Coordinates entry and worker behavior".into(),
                member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
                supporting_edge_ids: vec!["reference:call".into()],
                evidence_ids: vec!["ev:worker".into(), "ev:entry".into()],
            }],
            vec![],
        );
        let mut issues = Vec::new();
        validate_architecture_candidates(
            &response,
            &graph,
            &graph_evidence_ids(&graph),
            &mut issues,
        );
        validate_supplied_semantics(&request, &response, &mut issues);
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");

        materialize_architecture(&request, &mut response);
        assert_eq!(response.accepted_concepts.len(), 1);
        assert_eq!(
            response.accepted_concepts[0].supporting_edge_ids,
            ["relationship:call"]
        );
        assert!(
            response.accepted_concepts[0]
                .id
                .starts_with("architecture:concept:")
        );
        assert_eq!(
            response.accepted_concepts[0].evidence_ids,
            ["ev:entry", "ev:worker"]
        );
        let (concepts, relationships) = response.accepted_architecture(crate::AgentKind::Claude);
        assert!(relationships.is_empty());
        assert!(matches!(
            concepts[0].status,
            repo2okf_core::ArchitectureStatus::Draft
        ));
        assert!(matches!(
            &concepts[0].provenance,
            ClaimProvenance::Agent { provider, model: None } if provider == "claude"
        ));
        let stable_id = response.accepted_concepts[0].id.clone();
        let mut reordered_evidence = response.concept_candidates.clone();
        reordered_evidence[0].evidence_ids.reverse();
        let mut changed_request = request.clone();
        changed_request.ir_fingerprint = "unrelated-ir-change".into();
        let mut repeated = candidate_response(reordered_evidence, vec![]);
        materialize_architecture(&changed_request, &mut repeated);
        assert_eq!(repeated.accepted_concepts[0].id, stable_id);
        assert_eq!(
            repeated.accepted_concepts[0].evidence_ids,
            ["ev:entry", "ev:worker"]
        );
    }

    #[test]
    fn rejects_missing_duplicate_unknown_unrelated_or_incomplete_concept_evidence() {
        let mut graph = semantic_graph_fixture();
        graph
            .relationships
            .iter_mut()
            .find(|relationship| relationship.id == "relationship:call")
            .unwrap()
            .evidence_ids = vec!["ev:support".into()];
        let known_evidence_ids = graph_evidence_ids(&graph);
        let candidate = ConceptCandidate {
            candidate_key: "service".into(),
            title: "Service".into(),
            responsibility: "Coordinates entry and worker behavior".into(),
            member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
            supporting_edge_ids: vec!["reference:call".into()],
            evidence_ids: vec!["ev:entry".into(), "ev:support".into(), "ev:worker".into()],
        };
        let validate = |candidate: ConceptCandidate| {
            let response = candidate_response(vec![candidate], vec![]);
            let mut issues = Vec::new();
            validate_architecture_candidates(&response, &graph, &known_evidence_ids, &mut issues);
            issues
                .into_iter()
                .map(|issue| issue.code)
                .collect::<BTreeSet<_>>()
        };

        let mut missing = candidate.clone();
        missing.evidence_ids.clear();
        let codes = validate(missing);
        assert!(codes.contains("missing_concept_evidence"));
        assert!(codes.contains("missing_member_evidence"));
        assert!(codes.contains("missing_support_edge_evidence"));

        let mut duplicate = candidate.clone();
        duplicate.evidence_ids.push("ev:entry".into());
        assert!(validate(duplicate).contains("duplicate_concept_evidence"));

        let mut unknown = candidate.clone();
        unknown.evidence_ids.push("ev:not-real".into());
        assert!(validate(unknown).contains("unknown_concept_evidence"));

        let mut unrelated = candidate.clone();
        unrelated.evidence_ids.push("ev:other".into());
        assert!(validate(unrelated).contains("concept_evidence_unrelated"));

        let mut omits_support = candidate.clone();
        omits_support.evidence_ids = vec!["ev:entry".into(), "ev:worker".into()];
        assert!(validate(omits_support).contains("missing_support_edge_evidence"));

        let mut omits_member = candidate.clone();
        omits_member.evidence_ids = vec!["ev:entry".into(), "ev:support".into()];
        assert!(validate(omits_member).contains("missing_member_evidence"));

        let mut oversized = candidate;
        oversized.evidence_ids = vec!["ev:entry".into(); super::MAX_EVIDENCE_IDS_PER_CONCEPT + 1];
        assert!(validate(oversized).contains("too_many_concept_evidence_ids"));
    }

    #[test]
    fn rejects_concept_evidence_omitted_from_the_bounded_request() {
        let response = candidate_response(
            vec![ConceptCandidate {
                candidate_key: "service".into(),
                title: "Service".into(),
                responsibility: "Coordinates entry and worker behavior".into(),
                member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
                supporting_edge_ids: vec!["reference:call".into()],
                evidence_ids: vec!["ev:entry".into(), "ev:worker".into()],
            }],
            vec![],
        );
        let mut issues = Vec::new();
        validate_supplied_evidence(&response, &BTreeSet::new(), &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "concept_evidence_not_supplied")
        );
    }

    #[test]
    fn rejects_ambiguous_unresolved_unrelated_and_overlapping_candidates_atomically() {
        let graph = semantic_graph_fixture();
        let response = candidate_response(
            vec![
                ConceptCandidate {
                    candidate_key: "one".into(),
                    title: "One".into(),
                    responsibility: "First grouping".into(),
                    member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
                    supporting_edge_ids: vec!["reference:ambiguous".into()],
                    evidence_ids: vec!["ev:entry".into(), "ev:worker".into()],
                },
                ConceptCandidate {
                    candidate_key: "two".into(),
                    title: "Two".into(),
                    responsibility: "Second grouping".into(),
                    member_entity_ids: vec!["entity:worker".into(), "entity:other".into()],
                    supporting_edge_ids: vec!["reference:unresolved".into()],
                    evidence_ids: vec!["ev:other".into(), "ev:worker".into()],
                },
            ],
            vec![],
        );
        let mut issues = Vec::new();
        validate_architecture_candidates(
            &response,
            &graph,
            &graph_evidence_ids(&graph),
            &mut issues,
        );
        let codes = issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("semantic_edge_ambiguous"));
        assert!(codes.contains("semantic_edge_unresolved"));
        assert!(codes.contains("overlapping_concept_member"));
        assert!(codes.contains("concept_not_cohesive"));
        assert!(response.accepted_concepts.is_empty());
        assert!(response.accepted_relationships.is_empty());
    }

    #[test]
    fn materializes_valid_directed_dependency_with_relationship_ids() {
        let graph = semantic_graph_fixture();
        let request = request_for_graph(graph.clone());
        let mut response = candidate_response(
            vec![
                ConceptCandidate {
                    candidate_key: "source".into(),
                    title: "Source".into(),
                    responsibility: "Initiates work".into(),
                    member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
                    supporting_edge_ids: vec!["reference:call".into()],
                    evidence_ids: vec!["ev:entry".into(), "ev:worker".into()],
                },
                ConceptCandidate {
                    candidate_key: "target".into(),
                    title: "Target".into(),
                    responsibility: "Completes work".into(),
                    member_entity_ids: vec!["entity:other".into(), "entity:fourth".into()],
                    supporting_edge_ids: vec!["reference:other-call".into()],
                    evidence_ids: vec!["ev:fourth".into(), "ev:other".into()],
                },
            ],
            vec![RelationshipCandidate {
                source_candidate_key: "source".into(),
                target_candidate_key: "target".into(),
                kind: CandidateRelationshipKind::DependsOn,
                supporting_edge_ids: vec!["reference:cross".into()],
            }],
        );
        let mut issues = Vec::new();
        validate_architecture_candidates(
            &response,
            &graph,
            &graph_evidence_ids(&graph),
            &mut issues,
        );
        validate_supplied_semantics(&request, &response, &mut issues);
        assert!(issues.is_empty(), "unexpected issues: {issues:?}");

        materialize_architecture(&request, &mut response);
        assert_eq!(response.accepted_relationships.len(), 1);
        assert_eq!(
            response.accepted_relationships[0].supporting_edge_ids,
            ["relationship:cross"]
        );
        assert_eq!(
            response.accepted_relationships[0].evidence_ids,
            ["ev:entry"]
        );
        let (concepts, relationships) = response.accepted_architecture(crate::AgentKind::Codex);
        assert_eq!(concepts.len(), 2);
        assert_eq!(relationships.len(), 1);
        assert_eq!(
            relationships[0].supporting_relationship_ids,
            ["relationship:cross"]
        );
    }

    #[test]
    fn rejects_unknown_unsupplied_and_reversed_dependency_edges() {
        let graph = semantic_graph_fixture();
        let request = request_for_graph(graph.clone());
        let response = candidate_response(
            vec![
                ConceptCandidate {
                    candidate_key: "source".into(),
                    title: "Source".into(),
                    responsibility: "Source side".into(),
                    member_entity_ids: vec!["entity:entry".into(), "entity:worker".into()],
                    supporting_edge_ids: vec!["relationship:call".into()],
                    evidence_ids: vec!["ev:entry".into(), "ev:worker".into()],
                },
                ConceptCandidate {
                    candidate_key: "target".into(),
                    title: "Target".into(),
                    responsibility: "Target side".into(),
                    member_entity_ids: vec!["entity:other".into(), "entity:fourth".into()],
                    supporting_edge_ids: vec!["relationship:other-call".into()],
                    evidence_ids: vec!["ev:fourth".into(), "ev:other".into()],
                },
            ],
            vec![RelationshipCandidate {
                source_candidate_key: "target".into(),
                target_candidate_key: "source".into(),
                kind: CandidateRelationshipKind::DependsOn,
                supporting_edge_ids: vec!["relationship:cross".into(), "edge:not-real".into()],
            }],
        );
        let mut issues = Vec::new();
        validate_architecture_candidates(
            &response,
            &graph,
            &graph_evidence_ids(&graph),
            &mut issues,
        );
        validate_supplied_semantics(&request, &response, &mut issues);
        let codes = issues
            .iter()
            .map(|issue| issue.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("unknown_semantic_edge"));
        assert!(codes.contains("semantic_edge_not_supplied"));
        assert!(codes.contains("semantic_edge_reversed"));
    }

    #[test]
    fn incomplete_bounded_scope_forbids_repository_summary() {
        let mut graph = semantic_graph_fixture();
        graph.scope.complete = false;
        let request = request_for_graph(graph);
        let response = EnrichmentResponse {
            repository_summary: Some("This is the whole repository".into()),
            summary_evidence_ids: vec!["ev:entry".into()],
            ..EnrichmentResponse::default()
        };
        let mut issues = Vec::new();
        validate_supplied_semantics(&request, &response, &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "incomplete_scope_summary")
        );
    }

    #[test]
    fn graph_bounds_report_total_supplied_and_incomplete_scope() {
        let graph = semantic_graph_fixture();
        let mut ir = empty_ir_fixture();
        ir.entities = graph.entities.clone();
        ir.semantic_references = graph.references.clone();
        ir.relationships = graph.relationships.clone();
        ir.evidence = ["ev:entry", "ev:file", "ev:fourth", "ev:other", "ev:worker"]
            .into_iter()
            .map(|id| repo2okf_core::EvidenceRef {
                id: id.into(),
                path: "fixture.py".into(),
                start_line: 1,
                end_line: 1,
                start_byte: 0,
                end_byte: 1,
                content_hash: "fixture".into(),
                symbol: None,
                extractor: "fixture".into(),
            })
            .collect();
        let supplied = BTreeSet::from([
            "ev:entry".to_owned(),
            "ev:file".to_owned(),
            "ev:worker".to_owned(),
        ]);
        let bounded = bounded_semantic_graph(&ir, &supplied, false, 0);
        assert_eq!(bounded.scope.total_entities, 5);
        assert_eq!(bounded.scope.supplied_entities, 3);
        assert_eq!(bounded.scope.total_evidence, 5);
        assert_eq!(bounded.scope.supplied_evidence, 3);
        assert_eq!(bounded.scope.total_references, 5);
        assert!(!bounded.scope.complete);
        let persisted = bounded.scope.architecture_scope();
        assert_eq!(persisted.evidence_total, 5);
        assert_eq!(persisted.evidence_supplied, 3);
        assert_eq!(persisted.entities_total, 5);
        assert_eq!(persisted.entities_supplied, 3);
        assert_eq!(persisted.semantic_references_total, 5);
        assert!(!persisted.complete);
    }

    #[test]
    fn repair_loop_rejects_invalid_candidate_batch_atomically() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("README.md"), "# Fixture\n").expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let driver = RepairDriver::default();
        let process = ProcessConfig::new(temp.path().to_path_buf());
        let (response, stats) = enrich_with_repair(
            &driver,
            &ir,
            &process,
            OutputLocale::Ja,
            RepairOptions {
                max_repair_attempts: 1,
            },
        )
        .expect("second candidate batch should repair the first");
        assert_eq!(stats.attempts, 2);
        assert!(stats.repaired_issues > 0);
        assert!(stats.architecture_scope.is_some());
        assert!(response.accepted_concepts.is_empty());
        assert!(response.accepted_relationships.is_empty());
        assert_eq!(
            *driver.locales.lock().expect("request locales"),
            [OutputLocale::Ja, OutputLocale::Ja]
        );
        let repair_codes = driver.repair_codes.lock().expect("repair codes");
        assert!(
            repair_codes[1]
                .iter()
                .any(|code| code == "unknown_concept_member")
        );
        assert!(
            repair_codes[1]
                .iter()
                .any(|code| code == "missing_concept_evidence")
        );
    }

    #[derive(Default)]
    struct RepairDriver {
        calls: AtomicUsize,
        locales: Mutex<Vec<OutputLocale>>,
        repair_codes: Mutex<Vec<Vec<String>>>,
    }

    impl AgentDriver for RepairDriver {
        fn kind(&self) -> AgentKind {
            AgentKind::Codex
        }

        fn probe(&self, _config: &ProcessConfig) -> AgentProbe {
            AgentProbe {
                kind: AgentKind::Codex,
                executable: None,
                version: None,
                authenticated: None,
                capabilities: AgentCapabilities::default(),
                diagnostics: vec![],
            }
        }

        fn run(
            &self,
            request: &EnrichmentRequest,
            _config: &ProcessConfig,
        ) -> Result<EnrichmentResponse, crate::AgentError> {
            self.locales
                .lock()
                .expect("request locales")
                .push(request.output_locale);
            self.repair_codes.lock().expect("repair codes").push(
                request
                    .repair_issues
                    .iter()
                    .map(|issue| issue.code.clone())
                    .collect(),
            );
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(candidate_response(
                    vec![ConceptCandidate {
                        candidate_key: "fabricated".into(),
                        title: "Fabricated".into(),
                        responsibility: "Has no deterministic graph support".into(),
                        member_entity_ids: vec!["entity:nope".into(), "entity:also-nope".into()],
                        supporting_edge_ids: vec!["relationship:nope".into()],
                        evidence_ids: vec![],
                    }],
                    vec![],
                ));
            }
            Ok(EnrichmentResponse::default())
        }
    }

    fn candidate_response(
        concept_candidates: Vec<ConceptCandidate>,
        relationship_candidates: Vec<RelationshipCandidate>,
    ) -> EnrichmentResponse {
        EnrichmentResponse {
            concept_candidates,
            relationship_candidates,
            ..EnrichmentResponse::default()
        }
    }

    fn graph_evidence_ids(graph: &SuppliedSemanticGraph) -> BTreeSet<&str> {
        graph
            .entities
            .iter()
            .map(|entity| entity.evidence_id.as_str())
            .chain(
                graph
                    .references
                    .iter()
                    .map(|reference| reference.evidence_id.as_str()),
            )
            .chain(
                graph
                    .relationships
                    .iter()
                    .flat_map(|relationship| relationship.evidence_ids.iter().map(String::as_str)),
            )
            .collect()
    }

    fn request_for_graph(semantic_graph: SuppliedSemanticGraph) -> EnrichmentRequest {
        EnrichmentRequest {
            repository: "fixture".into(),
            ir_fingerprint: "fixture-fingerprint".into(),
            output_locale: OutputLocale::En,
            evidence: vec![],
            evidence_excerpts: vec![],
            coverage: vec![],
            semantic_graph,
            existing_agent_claims: vec![],
            existing_architecture_concepts: vec![],
            existing_architecture_relationships: vec![],
            repair_issues: vec![],
        }
    }

    fn empty_ir_fixture() -> repo2okf_core::RepositoryIr {
        repo2okf_core::RepositoryIr {
            schema_version: 2,
            repository: repo2okf_core::RepositoryMetadata {
                name: "fixture".into(),
                git_commit: None,
                git_inventory: false,
                extractor: "fixture".into(),
            },
            files: vec![],
            entities: vec![],
            imports: vec![],
            evidence: vec![],
            relationships: vec![],
            semantic_references: vec![],
            semantic_coverage: repo2okf_core::SemanticCoverage::default(),
            claims: vec![],
            architecture_concepts: vec![],
            architecture_relationships: vec![],
            architecture_scope: None,
            coverage: repo2okf_core::CoverageReport::default(),
            fingerprint: "fixture-fingerprint".into(),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete graph fixture keeps all validation cases on one consistent topology"
    )]
    fn semantic_graph_fixture() -> SuppliedSemanticGraph {
        let entity = |id: &str, evidence_id: &str| repo2okf_core::Entity {
            id: id.into(),
            kind: repo2okf_core::EntityKind::Function,
            name: id.into(),
            qualified_name: id.into(),
            path: "fixture.py".into(),
            language: Some(repo2okf_core::Language::Python),
            owner_id: Some("entity:file".into()),
            evidence_id: evidence_id.into(),
        };
        let entities = vec![
            entity("entity:entry", "ev:entry"),
            repo2okf_core::Entity {
                id: "entity:file".into(),
                kind: repo2okf_core::EntityKind::File,
                name: "fixture.py".into(),
                qualified_name: "fixture".into(),
                path: "fixture.py".into(),
                language: Some(repo2okf_core::Language::Python),
                owner_id: None,
                evidence_id: "ev:file".into(),
            },
            entity("entity:fourth", "ev:fourth"),
            entity("entity:other", "ev:other"),
            entity("entity:worker", "ev:worker"),
        ];
        let reference =
            |id: &str, source: &str, evidence_id: &str, resolution: SemanticResolution| {
                repo2okf_core::SemanticReference {
                    id: id.into(),
                    kind: SemanticReferenceKind::Call,
                    path: "fixture.py".into(),
                    scope_id: source.into(),
                    source_entity_id: Some(source.into()),
                    name: id.into(),
                    qualifier: None,
                    binding_name: None,
                    evidence_id: evidence_id.into(),
                    resolution,
                }
            };
        let references = vec![
            reference(
                "reference:ambiguous",
                "entity:entry",
                "ev:entry",
                SemanticResolution::Ambiguous {
                    candidate_entity_ids: vec!["entity:other".into(), "entity:worker".into()],
                    reason: "two candidates".into(),
                },
            ),
            reference(
                "reference:call",
                "entity:entry",
                "ev:entry",
                SemanticResolution::Resolved {
                    target_entity_id: "entity:worker".into(),
                },
            ),
            reference(
                "reference:cross",
                "entity:entry",
                "ev:entry",
                SemanticResolution::Resolved {
                    target_entity_id: "entity:other".into(),
                },
            ),
            reference(
                "reference:other-call",
                "entity:other",
                "ev:other",
                SemanticResolution::Resolved {
                    target_entity_id: "entity:fourth".into(),
                },
            ),
            reference(
                "reference:unresolved",
                "entity:worker",
                "ev:worker",
                SemanticResolution::Unresolved {
                    reason: "dynamic lookup".into(),
                },
            ),
        ];
        let relationship =
            |id: &str, source: &str, target: &str, reference_id: &str, evidence: &str| {
                repo2okf_core::Relationship {
                    id: id.into(),
                    source: source.into(),
                    target: target.into(),
                    kind: RelationshipKind::Calls,
                    origin: RelationshipOrigin::SemanticReference {
                        reference_id: reference_id.into(),
                    },
                    evidence_ids: vec![evidence.into()],
                }
            };
        let relationships = vec![
            relationship(
                "relationship:call",
                "entity:entry",
                "entity:worker",
                "reference:call",
                "ev:entry",
            ),
            relationship(
                "relationship:cross",
                "entity:entry",
                "entity:other",
                "reference:cross",
                "ev:entry",
            ),
            relationship(
                "relationship:other-call",
                "entity:other",
                "entity:fourth",
                "reference:other-call",
                "ev:other",
            ),
        ];
        SuppliedSemanticGraph {
            scope: crate::SemanticGraphScope {
                total_evidence: 5,
                supplied_evidence: 5,
                total_coverage_items: 0,
                supplied_coverage_items: 0,
                total_entities: entities.len(),
                supplied_entities: entities.len(),
                total_references: references.len(),
                supplied_references: references.len(),
                total_relationships: relationships.len(),
                supplied_relationships: relationships.len(),
                complete: true,
            },
            entities,
            references,
            relationships,
        }
    }
}
