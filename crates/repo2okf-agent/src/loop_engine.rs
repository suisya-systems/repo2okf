//! Evidence validation and bounded repair orchestration.

use std::collections::BTreeSet;

use repo2okf_core::{ClaimProvenance, RepositoryIr};

use crate::excerpts::verified_excerpts;
use crate::{
    AgentDriver, AgentError, EnrichmentRequest, EnrichmentResponse, EnrichmentStats, ProcessConfig,
    ValidationIssue,
};

const MAX_CLAIM_ID_CHARS: usize = 256;
const MAX_CLAIM_TEXT_CHARS: usize = 4096;
const MAX_SUMMARY_CHARS: usize = 8192;
const MAX_RESPONSE_CLAIMS: usize = 512;
const MAX_EVIDENCE_IDS_PER_CLAIM: usize = 32;

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

/// Run the vendor driver and return only after evidence validation succeeds.
///
/// # Errors
///
/// Returns an error when the vendor process fails or when every bounded repair
/// attempt still contains invalid or ungrounded claims.
pub fn enrich_with_repair(
    driver: &dyn AgentDriver,
    ir: &RepositoryIr,
    config: &ProcessConfig,
    options: RepairOptions,
) -> Result<(EnrichmentResponse, EnrichmentStats), AgentError> {
    let mut request = EnrichmentRequest {
        evidence: Vec::new(),
        evidence_excerpts: verified_excerpts(&config.repository, &ir.evidence),
        repository: ir.repository.name.clone(),
        ir_fingerprint: ir.fingerprint.clone(),
        coverage: Vec::new(),
        existing_agent_claims: Vec::new(),
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
    let maximum_attempts = options.max_repair_attempts.saturating_add(1).min(6);
    let mut repaired_issues = 0;
    for attempt in 1..=maximum_attempts {
        let mut response = driver.run(&request, config)?;
        stamp_agent_provenance(driver, &mut response);
        let mut issues = validate_response(ir, &response);
        validate_supplied_evidence(&response, &supplied_evidence_ids, &mut issues);
        if issues.is_empty() {
            return Ok((
                response,
                EnrichmentStats {
                    attempts: attempt,
                    repaired_issues,
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

    if let Some(summary) = response.repository_summary.as_deref().map(str::trim) {
        if !summary.is_empty()
            && !response.summary_evidence_ids.is_empty()
            && !response
                .claims
                .iter()
                .any(|claim| claim.id == "claim:agent:repository-summary")
        {
            response.claims.push(repo2okf_core::Claim {
                id: "claim:agent:repository-summary".into(),
                text: summary.to_owned(),
                evidence_ids: response.summary_evidence_ids.clone(),
                provenance: ClaimProvenance::Agent {
                    provider,
                    model: None,
                },
                confidence: None,
            });
        }
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
    use std::collections::BTreeSet;

    use repo2okf_core::{Claim, ClaimProvenance, ScanOptions, scan_repository};

    use crate::{EnrichmentResponse, ValidationIssue, validate_response};

    use super::validate_supplied_evidence;

    #[test]
    fn rejects_fabricated_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("README.md"), "# Project\n").expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let response = EnrichmentResponse {
            claims: vec![Claim {
                id: "claim:agent".into(),
                text: "Fabricated claim".into(),
                evidence_ids: vec!["evidence:not-real".into()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: Some(50),
            }],
            repository_summary: None,
            summary_evidence_ids: vec![],
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
                evidence_ids: vec![evidence_id.clone()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: Some(50),
            }],
            repository_summary: Some("unsafe\rsummary".into()),
            summary_evidence_ids: vec![evidence_id],
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
                evidence_ids: vec!["ev:omitted".into()],
                provenance: ClaimProvenance::Agent {
                    provider: "fixture".into(),
                    model: None,
                },
                confidence: None,
            }],
            repository_summary: None,
            summary_evidence_ids: vec![],
        };
        let mut issues = Vec::<ValidationIssue>::new();
        validate_supplied_evidence(&response, &BTreeSet::new(), &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == "evidence_not_supplied")
        );
    }
}
