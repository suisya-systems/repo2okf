//! Deterministic OKF v0.2 emission.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    CoverageClassification, DocumentPathError, EvidenceRecord, OKF_VERSION, OkfDocument, OkfSource,
    Repo2OkfMetadata, RepositoryIrView, concept_path,
};

/// Summary of a successful emission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmissionReport {
    /// Bundle root written by the emitter.
    pub output_dir: PathBuf,
    /// Relative paths written, in lexical order.
    pub files_written: Vec<PathBuf>,
    /// Number of included coverage items.
    pub included: usize,
    /// Number of explicitly excluded coverage items.
    pub excluded: usize,
    /// Number of unresolved coverage items.
    pub unresolved: usize,
}

/// Deterministic emitter failure.
#[derive(Debug, Error)]
pub enum EmitError {
    /// A concept ID cannot safely map into the bundle.
    #[error("invalid concept ID `{id}`: {source}")]
    InvalidConceptId {
        /// Unsafe ID.
        id: String,
        /// Path validation failure.
        #[source]
        source: DocumentPathError,
    },
    /// More than one input document has the same portable ID.
    #[error("duplicate concept ID: {0}")]
    DuplicateConceptId(String),
    /// More than one claim has the same bundle-scoped ID, or an ID is empty.
    #[error("duplicate claim ID: {0}")]
    DuplicateClaimId(String),
    /// A claim cannot be represented safely as one Markdown list item.
    #[error("invalid claim `{claim_id}` in `{concept_id}`: {reason}")]
    InvalidClaim {
        /// Owning concept.
        concept_id: String,
        /// Claim identifier.
        claim_id: String,
        /// Validation explanation.
        reason: String,
    },
    /// A concept is missing the only required OKF field.
    #[error("concept `{0}` has an empty type")]
    EmptyConceptType(String),
    /// Optional metadata is present but violates its family contract.
    #[error("invalid metadata in concept `{concept_id}`: {reason}")]
    InvalidMetadata {
        /// Concept containing the invalid metadata.
        concept_id: String,
        /// Validation explanation.
        reason: String,
    },
    /// An evidence record ID is duplicated.
    #[error("duplicate evidence ID: {0}")]
    DuplicateEvidenceId(String),
    /// An evidence record is malformed or unsafe.
    #[error("invalid evidence `{id}`: {reason}")]
    InvalidEvidence {
        /// Evidence identifier.
        id: String,
        /// Validation explanation.
        reason: String,
    },
    /// A claim has no evidence binding.
    #[error("claim `{claim_id}` in `{concept_id}` has no evidence")]
    ClaimWithoutEvidence {
        /// Owning concept.
        concept_id: String,
        /// Claim identifier.
        claim_id: String,
    },
    /// A claim or source points to evidence absent from the current IR.
    #[error("`{owner}` references unknown evidence ID `{evidence_id}`")]
    UnknownEvidence {
        /// Claim or concept containing the reference.
        owner: String,
        /// Missing evidence ID.
        evidence_id: String,
    },
    /// A coverage inclusion points at a missing concept.
    #[error("coverage item `{item_id}` includes missing concept `{concept_id}`")]
    MissingCoveredConcept {
        /// Coverage item ID.
        item_id: String,
        /// Missing concept ID.
        concept_id: String,
    },
    /// A relationship target is unsafe or reserved.
    #[error("relationship in `{concept_id}` has invalid target `{target}`: {source}")]
    InvalidRelationshipTarget {
        /// Source concept ID.
        concept_id: String,
        /// Invalid target ID.
        target: String,
        /// Path validation failure.
        #[source]
        source: DocumentPathError,
    },
    /// A relationship points at a concept absent from the emitted bundle.
    #[error("relationship in `{concept_id}` points at missing concept `{target}`")]
    MissingRelationshipTarget {
        /// Source concept ID.
        concept_id: String,
        /// Missing target ID.
        target: String,
    },
    /// An exclusion must explain why the item is intentionally absent.
    #[error("coverage item `{0}` has an empty exclusion reason")]
    EmptyExclusionReason(String),
    /// Coverage IDs are bundle-scoped and must be non-empty and unique.
    #[error("coverage item ID `{0}` is empty or duplicated")]
    DuplicateCoverageId(String),
    /// LLM confirmation alone must not populate OKF `verified`.
    #[error("AI claims in `{0}` are marked verified only by an agent")]
    AiOnlyVerification(String),
    /// YAML serialization failed.
    #[error("could not serialize OKF frontmatter: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// A filesystem operation failed.
    #[error("I/O error at `{path}`: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

/// Emit a deterministic OKF v0.2 bundle from a read-only repository IR view.
///
/// Documents, tags, sources, claims, relationships, and verification events
/// are sorted before serialization. The function never adds a `verified`
/// event merely because evidence resolved; verification remains an explicit,
/// independent act.
///
/// # Errors
///
/// Returns [`EmitError`] when the input violates OKF or `Repo2OKF`
/// invariants, or when the bundle cannot be written.
pub fn emit_okf<I, P>(ir: &I, output_dir: P) -> Result<EmissionReport, EmitError>
where
    I: RepositoryIrView + ?Sized,
    P: AsRef<Path>,
{
    let output_dir = output_dir.as_ref();
    let evidence = evidence_map(ir.evidence_records())?;
    let mut documents = ir.okf_documents().to_vec();

    validate_and_normalize_documents(&mut documents, &evidence)?;
    documents.sort_by_key(|document| portable_id(&document.id));
    validate_relationships(&documents)?;
    validate_coverage(ir.coverage_items(), &documents)?;

    fs::create_dir_all(output_dir).map_err(|source| EmitError::Io {
        path: output_dir.to_path_buf(),
        source,
    })?;

    let mut files_written = Vec::with_capacity(documents.len() + 1);
    let index = render_index(ir.repository_name(), &documents, ir.coverage_items())?;
    write_file(output_dir, Path::new("index.md"), &index)?;
    files_written.push(PathBuf::from("index.md"));

    for document in &documents {
        let relative = document
            .relative_path()
            .map_err(|source| EmitError::InvalidConceptId {
                id: document.id.clone(),
                source,
            })?;
        let content = render_document(document)?;
        write_file(output_dir, &relative, &content)?;
        files_written.push(relative);
    }
    files_written.sort();

    let (included, excluded, unresolved) = coverage_counts(ir.coverage_items());
    Ok(EmissionReport {
        output_dir: output_dir.to_path_buf(),
        files_written,
        included,
        excluded,
        unresolved,
    })
}

fn validate_and_normalize_documents(
    documents: &mut [OkfDocument],
    evidence: &BTreeMap<&str, &EvidenceRecord>,
) -> Result<(), EmitError> {
    let mut document_ids = BTreeSet::new();
    let mut claim_ids = BTreeSet::new();
    for document in documents {
        concept_path(&document.id).map_err(|source| EmitError::InvalidConceptId {
            id: document.id.clone(),
            source,
        })?;
        if !document_ids.insert(portable_id(&document.id)) {
            return Err(EmitError::DuplicateConceptId(document.id.clone()));
        }
        if document.metadata.concept_type.trim().is_empty() {
            return Err(EmitError::EmptyConceptType(document.id.clone()));
        }

        normalize_document(document, evidence, &mut claim_ids)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn normalize_document(
    document: &mut OkfDocument,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    claim_ids: &mut BTreeSet<String>,
) -> Result<(), EmitError> {
    validate_metadata(document)?;
    document.metadata.tags.sort();
    document.metadata.tags.dedup();
    document
        .metadata
        .verified
        .sort_by(|left, right| left.at.cmp(&right.at).then_with(|| left.by.cmp(&right.by)));
    document.relationships.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.label.cmp(&right.label))
    });
    document.relationships.dedup();
    document
        .claims
        .sort_by(|left, right| left.id.cmp(&right.id));

    let mut claim_evidence = Vec::new();
    for claim in &mut document.claims {
        if claim.id.trim().is_empty() || !claim_ids.insert(claim.id.clone()) {
            return Err(EmitError::DuplicateClaimId(claim.id.clone()));
        }
        if claim.text.trim().is_empty() {
            return Err(EmitError::InvalidClaim {
                concept_id: document.id.clone(),
                claim_id: claim.id.clone(),
                reason: "text must not be empty".to_owned(),
            });
        }
        if contains_line_break_or_control(&claim.text) {
            return Err(EmitError::InvalidClaim {
                concept_id: document.id.clone(),
                claim_id: claim.id.clone(),
                reason: "text must be a single Markdown-safe line".to_owned(),
            });
        }
        claim.evidence_ids.sort();
        claim.evidence_ids.dedup();
        if claim.evidence_ids.is_empty() {
            return Err(EmitError::ClaimWithoutEvidence {
                concept_id: document.id.clone(),
                claim_id: claim.id.clone(),
            });
        }
        for evidence_id in &claim.evidence_ids {
            let record =
                evidence
                    .get(evidence_id.as_str())
                    .ok_or_else(|| EmitError::UnknownEvidence {
                        owner: format!("{}:{}", document.id, claim.id),
                        evidence_id: evidence_id.clone(),
                    })?;
            claim_evidence.push((*record).clone());
        }
    }

    for record in &claim_evidence {
        ensure_evidence_source(document, record);
    }

    if (document.claims.iter().any(|claim| claim.ai_generated)
        || document
            .metadata
            .generated
            .as_ref()
            .is_some_and(|event| is_agent_actor(&event.by)))
        && !document.metadata.verified.is_empty()
        && !document
            .metadata
            .verified
            .iter()
            .any(|event| is_independent_verifier(&event.by))
    {
        return Err(EmitError::AiOnlyVerification(document.id.clone()));
    }

    for source in &mut document.metadata.sources {
        if let Some(evidence_id) = source.evidence_id.as_deref() {
            let record = evidence
                .get(evidence_id)
                .ok_or_else(|| EmitError::UnknownEvidence {
                    owner: document.id.clone(),
                    evidence_id: evidence_id.to_owned(),
                })?;
            // The current IR is authoritative. Emission always records the
            // path, line and hash actually checked, never stale provenance
            // supplied by an agent.
            source.resource = evidence_resource(record);
            source.content_hash = Some(record.content_hash.clone());
        }
    }
    validate_metadata(document)?;
    document.metadata.sources.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.evidence_id.cmp(&right.evidence_id))
            .then_with(|| left.resource.cmp(&right.resource))
    });
    document.metadata.sources.dedup();
    document.metadata.repo2okf = if document.claims.is_empty() && document.relationships.is_empty()
    {
        None
    } else {
        Some(Repo2OkfMetadata {
            claims: document.claims.clone(),
            relationships: document.relationships.clone(),
        })
    };
    Ok(())
}

fn validate_metadata(document: &OkfDocument) -> Result<(), EmitError> {
    let invalid = |reason: String| EmitError::InvalidMetadata {
        concept_id: document.id.clone(),
        reason,
    };
    if document
        .metadata
        .generated
        .as_ref()
        .is_some_and(|generated| !actor_has_identity(&generated.by))
    {
        return Err(invalid("generated.by must identify an actor".to_owned()));
    }
    if document
        .metadata
        .verified
        .iter()
        .any(|verification| !actor_has_identity(&verification.by))
    {
        return Err(invalid("verified[].by must identify an actor".to_owned()));
    }
    if document
        .metadata
        .usage_window
        .as_ref()
        .is_some_and(|window| window.from > window.to)
    {
        return Err(invalid(
            "usage_window.from must not be after usage_window.to".to_owned(),
        ));
    }
    let mut source_ids = BTreeSet::new();
    let mut source_evidence = BTreeSet::new();
    for source in &document.metadata.sources {
        if source.resource.trim().is_empty() {
            return Err(invalid("sources[].resource must not be empty".to_owned()));
        }
        if source
            .author
            .as_deref()
            .is_some_and(|author| !actor_has_identity(author))
        {
            return Err(invalid(format!(
                "source `{}` has an invalid author actor",
                source.id.as_deref().unwrap_or(&source.resource)
            )));
        }
        if let Some(id) = source.id.as_deref() {
            if !safe_footnote_id(id) || !source_ids.insert(id) {
                return Err(invalid(format!("source ID `{id}` is empty or duplicated")));
            }
        }
        if let Some(evidence_id) = source.evidence_id.as_deref() {
            if !source_evidence.insert(evidence_id) {
                return Err(invalid(format!(
                    "evidence `{evidence_id}` occurs in multiple sources"
                )));
            }
        }
        if source
            .usage_window
            .as_ref()
            .is_some_and(|window| window.from > window.to)
        {
            return Err(invalid(format!(
                "source `{}` has an inverted usage_window",
                source.id.as_deref().unwrap_or(&source.resource)
            )));
        }
        for (field, value) in [
            ("sources[].resource", source.resource.as_str()),
            (
                "sources[].title",
                source.title.as_deref().unwrap_or_default(),
            ),
            (
                "sources[].author",
                source.author.as_deref().unwrap_or_default(),
            ),
        ] {
            if contains_line_break_or_control(value) {
                return Err(invalid(format!(
                    "{field} must not contain line breaks or controls"
                )));
            }
        }
    }
    Ok(())
}

fn validate_relationships(documents: &[OkfDocument]) -> Result<(), EmitError> {
    let ids = documents
        .iter()
        .map(|document| portable_id(&document.id))
        .collect::<BTreeSet<_>>();
    for document in documents {
        for relationship in &document.relationships {
            concept_path(&relationship.target).map_err(|source| {
                EmitError::InvalidRelationshipTarget {
                    concept_id: document.id.clone(),
                    target: relationship.target.clone(),
                    source,
                }
            })?;
            if !ids.contains(&portable_id(&relationship.target)) {
                return Err(EmitError::MissingRelationshipTarget {
                    concept_id: document.id.clone(),
                    target: relationship.target.clone(),
                });
            }
        }
    }
    Ok(())
}

fn ensure_evidence_source(document: &mut OkfDocument, record: &EvidenceRecord) {
    if let Some(source) = document
        .metadata
        .sources
        .iter_mut()
        .find(|source| source.evidence_id.as_deref() == Some(record.id.as_str()))
    {
        source.id.get_or_insert_with(|| footnote_id(&record.id));
        source.resource = evidence_resource(record);
        source.content_hash = Some(record.content_hash.clone());
        return;
    }
    document.metadata.sources.push(OkfSource {
        id: Some(footnote_id(&record.id)),
        resource: evidence_resource(record),
        title: Some(format!("Source evidence {}", record.id)),
        author: Some("process:repo2okf-scanner".to_owned()),
        usage_count: None,
        last_modified: None,
        usage_window: None,
        evidence_id: Some(record.id.clone()),
        content_hash: Some(record.content_hash.clone()),
    });
}

fn evidence_resource(record: &EvidenceRecord) -> String {
    let line_fragment = record
        .line
        .map_or_else(String::new, |line| format!("#L{line}"));
    format!(
        "repo:{}{line_fragment}",
        encode_url_path(&record.path.replace('\\', "/"))
    )
}

fn evidence_map(records: &[EvidenceRecord]) -> Result<BTreeMap<&str, &EvidenceRecord>, EmitError> {
    let mut result = BTreeMap::new();
    for record in records {
        if record.id.trim().is_empty() {
            return Err(EmitError::InvalidEvidence {
                id: record.id.clone(),
                reason: "ID must not be empty".to_owned(),
            });
        }
        if record.content_hash.trim().is_empty() {
            return Err(EmitError::InvalidEvidence {
                id: record.id.clone(),
                reason: "content hash must not be empty".to_owned(),
            });
        }
        if record.line == Some(0) {
            return Err(EmitError::InvalidEvidence {
                id: record.id.clone(),
                reason: "source lines are one-based".to_owned(),
            });
        }
        if record.path.trim().is_empty() || unsafe_repository_path(&record.path) {
            return Err(EmitError::InvalidEvidence {
                id: record.id.clone(),
                reason: format!(
                    "path `{}` must be a safe repository-relative path",
                    record.path
                ),
            });
        }
        if result.insert(record.id.as_str(), record).is_some() {
            return Err(EmitError::DuplicateEvidenceId(record.id.clone()));
        }
    }
    Ok(result)
}

fn unsafe_repository_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let path = Path::new(&normalized);
    normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
        || normalized.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.ends_with('.')
                || part.ends_with(' ')
                || part.chars().any(|character| {
                    character.is_control()
                        || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                })
        })
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::Prefix(_) | std::path::Component::RootDir
            )
        })
}

fn validate_coverage(
    coverage: &[crate::model::CoverageItem],
    documents: &[OkfDocument],
) -> Result<(), EmitError> {
    let ids = documents
        .iter()
        .map(|document| portable_id(&document.id))
        .collect::<BTreeSet<_>>();
    let mut coverage_ids = BTreeSet::new();
    for item in coverage {
        if item.id.trim().is_empty() || !coverage_ids.insert(item.id.as_str()) {
            return Err(EmitError::DuplicateCoverageId(item.id.clone()));
        }
        match &item.classification {
            CoverageClassification::Included { concept_id } => {
                if !ids.contains(&portable_id(concept_id)) {
                    return Err(EmitError::MissingCoveredConcept {
                        item_id: item.id.clone(),
                        concept_id: concept_id.clone(),
                    });
                }
            }
            CoverageClassification::Excluded { reason } if reason.trim().is_empty() => {
                return Err(EmitError::EmptyExclusionReason(item.id.clone()));
            }
            CoverageClassification::Excluded { .. } | CoverageClassification::Unresolved => {}
        }
    }
    Ok(())
}

fn render_document(document: &OkfDocument) -> Result<String, EmitError> {
    let mut rendered = render_frontmatter(&document.metadata)?;
    let body = document.body.trim();
    if !body.is_empty() {
        rendered.push('\n');
        rendered.push_str(body);
        rendered.push('\n');
    }

    if !document.relationships.is_empty() {
        rendered.push_str("\n## Relationships\n\n");
        for relationship in &document.relationships {
            let label = relationship
                .label
                .as_deref()
                .unwrap_or(&relationship.target);
            let kind = relationship
                .kind
                .as_deref()
                .map_or_else(String::new, |kind| format!(" — {kind}"));
            writeln!(
                rendered,
                "- [{}](/{}.md){}",
                escape_markdown_label(label),
                encode_concept_link_target(&relationship.target),
                escape_markdown_inline(&kind)
            )
            .expect("writing to a String cannot fail");
        }
    }

    if !document.claims.is_empty() {
        let source_ids = document
            .metadata
            .sources
            .iter()
            .filter_map(|source| source.evidence_id.as_deref().zip(source.id.as_deref()))
            .collect::<BTreeMap<_, _>>();
        rendered.push_str("\n## Evidence-bound claims\n\n");
        for claim in &document.claims {
            rendered.push_str("- ");
            rendered.push_str(&escape_markdown_text(claim.text.trim()));
            for evidence_id in &claim.evidence_ids {
                if let Some(source_id) = source_ids.get(evidence_id.as_str()) {
                    write!(rendered, "[^{source_id}]").expect("writing to a String cannot fail");
                }
            }
            rendered.push('\n');
        }
        rendered.push('\n');
        let mut written = BTreeSet::new();
        for source in &document.metadata.sources {
            let Some(source_id) = source.id.as_deref() else {
                continue;
            };
            if source.evidence_id.is_none() || !written.insert(source_id) {
                continue;
            }
            let title = source.title.as_deref().unwrap_or(&source.resource);
            writeln!(
                rendered,
                "[^{source_id}]: {}",
                escape_markdown_inline(title)
            )
            .expect("writing to a String cannot fail");
        }
    }

    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn render_index(
    repository_name: &str,
    documents: &[OkfDocument],
    coverage: &[crate::model::CoverageItem],
) -> Result<String, EmitError> {
    #[derive(Serialize)]
    struct IndexFrontmatter {
        okf_version: &'static str,
    }
    let mut rendered = render_frontmatter(&IndexFrontmatter {
        okf_version: OKF_VERSION,
    })?;
    let title = if repository_name.trim().is_empty() {
        "Repository knowledge"
    } else {
        repository_name
    };
    write!(rendered, "\n# {}\n\n", escape_markdown_inline(title))
        .expect("writing to a String cannot fail");
    for document in documents {
        let label = document.metadata.title.as_deref().unwrap_or(&document.id);
        let description = document
            .metadata
            .description
            .as_deref()
            .map_or_else(String::new, |description| format!(" — {description}"));
        writeln!(
            rendered,
            "- [{}](/{}.md){}",
            escape_markdown_label(label),
            encode_concept_link_target(&document.id),
            escape_markdown_inline(&description)
        )
        .expect("writing to a String cannot fail");
    }
    let (included, excluded, unresolved) = coverage_counts(coverage);
    rendered.push_str("\n## Coverage\n\n");
    write!(
        rendered,
        "- Included: {included}\n- Excluded: {excluded}\n- Unresolved: {unresolved}\n"
    )
    .expect("writing to a String cannot fail");
    Ok(rendered)
}

fn render_frontmatter<T: Serialize>(metadata: &T) -> Result<String, EmitError> {
    let yaml = serde_yaml::to_string(metadata)?;
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    Ok(format!("---\n{}\n---\n", yaml.trim_end()))
}

fn write_file(root: &Path, relative: &Path, content: &str) -> Result<(), EmitError> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| EmitError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    fs::write(&path, content.as_bytes()).map_err(|source| EmitError::Io { path, source })
}

fn portable_id(id: &str) -> String {
    id.strip_suffix(".md")
        .unwrap_or(id)
        .replace('\\', "/")
        .to_lowercase()
}

fn is_independent_verifier(actor: &str) -> bool {
    actor
        .strip_prefix("human:")
        .or_else(|| actor.strip_prefix("process:"))
        .is_some_and(|identity| !identity.trim().is_empty())
}

fn actor_has_identity(actor: &str) -> bool {
    let actor = actor.trim();
    if let Some(identity) = actor
        .strip_prefix("human:")
        .or_else(|| actor.strip_prefix("process:"))
    {
        return !identity.trim().is_empty();
    }
    actor.split_once('/').is_some_and(|(producer, version)| {
        !producer.trim().is_empty() && !version.trim().is_empty()
    })
}

fn is_agent_actor(actor: &str) -> bool {
    let actor = actor.to_ascii_lowercase();
    actor.starts_with("agent:")
        || actor.contains("repo2okf-agent")
        || actor.contains("codex")
        || actor.contains("claude")
        || actor.contains("gemini")
        || actor.contains("agent")
}

fn contains_line_break_or_control(value: &str) -> bool {
    value
        .chars()
        .any(|character| character == '\n' || character == '\r' || character.is_control())
}

fn safe_footnote_id(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
}

fn escape_markdown_label(value: &str) -> String {
    escape_html(value)
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

fn escape_markdown_inline(value: &str) -> String {
    escape_html(value)
        .replace('\\', "\\\\")
        .replace(['\n', '\r'], " ")
}

fn escape_markdown_text(value: &str) -> String {
    let escaped = escape_html(value).replace('\\', "\\\\");
    let mut output = String::with_capacity(escaped.len());
    for character in escaped.chars() {
        if matches!(
            character,
            '`' | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '<'
                | '>'
                | '('
                | ')'
                | '#'
                | '+'
                | '-'
                | '!'
                | '|'
        ) {
            output.push('\\');
        }
        output.push(character);
    }
    output
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn encode_url_path(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn encode_concept_link_target(value: &str) -> String {
    let normalized = value
        .strip_suffix(".md")
        .unwrap_or(value)
        .replace('\\', "/");
    encode_url_path(&normalized)
}

fn footnote_id(evidence_id: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(9 + evidence_id.len() * 2);
    output.push_str("evidence-");
    for byte in evidence_id.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn coverage_counts(coverage: &[crate::model::CoverageItem]) -> (usize, usize, usize) {
    coverage.iter().fold((0, 0, 0), |mut counts, item| {
        match item.classification {
            CoverageClassification::Included { .. } => counts.0 += 1,
            CoverageClassification::Excluded { .. } => counts.1 += 1,
            CoverageClassification::Unresolved => counts.2 += 1,
        }
        counts
    })
}
