//! OKF conformance and `Repo2OKF` evidence verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use chrono::{NaiveDate, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::model::{
    CoverageClassification, CoverageItem, EvidenceRecord, OKF_VERSION, OkfArchitectureConcept,
    OkfMetadata, OkfRelationship, ProjectedSemanticRelationship, SemanticInventory, concept_path,
};

/// A freshness invariant that differs from the persisted compiler snapshot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FreshnessMismatch {
    /// The freshly scanned repository differs from the persisted IR.
    Repository,
    /// The compiler-owned bundle differs from a fresh deterministic emission.
    GeneratedBundle,
}

/// Controls strict checks layered on top of baseline OKF v0.2 conformance.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyOptions {
    /// Minimum included fraction among non-excluded inventory items, in the
    /// inclusive range `0.0..=1.0`.
    pub minimum_coverage: f64,
    /// Promote broken cross-links from warnings to errors.
    ///
    /// OKF v0.2 consumers must tolerate broken links, so this switch is a
    /// `Repo2OKF` quality gate rather than a baseline conformance requirement.
    pub broken_links_are_errors: bool,
    /// Promote concepts past `stale_after` from warnings to errors.
    pub stale_documents_are_errors: bool,
    /// Date used to evaluate `stale_after`.
    pub today: NaiveDate,
    /// Exact concept IDs expected in a compiler-owned bundle. When present,
    /// extra or missing concept files are errors.
    pub expected_concepts: Option<BTreeSet<String>>,
    /// Freshness mismatches detected by the host before structural validation.
    pub freshness_mismatches: BTreeSet<FreshnessMismatch>,
    /// Repository graph IDs against which generated semantic metadata is checked.
    ///
    /// Absence preserves baseline validation for hand-authored OKF bundles.
    pub semantic_inventory: Option<SemanticInventory>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            minimum_coverage: 1.0,
            broken_links_are_errors: true,
            stale_documents_are_errors: false,
            today: Utc::now().date_naive(),
            expected_concepts: None,
            freshness_mismatches: BTreeSet::new(),
            semantic_inventory: None,
        }
    }
}

/// Diagnostic severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A failed invariant that makes strict verification fail.
    Error,
    /// A surfaced quality or freshness concern allowed by the OKF spec.
    Warning,
}

/// One machine-readable verification finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationIssue {
    /// Stable diagnostic code.
    pub code: String,
    /// Finding severity.
    pub severity: Severity,
    /// Bundle-relative affected document, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,
    /// Human-readable explanation.
    pub message: String,
}

/// Deterministic result of verifying a bundle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// `true` when no error-level findings occurred.
    pub valid: bool,
    /// Number of concept documents parsed.
    pub concepts: usize,
    /// Included fraction among non-excluded inventory items in `0.0..=1.0`.
    pub coverage: f64,
    /// Error count.
    pub errors: usize,
    /// Warning count.
    pub warnings: usize,
    /// Findings in deterministic order.
    pub issues: Vec<VerificationIssue>,
}

impl VerificationReport {
    fn from_issues(concepts: usize, coverage: f64, mut issues: Vec<VerificationIssue>) -> Self {
        issues.sort_by(|left, right| {
            severity_rank(left.severity)
                .cmp(&severity_rank(right.severity))
                .then_with(|| left.document.cmp(&right.document))
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.message.cmp(&right.message))
        });
        let errors = issues
            .iter()
            .filter(|issue| issue.severity == Severity::Error)
            .count();
        let warnings = issues.len() - errors;
        Self {
            valid: errors == 0,
            concepts,
            coverage,
            errors,
            warnings,
            issues,
        }
    }

    /// Return whether a diagnostic code occurs in the report.
    pub fn has_code(&self, code: &str) -> bool {
        self.issues.iter().any(|issue| issue.code == code)
    }
}

#[derive(Debug)]
struct ParsedConcept {
    relative_path: PathBuf,
    id: String,
    metadata: OkfMetadata,
    body: String,
}

/// Verify an emitted OKF bundle against OKF v0.2 and `Repo2OKF`'s stricter
/// evidence, coverage, path-safety, and freshness invariants.
pub fn verify_okf<P: AsRef<Path>>(
    bundle_dir: P,
    evidence: &[EvidenceRecord],
    coverage: &[CoverageItem],
    options: &VerifyOptions,
) -> VerificationReport {
    let bundle_dir = bundle_dir.as_ref();
    let mut issues = Vec::new();
    validate_options(options, &mut issues);
    if options
        .freshness_mismatches
        .contains(&FreshnessMismatch::Repository)
    {
        error(
            &mut issues,
            "repository-ir-stale",
            None,
            "repository inventory differs from the snapshot used to generate this bundle"
                .to_owned(),
        );
    }
    if options
        .freshness_mismatches
        .contains(&FreshnessMismatch::GeneratedBundle)
    {
        error(
            &mut issues,
            "generated-bundle-stale",
            None,
            "compiler-owned OKF bundle differs from a fresh deterministic emission".to_owned(),
        );
    }

    let evidence = collect_evidence(evidence, &mut issues);
    let bundle_files = collect_bundle_files(bundle_dir, &mut issues);
    validate_portable_file_collisions(&bundle_files, &mut issues);
    let markdown_files = bundle_files
        .iter()
        .filter(|path| is_markdown(path))
        .cloned()
        .collect::<Vec<_>>();
    validate_root_index(bundle_dir, &markdown_files, &mut issues);

    let mut concepts = Vec::new();
    let mut concept_ids = BTreeMap::new();
    for relative in &markdown_files {
        let filename = relative.file_name().and_then(|value| value.to_str());
        match filename.map(str::to_ascii_lowercase).as_deref() {
            Some("index.md") => validate_index(bundle_dir, relative, &mut issues),
            Some("log.md") => validate_log(bundle_dir, relative, &mut issues),
            _ => {
                if let Some(concept) = parse_concept(bundle_dir, relative, &mut issues) {
                    let portable = concept.id.to_lowercase();
                    if let Some(previous) = concept_ids.insert(portable, concept.id.clone()) {
                        error(
                            &mut issues,
                            "duplicate-concept-id",
                            Some(path_string(relative)),
                            format!(
                                "concept ID `{}` collides with `{previous}` on portable filesystems",
                                concept.id
                            ),
                        );
                    }
                    concepts.push(concept);
                }
            }
        }
    }
    concepts.sort_by(|left, right| left.id.cmp(&right.id));

    let existing = bundle_files
        .iter()
        .map(|path| normalize_slashes(path))
        .collect::<BTreeSet<_>>();
    validate_reserved_links(bundle_dir, &markdown_files, &existing, options, &mut issues);
    let valid_concept_ids = concepts
        .iter()
        .map(|concept| concept.id.to_lowercase())
        .collect::<BTreeSet<_>>();
    validate_expected_concepts(&valid_concept_ids, options, &mut issues);
    validate_concepts(&concepts, &existing, &evidence, options, &mut issues);
    let ratio = validate_coverage(coverage, &valid_concept_ids, options, &mut issues);

    VerificationReport::from_issues(concepts.len(), ratio, issues)
}

fn validate_expected_concepts(
    actual: &BTreeSet<String>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) {
    let Some(expected) = &options.expected_concepts else {
        return;
    };
    let expected = expected
        .iter()
        .map(|id| {
            id.strip_suffix(".md")
                .unwrap_or(id)
                .replace('\\', "/")
                .to_lowercase()
        })
        .collect::<BTreeSet<_>>();
    for id in expected.difference(actual) {
        error(
            issues,
            "missing-expected-concept",
            None,
            format!("expected concept `{id}` is absent from the bundle"),
        );
    }
    for id in actual.difference(&expected) {
        error(
            issues,
            "unexpected-concept",
            Some(format!("{id}.md")),
            format!("concept `{id}` is not present in the current repository snapshot"),
        );
    }
}

fn validate_options(options: &VerifyOptions, issues: &mut Vec<VerificationIssue>) {
    if !options.minimum_coverage.is_finite() || !(0.0..=1.0).contains(&options.minimum_coverage) {
        error(
            issues,
            "invalid-coverage-threshold",
            None,
            format!(
                "minimum coverage must be between 0 and 1, got {}",
                options.minimum_coverage
            ),
        );
    }
}

fn collect_evidence<'a>(
    evidence: &'a [EvidenceRecord],
    issues: &mut Vec<VerificationIssue>,
) -> BTreeMap<&'a str, &'a EvidenceRecord> {
    let mut records = BTreeMap::new();
    for record in evidence {
        if record.id.trim().is_empty() {
            error(
                issues,
                "empty-evidence-id",
                None,
                "evidence IDs must not be empty".to_owned(),
            );
            continue;
        }
        if records.insert(record.id.as_str(), record).is_some() {
            error(
                issues,
                "duplicate-evidence-id",
                None,
                format!("duplicate evidence ID `{}`", record.id),
            );
        }
        if record.content_hash.trim().is_empty() {
            error(
                issues,
                "empty-evidence-hash",
                None,
                format!("evidence `{}` has an empty content hash", record.id),
            );
        }
        if record.line == Some(0) {
            error(
                issues,
                "invalid-evidence-line",
                None,
                format!("evidence `{}` uses line zero", record.id),
            );
        }
        if record.path.trim().is_empty() || unsafe_repository_path(&record.path) {
            error(
                issues,
                "unsafe-evidence-path",
                None,
                format!(
                    "evidence `{}` has unsafe repository-relative path `{}`",
                    record.id, record.path
                ),
            );
        }
    }
    records
}

fn collect_bundle_files(root: &Path, issues: &mut Vec<VerificationIssue>) -> Vec<PathBuf> {
    if !root.is_dir() {
        error(
            issues,
            "bundle-not-found",
            None,
            format!("bundle directory `{}` does not exist", root.display()),
        );
        return Vec::new();
    }
    let mut files = Vec::new();
    collect_dir(root, root, &mut files, issues);
    files.sort_by_key(|path| normalize_slashes(path));
    files
}

fn collect_dir(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    issues: &mut Vec<VerificationIssue>,
) {
    let read_entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(source) => {
            error(
                issues,
                "io-error",
                directory.strip_prefix(root).ok().map(path_string),
                format!("could not read directory: {source}"),
            );
            return;
        }
    };
    let mut entries = Vec::new();
    for entry in read_entries {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(source) => error(
                issues,
                "io-error",
                directory.strip_prefix(root).ok().map(path_string),
                format!("could not read directory entry: {source}"),
            ),
        }
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(value) => value,
            Err(source) => {
                error(
                    issues,
                    "io-error",
                    path.strip_prefix(root).ok().map(path_string),
                    format!("could not inspect file type: {source}"),
                );
                continue;
            }
        };
        let linked = file_type.is_symlink()
            || fs::symlink_metadata(&path)
                .is_ok_and(|metadata| is_link_or_reparse_point(&metadata));
        if linked {
            error(
                issues,
                "symlink-not-allowed",
                path.strip_prefix(root).ok().map(path_string),
                "bundle verification does not follow symbolic links".to_owned(),
            );
        } else if file_type.is_dir() {
            collect_dir(root, &path, files, issues);
        } else if file_type.is_file()
            && let Ok(relative) = path.strip_prefix(root)
        {
            files.push(relative.to_path_buf());
        }
    }
}

#[cfg(windows)]
fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn is_markdown(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("md"))
}

fn validate_portable_file_collisions(files: &[PathBuf], issues: &mut Vec<VerificationIssue>) {
    let mut portable_paths = BTreeMap::new();
    for path in files {
        let relative = normalize_slashes(path);
        let portable = relative.to_lowercase();
        if let Some(previous) = portable_paths.insert(portable, relative.clone()) {
            error(
                issues,
                "duplicate-portable-path",
                Some(relative.clone()),
                format!("bundle path `{relative}` collides with `{previous}`"),
            );
        }
    }
}

fn validate_root_index(root: &Path, files: &[PathBuf], issues: &mut Vec<VerificationIssue>) {
    let Some(index) = files
        .iter()
        .find(|path| normalize_slashes(path).eq_ignore_ascii_case("index.md"))
    else {
        warning(
            issues,
            "missing-root-index",
            None,
            "root index.md is recommended for progressive disclosure".to_owned(),
        );
        return;
    };
    let Some(contents) = read_text(root, index, issues) else {
        return;
    };
    let Some((yaml, _)) = split_frontmatter(&contents) else {
        warning(
            issues,
            "missing-okf-version",
            Some(path_string(index)),
            "root index.md does not declare okf_version".to_owned(),
        );
        return;
    };
    match serde_yaml::from_str::<BTreeMap<String, serde_yaml::Value>>(yaml) {
        Ok(metadata) => match metadata.get("okf_version").and_then(value_as_string) {
            Some(version) if version == OKF_VERSION => {}
            Some(version) => error(
                issues,
                "unsupported-okf-version",
                Some(path_string(index)),
                format!("expected OKF {OKF_VERSION}, found `{version}`"),
            ),
            None => warning(
                issues,
                "missing-okf-version",
                Some(path_string(index)),
                "root index.md does not declare okf_version".to_owned(),
            ),
        },
        Err(source) => error(
            issues,
            "invalid-index-frontmatter",
            Some(path_string(index)),
            format!("could not parse root index frontmatter: {source}"),
        ),
    }
}

fn validate_index(root: &Path, relative: &Path, issues: &mut Vec<VerificationIssue>) {
    if relative.components().count() == 1 {
        return;
    }
    let Some(contents) = read_text(root, relative, issues) else {
        return;
    };
    if split_frontmatter(&contents).is_some() {
        error(
            issues,
            "nested-index-frontmatter",
            Some(path_string(relative)),
            "only the bundle-root index.md may carry frontmatter".to_owned(),
        );
    }
}

fn validate_log(root: &Path, relative: &Path, issues: &mut Vec<VerificationIssue>) {
    let Some(contents) = read_text(root, relative, issues) else {
        return;
    };
    if split_frontmatter(&contents).is_some() {
        error(
            issues,
            "log-frontmatter",
            Some(path_string(relative)),
            "log.md must not carry concept frontmatter".to_owned(),
        );
    }
    for line in contents.lines().filter(|line| line.starts_with("## ")) {
        if NaiveDate::parse_from_str(line.trim_start_matches("## ").trim(), "%Y-%m-%d").is_err() {
            error(
                issues,
                "invalid-log-date",
                Some(path_string(relative)),
                format!("log date heading must use YYYY-MM-DD: `{line}`"),
            );
        }
    }
}

fn validate_reserved_links(
    root: &Path,
    markdown_files: &[PathBuf],
    existing: &BTreeSet<String>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) {
    for relative in markdown_files {
        let filename = relative
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        if !matches!(filename.as_deref(), Some("index.md" | "log.md")) {
            continue;
        }
        let Some(contents) = read_text(root, relative, issues) else {
            continue;
        };
        let body = split_frontmatter(&contents).map_or(contents.as_str(), |(_, body)| body);
        validate_markdown_links(
            relative,
            &markdown_without_code(body),
            existing,
            options,
            issues,
        );
    }
}

fn parse_concept(
    root: &Path,
    relative: &Path,
    issues: &mut Vec<VerificationIssue>,
) -> Option<ParsedConcept> {
    let contents = read_text(root, relative, issues)?;
    let Some((yaml, body)) = split_frontmatter(&contents) else {
        error(
            issues,
            "missing-frontmatter",
            Some(path_string(relative)),
            "concept must start with YAML frontmatter".to_owned(),
        );
        return None;
    };
    let metadata = match serde_yaml::from_str::<OkfMetadata>(yaml) {
        Ok(metadata) => metadata,
        Err(source) => {
            error(
                issues,
                "invalid-frontmatter",
                Some(path_string(relative)),
                format!("could not parse concept frontmatter: {source}"),
            );
            return None;
        }
    };
    if metadata.concept_type.trim().is_empty() {
        error(
            issues,
            "empty-concept-type",
            Some(path_string(relative)),
            "frontmatter `type` must be a non-empty string".to_owned(),
        );
    }
    let id = relative
        .with_extension("")
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if let Err(source) = concept_path(&id) {
        error(
            issues,
            "invalid-concept-id",
            Some(path_string(relative)),
            format!("concept path is not portable: {source}"),
        );
    }
    Some(ParsedConcept {
        relative_path: relative.to_path_buf(),
        id,
        metadata,
        body: body.to_owned(),
    })
}

#[allow(clippy::too_many_lines)]
fn validate_concepts(
    concepts: &[ParsedConcept],
    existing: &BTreeSet<String>,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) {
    let footnote =
        Regex::new(r"\[\^(?P<id>[^\]]+)\]").expect("static Markdown footnote regex must compile");
    let mut bundle_claim_ids = BTreeSet::new();
    let mut actual_projected_relationships = BTreeSet::new();

    for concept in concepts {
        let document = Some(path_string(&concept.relative_path));
        if concept
            .metadata
            .generated
            .as_ref()
            .is_some_and(|generated| !actor_has_identity(&generated.by))
        {
            error(
                issues,
                "empty-generated-actor",
                document.clone(),
                "generated.by must identify an actor".to_owned(),
            );
        }
        for verification in &concept.metadata.verified {
            if !actor_has_identity(&verification.by) {
                error(
                    issues,
                    "empty-verification-actor",
                    document.clone(),
                    "verified[].by must identify an actor".to_owned(),
                );
            }
        }
        if concept
            .metadata
            .usage_window
            .as_ref()
            .is_some_and(|window| window.from > window.to)
        {
            error(
                issues,
                "invalid-usage-window",
                document.clone(),
                "usage_window.from must not be after usage_window.to".to_owned(),
            );
        }
        if let Some(resource) = concept.metadata.resource.as_deref() {
            validate_path_value(&concept.relative_path, resource, "resource", issues);
        }
        validate_computation_paths(concept, issues);
        for source in &concept.metadata.sources {
            validate_path_value(
                &concept.relative_path,
                &source.resource,
                "sources[].resource",
                issues,
            );
        }
        let source_by_evidence = validate_sources(concept, evidence, issues);
        let source_ids = concept
            .metadata
            .sources
            .iter()
            .filter_map(|source| source.id.as_deref())
            .collect::<BTreeSet<_>>();

        let visible_body = markdown_without_code(&concept.body);
        validate_markdown_links(
            &concept.relative_path,
            &visible_body,
            existing,
            options,
            issues,
        );
        for capture in footnote.captures_iter(&visible_body) {
            let Some(id) = capture.name("id").map(|value| value.as_str()) else {
                continue;
            };
            if !source_ids.contains(id) {
                error(
                    issues,
                    "unresolved-source-footnote",
                    document.clone(),
                    format!("footnote `^{id}` does not resolve to sources[].id"),
                );
            }
        }

        if let Some(extension) = &concept.metadata.repo2okf {
            for relationship in &extension.relationships {
                let target = format!(
                    "/{}.md",
                    relationship
                        .target
                        .strip_suffix(".md")
                        .unwrap_or(&relationship.target)
                );
                validate_link(&concept.relative_path, &target, existing, options, issues);
                let derived = !relationship.source_relationship_ids.is_empty()
                    || !relationship.origin_reference_ids.is_empty()
                    || !relationship.evidence_ids.is_empty();
                if derived && relationship.evidence_ids.is_empty() {
                    error(
                        issues,
                        "relationship-without-evidence",
                        document.clone(),
                        format!(
                            "repository-derived relationship to `{}` has no evidence IDs",
                            relationship.target
                        ),
                    );
                }
                let semantic = relationship
                    .kind
                    .as_deref()
                    .is_some_and(is_semantic_relationship_kind);
                if semantic && (options.semantic_inventory.is_some() || derived) {
                    if relationship.source_relationship_ids.is_empty() {
                        error(
                            issues,
                            "semantic-relationship-without-graph-edge",
                            document.clone(),
                            format!(
                                "semantic relationship `{}` to `{}` has no graph relationship ID",
                                relationship.kind.as_deref().unwrap_or_default(),
                                relationship.target
                            ),
                        );
                    }
                    if relationship.origin_reference_ids.is_empty() {
                        error(
                            issues,
                            "semantic-relationship-without-origin",
                            document.clone(),
                            format!(
                                "semantic relationship `{}` to `{}` has no origin reference",
                                relationship.kind.as_deref().unwrap_or_default(),
                                relationship.target
                            ),
                        );
                    }
                }
                if options
                    .semantic_inventory
                    .as_ref()
                    .is_some_and(|inventory| inventory.projection_contract_complete)
                    && is_projection_contract_relationship(relationship)
                    && !actual_projected_relationships.insert(
                        ProjectedSemanticRelationship::from_okf(&concept.id, relationship),
                    )
                {
                    error(
                        issues,
                        "duplicate-semantic-projection",
                        document.clone(),
                        format!(
                            "semantic relationship `{}` to `{}` is projected more than once",
                            relationship.kind.as_deref().unwrap_or_default(),
                            relationship.target
                        ),
                    );
                }
                validate_relationship_ids(
                    concept,
                    relationship,
                    evidence,
                    &source_by_evidence,
                    options.semantic_inventory.as_ref(),
                    issues,
                );
            }
            if let Some(architecture) = &extension.architecture {
                validate_architecture_metadata(
                    concept,
                    architecture,
                    evidence,
                    &source_by_evidence,
                    options.semantic_inventory.as_ref(),
                    issues,
                );
            }
            for claim in &extension.claims {
                let bundle_claim_id = format!("{}:{}", concept.id, claim.id);
                if claim.id.trim().is_empty() || !bundle_claim_ids.insert(bundle_claim_id) {
                    error(
                        issues,
                        "duplicate-claim-id",
                        document.clone(),
                        format!("claim ID `{}` is empty or duplicated", claim.id),
                    );
                }
                if claim.evidence_ids.is_empty() {
                    error(
                        issues,
                        "claim-without-evidence",
                        document.clone(),
                        format!("claim `{}` has no evidence IDs", claim.id),
                    );
                }
                for id in &claim.evidence_ids {
                    if !evidence.contains_key(id.as_str()) {
                        error(
                            issues,
                            "unresolved-evidence-id",
                            document.clone(),
                            format!("claim `{}` references unknown evidence `{id}`", claim.id),
                        );
                    } else if !source_by_evidence.contains(id.as_str()) {
                        error(
                            issues,
                            "claim-evidence-not-sourced",
                            document.clone(),
                            format!(
                                "claim `{}` evidence `{id}` has no matching sources[].evidence_id",
                                claim.id
                            ),
                        );
                    }
                }
            }
            if extension.claims.iter().any(|claim| claim.ai_generated)
                && !concept.metadata.verified.is_empty()
                && !concept
                    .metadata
                    .verified
                    .iter()
                    .any(|event| is_independent_verifier(&event.by))
            {
                error(
                    issues,
                    "ai-only-verification",
                    document.clone(),
                    "LLM generation or evidence binding does not itself qualify as OKF verification"
                        .to_owned(),
                );
            }
        }

        if concept
            .metadata
            .generated
            .as_ref()
            .is_some_and(|event| is_agent_actor(&event.by))
            && !concept.metadata.verified.is_empty()
            && !concept
                .metadata
                .verified
                .iter()
                .any(|event| is_independent_verifier(&event.by))
        {
            error(
                issues,
                "ai-only-verification",
                document.clone(),
                "agent-generated content requires independent human or process verification"
                    .to_owned(),
            );
        }

        if let Some(stale_after) = concept.metadata.stale_after
            && options.today >= stale_after
        {
            issue(
                issues,
                "stale-document",
                if options.stale_documents_are_errors {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                document,
                format!("concept is stale as of {stale_after}"),
            );
        }
    }

    if let Some(inventory) = options
        .semantic_inventory
        .as_ref()
        .filter(|inventory| inventory.projection_contract_complete)
    {
        let expected = inventory
            .projected_relationships
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        for missing in expected.difference(&actual_projected_relationships) {
            error(
                issues,
                "missing-semantic-projection",
                None,
                format!(
                    "bundle omits canonical relationship {} --{}--> {}",
                    missing.source_concept_id, missing.kind, missing.target_concept_id
                ),
            );
        }
        for unexpected in actual_projected_relationships.difference(&expected) {
            error(
                issues,
                "unexpected-semantic-projection",
                None,
                format!(
                    "bundle contains non-canonical relationship {} --{}--> {}",
                    unexpected.source_concept_id, unexpected.kind, unexpected.target_concept_id
                ),
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_sources<'a>(
    concept: &'a ParsedConcept,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    issues: &mut Vec<VerificationIssue>,
) -> BTreeSet<&'a str> {
    let document = Some(path_string(&concept.relative_path));
    let mut source_ids = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    for source in &concept.metadata.sources {
        if source.resource.trim().is_empty() {
            error(
                issues,
                "empty-source-resource",
                document.clone(),
                "sources[].resource must not be empty".to_owned(),
            );
        }
        if source
            .author
            .as_deref()
            .is_some_and(|author| !actor_has_identity(author))
        {
            error(
                issues,
                "invalid-source-author",
                document.clone(),
                format!(
                    "source `{}` has an invalid author actor",
                    source.id.as_deref().unwrap_or(&source.resource)
                ),
            );
        }
        if let Some(id) = source.id.as_deref()
            && (id.trim().is_empty() || !source_ids.insert(id))
        {
            error(
                issues,
                "duplicate-source-id",
                document.clone(),
                format!("source ID `{id}` is empty or duplicated within the concept"),
            );
        }
        if source
            .usage_window
            .as_ref()
            .is_some_and(|window| window.from > window.to)
        {
            error(
                issues,
                "invalid-usage-window",
                document.clone(),
                format!(
                    "source `{}` usage_window.from must not be after usage_window.to",
                    source.id.as_deref().unwrap_or(&source.resource)
                ),
            );
        }
        if source.usage_count.is_some()
            && source.usage_window.is_none()
            && concept.metadata.usage_window.is_none()
        {
            warning(
                issues,
                "usage-count-without-window",
                document.clone(),
                format!(
                    "source `{}` has usage_count without a usage_window",
                    source.id.as_deref().unwrap_or(&source.resource)
                ),
            );
        }
        let Some(evidence_id) = source.evidence_id.as_deref() else {
            continue;
        };
        if !evidence_ids.insert(evidence_id) {
            error(
                issues,
                "duplicate-source-evidence",
                document.clone(),
                format!("evidence `{evidence_id}` occurs in more than one source entry"),
            );
        }
        match evidence.get(evidence_id) {
            None => error(
                issues,
                "unresolved-evidence-id",
                document.clone(),
                format!("source references unknown evidence `{evidence_id}`"),
            ),
            Some(record)
                if source.content_hash.as_deref() != Some(record.content_hash.as_str()) =>
            {
                error(
                    issues,
                    "stale-evidence-hash",
                    document.clone(),
                    format!(
                        "source evidence `{evidence_id}` hash does not match the current repository IR"
                    ),
                );
            }
            Some(_) => {}
        }
        if let Some(record) = evidence.get(evidence_id) {
            validate_evidence_resource(concept, source, record, issues);
        }
    }
    evidence_ids
}

fn validate_relationship_ids(
    concept: &ParsedConcept,
    relationship: &OkfRelationship,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    source_by_evidence: &BTreeSet<&str>,
    semantic_inventory: Option<&SemanticInventory>,
    issues: &mut Vec<VerificationIssue>,
) {
    let document = Some(path_string(&concept.relative_path));
    for (field, ids) in [
        (
            "source_relationship_ids",
            relationship.source_relationship_ids.as_slice(),
        ),
        (
            "origin_reference_ids",
            relationship.origin_reference_ids.as_slice(),
        ),
        ("evidence_ids", relationship.evidence_ids.as_slice()),
    ] {
        let mut seen = BTreeSet::new();
        for id in ids {
            if id.trim().is_empty() {
                error(
                    issues,
                    "invalid-relationship-provenance",
                    document.clone(),
                    format!(
                        "relationship to `{}` contains an empty {field} entry",
                        relationship.target
                    ),
                );
            } else if !seen.insert(id) {
                error(
                    issues,
                    "duplicate-relationship-provenance",
                    document.clone(),
                    format!(
                        "relationship to `{}` repeats `{id}` in {field}",
                        relationship.target
                    ),
                );
            }
        }
    }

    for id in &relationship.evidence_ids {
        if !evidence.contains_key(id.as_str()) {
            error(
                issues,
                "unresolved-evidence-id",
                document.clone(),
                format!(
                    "relationship to `{}` references unknown evidence `{id}`",
                    relationship.target
                ),
            );
        } else if !source_by_evidence.contains(id.as_str()) {
            error(
                issues,
                "relationship-evidence-not-sourced",
                document.clone(),
                format!(
                    "relationship to `{}` evidence `{id}` has no matching sources[].evidence_id",
                    relationship.target
                ),
            );
        }
    }

    if let Some(inventory) = semantic_inventory {
        for id in &relationship.source_relationship_ids {
            if !inventory.relationship_ids.iter().any(|known| known == id) {
                error(
                    issues,
                    "unknown-graph-relationship",
                    document.clone(),
                    format!(
                        "relationship to '{}' cites unknown graph edge '{id}'",
                        relationship.target
                    ),
                );
            }
        }
        for id in &relationship.origin_reference_ids {
            if !inventory
                .resolved_reference_ids
                .iter()
                .any(|known| known == id)
            {
                error(
                    issues,
                    "non-resolved-relationship-origin",
                    document.clone(),
                    format!(
                        "relationship to '{}' cites missing or non-resolved reference '{id}'",
                        relationship.target
                    ),
                );
            }
        }
        validate_semantic_projection_tuple(concept, relationship, inventory, document, issues);
    }
}

fn validate_semantic_projection_tuple(
    concept: &ParsedConcept,
    relationship: &OkfRelationship,
    inventory: &SemanticInventory,
    document: Option<String>,
    issues: &mut Vec<VerificationIssue>,
) {
    if !inventory.projection_contract_complete || !is_projection_contract_relationship(relationship)
    {
        return;
    }
    let projected = ProjectedSemanticRelationship::from_okf(&concept.id, relationship);
    if !inventory.projected_relationships.contains(&projected) {
        error(
            issues,
            "semantic-projection-mismatch",
            document,
            format!(
                "semantic relationship to '{}' does not match its canonical repository projection",
                relationship.target
            ),
        );
    }
}

#[allow(clippy::too_many_lines)]
fn validate_architecture_metadata(
    concept: &ParsedConcept,
    architecture: &OkfArchitectureConcept,
    evidence: &BTreeMap<&str, &EvidenceRecord>,
    source_by_evidence: &BTreeSet<&str>,
    semantic_inventory: Option<&SemanticInventory>,
    issues: &mut Vec<VerificationIssue>,
) {
    let document = Some(path_string(&concept.relative_path));
    if concept.metadata.status != Some(crate::model::OkfStatus::Draft) {
        error(
            issues,
            "architecture-not-draft",
            document.clone(),
            "agent-proposed architecture concepts must remain draft".to_owned(),
        );
    }
    if !concept
        .metadata
        .generated
        .as_ref()
        .is_some_and(|event| is_agent_actor(&event.by))
    {
        error(
            issues,
            "architecture-without-agent-provenance",
            document.clone(),
            "architecture concept must identify the proposing agent".to_owned(),
        );
    }
    if architecture.source_concept_id.trim().is_empty()
        || architecture.member_entity_ids.len() < 2
        || architecture.supporting_relationship_ids.is_empty()
        || architecture.evidence_ids.is_empty()
    {
        error(
            issues,
            "invalid-architecture-support",
            document.clone(),
            "architecture concept lacks graph members, support, or evidence".to_owned(),
        );
    }
    for (field, ids) in [
        (
            "member_entity_ids",
            architecture.member_entity_ids.as_slice(),
        ),
        (
            "supporting_relationship_ids",
            architecture.supporting_relationship_ids.as_slice(),
        ),
        ("evidence_ids", architecture.evidence_ids.as_slice()),
    ] {
        let mut seen = BTreeSet::new();
        for id in ids {
            if id.trim().is_empty() || !seen.insert(id) {
                error(
                    issues,
                    "invalid-architecture-support",
                    document.clone(),
                    format!("{field} contains an empty or duplicate ID"),
                );
            }
        }
    }
    for id in &architecture.evidence_ids {
        if !evidence.contains_key(id.as_str()) {
            error(
                issues,
                "unresolved-evidence-id",
                document.clone(),
                format!("architecture concept references unknown evidence '{id}'"),
            );
        } else if !source_by_evidence.contains(id.as_str()) {
            error(
                issues,
                "architecture-evidence-not-sourced",
                document.clone(),
                format!("architecture evidence '{id}' has no matching sources[].evidence_id"),
            );
        }
    }
    if let Some(inventory) = semantic_inventory {
        if !inventory
            .architecture_concept_ids
            .iter()
            .any(|known| known == &architecture.source_concept_id)
        {
            error(
                issues,
                "unknown-architecture-concept",
                document.clone(),
                format!(
                    "architecture source concept '{}' is absent from the repository IR",
                    architecture.source_concept_id
                ),
            );
        }
        for id in &architecture.member_entity_ids {
            if !inventory.entity_ids.iter().any(|known| known == id) {
                error(
                    issues,
                    "unknown-architecture-member",
                    document.clone(),
                    format!("architecture member '{id}' is absent from the repository IR"),
                );
            }
        }
        for id in &architecture.supporting_relationship_ids {
            if !inventory.relationship_ids.iter().any(|known| known == id) {
                error(
                    issues,
                    "unknown-graph-relationship",
                    document.clone(),
                    format!("architecture support edge '{id}' is absent from the repository IR"),
                );
            }
        }
        if architecture.scope != inventory.architecture_scope {
            error(
                issues,
                "architecture-scope-mismatch",
                document,
                "architecture scope differs from the repository IR".to_owned(),
            );
        }
    }
}

fn validate_computation_paths(concept: &ParsedConcept, issues: &mut Vec<VerificationIssue>) {
    if let Some(value) = concept
        .metadata
        .extensions
        .get("computation")
        .and_then(serde_yaml::Value::as_str)
    {
        validate_path_value(&concept.relative_path, value, "computation", issues);
    }
    for family in ["executor", "attester"] {
        let Some(resource) = concept
            .metadata
            .extensions
            .get(family)
            .and_then(serde_yaml::Value::as_mapping)
            .and_then(|mapping| mapping.get(serde_yaml::Value::String("resource".to_owned())))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        validate_path_value(
            &concept.relative_path,
            resource,
            &format!("{family}.resource"),
            issues,
        );
    }
}

fn validate_evidence_resource(
    concept: &ParsedConcept,
    source: &crate::model::OkfSource,
    evidence: &EvidenceRecord,
    issues: &mut Vec<VerificationIssue>,
) {
    let Some(resource) = source.resource.strip_prefix("repo:") else {
        return;
    };
    let (raw_path, fragment) = resource
        .split_once('#')
        .map_or((resource, None), |(path, fragment)| (path, Some(fragment)));
    let decoded_path = percent_decode(raw_path);
    if decoded_path.replace('\\', "/") != evidence.path.replace('\\', "/") {
        error(
            issues,
            "evidence-resource-mismatch",
            Some(path_string(&concept.relative_path)),
            format!(
                "source evidence `{}` displays `{decoded_path}` instead of `{}`",
                evidence.id, evidence.path
            ),
        );
    }
    if let Some(expected) = evidence.line {
        let actual = fragment
            .and_then(|fragment| fragment.strip_prefix('L'))
            .and_then(|line| line.parse::<u32>().ok());
        if actual != Some(expected) {
            error(
                issues,
                "evidence-line-mismatch",
                Some(path_string(&concept.relative_path)),
                format!(
                    "source evidence `{}` line fragment does not match line {expected}",
                    evidence.id
                ),
            );
        }
    }
}

fn validate_markdown_links(
    source: &Path,
    body: &str,
    existing: &BTreeSet<String>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) {
    let inline = Regex::new(r#"!?\[[^\]]*\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)"#)
        .expect("static Markdown link regex must compile");
    let reference = Regex::new(r"(?m)^\s*\[[^\]^][^\]]*\]:\s*(?P<target>\S+)")
        .expect("static Markdown reference regex must compile");
    for captures in inline
        .captures_iter(body)
        .chain(reference.captures_iter(body))
    {
        let Some(target) = captures.name("target").map(|value| value.as_str()) else {
            continue;
        };
        validate_link(
            source,
            target.trim_matches(['<', '>']),
            existing,
            options,
            issues,
        );
    }
}

fn markdown_without_code(body: &str) -> String {
    let mut visible = String::with_capacity(body.len());
    let mut fence: Option<char> = None;
    for line in body.lines() {
        let trimmed = line.trim_start();
        let marker = if trimmed.starts_with("```") {
            Some('`')
        } else if trimmed.starts_with("~~~") {
            Some('~')
        } else {
            None
        };
        if let Some(marker) = marker {
            fence = if fence == Some(marker) {
                None
            } else if fence.is_none() {
                Some(marker)
            } else {
                fence
            };
            visible.push('\n');
        } else if fence.is_some() || line.starts_with("    ") || line.starts_with('\t') {
            visible.push('\n');
        } else {
            let mut in_code = false;
            for character in line.chars() {
                if character == '`' {
                    in_code = !in_code;
                    visible.push(' ');
                } else if in_code {
                    visible.push(' ');
                } else {
                    visible.push(character);
                }
            }
            visible.push('\n');
        }
    }
    visible
}

fn validate_link(
    source: &Path,
    raw_target: &str,
    existing: &BTreeSet<String>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) {
    if is_external_target(raw_target) || raw_target.starts_with('#') {
        return;
    }
    let target = raw_target
        .split(['#', '?'])
        .next()
        .map(percent_decode)
        .unwrap_or_default();
    if target.is_empty() {
        return;
    }
    let base = source.parent().unwrap_or_else(|| Path::new(""));
    let initial = if target.starts_with('/') {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    let target = target.trim_start_matches('/').replace('\\', "/");
    let Some(normalized) = normalize_relative(initial, Path::new(&target)) else {
        error(
            issues,
            "path-traversal",
            Some(path_string(source)),
            format!("link escapes the bundle root: `{raw_target}`"),
        );
        return;
    };
    let mut candidates = vec![normalize_slashes(&normalized)];
    if normalized.extension().is_none() {
        candidates.push(normalize_slashes(&normalized.with_extension("md")));
        candidates.push(normalize_slashes(&normalized.join("index.md")));
    }
    if !candidates
        .iter()
        .any(|candidate| existing.contains(candidate))
    {
        issue(
            issues,
            "broken-link",
            if options.broken_links_are_errors {
                Severity::Error
            } else {
                Severity::Warning
            },
            Some(path_string(source)),
            format!("link target does not exist: `{raw_target}`"),
        );
    }
}

fn validate_path_value(
    source: &Path,
    raw_target: &str,
    field: &str,
    issues: &mut Vec<VerificationIssue>,
) {
    if let Some(repository_path) = raw_target.strip_prefix("repo:") {
        let repository_path =
            percent_decode(repository_path.split('#').next().unwrap_or(repository_path));
        if unsafe_repository_path(&repository_path) {
            error(
                issues,
                "path-traversal",
                Some(path_string(source)),
                format!("{field} escapes the repository root: `{raw_target}`"),
            );
        }
        return;
    }
    if is_external_target(raw_target) || !looks_path_like(raw_target) {
        return;
    }
    let target = raw_target
        .split(['#', '?'])
        .next()
        .map(percent_decode)
        .unwrap_or_default();
    let base = source.parent().unwrap_or_else(|| Path::new(""));
    let initial = if target.starts_with('/') {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    let target = target.trim_start_matches('/').replace('\\', "/");
    if normalize_relative(initial, Path::new(&target)).is_none() {
        error(
            issues,
            "path-traversal",
            Some(path_string(source)),
            format!("{field} escapes the bundle root: `{raw_target}`"),
        );
    }
}

#[allow(clippy::cast_precision_loss)]
fn validate_coverage(
    coverage: &[CoverageItem],
    concepts: &BTreeSet<String>,
    options: &VerifyOptions,
    issues: &mut Vec<VerificationIssue>,
) -> f64 {
    let mut seen = BTreeSet::new();
    let mut included = 0_usize;
    let mut unresolved = 0_usize;
    for item in coverage {
        if item.id.trim().is_empty() || !seen.insert(item.id.as_str()) {
            error(
                issues,
                "duplicate-coverage-id",
                None,
                format!("coverage ID `{}` is empty or duplicated", item.id),
            );
        }
        match &item.classification {
            CoverageClassification::Included { concept_id } => {
                included += 1;
                let concept_id = concept_id
                    .strip_suffix(".md")
                    .unwrap_or(concept_id)
                    .replace('\\', "/");
                if !concepts.contains(&concept_id.to_lowercase()) {
                    error(
                        issues,
                        "missing-covered-concept",
                        None,
                        format!(
                            "coverage item `{}` includes missing concept `{concept_id}`",
                            item.id
                        ),
                    );
                }
            }
            CoverageClassification::Excluded { reason } => {
                if reason.trim().is_empty() {
                    error(
                        issues,
                        "empty-exclusion-reason",
                        None,
                        format!("coverage item `{}` has no exclusion reason", item.id),
                    );
                }
            }
            CoverageClassification::Unresolved => unresolved += 1,
        }
    }
    let accountable = included + unresolved;
    let ratio = if accountable == 0 {
        1.0
    } else {
        included as f64 / accountable as f64
    };
    if options.minimum_coverage.is_finite()
        && (0.0..=1.0).contains(&options.minimum_coverage)
        && ratio + f64::EPSILON < options.minimum_coverage
    {
        error(
            issues,
            "coverage-below-threshold",
            None,
            format!(
                "included coverage {:.2}% is below required {:.2}%",
                ratio * 100.0,
                options.minimum_coverage * 100.0
            ),
        );
    }
    ratio
}

fn normalize_relative(mut result: PathBuf, target: &Path) -> Option<PathBuf> {
    for component in target.components() {
        match component {
            Component::Normal(value) => result.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(result)
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
        || path
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
}

fn split_frontmatter(contents: &str) -> Option<(&str, &str)> {
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    if let Some(rest) = contents.strip_prefix("---\n") {
        let (yaml, body) = rest.split_once("\n---\n")?;
        return Some((yaml, body));
    }
    let rest = contents.strip_prefix("---\r\n")?;
    let (yaml, body) = rest.split_once("\r\n---\r\n")?;
    Some((yaml, body))
}

fn read_text(root: &Path, relative: &Path, issues: &mut Vec<VerificationIssue>) -> Option<String> {
    let path = root.join(relative);
    match fs::read_to_string(&path) {
        Ok(contents) => Some(contents),
        Err(source) => {
            error(
                issues,
                "invalid-utf8-or-io",
                Some(path_string(relative)),
                format!("could not read UTF-8 Markdown: {source}"),
            );
            None
        }
    }
}

fn value_as_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn is_semantic_relationship_kind(kind: &str) -> bool {
    matches!(kind, "calls" | "extends" | "type_uses" | "decorated_by")
}

fn is_projection_contract_relationship(relationship: &OkfRelationship) -> bool {
    !relationship.origin_reference_ids.is_empty()
        || (relationship.kind.as_deref() == Some("depends_on")
            && !relationship.source_relationship_ids.is_empty())
}

fn is_external_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("mailto:")
        || lower.starts_with("data:")
        || lower.starts_with("repo:")
        || lower.starts_with("urn:")
}

fn looks_path_like(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.contains('/')
        || value.contains('\\')
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

fn normalize_slashes(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn path_string(path: &Path) -> String {
    normalize_slashes(path)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2]))
        {
            result.push((high << 4) | low);
            index += 3;
            continue;
        }
        result.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&result).into_owned()
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
    }
}

fn error(
    issues: &mut Vec<VerificationIssue>,
    code: &str,
    document: Option<String>,
    message: String,
) {
    issue(issues, code, Severity::Error, document, message);
}

fn warning(
    issues: &mut Vec<VerificationIssue>,
    code: &str,
    document: Option<String>,
    message: String,
) {
    issue(issues, code, Severity::Warning, document, message);
}

fn issue(
    issues: &mut Vec<VerificationIssue>,
    code: &str,
    severity: Severity,
    document: Option<String>,
    message: String,
) {
    issues.push(VerificationIssue {
        code: code.to_owned(),
        severity,
        document,
        message,
    });
}
