//! Public OKF v0.2 data model.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml::Value;
use thiserror::Error;

/// The OKF version emitted by this crate.
pub const OKF_VERSION: &str = "0.2";

/// One OKF concept document.
///
/// The document identifier is the bundle-relative path without the `.md`
/// suffix. It is deliberately not serialized into frontmatter because OKF
/// derives concept identity from the document path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OkfDocument {
    /// Bundle-relative concept ID (for example, `modules/auth`).
    #[serde(skip)]
    pub id: String,
    /// Standard and producer-defined frontmatter.
    #[serde(flatten)]
    pub metadata: OkfMetadata,
    /// Markdown following the YAML frontmatter.
    #[serde(skip)]
    pub body: String,
    /// Explicit relationships used to render stable Markdown links.
    #[serde(skip)]
    pub relationships: Vec<OkfRelationship>,
    /// Evidence-bound claims used by the stricter `Repo2OKF` verifier.
    #[serde(skip)]
    pub claims: Vec<OkfClaim>,
}

impl OkfDocument {
    /// Construct a concept document with the only frontmatter field required
    /// by OKF v0.2.
    pub fn new(id: impl Into<String>, concept_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            metadata: OkfMetadata::new(concept_type),
            body: String::new(),
            relationships: Vec::new(),
            claims: Vec::new(),
        }
    }

    /// Return the canonical output path for this concept.
    ///
    /// # Errors
    ///
    /// Returns [`DocumentPathError`] if the ID is unsafe or not portable.
    pub fn relative_path(&self) -> Result<PathBuf, DocumentPathError> {
        concept_path(&self.id)
    }
}

/// OKF v0.2 frontmatter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OkfMetadata {
    /// Concept type. This is the only always-required OKF field.
    #[serde(rename = "type")]
    pub concept_type: String,
    /// Human-readable display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// One-line summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Canonical URI or path for the represented resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// Cross-cutting categorization tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Materials from which this concept was derived.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<OkfSource>,
    /// Shared usage window for source `usage_count` signals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_window: Option<UsageWindow>,
    /// Who or what generated the current content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated: Option<Generated>,
    /// Independent confirmations of the current content.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_verified",
        serialize_with = "serialize_verified"
    )]
    pub verified: Vec<Verification>,
    /// Lifecycle state. Absence means `stable` in OKF.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<OkfStatus>,
    /// Absolute date on/after which the concept is stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_after: Option<NaiveDate>,
    /// `Repo2OKF`'s evidence and relationship extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo2okf: Option<Repo2OkfMetadata>,
    /// Producer-defined fields, preserved during round trips.
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, Value>,
}

impl OkfMetadata {
    /// Construct frontmatter with a concept type.
    pub fn new(concept_type: impl Into<String>) -> Self {
        Self {
            concept_type: concept_type.into(),
            title: None,
            description: None,
            resource: None,
            tags: Vec::new(),
            sources: Vec::new(),
            usage_window: None,
            generated: None,
            verified: Vec::new(),
            status: None,
            stale_after: None,
            repo2okf: None,
            extensions: BTreeMap::new(),
        }
    }
}

/// Producer extension that makes evidence-bound generation mechanically
/// verifiable without changing OKF's standard fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repo2OkfMetadata {
    /// Structured semantic claims rendered into the Markdown body.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<OkfClaim>,
    /// Structured relationships rendered as standard Markdown links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<OkfRelationship>,
}

/// A stable source entry in a concept's provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkfSource {
    /// Optional stable key for per-claim attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Required concrete artifact, path, URI, or scope descriptor.
    pub resource: String,
    /// Human-readable source label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Actor that produced the source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Coarse source usage/liveness signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_count: Option<u64>,
    /// Date on which the source itself last changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<NaiveDate>,
    /// Per-source override for the shared usage window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_window: Option<UsageWindow>,
    /// `Repo2OKF` evidence identifier backing this source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    /// Hash of the source bytes when the concept was generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// Date range framing a `usage_count` signal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageWindow {
    /// Inclusive window start.
    pub from: NaiveDate,
    /// Inclusive window end.
    pub to: NaiveDate,
}

/// Content generation event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generated {
    /// Actor following the OKF actor convention.
    pub by: String,
    /// Last meaningful content change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<DateTime<Utc>>,
}

/// Content verification event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// Human or deterministic-process actor.
    pub by: String,
    /// Verification time.
    pub at: DateTime<Utc>,
}

/// OKF lifecycle state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OkfStatus {
    /// Incomplete or not yet reviewed.
    Draft,
    /// Ready for consumption (also the implicit default).
    #[default]
    Stable,
    /// Retained only for history and incoming links.
    Deprecated,
}

/// A directed relationship between two concept IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkfRelationship {
    /// Target concept ID.
    pub target: String,
    /// Human-facing link label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Producer-defined relationship kind. OKF links themselves are untyped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// A semantic assertion and its `Repo2OKF` evidence bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkfClaim {
    /// Stable claim identifier within the bundle.
    pub id: String,
    /// Human-readable assertion.
    pub text: String,
    /// Evidence identifiers that must resolve against the repository IR.
    #[serde(default)]
    pub evidence_ids: Vec<String>,
    /// Whether the claim was proposed by an LLM.
    #[serde(default)]
    pub ai_generated: bool,
    /// Agent CLI provider that proposed this claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_provider: Option<String>,
    /// Untrusted model identifier carried by imported IR, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_reported_model: Option<String>,
}

/// A coverage item classification exported by the core scanner/planner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "classification", rename_all = "snake_case")]
pub enum CoverageClassification {
    /// Represented by the named concept.
    Included {
        /// Concept ID that covers the item.
        concept_id: String,
    },
    /// Deliberately omitted, with a non-empty rationale.
    Excluded {
        /// Reason for excluding the item.
        reason: String,
    },
    /// Not yet classified or represented.
    Unresolved,
}

/// One scannable repository item and its coverage classification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageItem {
    /// Stable scanner/planner identifier.
    pub id: String,
    /// Item classification.
    #[serde(flatten)]
    pub classification: CoverageClassification,
}

/// Bundle-level input accepted by the deterministic emitter.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct OkfBundle {
    /// Optional bundle display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Concept documents.
    #[serde(default)]
    pub documents: Vec<OkfDocument>,
    /// Coverage classifications from repository discovery.
    #[serde(default)]
    pub coverage: Vec<CoverageItem>,
}

/// Evidence material exposed by `repo2okf-core` to the verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// Stable evidence identifier.
    pub id: String,
    /// Repository-relative path.
    pub path: String,
    /// Optional source line (one-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Hash of the evidence-bearing source bytes.
    pub content_hash: String,
}

/// Repository facts required by the format emitter and verifier.
///
/// The core crate can implement [`RepositoryIrView`] directly for its richer
/// `RepositoryIr`; this portable snapshot keeps the format crate easy to test
/// and useful as an embeddable library.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    /// Repository title used in the root index.
    pub repository: String,
    /// Documents planned by the scanner/coverage planner.
    #[serde(default)]
    pub documents: Vec<OkfDocument>,
    /// Evidence lookup table.
    #[serde(default)]
    pub evidence: Vec<EvidenceRecord>,
    /// Complete coverage classification.
    #[serde(default)]
    pub coverage: Vec<CoverageItem>,
}

/// Minimal read-only view needed to emit OKF from a repository IR.
pub trait RepositoryIrView {
    /// Repository display name.
    fn repository_name(&self) -> &str;
    /// Planned documents.
    fn okf_documents(&self) -> &[OkfDocument];
    /// Evidence records.
    fn evidence_records(&self) -> &[EvidenceRecord];
    /// Coverage classifications.
    fn coverage_items(&self) -> &[CoverageItem];
}

impl RepositoryIrView for RepositorySnapshot {
    fn repository_name(&self) -> &str {
        &self.repository
    }

    fn okf_documents(&self) -> &[OkfDocument] {
        &self.documents
    }

    fn evidence_records(&self) -> &[EvidenceRecord] {
        &self.evidence
    }

    fn coverage_items(&self) -> &[CoverageItem] {
        &self.coverage
    }
}

/// Error returned when a concept ID cannot safely become a bundle path.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DocumentPathError {
    /// Empty concept ID.
    #[error("concept ID must not be empty")]
    Empty,
    /// Absolute paths are not allowed.
    #[error("concept ID must be bundle-relative: {0}")]
    Absolute(String),
    /// Traversal or platform-specific prefix was found.
    #[error("concept ID contains an unsafe path component: {0}")]
    Unsafe(String),
    /// Reserved OKF filenames cannot identify concepts.
    #[error("concept ID uses reserved filename: {0}")]
    Reserved(String),
}

/// Convert an OKF concept ID into a safe relative Markdown path.
///
/// # Errors
///
/// Returns [`DocumentPathError`] if the ID is empty, absolute, traversing,
/// reserved by OKF, or unsafe on a supported filesystem.
pub fn concept_path(id: &str) -> Result<PathBuf, DocumentPathError> {
    if id.trim().is_empty() {
        return Err(DocumentPathError::Empty);
    }
    let trimmed = id.strip_suffix(".md").unwrap_or(id);
    let normalized = trimmed.replace('\\', "/");
    let path = Path::new(&normalized);
    if path.is_absolute()
        || normalized.starts_with('/')
        || has_windows_drive_or_unc_prefix(&normalized)
    {
        return Err(DocumentPathError::Absolute(id.to_owned()));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(DocumentPathError::Unsafe(id.to_owned()));
    }
    if normalized.split('/').any(unsafe_portable_component) {
        return Err(DocumentPathError::Unsafe(id.to_owned()));
    }
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if matches!(filename.to_ascii_lowercase().as_str(), "index" | "log") {
        return Err(DocumentPathError::Reserved(id.to_owned()));
    }
    Ok(PathBuf::from(format!("{normalized}.md")))
}

fn has_windows_drive_or_unc_prefix(path: &str) -> bool {
    path.starts_with("//")
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

fn unsafe_portable_component(component: &str) -> bool {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
    {
        return true;
    }
    let basename = component
        .split_once('.')
        .map_or(component, |(basename, _)| basename)
        .to_ascii_uppercase();
    matches!(basename.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || basename.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || basename.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
}

fn serialize_verified<S>(verified: &[Verification], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    verified.serialize(serializer)
}

fn deserialize_verified<'de, D>(deserializer: D) -> Result<Vec<Verification>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Verification),
        Many(Vec<Verification>),
    }

    Option::<OneOrMany>::deserialize(deserializer).map(|value| match value {
        None => Vec::new(),
        Some(OneOrMany::One(value)) => vec![value],
        Some(OneOrMany::Many(values)) => values,
    })
}
