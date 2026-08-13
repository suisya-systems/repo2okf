//! Repository intermediate representation and evidence model.

use std::{collections::BTreeSet, path::Path};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A language understood by the initial scanner set.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// ECMAScript JavaScript.
    JavaScript,
    /// TypeScript or TSX.
    TypeScript,
    /// Go source.
    Go,
    /// Python source.
    Python,
    /// Rust source.
    Rust,
    /// Markdown documentation.
    Markdown,
}

impl Language {
    /// Stable language label used in configuration and output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Markdown => "markdown",
        }
    }

    /// Infer a supported language from a repository-relative filename.
    pub fn from_path(path: &str) -> Option<Self> {
        let extension = Path::new(path).extension()?.to_str()?;
        match extension.to_ascii_lowercase().as_str() {
            "js" | "jsx" | "mjs" | "cjs" => Some(Self::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Self::TypeScript),
            "go" => Some(Self::Go),
            "py" => Some(Self::Python),
            "rs" => Some(Self::Rust),
            "md" | "markdown" => Some(Self::Markdown),
            _ => None,
        }
    }
}

/// Deterministic repository-level metadata.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RepositoryMetadata {
    /// Display name derived from the scan root.
    pub name: String,
    /// Git commit at scan time, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    /// Whether file discovery used Git's tracked/untracked inventory.
    pub git_inventory: bool,
    /// Scanner implementation version.
    pub extractor: String,
}

/// How a discovered file was processed.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Content was parsed by a language-aware or Markdown scanner.
    Parsed,
    /// Content was inventoried, but its language is not supported yet.
    Unsupported,
    /// Content was not parsed because it is not valid UTF-8 or contains NUL.
    Binary,
    /// Content was hashed but was larger than the configured parser limit.
    TooLarge,
    /// A symbolic link was inventoried but never followed.
    SymlinkSkipped,
}

/// One discovered repository file.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct FileRecord {
    /// Normalized repository-relative path using `/` separators.
    pub path: String,
    /// Detected supported language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Size in bytes.
    pub size: u64,
    /// BLAKE3 hash of file bytes, empty only for skipped symlinks.
    pub content_hash: String,
    /// Scanner disposition.
    pub status: ScanStatus,
    /// Evidence covering the entire file when its bytes were read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
}

/// A precise, re-resolvable span of source evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EvidenceRef {
    /// Stable content-derived evidence identifier.
    pub id: String,
    /// Normalized repository-relative source path.
    pub path: String,
    /// One-based inclusive starting line.
    pub start_line: u32,
    /// One-based inclusive ending line.
    pub end_line: u32,
    /// Zero-based inclusive byte offset.
    pub start_byte: u64,
    /// Zero-based exclusive byte offset.
    pub end_byte: u64,
    /// BLAKE3 hash of the complete source file at extraction time.
    pub content_hash: String,
    /// Symbol name associated with this span.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Extractor that produced the evidence.
    pub extractor: String,
}

/// Entity kinds in the OKF-independent repository graph.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    /// A repository file.
    File,
    /// A function declaration.
    Function,
    /// A method declaration.
    Method,
    /// A class declaration.
    Class,
    /// A TypeScript interface.
    Interface,
    /// A named type declaration or alias.
    Type,
    /// An enum declaration.
    Enum,
    /// A package or module-level variable.
    Variable,
    /// A Markdown heading.
    Heading,
}

/// One source-backed graph entity.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Entity {
    /// Stable entity identifier.
    pub id: String,
    /// Entity kind.
    pub kind: EntityKind,
    /// Human-readable source name.
    pub name: String,
    /// Repository-relative source path.
    pub path: String,
    /// Source language, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    /// Evidence span establishing this entity.
    pub evidence_id: String,
}

/// A source-level import reference.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ImportRecord {
    /// File containing the import.
    pub path: String,
    /// Imported module/package specifier.
    pub specifier: String,
    /// Evidence span for the import.
    pub evidence_id: String,
}

/// Relationship types in the repository graph.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    /// A file contains a declaration or heading.
    Contains,
    /// A source file imports a module/package specifier.
    Imports,
}

/// A directed relationship backed by evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Relationship {
    /// Stable relationship identifier.
    pub id: String,
    /// Source entity identifier.
    pub source: String,
    /// Target entity ID or stable external module ID.
    pub target: String,
    /// Relationship kind.
    pub kind: RelationshipKind,
    /// Evidence establishing the edge.
    pub evidence_ids: Vec<String>,
}

/// Origin of a repository knowledge claim.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimProvenance {
    /// Claim produced by deterministic code.
    Deterministic {
        /// Process actor identifier.
        process: String,
    },
    /// Claim proposed by an agent and not automatically trusted.
    Agent {
        /// Vendor driver name.
        provider: String,
        /// Reported model, when supplied by the CLI.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
}

/// An evidence-bound statement suitable for semantic enrichment.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Claim {
    /// Stable claim ID.
    pub id: String,
    /// Human-readable statement.
    pub text: String,
    /// Evidence IDs supporting this claim.
    pub evidence_ids: Vec<String>,
    /// Claim origin.
    pub provenance: ClaimProvenance,
    /// Optional confidence from 0 through 100. It is not a trust score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

/// Inventory item type accounted for by coverage.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoverageKind {
    /// File-level coverage.
    File,
    /// Source declaration or heading coverage.
    Entity,
    /// Import edge coverage.
    Import,
}

/// Complete classification for one discovered inventory item.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CoverageDisposition {
    /// Item is represented by the named OKF concept.
    Included {
        /// Planned bundle-relative concept ID.
        concept_id: String,
    },
    /// Item is intentionally omitted with a durable reason.
    Excluded {
        /// Non-empty exclusion rationale.
        reason: String,
    },
    /// Scanner discovered the item but could not yet represent it.
    Unresolved {
        /// Optional explanation to guide a later scanner or agent pass.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// One classified coverage item.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CoverageItem {
    /// Stable coverage item identifier.
    pub id: String,
    /// Inventory kind.
    pub kind: CoverageKind,
    /// Human-readable inventory subject.
    pub subject: String,
    /// Evidence supporting discovery of the item.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    /// Exhaustive classification.
    pub disposition: CoverageDisposition,
}

/// Coverage totals and item-level accounting.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct CoverageReport {
    /// Complete item list in deterministic order.
    pub items: Vec<CoverageItem>,
    /// Number of represented items.
    pub included: usize,
    /// Number of intentionally excluded items.
    pub excluded: usize,
    /// Number of unresolved items.
    pub unresolved: usize,
}

impl CoverageReport {
    /// Construct totals from a complete item list and sort it by ID.
    pub fn from_items(mut items: Vec<CoverageItem>) -> Self {
        items.sort_by(|left, right| left.id.cmp(&right.id));
        let included = items
            .iter()
            .filter(|item| matches!(item.disposition, CoverageDisposition::Included { .. }))
            .count();
        let excluded = items
            .iter()
            .filter(|item| matches!(item.disposition, CoverageDisposition::Excluded { .. }))
            .count();
        let unresolved = items
            .iter()
            .filter(|item| matches!(item.disposition, CoverageDisposition::Unresolved { .. }))
            .count();
        Self {
            items,
            included,
            excluded,
            unresolved,
        }
    }

    /// Included fraction among all non-excluded inventory items.
    #[allow(
        clippy::cast_precision_loss,
        reason = "coverage is intentionally exposed as an approximate floating-point ratio"
    )]
    pub fn ratio(&self) -> f64 {
        let accountable = self.included + self.unresolved;
        if accountable == 0 {
            1.0
        } else {
            self.included as f64 / accountable as f64
        }
    }

    /// Verify the coverage partition and evidence references against an IR.
    ///
    /// # Errors
    ///
    /// Returns an error when item IDs repeat, an exclusion has no rationale,
    /// evidence is missing, or the stored totals disagree with the items.
    pub fn validate(&self, evidence_ids: &BTreeSet<&str>) -> Result<(), String> {
        let mut ids = BTreeSet::new();
        for item in &self.items {
            if !ids.insert(item.id.as_str()) {
                return Err(format!("duplicate coverage item ID: {}", item.id));
            }
            if matches!(&item.disposition, CoverageDisposition::Excluded { reason } if reason.trim().is_empty())
            {
                return Err(format!("coverage exclusion {} has no reason", item.id));
            }
            for evidence_id in &item.evidence_ids {
                if !evidence_ids.contains(evidence_id.as_str()) {
                    return Err(format!(
                        "coverage item {} references missing evidence {}",
                        item.id, evidence_id
                    ));
                }
            }
        }
        let recomputed = Self::from_items(self.items.clone());
        if (self.included, self.excluded, self.unresolved)
            != (
                recomputed.included,
                recomputed.excluded,
                recomputed.unresolved,
            )
        {
            return Err("coverage totals do not match item classifications".into());
        }
        Ok(())
    }
}

/// Complete deterministic repository intermediate representation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct RepositoryIr {
    /// Serialized schema version.
    pub schema_version: u32,
    /// Repository metadata.
    pub repository: RepositoryMetadata,
    /// Complete file inventory in lexical path order.
    pub files: Vec<FileRecord>,
    /// Source entities in stable ID order.
    pub entities: Vec<Entity>,
    /// Import records in deterministic order.
    pub imports: Vec<ImportRecord>,
    /// Evidence graph lookup records.
    pub evidence: Vec<EvidenceRef>,
    /// Source relationships.
    pub relationships: Vec<Relationship>,
    /// Deterministic and optional agent claims.
    pub claims: Vec<Claim>,
    /// Exhaustive coverage accounting.
    pub coverage: CoverageReport,
    /// BLAKE3 fingerprint of all deterministic fields above except claims from agents.
    pub fingerprint: String,
}

impl RepositoryIr {
    /// Return all evidence IDs for fast validation.
    pub fn evidence_ids(&self) -> BTreeSet<&str> {
        self.evidence
            .iter()
            .map(|record| record.id.as_str())
            .collect()
    }

    /// Validate cross-record IDs, spans and claim evidence references.
    ///
    /// # Errors
    ///
    /// Returns an error when the IR contains duplicate IDs, unsafe or invalid
    /// evidence spans, dangling evidence references, or invalid coverage.
    pub fn validate(&self) -> Result<(), String> {
        let mut evidence_ids = BTreeSet::new();
        for evidence in &self.evidence {
            if !evidence_ids.insert(evidence.id.as_str()) {
                return Err(format!("duplicate evidence ID: {}", evidence.id));
            }
            if evidence.start_line == 0
                || evidence.end_line < evidence.start_line
                || evidence.end_byte < evidence.start_byte
            {
                return Err(format!("invalid evidence span: {}", evidence.id));
            }
            if evidence.path.starts_with('/')
                || evidence.path.contains("../")
                || evidence.path.contains('\\')
            {
                return Err(format!("unsafe evidence path: {}", evidence.path));
            }
        }

        let mut entity_ids = BTreeSet::new();
        for entity in &self.entities {
            if !entity_ids.insert(entity.id.as_str()) {
                return Err(format!("duplicate entity ID: {}", entity.id));
            }
            if !evidence_ids.contains(entity.evidence_id.as_str()) {
                return Err(format!(
                    "entity {} references missing evidence {}",
                    entity.id, entity.evidence_id
                ));
            }
        }

        let mut claim_ids = BTreeSet::new();
        for claim in &self.claims {
            if !claim_ids.insert(claim.id.as_str()) {
                return Err(format!("duplicate claim ID: {}", claim.id));
            }
            if claim.evidence_ids.is_empty() {
                return Err(format!("claim {} has no evidence", claim.id));
            }
            if claim.confidence.is_some_and(|value| value > 100) {
                return Err(format!("claim {} confidence exceeds 100", claim.id));
            }
            for evidence_id in &claim.evidence_ids {
                if !evidence_ids.contains(evidence_id.as_str()) {
                    return Err(format!(
                        "claim {} references missing evidence {}",
                        claim.id, evidence_id
                    ));
                }
            }
        }
        self.coverage.validate(&evidence_ids)
    }

    /// Add validated agent claims while preserving stable ordering and IDs.
    ///
    /// # Errors
    ///
    /// Returns an error when a claim ID already exists, a claim has no
    /// evidence, or a claim references evidence absent from this IR.
    pub fn extend_claims(&mut self, claims: impl IntoIterator<Item = Claim>) -> Result<(), String> {
        let evidence_ids = self.evidence_ids();
        let mut known: BTreeSet<String> =
            self.claims.iter().map(|claim| claim.id.clone()).collect();
        let mut accepted = Vec::new();
        for mut claim in claims {
            if !known.insert(claim.id.clone()) {
                return Err(format!("duplicate claim ID: {}", claim.id));
            }
            claim.evidence_ids.sort();
            claim.evidence_ids.dedup();
            if claim.evidence_ids.is_empty() {
                return Err(format!("claim {} has no evidence", claim.id));
            }
            for evidence_id in &claim.evidence_ids {
                if !evidence_ids.contains(evidence_id.as_str()) {
                    return Err(format!(
                        "claim {} references missing evidence {}",
                        claim.id, evidence_id
                    ));
                }
            }
            accepted.push(claim);
        }
        self.claims.extend(accepted);
        self.claims.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CoverageDisposition, CoverageItem, CoverageKind, CoverageReport};

    #[test]
    fn coverage_ratio_ignores_intentional_exclusions() {
        let report = CoverageReport::from_items(vec![
            CoverageItem {
                id: "a".into(),
                kind: CoverageKind::File,
                subject: "a".into(),
                evidence_ids: vec![],
                disposition: CoverageDisposition::Included {
                    concept_id: "a".into(),
                },
            },
            CoverageItem {
                id: "b".into(),
                kind: CoverageKind::File,
                subject: "b".into(),
                evidence_ids: vec![],
                disposition: CoverageDisposition::Excluded {
                    reason: "binary".into(),
                },
            },
            CoverageItem {
                id: "c".into(),
                kind: CoverageKind::File,
                subject: "c".into(),
                evidence_ids: vec![],
                disposition: CoverageDisposition::Unresolved { reason: None },
            },
        ]);
        assert!((report.ratio() - 0.5).abs() < f64::EPSILON);
    }
}
