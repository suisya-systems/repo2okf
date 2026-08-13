//! Repository intermediate representation and evidence model.

use std::{borrow::Cow, collections::BTreeSet, fmt, path::Path, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Natural-language locale used when rendering human-readable output.
///
/// The locale is intentionally not stored in [`RepositoryIr`]: changing it
/// only re-renders structured facts and never changes repository analysis.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum OutputLocale {
    /// English output.
    #[default]
    En,
    /// Japanese output.
    Ja,
}

impl OutputLocale {
    /// Stable locale label used in configuration and output metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ja => "ja",
        }
    }
}

impl fmt::Display for OutputLocale {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for OutputLocale {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "en" => Ok(Self::En),
            "ja" => Ok(Self::Ja),
            _ => Err(format!(
                "unsupported output locale `{value}`; expected `en` or `ja`"
            )),
        }
    }
}

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

impl EntityKind {
    /// Stable entity-kind label used in facts and output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Function => "function",
            Self::Method => "method",
            Self::Class => "class",
            Self::Interface => "interface",
            Self::Type => "type",
            Self::Enum => "enum",
            Self::Variable => "variable",
            Self::Heading => "heading",
        }
    }
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
    /// Stable language-level qualified name.
    pub qualified_name: String,
    /// Lexical owner entity. Top-level declarations are owned by their file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
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
    /// A function or scope directly calls a statically resolved function or class.
    Calls,
    /// A class directly extends a statically resolved base class.
    Extends,
    /// A declaration uses a statically resolved name in a type annotation.
    TypeUses,
    /// A declaration is decorated by a statically resolved decorator.
    DecoratedBy,
}

/// How a relationship was established.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelationshipOrigin {
    /// Directly observed syntax, such as containment or a module import.
    ObservedSyntax,
    /// A uniquely resolved semantic reference produced this edge.
    SemanticReference {
        /// Reference whose resolution establishes the edge.
        reference_id: String,
    },
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
    /// Auditable origin of the relationship.
    pub origin: RelationshipOrigin,
    /// Evidence establishing the edge.
    pub evidence_ids: Vec<String>,
}

/// Architecture-relevant source reference kinds.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SemanticReferenceKind {
    /// A name introduced by an import statement.
    ImportBinding,
    /// The callee of a call expression.
    Call,
    /// A base named by a class declaration.
    Extends,
    /// A name used in a type annotation.
    TypeUse,
    /// A decorator applied to a declaration.
    Decorator,
}

/// Conservative outcome of resolving one semantic reference.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SemanticResolution {
    /// Exactly one repository entity was mechanically established.
    Resolved {
        /// Existing entity targeted by the reference.
        target_entity_id: String,
    },
    /// The reference names behavior outside the scanned repository.
    External {
        /// Stable external name, not an entity ID.
        target: String,
        /// Non-empty reason the target is classified as external.
        reason: String,
    },
    /// Multiple repository entities remain possible.
    Ambiguous {
        /// Sorted, unique candidate entity IDs.
        candidate_entity_ids: Vec<String>,
        /// Non-empty explanation of the ambiguity.
        reason: String,
    },
    /// No sound target can be established.
    Unresolved {
        /// Non-empty explanation of the unresolved case.
        reason: String,
    },
}

/// One evidence-backed semantic reference.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SemanticReference {
    /// Stable reference identifier derived from source identity and evidence.
    pub id: String,
    /// Reference kind.
    pub kind: SemanticReferenceKind,
    /// Repository-relative path containing the occurrence.
    pub path: String,
    /// Lexical scope entity containing the occurrence. A file is a scope.
    pub scope_id: String,
    /// Declaration responsible for the reference, when more specific than scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_entity_id: Option<String>,
    /// Source spelling or bound name represented by this reference.
    pub name: String,
    /// Optional module or namespace qualifier needed to resolve the source name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    /// Name introduced into the scope by an import, including aliases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_name: Option<String>,
    /// Exact source occurrence establishing the reference.
    pub evidence_id: String,
    /// Complete conservative classification.
    pub resolution: SemanticResolution,
}

/// Aggregate semantic-reference accounting.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SemanticCoverage {
    /// All semantic references.
    pub total: usize,
    /// References with one mechanically established entity target.
    pub resolved: usize,
    /// References classified outside the scanned repository.
    #[serde(rename = "external")]
    pub external_: usize,
    /// References with multiple valid repository candidates.
    pub ambiguous: usize,
    /// References for which no sound target can be selected.
    pub unresolved: usize,
}

impl SemanticCoverage {
    /// Compute totals from the complete reference inventory.
    pub fn from_references(references: &[SemanticReference]) -> Self {
        let mut report = Self {
            total: references.len(),
            ..Self::default()
        };
        for reference in references {
            match reference.resolution {
                SemanticResolution::Resolved { .. } => report.resolved += 1,
                SemanticResolution::External { .. } => report.external_ += 1,
                SemanticResolution::Ambiguous { .. } => report.ambiguous += 1,
                SemanticResolution::Unresolved { .. } => report.unresolved += 1,
            }
        }
        report
    }

    /// Verify that stored totals classify the inventory exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when any stored count differs from the references.
    pub fn validate(&self, references: &[SemanticReference]) -> Result<(), String> {
        let recomputed = Self::from_references(references);
        if self != &recomputed {
            return Err("semantic coverage totals do not match reference classifications".into());
        }
        Ok(())
    }
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

/// Locale-neutral deterministic fact underlying a human-readable claim.
///
/// Source identifiers and source-language tokens are stored verbatim. A
/// formatter can therefore select a natural language without translating or
/// reinterpreting repository facts.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimFact {
    /// A source entity is declared in a file.
    Declaration {
        /// Repository-relative source path.
        path: String,
        /// Source entity kind.
        entity_kind: EntityKind,
        /// Verbatim source name.
        name: String,
    },
    /// A Python source entity has a docstring.
    PythonSymbolDocstring {
        /// Repository-relative source path.
        path: String,
        /// Source entity kind.
        entity_kind: EntityKind,
        /// Verbatim source name.
        name: String,
    },
    /// A Python module has a module docstring.
    PythonModuleDocstring {
        /// Repository-relative source path.
        path: String,
    },
}

impl ClaimFact {
    fn text(&self, locale: OutputLocale) -> String {
        match (self, locale) {
            (
                Self::Declaration {
                    path,
                    entity_kind,
                    name,
                },
                OutputLocale::En,
            ) => format!("{} declares {} `{}`.", path, entity_kind.as_str(), name),
            (
                Self::Declaration {
                    path,
                    entity_kind,
                    name,
                },
                OutputLocale::Ja,
            ) => format!(
                "{} では、{} `{}` が宣言されています。",
                path,
                entity_kind_ja_label(*entity_kind),
                name
            ),
            (
                Self::PythonSymbolDocstring {
                    path,
                    entity_kind,
                    name,
                },
                OutputLocale::En,
            ) => format!(
                "{} declares {} `{}` with a Python docstring.",
                path,
                entity_kind.as_str(),
                name
            ),
            (
                Self::PythonSymbolDocstring {
                    path,
                    entity_kind,
                    name,
                },
                OutputLocale::Ja,
            ) => format!(
                "{} で宣言された{} `{}` には、Python のドキュメント文字列があります。",
                path,
                entity_kind_ja_label(*entity_kind),
                name
            ),
            (Self::PythonModuleDocstring { path }, OutputLocale::En) => {
                format!("{path} has a Python module docstring.")
            }
            (Self::PythonModuleDocstring { path }, OutputLocale::Ja) => {
                format!("{path} には Python モジュールのドキュメント文字列があります。")
            }
        }
    }

    fn validate(&self) -> Result<(), &'static str> {
        let (path, name) = match self {
            Self::Declaration { path, name, .. }
            | Self::PythonSymbolDocstring { path, name, .. } => {
                (path.as_str(), Some(name.as_str()))
            }
            Self::PythonModuleDocstring { path } => (path.as_str(), None),
        };
        if path.trim().is_empty() {
            return Err("has an empty fact path");
        }
        if name.is_some_and(|value| value.trim().is_empty()) {
            return Err("has an empty fact name");
        }
        Ok(())
    }
}

const fn entity_kind_ja_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::File => "ファイル",
        EntityKind::Function => "関数",
        EntityKind::Method => "メソッド",
        EntityKind::Class => "クラス",
        EntityKind::Interface => "インターフェース",
        EntityKind::Type => "型",
        EntityKind::Enum => "列挙型",
        EntityKind::Variable => "変数",
        EntityKind::Heading => "見出し",
    }
}

/// An evidence-bound statement suitable for semantic enrichment.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Claim {
    /// Stable claim ID.
    pub id: String,
    /// Human-readable statement.
    pub text: String,
    /// Locale-neutral fact for deterministic, re-renderable claims.
    ///
    /// This is absent on agent claims and legacy version 2 IR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact: Option<ClaimFact>,
    /// Evidence IDs supporting this claim.
    pub evidence_ids: Vec<String>,
    /// Claim origin.
    pub provenance: ClaimProvenance,
    /// Optional confidence from 0 through 100. It is not a trust score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

impl Claim {
    /// Render this claim in the requested locale.
    ///
    /// Agent claims and legacy deterministic claims without a structured fact
    /// retain their original text because translating them would require new
    /// model inference.
    pub fn text_for(&self, locale: OutputLocale) -> Cow<'_, str> {
        self.fact.as_ref().map_or_else(
            || Cow::Borrowed(self.text.as_str()),
            |fact| Cow::Owned(fact.text(locale)),
        )
    }
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

/// Verification state of an interpreted architecture record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureStatus {
    /// An untrusted interpretation that requires human review.
    Draft,
}

/// A persisted higher-level architecture interpretation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ArchitectureConcept {
    /// Host-assigned stable concept identifier.
    pub id: String,
    /// Concise display title.
    pub title: String,
    /// Concise responsibility statement.
    pub responsibility: String,
    /// Sorted, unique repository entity members.
    pub member_entity_ids: Vec<String>,
    /// Sorted, unique semantic relationships supporting cohesion.
    pub supporting_relationship_ids: Vec<String>,
    /// Sorted, unique source evidence supporting the interpretation.
    pub evidence_ids: Vec<String>,
    /// Architecture interpretations are never mechanically verified.
    pub status: ArchitectureStatus,
    /// Actor that proposed the interpretation.
    pub provenance: ClaimProvenance,
}

/// Supported interpreted architecture relationship kinds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureRelationshipKind {
    /// The source concept depends on the target concept.
    DependsOn,
}

/// A persisted relationship between interpreted architecture concepts.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ArchitectureRelationship {
    /// Host-assigned stable relationship identifier.
    pub id: String,
    /// Existing source architecture concept.
    pub source_concept_id: String,
    /// Existing target architecture concept.
    pub target_concept_id: String,
    /// Interpreted relationship kind.
    pub kind: ArchitectureRelationshipKind,
    /// Sorted, unique resolved semantic edges establishing direction.
    pub supporting_relationship_ids: Vec<String>,
    /// Sorted, unique source evidence supporting those edges.
    pub evidence_ids: Vec<String>,
    /// Architecture interpretations are never mechanically verified.
    pub status: ArchitectureStatus,
    /// Actor that proposed the interpretation.
    pub provenance: ClaimProvenance,
}

/// Host-computed bounds of the semantic graph supplied to architecture synthesis.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ArchitectureScope {
    /// Total evidence records and excerpts available in the IR.
    pub evidence_total: usize,
    /// Evidence records and excerpts supplied to the agent.
    pub evidence_supplied: usize,
    /// Total ordinary coverage items available in the IR.
    pub coverage_items_total: usize,
    /// Ordinary coverage items supplied to the agent.
    pub coverage_items_supplied: usize,
    /// Total source entities available in the IR.
    pub entities_total: usize,
    /// Source entities supplied to the agent.
    pub entities_supplied: usize,
    /// Total semantic references available in the IR.
    pub semantic_references_total: usize,
    /// Semantic references supplied to the agent.
    pub semantic_references_supplied: usize,
    /// Total resolved semantic relationships available in the IR.
    pub semantic_relationships_total: usize,
    /// Resolved semantic relationships supplied to the agent.
    pub semantic_relationships_supplied: usize,
    /// True only when every total was supplied without truncation.
    pub complete: bool,
}

impl ArchitectureScope {
    fn validate(&self) -> Result<(), String> {
        let pairs = [
            (self.evidence_supplied, self.evidence_total, "evidence"),
            (
                self.coverage_items_supplied,
                self.coverage_items_total,
                "coverage items",
            ),
            (self.entities_supplied, self.entities_total, "entities"),
            (
                self.semantic_references_supplied,
                self.semantic_references_total,
                "semantic references",
            ),
            (
                self.semantic_relationships_supplied,
                self.semantic_relationships_total,
                "semantic relationships",
            ),
        ];
        for (supplied, total, subject) in pairs {
            if supplied > total {
                return Err(format!(
                    "architecture scope supplied {subject} exceeds total"
                ));
            }
            if self.complete && supplied != total {
                return Err(format!("complete architecture scope omits some {subject}"));
            }
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
    /// Complete architecture-relevant semantic-reference inventory.
    pub semantic_references: Vec<SemanticReference>,
    /// Exact classification totals for semantic references.
    pub semantic_coverage: SemanticCoverage,
    /// Deterministic and optional agent claims.
    pub claims: Vec<Claim>,
    /// Persisted, always-draft architecture concepts proposed by an agent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architecture_concepts: Vec<ArchitectureConcept>,
    /// Persisted, always-draft relationships between architecture concepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architecture_relationships: Vec<ArchitectureRelationship>,
    /// Host-computed semantic graph bounds used for architecture synthesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture_scope: Option<ArchitectureScope>,
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

    /// Validate all cross-record IDs, resolutions, origins and evidence references.
    ///
    /// # Errors
    ///
    /// Returns an error when the IR contains duplicate or dangling IDs, unsafe
    /// evidence spans, invalid semantic classifications, or invalid coverage.
    #[allow(
        clippy::too_many_lines,
        reason = "cross-record validation is intentionally kept as one auditable transaction"
    )]
    pub fn validate(&self) -> Result<(), String> {
        let files_by_path = self
            .files
            .iter()
            .map(|file| (file.path.as_str(), file))
            .collect::<std::collections::BTreeMap<_, _>>();
        let file_paths = files_by_path.keys().copied().collect::<BTreeSet<_>>();
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
            let Some(file) = files_by_path.get(evidence.path.as_str()) else {
                return Err(format!(
                    "evidence {} references missing file {}",
                    evidence.id, evidence.path
                ));
            };
            if evidence.end_byte > file.size {
                return Err(format!(
                    "evidence {} extends past the source file",
                    evidence.id
                ));
            }
            if evidence.content_hash != file.content_hash {
                return Err(format!(
                    "evidence {} content hash disagrees with the source file",
                    evidence.id
                ));
            }
        }
        let evidence_by_id = self
            .evidence
            .iter()
            .map(|evidence| (evidence.id.as_str(), evidence))
            .collect::<std::collections::BTreeMap<_, _>>();

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
            if evidence_by_id[entity.evidence_id.as_str()].path != entity.path {
                return Err(format!(
                    "entity {} evidence belongs to a different file",
                    entity.id
                ));
            }
            if entity.qualified_name.trim().is_empty() {
                return Err(format!("entity {} has no qualified name", entity.id));
            }
            if !file_paths.contains(entity.path.as_str()) {
                return Err(format!(
                    "entity {} references missing file {}",
                    entity.id, entity.path
                ));
            }
        }
        for entity in &self.entities {
            if let Some(owner_id) = &entity.owner_id {
                if owner_id == &entity.id {
                    return Err(format!("entity {} owns itself", entity.id));
                }
                if !entity_ids.contains(owner_id.as_str()) {
                    return Err(format!(
                        "entity {} references missing owner {}",
                        entity.id, owner_id
                    ));
                }
                let Some(owner) = self
                    .entities
                    .iter()
                    .find(|candidate| candidate.id == *owner_id)
                else {
                    return Err(format!(
                        "entity {} references missing owner {}",
                        entity.id, owner_id
                    ));
                };
                if owner.path != entity.path {
                    return Err(format!(
                        "entity {} owner belongs to a different file",
                        entity.id
                    ));
                }
            } else if entity.kind != EntityKind::File {
                return Err(format!("non-file entity {} has no owner", entity.id));
            }
        }
        validate_owner_graph(&self.entities)?;

        let mut reference_ids = BTreeSet::new();
        for reference in &self.semantic_references {
            if !reference_ids.insert(reference.id.as_str()) {
                return Err(format!("duplicate semantic reference ID: {}", reference.id));
            }
            if reference.name.trim().is_empty() {
                return Err(format!("semantic reference {} has no name", reference.id));
            }
            if !file_paths.contains(reference.path.as_str()) {
                return Err(format!(
                    "semantic reference {} references missing file {}",
                    reference.id, reference.path
                ));
            }
            if !entity_ids.contains(reference.scope_id.as_str()) {
                return Err(format!(
                    "semantic reference {} has missing scope {}",
                    reference.id, reference.scope_id
                ));
            }
            if reference
                .source_entity_id
                .as_deref()
                .is_some_and(|id| !entity_ids.contains(id))
            {
                return Err(format!(
                    "semantic reference {} has a missing source entity",
                    reference.id
                ));
            }
            if !evidence_ids.contains(reference.evidence_id.as_str()) {
                return Err(format!(
                    "semantic reference {} references missing evidence {}",
                    reference.id, reference.evidence_id
                ));
            }
            if evidence_by_id[reference.evidence_id.as_str()].path != reference.path {
                return Err(format!(
                    "semantic reference {} evidence belongs to a different file",
                    reference.id
                ));
            }
            let Some(scope) = self
                .entities
                .iter()
                .find(|entity| entity.id == reference.scope_id)
            else {
                return Err(format!(
                    "semantic reference {} has missing scope {}",
                    reference.id, reference.scope_id
                ));
            };
            if scope.path != reference.path {
                return Err(format!(
                    "semantic reference {} scope belongs to a different file",
                    reference.id
                ));
            }
            if let Some(source_id) = reference.source_entity_id.as_deref() {
                let Some(source) = self.entities.iter().find(|entity| entity.id == source_id)
                else {
                    return Err(format!(
                        "semantic reference {} has a missing source entity",
                        reference.id
                    ));
                };
                if source.path != reference.path {
                    return Err(format!(
                        "semantic reference {} source belongs to a different file",
                        reference.id
                    ));
                }
            }
            match &reference.resolution {
                SemanticResolution::Resolved { target_entity_id } => {
                    if !entity_ids.contains(target_entity_id.as_str()) {
                        return Err(format!(
                            "semantic reference {} resolves to missing entity {}",
                            reference.id, target_entity_id
                        ));
                    }
                }
                SemanticResolution::External { target, reason } => {
                    if target.trim().is_empty() || reason.trim().is_empty() {
                        return Err(format!(
                            "external semantic reference {} lacks target or reason",
                            reference.id
                        ));
                    }
                }
                SemanticResolution::Ambiguous {
                    candidate_entity_ids,
                    reason,
                } => {
                    if candidate_entity_ids.len() < 2 || reason.trim().is_empty() {
                        return Err(format!(
                            "ambiguous semantic reference {} lacks candidates or reason",
                            reference.id
                        ));
                    }
                    if !is_sorted_unique(candidate_entity_ids) {
                        return Err(format!(
                            "semantic reference {} candidates are not sorted and unique",
                            reference.id
                        ));
                    }
                    for candidate in candidate_entity_ids {
                        if !entity_ids.contains(candidate.as_str()) {
                            return Err(format!(
                                "semantic reference {} has missing candidate {}",
                                reference.id, candidate
                            ));
                        }
                    }
                }
                SemanticResolution::Unresolved { reason } if reason.trim().is_empty() => {
                    return Err(format!(
                        "unresolved semantic reference {} has no reason",
                        reference.id
                    ));
                }
                SemanticResolution::Unresolved { .. } => {}
            }
        }
        self.semantic_coverage.validate(&self.semantic_references)?;

        let references_by_id = self
            .semantic_references
            .iter()
            .map(|reference| (reference.id.as_str(), reference))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut relationship_ids = BTreeSet::new();
        for relationship in &self.relationships {
            if !relationship_ids.insert(relationship.id.as_str()) {
                return Err(format!("duplicate relationship ID: {}", relationship.id));
            }
            if !entity_ids.contains(relationship.source.as_str()) {
                return Err(format!(
                    "relationship {} has missing source {}",
                    relationship.id, relationship.source
                ));
            }
            let target_is_entity = entity_ids.contains(relationship.target.as_str());
            if !(target_is_entity
                || relationship.kind == RelationshipKind::Imports
                    && matches!(relationship.origin, RelationshipOrigin::ObservedSyntax)
                    && relationship.target.starts_with("module:"))
            {
                return Err(format!(
                    "relationship {} has missing target {}",
                    relationship.id, relationship.target
                ));
            }
            if relationship.evidence_ids.is_empty() {
                return Err(format!("relationship {} has no evidence", relationship.id));
            }
            for evidence_id in &relationship.evidence_ids {
                if !evidence_ids.contains(evidence_id.as_str()) {
                    return Err(format!(
                        "relationship {} references missing evidence {}",
                        relationship.id, evidence_id
                    ));
                }
            }
            match &relationship.origin {
                RelationshipOrigin::ObservedSyntax => {
                    if matches!(
                        relationship.kind,
                        RelationshipKind::Calls
                            | RelationshipKind::Extends
                            | RelationshipKind::TypeUses
                            | RelationshipKind::DecoratedBy
                    ) {
                        return Err(format!(
                            "semantic relationship {} has no semantic-reference origin",
                            relationship.id
                        ));
                    }
                }
                RelationshipOrigin::SemanticReference { reference_id } => {
                    let Some(reference) = references_by_id.get(reference_id.as_str()) else {
                        return Err(format!(
                            "relationship {} references missing origin {}",
                            relationship.id, reference_id
                        ));
                    };
                    let SemanticResolution::Resolved { target_entity_id } = &reference.resolution
                    else {
                        return Err(format!(
                            "relationship {} originates from a non-resolved reference",
                            relationship.id
                        ));
                    };
                    if &relationship.target != target_entity_id
                        || !relationship
                            .evidence_ids
                            .iter()
                            .any(|id| id == &reference.evidence_id)
                    {
                        return Err(format!(
                            "relationship {} disagrees with its origin reference",
                            relationship.id
                        ));
                    }
                    let expected_kind = relationship_kind_for_reference(reference.kind);
                    if relationship.kind != expected_kind {
                        return Err(format!(
                            "relationship {} kind disagrees with its origin reference",
                            relationship.id
                        ));
                    }
                    let expected_source = reference
                        .source_entity_id
                        .as_deref()
                        .unwrap_or(reference.scope_id.as_str());
                    if relationship.source != expected_source {
                        return Err(format!(
                            "relationship {} source disagrees with its origin reference",
                            relationship.id
                        ));
                    }
                }
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
            match (&claim.provenance, &claim.fact) {
                (ClaimProvenance::Deterministic { .. }, None) if self.schema_version >= 3 => {
                    return Err(format!(
                        "deterministic claim {} has no structured fact",
                        claim.id
                    ));
                }
                (ClaimProvenance::Agent { .. }, Some(_)) => {
                    return Err(format!(
                        "agent claim {} must not supply a deterministic fact",
                        claim.id
                    ));
                }
                (ClaimProvenance::Deterministic { .. }, Some(fact)) => {
                    fact.validate()
                        .map_err(|reason| format!("claim {} {reason}", claim.id))?;
                    if claim.text != fact.text(OutputLocale::En) {
                        return Err(format!(
                            "deterministic claim {} text disagrees with its structured fact",
                            claim.id
                        ));
                    }
                }
                (_, None) => {}
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
        self.coverage.validate(&evidence_ids)?;
        self.validate_architecture(&entity_ids, &relationship_ids, &evidence_ids)
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
            if matches!(claim.provenance, ClaimProvenance::Agent { .. }) && claim.fact.is_some() {
                return Err(format!(
                    "agent claim {} must not supply a deterministic fact",
                    claim.id
                ));
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

    /// Atomically replace persisted architecture interpretations after validating them.
    ///
    /// # Errors
    ///
    /// Returns an error without mutating this IR when concepts or relationships
    /// contain unknown graph IDs, overlap, lack evidence, or violate direction.
    pub fn set_architecture(
        &mut self,
        concepts: Vec<ArchitectureConcept>,
        relationships: Vec<ArchitectureRelationship>,
    ) -> Result<(), String> {
        self.set_architecture_with_scope(concepts, relationships, None)
    }

    /// Atomically replace architecture interpretations and their supplied graph bounds.
    ///
    /// # Errors
    ///
    /// Returns an error without mutation when architecture graph validation or
    /// supplied/total scope accounting fails.
    pub fn set_architecture_with_scope(
        &mut self,
        mut concepts: Vec<ArchitectureConcept>,
        mut relationships: Vec<ArchitectureRelationship>,
        scope: Option<ArchitectureScope>,
    ) -> Result<(), String> {
        concepts.sort_by(|left, right| left.id.cmp(&right.id));
        relationships.sort_by(|left, right| left.id.cmp(&right.id));
        let mut candidate = self.clone();
        candidate.architecture_concepts = concepts;
        candidate.architecture_relationships = relationships;
        candidate.architecture_scope = scope;
        candidate.validate()?;
        self.architecture_concepts = candidate.architecture_concepts;
        self.architecture_relationships = candidate.architecture_relationships;
        self.architecture_scope = candidate.architecture_scope;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "architecture graph invariants are easier to audit together"
    )]
    fn validate_architecture(
        &self,
        entity_ids: &BTreeSet<&str>,
        relationship_ids: &BTreeSet<&str>,
        evidence_ids: &BTreeSet<&str>,
    ) -> Result<(), String> {
        if let Some(scope) = &self.architecture_scope {
            scope.validate()?;
            let semantic_relationships_total = self
                .relationships
                .iter()
                .filter(|relationship| {
                    matches!(
                        relationship.origin,
                        RelationshipOrigin::SemanticReference { .. }
                    )
                })
                .count();
            let expected_totals = [
                (scope.evidence_total, self.evidence.len(), "evidence"),
                (
                    scope.coverage_items_total,
                    self.coverage.items.len(),
                    "coverage items",
                ),
                (scope.entities_total, self.entities.len(), "entities"),
                (
                    scope.semantic_references_total,
                    self.semantic_references.len(),
                    "semantic references",
                ),
                (
                    scope.semantic_relationships_total,
                    semantic_relationships_total,
                    "semantic relationships",
                ),
            ];
            for (reported, actual, subject) in expected_totals {
                if reported != actual {
                    return Err(format!(
                        "architecture scope reports {reported} total {subject}, but the IR contains {actual}"
                    ));
                }
            }
        }
        let graph_relationships = self
            .relationships
            .iter()
            .map(|relationship| (relationship.id.as_str(), relationship))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut concept_ids = BTreeSet::new();
        let mut assigned_members = BTreeSet::new();
        for concept in &self.architecture_concepts {
            if !concept_ids.insert(concept.id.as_str()) {
                return Err(format!("duplicate architecture concept ID: {}", concept.id));
            }
            if concept.title.trim().is_empty() || concept.responsibility.trim().is_empty() {
                return Err(format!(
                    "architecture concept {} lacks title or responsibility",
                    concept.id
                ));
            }
            if concept.member_entity_ids.len() < 2 || !is_sorted_unique(&concept.member_entity_ids)
            {
                return Err(format!(
                    "architecture concept {} needs at least two sorted unique members",
                    concept.id
                ));
            }
            if concept.supporting_relationship_ids.is_empty()
                || !is_sorted_unique(&concept.supporting_relationship_ids)
                || concept.evidence_ids.is_empty()
                || !is_sorted_unique(&concept.evidence_ids)
            {
                return Err(format!(
                    "architecture concept {} lacks sorted unique graph support",
                    concept.id
                ));
            }
            if !matches!(concept.provenance, ClaimProvenance::Agent { .. }) {
                return Err(format!(
                    "architecture concept {} must have agent provenance",
                    concept.id
                ));
            }
            let members = concept
                .member_entity_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            for member in &members {
                if !entity_ids.contains(member) {
                    return Err(format!(
                        "architecture concept {} has missing member {}",
                        concept.id, member
                    ));
                }
                if !assigned_members.insert(*member) {
                    return Err(format!(
                        "architecture member {} belongs to multiple concepts",
                        *member
                    ));
                }
            }
            let cited_evidence = concept
                .evidence_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if !cited_evidence.iter().all(|id| evidence_ids.contains(id)) {
                return Err(format!(
                    "architecture concept {} references missing evidence",
                    concept.id
                ));
            }
            let mut has_cohesion_edge = false;
            for supporting_id in &concept.supporting_relationship_ids {
                let Some(edge) = graph_relationships.get(supporting_id.as_str()) else {
                    return Err(format!(
                        "architecture concept {} has missing support edge {}",
                        concept.id, supporting_id
                    ));
                };
                if !matches!(edge.origin, RelationshipOrigin::SemanticReference { .. }) {
                    return Err(format!(
                        "architecture concept {} cites a non-semantic support edge",
                        concept.id
                    ));
                }
                if members.contains(edge.source.as_str()) && members.contains(edge.target.as_str())
                {
                    has_cohesion_edge = true;
                }
                if !edge
                    .evidence_ids
                    .iter()
                    .all(|id| cited_evidence.contains(id.as_str()))
                {
                    return Err(format!(
                        "architecture concept {} omits support-edge evidence",
                        concept.id
                    ));
                }
            }
            if !has_cohesion_edge {
                return Err(format!(
                    "architecture concept {} has no cohesion edge between members",
                    concept.id
                ));
            }
        }

        let concepts = self
            .architecture_concepts
            .iter()
            .map(|concept| (concept.id.as_str(), concept))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut architecture_relationship_ids = BTreeSet::new();
        for relationship in &self.architecture_relationships {
            if !architecture_relationship_ids.insert(relationship.id.as_str()) {
                return Err(format!(
                    "duplicate architecture relationship ID: {}",
                    relationship.id
                ));
            }
            if relationship.source_concept_id == relationship.target_concept_id {
                return Err(format!(
                    "architecture relationship {} is a self-edge",
                    relationship.id
                ));
            }
            let Some(source) = concepts.get(relationship.source_concept_id.as_str()) else {
                return Err(format!(
                    "architecture relationship {} has missing source concept",
                    relationship.id
                ));
            };
            let Some(target) = concepts.get(relationship.target_concept_id.as_str()) else {
                return Err(format!(
                    "architecture relationship {} has missing target concept",
                    relationship.id
                ));
            };
            if relationship.supporting_relationship_ids.is_empty()
                || !is_sorted_unique(&relationship.supporting_relationship_ids)
                || relationship.evidence_ids.is_empty()
                || !is_sorted_unique(&relationship.evidence_ids)
                || !matches!(relationship.provenance, ClaimProvenance::Agent { .. })
            {
                return Err(format!(
                    "architecture relationship {} lacks valid graph support",
                    relationship.id
                ));
            }
            let source_members = source
                .member_entity_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let target_members = target
                .member_entity_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let cited_evidence = relationship
                .evidence_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if !cited_evidence.iter().all(|id| evidence_ids.contains(id)) {
                return Err(format!(
                    "architecture relationship {} references missing evidence",
                    relationship.id
                ));
            }
            for supporting_id in &relationship.supporting_relationship_ids {
                if !relationship_ids.contains(supporting_id.as_str()) {
                    return Err(format!(
                        "architecture relationship {} has missing support edge {}",
                        relationship.id, supporting_id
                    ));
                }
                let edge = graph_relationships[supporting_id.as_str()];
                if !matches!(edge.origin, RelationshipOrigin::SemanticReference { .. })
                    || !source_members.contains(edge.source.as_str())
                    || !target_members.contains(edge.target.as_str())
                {
                    return Err(format!(
                        "architecture relationship {} support has the wrong direction",
                        relationship.id
                    ));
                }
                if !edge
                    .evidence_ids
                    .iter()
                    .all(|id| cited_evidence.contains(id.as_str()))
                {
                    return Err(format!(
                        "architecture relationship {} omits support-edge evidence",
                        relationship.id
                    ));
                }
            }
        }
        Ok(())
    }
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_owner_graph(entities: &[Entity]) -> Result<(), String> {
    let entities_by_id = entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity))
        .collect::<std::collections::BTreeMap<_, _>>();
    for entity in entities {
        let mut visited = BTreeSet::new();
        let mut current = Some(entity.id.as_str());
        while let Some(id) = current {
            if !visited.insert(id) {
                return Err(format!("entity ownership contains a cycle at {id}"));
            }
            current = entities_by_id
                .get(id)
                .and_then(|candidate| candidate.owner_id.as_deref());
        }
    }
    Ok(())
}

const fn relationship_kind_for_reference(kind: SemanticReferenceKind) -> RelationshipKind {
    match kind {
        SemanticReferenceKind::ImportBinding => RelationshipKind::Imports,
        SemanticReferenceKind::Call => RelationshipKind::Calls,
        SemanticReferenceKind::Extends => RelationshipKind::Extends,
        SemanticReferenceKind::TypeUse => RelationshipKind::TypeUses,
        SemanticReferenceKind::Decorator => RelationshipKind::DecoratedBy,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArchitectureScope, Claim, ClaimFact, ClaimProvenance, CoverageDisposition, CoverageItem,
        CoverageKind, CoverageReport, Entity, EntityKind, Language, OutputLocale, SemanticCoverage,
        SemanticReference, SemanticReferenceKind, SemanticResolution, validate_owner_graph,
    };

    #[test]
    fn output_locale_has_stable_labels_and_strict_parsing() {
        assert_eq!(OutputLocale::default(), OutputLocale::En);
        assert_eq!(OutputLocale::En.as_str(), "en");
        assert_eq!(OutputLocale::Ja.to_string(), "ja");
        assert_eq!("ja".parse(), Ok(OutputLocale::Ja));
        assert!("fr".parse::<OutputLocale>().is_err());
        assert_eq!(
            serde_json::to_string(&OutputLocale::Ja).expect("locale JSON"),
            "\"ja\""
        );
    }

    #[test]
    fn structured_claim_facts_render_without_translating_source_tokens() {
        let claims = [
            Claim {
                id: "claim:declaration".into(),
                text: "src/app.py declares function `greet`.".into(),
                fact: Some(ClaimFact::Declaration {
                    path: "src/app.py".into(),
                    entity_kind: EntityKind::Function,
                    name: "greet".into(),
                }),
                evidence_ids: vec!["evidence:declaration".into()],
                provenance: ClaimProvenance::Deterministic {
                    process: "test".into(),
                },
                confidence: Some(100),
            },
            Claim {
                id: "claim:symbol-docstring".into(),
                text: "src/app.py declares function `greet` with a Python docstring.".into(),
                fact: Some(ClaimFact::PythonSymbolDocstring {
                    path: "src/app.py".into(),
                    entity_kind: EntityKind::Function,
                    name: "greet".into(),
                }),
                evidence_ids: vec!["evidence:docstring".into()],
                provenance: ClaimProvenance::Deterministic {
                    process: "test".into(),
                },
                confidence: Some(100),
            },
            Claim {
                id: "claim:module-docstring".into(),
                text: "src/app.py has a Python module docstring.".into(),
                fact: Some(ClaimFact::PythonModuleDocstring {
                    path: "src/app.py".into(),
                }),
                evidence_ids: vec!["evidence:module".into()],
                provenance: ClaimProvenance::Deterministic {
                    process: "test".into(),
                },
                confidence: Some(100),
            },
        ];

        for claim in &claims {
            assert_eq!(claim.text_for(OutputLocale::En), claim.text);
        }
        assert_eq!(
            claims[0].text_for(OutputLocale::Ja),
            "src/app.py では、関数 `greet` が宣言されています。"
        );
        assert_eq!(
            claims[1].text_for(OutputLocale::Ja),
            "src/app.py で宣言された関数 `greet` には、Python のドキュメント文字列があります。"
        );
        assert_eq!(
            claims[2].text_for(OutputLocale::Ja),
            "src/app.py には Python モジュールのドキュメント文字列があります。"
        );
    }

    #[test]
    fn unstructured_claim_text_is_preserved_for_every_locale() {
        let claim = Claim {
            id: "claim:agent".into(),
            text: "Agent-authored text".into(),
            fact: None,
            evidence_ids: vec!["evidence:agent".into()],
            provenance: ClaimProvenance::Agent {
                provider: "test".into(),
                model: None,
            },
            confidence: None,
        };

        assert_eq!(claim.text_for(OutputLocale::En), "Agent-authored text");
        assert_eq!(claim.text_for(OutputLocale::Ja), "Agent-authored text");
    }

    #[test]
    fn legacy_claims_deserialize_without_structured_facts() {
        let claim: Claim = serde_json::from_value(serde_json::json!({
            "id": "claim:legacy",
            "text": "Legacy deterministic text.",
            "evidence_ids": ["evidence:legacy"],
            "provenance": {
                "kind": "deterministic",
                "process": "legacy"
            },
            "confidence": 100
        }))
        .expect("legacy claim");

        assert_eq!(claim.fact, None);
        assert_eq!(
            claim.text_for(OutputLocale::Ja),
            "Legacy deterministic text."
        );
    }

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

    #[test]
    fn semantic_coverage_accounts_for_every_resolution_state() {
        let resolution = [
            SemanticResolution::Resolved {
                target_entity_id: "entity:target".into(),
            },
            SemanticResolution::External {
                target: "requests".into(),
                reason: "outside repository".into(),
            },
            SemanticResolution::Ambiguous {
                candidate_entity_ids: vec!["entity:a".into(), "entity:b".into()],
                reason: "two targets".into(),
            },
            SemanticResolution::Unresolved {
                reason: "dynamic".into(),
            },
        ];
        let references = resolution
            .into_iter()
            .enumerate()
            .map(|(index, resolution)| SemanticReference {
                id: format!("ref:{index}"),
                kind: SemanticReferenceKind::Call,
                path: "source.py".into(),
                scope_id: "entity:source".into(),
                source_entity_id: Some("entity:source".into()),
                name: "target".into(),
                qualifier: None,
                binding_name: None,
                evidence_id: format!("ev:{index}"),
                resolution,
            })
            .collect::<Vec<_>>();
        let report = SemanticCoverage::from_references(&references);
        assert_eq!(report.total, 4);
        assert_eq!(report.resolved, 1);
        assert_eq!(report.external_, 1);
        assert_eq!(report.ambiguous, 1);
        assert_eq!(report.unresolved, 1);
        report.validate(&references).expect("coverage");

        let mut invalid = report;
        invalid.resolved += 1;
        assert!(invalid.validate(&references).is_err());
    }

    #[test]
    fn architecture_scope_never_overstates_completeness() {
        let partial = ArchitectureScope {
            evidence_total: 10,
            evidence_supplied: 8,
            coverage_items_total: 4,
            coverage_items_supplied: 4,
            entities_total: 5,
            entities_supplied: 5,
            semantic_references_total: 3,
            semantic_references_supplied: 3,
            semantic_relationships_total: 2,
            semantic_relationships_supplied: 2,
            complete: false,
        };
        partial.validate().expect("honest partial scope");

        let mut overstated = partial.clone();
        overstated.complete = true;
        assert!(overstated.validate().is_err());

        let mut impossible = partial;
        impossible.entities_supplied = impossible.entities_total + 1;
        assert!(impossible.validate().is_err());
    }

    #[test]
    fn entity_owner_cycles_are_rejected() {
        let entities = vec![
            Entity {
                id: "entity:a".into(),
                kind: EntityKind::Class,
                name: "A".into(),
                qualified_name: "A".into(),
                owner_id: Some("entity:b".into()),
                path: "source.py".into(),
                language: Some(Language::Python),
                evidence_id: "evidence:a".into(),
            },
            Entity {
                id: "entity:b".into(),
                kind: EntityKind::Class,
                name: "B".into(),
                qualified_name: "A.B".into(),
                owner_id: Some("entity:a".into()),
                path: "source.py".into(),
                language: Some(Language::Python),
                evidence_id: "evidence:b".into(),
            },
        ];
        assert!(validate_owner_graph(&entities).is_err());
    }
}
