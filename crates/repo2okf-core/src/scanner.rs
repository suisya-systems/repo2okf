//! Safe filesystem discovery and language-aware source extraction.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::Command,
};

use ignore::WalkBuilder;
use rayon::prelude::*;
use thiserror::Error;
use tree_sitter::{Node, Parser};

use crate::python_resolver::resolve_python_imports;
use crate::{
    Claim, ClaimProvenance, CoverageDisposition, CoverageItem, CoverageKind, CoverageReport,
    EXTRACTOR_VERSION, Entity, EntityKind, EvidenceRef, FileRecord, IR_SCHEMA_VERSION,
    ImportRecord, Language, Relationship, RelationshipKind, RelationshipOrigin, RepositoryIr,
    RepositoryMetadata, ScanStatus, SemanticCoverage, SemanticReference, SemanticReferenceKind,
    SemanticResolution,
};

/// Repository scan configuration.
#[derive(Clone, Debug)]
pub struct ScanOptions {
    /// Include dot-prefixed files and directories.
    pub include_hidden: bool,
    /// Maximum bytes loaded into a language parser. Larger files are still hashed.
    pub max_file_bytes: u64,
    /// Enabled language scanners.
    pub languages: BTreeSet<Language>,
    /// Prefer `git ls-files` when the caller explicitly trusts repository Git
    /// configuration. Disabled by default because Git may invoke fsmonitor.
    pub prefer_git: bool,
    /// Repository-relative directory roots excluded from discovery in addition
    /// to built-in generated paths.
    pub excluded_roots: BTreeSet<PathBuf>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_file_bytes: 2 * 1024 * 1024,
            languages: [
                Language::JavaScript,
                Language::TypeScript,
                Language::Go,
                Language::Python,
                Language::Rust,
                Language::Markdown,
            ]
            .into_iter()
            .collect(),
            prefer_git: false,
            excluded_roots: BTreeSet::new(),
        }
    }
}

/// Deterministic scan failure.
#[derive(Debug, Error)]
pub enum ScanError {
    /// The requested scan root is invalid.
    #[error("repository root is not a directory: {0}")]
    InvalidRoot(PathBuf),
    /// A repository file could not be inspected.
    #[error("I/O error at `{path}`: {source}")]
    Io {
        /// Affected path.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// Tree-sitter rejected a bundled grammar.
    #[error("could not initialize {language} parser: {message}")]
    Parser {
        /// Language label.
        language: &'static str,
        /// Tree-sitter diagnostic.
        message: String,
    },
    /// A deterministic fingerprint could not be serialized.
    #[error("could not serialize repository fingerprint: {0}")]
    Fingerprint(#[from] serde_json::Error),
    /// Scanner produced an internally inconsistent IR.
    #[error("scanner invariant failed: {0}")]
    InvalidIr(String),
}

/// Identity snapshot for the canonical repository directory.
///
/// The standard library does not provide portable handle-relative tree walks,
/// so these checks cannot eliminate a swap away and back entirely between two
/// path operations. They do fail closed whenever a root rename, link/reparse
/// replacement, identity change, or observable metadata change overlaps one of
/// the scan checkpoints.
#[derive(Debug)]
struct RootIdentity {
    path: PathBuf,
    handle: same_file::Handle,
    metadata: fs::Metadata,
}

impl RootIdentity {
    fn capture(path: PathBuf) -> Result<Self, ScanError> {
        let metadata = fs::symlink_metadata(&path).map_err(|source| ScanError::Io {
            path: path.clone(),
            source,
        })?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            return Err(changed_root_error(&path));
        }
        let handle = same_file::Handle::from_path(&path).map_err(|source| ScanError::Io {
            path: path.clone(),
            source,
        })?;
        let current = fs::symlink_metadata(&path).map_err(|source| ScanError::Io {
            path: path.clone(),
            source,
        })?;
        let confirmation = same_file::Handle::from_path(&path).map_err(|source| ScanError::Io {
            path: path.clone(),
            source,
        })?;
        if is_link_or_reparse_point(&current)
            || !current.file_type().is_dir()
            || handle != confirmation
            || !same_file_identity(&metadata, &current)
            || metadata_changed_during_read(&metadata, &current)
        {
            return Err(changed_root_error(&path));
        }
        let identity = Self {
            path,
            handle,
            metadata: current,
        };
        identity.verify()?;
        Ok(identity)
    }

    fn verify(&self) -> Result<(), ScanError> {
        let current = fs::symlink_metadata(&self.path).map_err(|source| ScanError::Io {
            path: self.path.clone(),
            source,
        })?;
        let current_handle =
            same_file::Handle::from_path(&self.path).map_err(|source| ScanError::Io {
                path: self.path.clone(),
                source,
            })?;
        if is_link_or_reparse_point(&current)
            || !current.file_type().is_dir()
            || current_handle != self.handle
            || !same_file_identity(&self.metadata, &current)
            || metadata_changed_during_read(&self.metadata, &current)
        {
            return Err(changed_root_error(&self.path));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct FileExtraction {
    file: FileRecord,
    entities: Vec<Entity>,
    imports: Vec<ImportRecord>,
    evidence: Vec<EvidenceRef>,
    relationships: Vec<Relationship>,
    claims: Vec<Claim>,
    coverage: Vec<CoverageItem>,
    semantic_references: Vec<SemanticReference>,
    python_bindings: Vec<PythonBinding>,
}

#[derive(Debug)]
struct ParsedSymbol {
    kind: EntityKind,
    name: String,
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    end_line: u32,
    docstring: Option<ParsedSpan>,
    owner_start_byte: Option<usize>,
    qualified_name: String,
    conditional_binding: bool,
}

#[derive(Clone, Copy, Debug)]
struct ParsedSpan {
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    end_line: u32,
}

#[derive(Debug)]
struct ParsedImport {
    specifier: String,
    bindings: Vec<ParsedImportBinding>,
    scope_start_byte: Option<usize>,
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    end_line: u32,
    conditional_binding: bool,
}

#[derive(Clone, Debug)]
struct ParsedImportBinding {
    imported_name: String,
    qualifier: Option<String>,
    binding_name: String,
}

#[derive(Clone, Debug)]
struct ParsedSemanticReference {
    kind: SemanticReferenceKind,
    name: String,
    qualifier: Option<String>,
    binding_name: Option<String>,
    span: ParsedSpan,
    scope_start_byte: Option<usize>,
    source_start_byte: Option<usize>,
    forced_unresolved_reason: Option<&'static str>,
}

const PENDING_SEMANTIC_RESOLUTION_REASON: &str =
    "semantic resolution is pending repository assembly";
const PYTHON_COMPREHENSION_RESOLUTION_REASON: &str =
    "Python comprehension scopes are intentionally unresolved in this semantic slice";
const PYTHON_CONDITIONAL_BINDING_RESOLUTION_REASON: &str =
    "Python conditional binding may not execute on every path";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PythonBindingKind {
    Local,
    Declaration,
    Import,
    ConditionalDeclaration,
    ConditionalImport,
    Delete,
    Global,
    Nonlocal,
}

#[derive(Clone, Debug)]
struct ParsedPythonBinding {
    name: String,
    scope_start_byte: Option<usize>,
    kind: PythonBindingKind,
    visible_after_byte: usize,
}

#[derive(Clone, Debug)]
struct PythonBinding {
    name: String,
    scope_id: String,
    kind: PythonBindingKind,
    visible_after_byte: u64,
}

#[derive(Debug)]
struct ParsedFile {
    symbols: Vec<ParsedSymbol>,
    imports: Vec<ParsedImport>,
    docstring: Option<ParsedSpan>,
    semantic_references: Vec<ParsedSemanticReference>,
    python_bindings: Vec<ParsedPythonBinding>,
}

/// Scan a repository without executing its code or build system.
///
/// # Errors
///
/// Returns an error when the root is invalid, repository files cannot be read,
/// a language parser cannot initialize, or the resulting IR is inconsistent.
#[allow(
    clippy::too_many_lines,
    reason = "the scan pipeline keeps identity checkpoints and deterministic assembly visible"
)]
pub fn scan_repository(root: &Path, options: &ScanOptions) -> Result<RepositoryIr, ScanError> {
    if !root.is_dir() {
        return Err(ScanError::InvalidRoot(root.to_path_buf()));
    }
    let root = root.canonicalize().map_err(|source| ScanError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    let root_identity = RootIdentity::capture(root.clone())?;
    root_identity.verify()?;
    let (paths, git_inventory) = discover_files(&root, options)?;
    root_identity.verify()?;
    let extractions: Vec<FileExtraction> = paths
        .par_iter()
        .map(|path| {
            root_identity.verify()?;
            let extraction = extract_file(&root_identity, path, options)?;
            root_identity.verify()?;
            Ok::<FileExtraction, ScanError>(extraction)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut files = Vec::with_capacity(extractions.len());
    let mut entities = Vec::new();
    let mut imports = Vec::new();
    let mut evidence = Vec::new();
    let mut relationships = Vec::new();
    let mut claims = Vec::new();
    let mut coverage_items = Vec::new();
    let mut semantic_references = Vec::new();
    let mut python_bindings = Vec::new();
    for extraction in extractions {
        files.push(extraction.file);
        entities.extend(extraction.entities);
        imports.extend(extraction.imports);
        evidence.extend(extraction.evidence);
        relationships.extend(extraction.relationships);
        claims.extend(extraction.claims);
        coverage_items.extend(extraction.coverage);
        semantic_references.extend(extraction.semantic_references);
        python_bindings.extend(extraction.python_bindings);
    }

    resolve_typescript_javascript_imports(
        &files,
        &entities,
        &imports,
        &mut relationships,
        &mut coverage_items,
    );
    resolve_python_imports(
        &files,
        &entities,
        &imports,
        &mut relationships,
        &mut coverage_items,
    );
    resolve_python_semantics(
        &entities,
        &evidence,
        &python_bindings,
        &mut semantic_references,
        &mut relationships,
    );

    files.sort_by(|left, right| left.path.cmp(&right.path));
    entities.sort_by(|left, right| left.id.cmp(&right.id));
    imports.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.specifier.cmp(&right.specifier))
            .then_with(|| left.evidence_id.cmp(&right.evidence_id))
    });
    imports.dedup_by(|left, right| {
        left.path == right.path
            && left.specifier == right.specifier
            && left.evidence_id == right.evidence_id
    });
    evidence.sort_by(|left, right| left.id.cmp(&right.id));
    evidence.dedup_by(|left, right| left.id == right.id);
    relationships.sort_by(|left, right| left.id.cmp(&right.id));
    relationships.dedup_by(|left, right| left.id == right.id);
    claims.sort_by(|left, right| left.id.cmp(&right.id));
    claims.dedup_by(|left, right| left.id == right.id);
    semantic_references.sort_by(|left, right| left.id.cmp(&right.id));
    semantic_references.dedup_by(|left, right| left.id == right.id);
    let semantic_coverage = SemanticCoverage::from_references(&semantic_references);
    let coverage = CoverageReport::from_items(coverage_items);

    let repository = RepositoryMetadata {
        name: root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("repository")
            .to_owned(),
        git_commit: options.prefer_git.then(|| git_head(&root)).flatten(),
        git_inventory,
        extractor: EXTRACTOR_VERSION.into(),
    };

    let fingerprint = fingerprint_ir(
        &repository,
        &files,
        &entities,
        &imports,
        &evidence,
        &relationships,
        &semantic_references,
        &semantic_coverage,
        &claims,
        &coverage,
    )?;
    let ir = RepositoryIr {
        schema_version: IR_SCHEMA_VERSION,
        repository,
        files,
        entities,
        imports,
        evidence,
        relationships,
        semantic_references,
        semantic_coverage,
        claims,
        architecture_concepts: Vec::new(),
        architecture_relationships: Vec::new(),
        architecture_scope: None,
        coverage,
        fingerprint,
    };
    ir.validate().map_err(ScanError::InvalidIr)?;
    root_identity.verify()?;
    Ok(ir)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelativeImportFailure {
    EscapesRepository,
    Missing,
    Ambiguous,
}

fn resolve_typescript_javascript_imports(
    files: &[FileRecord],
    entities: &[Entity],
    imports: &[ImportRecord],
    relationships: &mut Vec<Relationship>,
    coverage: &mut [CoverageItem],
) {
    let source_languages = files
        .iter()
        .filter_map(|file| file.language.map(|language| (file.path.as_str(), language)))
        .collect::<BTreeMap<_, _>>();
    let file_entities = entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::File)
        .map(|entity| (entity.path.as_str(), entity.id.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut portable_paths = BTreeMap::<String, Vec<&str>>::new();
    for path in file_entities.keys() {
        portable_paths
            .entry(path.to_lowercase())
            .or_default()
            .push(path);
    }

    let mut unresolved_evidence = BTreeSet::new();
    for import in imports {
        let Some(language) = source_languages.get(import.path.as_str()).copied() else {
            continue;
        };
        if !matches!(language, Language::JavaScript | Language::TypeScript)
            || !is_relative_javascript_specifier(&import.specifier)
        {
            continue;
        }

        match resolve_relative_javascript_target(
            &import.path,
            &import.specifier,
            &file_entities,
            &portable_paths,
        ) {
            Ok(target) => {
                if let Some(relationship) = relationships.iter_mut().find(|relationship| {
                    relationship.kind == RelationshipKind::Imports
                        && relationship
                            .evidence_ids
                            .iter()
                            .any(|id| id == &import.evidence_id)
                }) {
                    target.clone_into(&mut relationship.target);
                }
            }
            Err(failure) => {
                unresolved_evidence.insert(import.evidence_id.as_str());
                if let Some(item) = coverage.iter_mut().find(|item| {
                    item.kind == CoverageKind::Import
                        && item.evidence_ids.iter().any(|id| id == &import.evidence_id)
                }) {
                    item.disposition = CoverageDisposition::Unresolved {
                        reason: Some(relative_import_failure_reason(failure).to_owned()),
                    };
                }
            }
        }
    }

    relationships.retain(|relationship| {
        relationship.kind != RelationshipKind::Imports
            || !relationship
                .evidence_ids
                .iter()
                .any(|id| unresolved_evidence.contains(id.as_str()))
    });
}

#[allow(
    clippy::too_many_lines,
    reason = "repository-wide Python resolution setup and edge materialization stay auditable together"
)]
fn resolve_python_semantics(
    entities: &[Entity],
    evidence: &[EvidenceRef],
    bindings: &[PythonBinding],
    references: &mut [SemanticReference],
    relationships: &mut Vec<Relationship>,
) {
    let entities_by_id = entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity))
        .collect::<BTreeMap<_, _>>();
    let evidence_spans = evidence
        .iter()
        .map(|record| (record.id.as_str(), (record.start_byte, record.end_byte)))
        .collect::<BTreeMap<_, _>>();
    let mut python_modules = BTreeMap::<String, Vec<String>>::new();
    for entity in entities.iter().filter(|entity| {
        entity.kind == EntityKind::File && entity.language == Some(Language::Python)
    }) {
        for module in semantic_python_modules_for_path(&entity.path) {
            python_modules
                .entry(module)
                .or_default()
                .push(entity.id.clone());
        }
    }
    for candidates in python_modules.values_mut() {
        candidates.sort();
        candidates.dedup();
    }
    let mut portable_python_modules = BTreeMap::<String, BTreeSet<String>>::new();
    for module in python_modules.keys() {
        portable_python_modules
            .entry(module.to_lowercase())
            .or_default()
            .insert(module.clone());
    }
    let qualified_names_by_id = entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity.qualified_name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let conditional_declaration_names = bindings
        .iter()
        .filter(|binding| binding.kind == PythonBindingKind::ConditionalDeclaration)
        .map(|binding| (binding.scope_id.as_str(), binding.name.as_str()))
        .collect::<BTreeSet<_>>();
    let conditional_qualified_names = bindings
        .iter()
        .filter(|binding| {
            matches!(
                binding.kind,
                PythonBindingKind::ConditionalDeclaration | PythonBindingKind::ConditionalImport
            )
        })
        .filter_map(|binding| {
            qualified_names_by_id
                .get(binding.scope_id.as_str())
                .map(|owner| format!("{owner}.{}", binding.name))
        })
        .collect::<BTreeSet<_>>();
    let declarations = entities
        .iter()
        .filter(|entity| {
            entity.language == Some(Language::Python)
                && entity.kind != EntityKind::File
                && !entity.owner_id.as_deref().is_some_and(|owner_id| {
                    conditional_declaration_names.contains(&(owner_id, entity.name.as_str()))
                })
        })
        .collect::<Vec<_>>();
    let import_references = references
        .iter()
        .filter(|reference| reference.kind == SemanticReferenceKind::ImportBinding)
        .map(|reference| {
            let mut reference = reference.clone();
            if matches!(
                &reference.resolution,
                SemanticResolution::Unresolved { reason }
                    if reason == PENDING_SEMANTIC_RESOLUTION_REASON
            ) {
                reference.resolution = resolve_python_import_binding(
                    &reference,
                    &declarations,
                    &python_modules,
                    &portable_python_modules,
                    &conditional_qualified_names,
                    &entities_by_id,
                );
            }
            reference
        })
        .collect::<Vec<_>>();
    let parent_scopes = entities
        .iter()
        .filter_map(|entity| {
            entity
                .owner_id
                .as_ref()
                .map(|owner| (entity.id.as_str(), owner.as_str()))
        })
        .collect::<BTreeMap<_, _>>();

    for reference in references.iter_mut() {
        if matches!(
            &reference.resolution,
            SemanticResolution::Unresolved { reason }
                if reason != PENDING_SEMANTIC_RESOLUTION_REASON
        ) {
            continue;
        }
        reference.resolution = match reference.kind {
            SemanticReferenceKind::ImportBinding => resolve_python_import_binding(
                reference,
                &declarations,
                &python_modules,
                &portable_python_modules,
                &conditional_qualified_names,
                &entities_by_id,
            ),
            SemanticReferenceKind::Call
            | SemanticReferenceKind::Extends
            | SemanticReferenceKind::TypeUse
            | SemanticReferenceKind::Decorator => resolve_python_named_reference(
                reference,
                &declarations,
                &import_references,
                bindings,
                &parent_scopes,
                &entities_by_id,
                &evidence_spans,
            ),
        };
    }

    relationships.retain(|relationship| {
        !matches!(
            relationship.origin,
            RelationshipOrigin::SemanticReference { .. }
        )
    });
    for reference in references.iter() {
        let SemanticResolution::Resolved { target_entity_id } = &reference.resolution else {
            continue;
        };
        let source = reference
            .source_entity_id
            .as_deref()
            .unwrap_or(reference.scope_id.as_str());
        relationships.push(Relationship {
            id: stable_id(
                "rel",
                &[
                    semantic_reference_kind_label(reference.kind),
                    source,
                    target_entity_id,
                    &reference.id,
                ],
            ),
            source: source.to_owned(),
            target: target_entity_id.clone(),
            kind: relationship_kind_for_semantic_reference(reference.kind),
            origin: RelationshipOrigin::SemanticReference {
                reference_id: reference.id.clone(),
            },
            evidence_ids: vec![reference.evidence_id.clone()],
        });
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "module identity, portable path, and member resolution checks stay together for fail-closed auditing"
)]
fn resolve_python_import_binding(
    reference: &SemanticReference,
    declarations: &[&Entity],
    python_modules: &BTreeMap<String, Vec<String>>,
    portable_python_modules: &BTreeMap<String, BTreeSet<String>>,
    conditional_qualified_names: &BTreeSet<String>,
    entities_by_id: &BTreeMap<&str, &Entity>,
) -> SemanticResolution {
    if reference.name == "*" {
        return SemanticResolution::Unresolved {
            reason: "wildcard imports do not establish a unique binding target".to_owned(),
        };
    }
    let Some(qualifier) = reference.qualifier.as_deref() else {
        if let Some(resolution) =
            python_module_case_guard(&reference.name, python_modules, portable_python_modules)
        {
            return resolution;
        }
        let module_targets = python_module_entity_candidates(&reference.name, python_modules);
        return resolution_from_candidates(
            module_targets,
            Some(reference.name.clone()),
            "imported Python module is outside the scanned repository",
            "imported Python module matches multiple repository files",
        );
    };
    if qualifier == "__future__" {
        return SemanticResolution::External {
            target: format!("{qualifier}.{}", reference.name),
            reason: "Python future imports are compiler directives".to_owned(),
        };
    }
    if qualifier.bytes().all(|byte| byte == b'.') {
        return SemanticResolution::Unresolved {
            reason: "dots-only imports may refer to a package attribute or a same-named submodule"
                .to_owned(),
        };
    }
    let Some(module) = normalize_python_module_name(&reference.path, qualifier) else {
        return SemanticResolution::Unresolved {
            reason: "relative Python import escapes the repository package root".to_owned(),
        };
    };
    if let Some(resolution) =
        python_module_case_guard(&module, python_modules, portable_python_modules)
    {
        return resolution;
    }
    let imported_qualified_name = if module.is_empty() {
        reference.name.clone()
    } else {
        format!("{module}.{}", reference.name)
    };
    if conditional_qualified_names.iter().any(|conditional| {
        imported_qualified_name == *conditional
            || imported_qualified_name
                .strip_prefix(conditional)
                .is_some_and(|suffix| suffix.starts_with('.'))
    }) {
        return SemanticResolution::Unresolved {
            reason: PYTHON_CONDITIONAL_BINDING_RESOLUTION_REASON.to_owned(),
        };
    }
    let local_module_candidates = python_module_entity_candidates(&module, python_modules);
    if let Some(resolution) = python_module_case_guard(
        &imported_qualified_name,
        python_modules,
        portable_python_modules,
    ) {
        return resolution;
    }
    let imported_module_candidates =
        python_module_entity_candidates(&imported_qualified_name, python_modules);
    if local_module_candidates.len() > 1 {
        let mut member_candidates = declarations
            .iter()
            .filter(|entity| {
                entity.qualified_name == imported_qualified_name
                    && local_module_candidates
                        .iter()
                        .any(|file_id| entity_belongs_to_file(entity, file_id, entities_by_id))
            })
            .map(|entity| entity.id.clone())
            .collect::<Vec<_>>();
        member_candidates.extend(imported_module_candidates);
        member_candidates.sort();
        member_candidates.dedup();
        return if member_candidates.len() > 1 {
            SemanticResolution::Ambiguous {
                candidate_entity_ids: member_candidates,
                reason: "Python qualifier and member match multiple repository declarations"
                    .to_owned(),
            }
        } else {
            SemanticResolution::Unresolved {
                reason: "Python qualifier module has multiple repository candidates".to_owned(),
            }
        };
    }
    if local_module_candidates.is_empty() {
        if !imported_module_candidates.is_empty() {
            return resolution_from_candidates(
                imported_module_candidates,
                None,
                "",
                "imported Python module matches multiple repository files",
            );
        }
        return if qualifier.starts_with('.')
            || python_module_has_repository_prefix(&module, portable_python_modules)
        {
            SemanticResolution::Unresolved {
                reason: "Python qualifier is not a uniquely scanned importable module".to_owned(),
            }
        } else {
            SemanticResolution::External {
                target: imported_qualified_name,
                reason: "absolute Python qualifier module is outside the scanned repository"
                    .to_owned(),
            }
        };
    }
    let local_module_id = &local_module_candidates[0];
    let mut candidates = declarations
        .iter()
        .filter(|entity| {
            entity.qualified_name == imported_qualified_name
                && entity_belongs_to_file(entity, local_module_id, entities_by_id)
        })
        .map(|entity| entity.id.clone())
        .collect::<Vec<_>>();
    candidates.extend(imported_module_candidates);
    if candidates.is_empty() {
        return SemanticResolution::Unresolved {
            reason: "scanned Python module does not expose this name as a static declaration"
                .to_owned(),
        };
    }
    resolution_from_candidates(
        candidates,
        (!qualifier.starts_with('.')).then_some(imported_qualified_name),
        "imported Python symbol is outside the scanned repository or not exported as a declaration",
        "imported Python symbol matches multiple repository declarations",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "fail-closed lexical and import resolution branches are kept together for auditability"
)]
fn resolve_python_named_reference(
    reference: &SemanticReference,
    declarations: &[&Entity],
    import_references: &[SemanticReference],
    bindings: &[PythonBinding],
    parent_scopes: &BTreeMap<&str, &str>,
    entities_by_id: &BTreeMap<&str, &Entity>,
    evidence_spans: &BTreeMap<&str, (u64, u64)>,
) -> SemanticResolution {
    if reference.name.contains('.') {
        return SemanticResolution::Unresolved {
            reason: "member or qualified access may use dynamic Python dispatch".to_owned(),
        };
    }
    let reference_start = evidence_spans
        .get(reference.evidence_id.as_str())
        .map(|(start, _)| *start);
    let reference_scope_kind = entities_by_id
        .get(reference.scope_id.as_str())
        .map(|entity| entity.kind);
    let reference_is_immediate = matches!(
        reference_scope_kind,
        Some(EntityKind::File | EntityKind::Class)
    );
    let mut scope = Some(reference.scope_id.as_str());
    while let Some(scope_id) = scope {
        let lookup_is_ordered = reference_is_immediate
            || scope_id == reference.scope_id
                && matches!(
                    reference_scope_kind,
                    Some(EntityKind::Function | EntityKind::Method)
                );
        let scope_bindings = bindings
            .iter()
            .filter(|binding| {
                binding.scope_id == scope_id
                    && binding.name == reference.name
                    && (binding.kind != PythonBindingKind::Local
                        || !reference_is_immediate
                        || reference_start.is_some_and(|start| binding.visible_after_byte <= start))
            })
            .collect::<Vec<_>>();
        let has_scope_redirect = scope_bindings.iter().any(|binding| {
            matches!(
                binding.kind,
                PythonBindingKind::Global | PythonBindingKind::Nonlocal
            )
        });
        let has_redirect_conflict = scope_bindings.iter().any(|binding| {
            matches!(
                binding.kind,
                PythonBindingKind::Local
                    | PythonBindingKind::Declaration
                    | PythonBindingKind::Import
                    | PythonBindingKind::ConditionalDeclaration
                    | PythonBindingKind::ConditionalImport
                    | PythonBindingKind::Delete
            )
        });
        if has_scope_redirect && has_redirect_conflict {
            return SemanticResolution::Unresolved {
                reason: "global or nonlocal name is rebound in the same scope".to_owned(),
            };
        }
        if let Some(binding) = scope_bindings
            .iter()
            .find(|binding| binding.kind == PythonBindingKind::Global)
        {
            let _ = binding;
            let root = root_file_scope(scope_id, parent_scopes, entities_by_id);
            if root == Some(scope_id) {
                // `global` at module scope is redundant and does not alter lookup.
            } else {
                scope = root;
                continue;
            }
        }
        if scope_bindings
            .iter()
            .any(|binding| binding.kind == PythonBindingKind::Nonlocal)
        {
            scope = next_python_resolution_scope(scope_id, parent_scopes, entities_by_id);
            continue;
        }
        if scope_bindings.iter().any(|binding| {
            matches!(
                binding.kind,
                PythonBindingKind::ConditionalDeclaration | PythonBindingKind::ConditionalImport
            )
        }) {
            return SemanticResolution::Unresolved {
                reason: PYTHON_CONDITIONAL_BINDING_RESOLUTION_REASON.to_owned(),
            };
        }
        if scope_bindings
            .iter()
            .any(|binding| binding.kind == PythonBindingKind::Delete)
        {
            return SemanticResolution::Unresolved {
                reason: "name may have been removed by a Python del statement in this scope"
                    .to_owned(),
            };
        }
        if scope_bindings
            .iter()
            .any(|binding| binding.kind == PythonBindingKind::Local)
        {
            return SemanticResolution::Unresolved {
                reason: "name is shadowed by a parameter or assignment in the lexical scope"
                    .to_owned(),
            };
        }

        let is_visible = |evidence_id: &str| {
            !lookup_is_ordered
                || evidence_spans
                    .get(evidence_id)
                    .zip(reference_start)
                    .is_some_and(|((_, candidate_end), reference_start)| {
                        *candidate_end <= reference_start
                    })
        };
        let raw_declarations = declarations
            .iter()
            .filter(|entity| {
                entity.owner_id.as_deref() == Some(scope_id)
                    && entity.name == reference.name
                    && is_visible(&entity.evidence_id)
            })
            .copied()
            .collect::<Vec<_>>();
        let mut candidates = raw_declarations
            .iter()
            .filter(|entity| semantic_target_kind_allowed(reference.kind, entity.kind))
            .map(|entity| entity.id.clone())
            .collect::<Vec<_>>();
        let matching_imports = import_references
            .iter()
            .filter(|import| {
                import.scope_id == scope_id
                    && import.binding_name.as_deref() == Some(reference.name.as_str())
                    && is_visible(&import.evidence_id)
            })
            .collect::<Vec<_>>();
        let wildcard_taint = import_references.iter().any(|import| {
            import.scope_id == scope_id
                && import.binding_name.as_deref() == Some("*")
                && is_visible(&import.evidence_id)
        });
        if wildcard_taint {
            return SemanticResolution::Unresolved {
                reason: "wildcard import may bind this bare name in the lexical scope".to_owned(),
            };
        }
        if raw_declarations.is_empty()
            && matching_imports.is_empty()
            && lookup_is_ordered
            && scope_bindings.iter().any(|binding| {
                matches!(
                    binding.kind,
                    PythonBindingKind::Declaration | PythonBindingKind::Import
                ) && reference_start.is_none_or(|start| binding.visible_after_byte > start)
            })
        {
            return SemanticResolution::Unresolved {
                reason: "name is bound later in the currently executing Python scope".to_owned(),
            };
        }
        candidates.sort();
        candidates.dedup();
        if !raw_declarations.is_empty() && !matching_imports.is_empty() {
            return SemanticResolution::Unresolved {
                reason: "local declaration conflicts with an import binding of the same name"
                    .to_owned(),
            };
        }
        if !raw_declarations.is_empty() {
            if candidates.is_empty() {
                return SemanticResolution::Unresolved {
                    reason: "local declaration is incompatible with this semantic reference kind"
                        .to_owned(),
                };
            }
            return resolution_from_candidates(
                candidates,
                None,
                "",
                "name resolves to multiple lexical or imported declarations",
            );
        }
        if matching_imports.len() == 1 {
            return match &matching_imports[0].resolution {
                SemanticResolution::Resolved { target_entity_id }
                    if entities_by_id
                        .get(target_entity_id.as_str())
                        .is_some_and(|entity| {
                            semantic_target_kind_allowed(reference.kind, entity.kind)
                        }) =>
                {
                    SemanticResolution::Resolved {
                        target_entity_id: target_entity_id.clone(),
                    }
                }
                SemanticResolution::External { target, reason } => SemanticResolution::External {
                    target: target.clone(),
                    reason: reason.clone(),
                },
                SemanticResolution::Resolved { .. } => SemanticResolution::Unresolved {
                    reason: "import binding target is not valid for this semantic reference kind"
                        .to_owned(),
                },
                SemanticResolution::Ambiguous { .. } => SemanticResolution::Unresolved {
                    reason: "ambiguous import binding cannot establish a unique name target"
                        .to_owned(),
                },
                SemanticResolution::Unresolved { reason } => SemanticResolution::Unresolved {
                    reason: reason.clone(),
                },
            };
        }
        if matching_imports.len() > 1 {
            return SemanticResolution::Unresolved {
                reason: "multiple import bindings with this name prevent unique resolution"
                    .to_owned(),
            };
        }
        scope = next_python_resolution_scope(scope_id, parent_scopes, entities_by_id);
    }
    SemanticResolution::Unresolved {
        reason: "name is not a uniquely known lexical declaration or import binding".to_owned(),
    }
}

fn next_python_resolution_scope<'a>(
    scope_id: &'a str,
    parent_scopes: &BTreeMap<&'a str, &'a str>,
    entities_by_id: &BTreeMap<&str, &Entity>,
) -> Option<&'a str> {
    let mut parent = parent_scopes.get(scope_id).copied()?;
    let current = entities_by_id.get(scope_id)?;
    if current.kind == EntityKind::Class
        || matches!(current.kind, EntityKind::Function | EntityKind::Method)
            && entities_by_id
                .get(parent)
                .is_some_and(|entity| entity.kind == EntityKind::Class)
    {
        while entities_by_id
            .get(parent)
            .is_some_and(|entity| entity.kind == EntityKind::Class)
        {
            parent = parent_scopes.get(parent).copied()?;
        }
    }
    Some(parent)
}

fn semantic_target_kind_allowed(
    reference_kind: SemanticReferenceKind,
    entity_kind: EntityKind,
) -> bool {
    match reference_kind {
        SemanticReferenceKind::ImportBinding => true,
        SemanticReferenceKind::Call | SemanticReferenceKind::Decorator => matches!(
            entity_kind,
            EntityKind::Function | EntityKind::Method | EntityKind::Class
        ),
        SemanticReferenceKind::Extends => entity_kind == EntityKind::Class,
        SemanticReferenceKind::TypeUse => matches!(
            entity_kind,
            EntityKind::Class | EntityKind::Interface | EntityKind::Type | EntityKind::Enum
        ),
    }
}

fn root_file_scope<'a>(
    scope_id: &'a str,
    parent_scopes: &BTreeMap<&'a str, &'a str>,
    entities_by_id: &BTreeMap<&str, &Entity>,
) -> Option<&'a str> {
    let mut current = scope_id;
    loop {
        if entities_by_id
            .get(current)
            .is_some_and(|entity| entity.kind == EntityKind::File)
        {
            return Some(current);
        }
        current = parent_scopes.get(current).copied()?;
    }
}

fn python_module_entity_candidates(
    module: &str,
    python_modules: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    python_modules.get(module).cloned().unwrap_or_default()
}

fn semantic_python_modules_for_path(path: &str) -> BTreeSet<String> {
    let mut components = path.split('/').collect::<Vec<_>>();
    let Some(filename) = components.pop() else {
        return BTreeSet::new();
    };
    let Some(stem) = filename
        .get(filename.len().saturating_sub(3)..)
        .filter(|suffix| suffix.eq_ignore_ascii_case(".py"))
        .and_then(|_| filename.get(..filename.len().saturating_sub(3)))
    else {
        return BTreeSet::new();
    };
    if !stem.eq_ignore_ascii_case("__init__") {
        components.push(stem);
    }
    if components
        .iter()
        .any(|component| component.is_empty() || component.contains('.'))
    {
        return BTreeSet::new();
    }
    let canonical = components.join(".");
    let mut modules = BTreeSet::from([canonical.clone()]);
    if canonical
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("src."))
        && canonical.len() > 4
    {
        modules.insert(canonical[4..].to_owned());
    }
    modules
}

fn python_module_case_guard(
    module: &str,
    python_modules: &BTreeMap<String, Vec<String>>,
    portable_python_modules: &BTreeMap<String, BTreeSet<String>>,
) -> Option<SemanticResolution> {
    let portable_matches = portable_python_modules.get(&module.to_lowercase())?;
    if !python_modules.contains_key(module) {
        return Some(SemanticResolution::Unresolved {
            reason: "Python module differs from a scanned repository path only by case".to_owned(),
        });
    }
    (portable_matches.len() > 1).then(|| SemanticResolution::Unresolved {
        reason: "Python module name has a portable case collision in the repository".to_owned(),
    })
}

fn python_module_has_repository_prefix(
    module: &str,
    portable_python_modules: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let mut prefix = module;
    loop {
        if portable_python_modules.contains_key(&prefix.to_lowercase()) {
            return true;
        }
        let Some((parent, _)) = prefix.rsplit_once('.') else {
            return false;
        };
        prefix = parent;
    }
}

fn entity_belongs_to_file(
    entity: &Entity,
    file_id: &str,
    entities_by_id: &BTreeMap<&str, &Entity>,
) -> bool {
    let mut owner = entity.owner_id.as_deref();
    while let Some(owner_id) = owner {
        if owner_id == file_id {
            return true;
        }
        owner = entities_by_id
            .get(owner_id)
            .and_then(|owner_entity| owner_entity.owner_id.as_deref());
    }
    false
}

fn normalize_python_module_name(importing_path: &str, specifier: &str) -> Option<String> {
    let leading_dots = specifier.bytes().take_while(|byte| *byte == b'.').count();
    if leading_dots == 0 {
        return Some(specifier.to_owned());
    }
    let mut components = importing_path.split('/').collect::<Vec<_>>();
    let filename = components.pop()?;
    if components
        .first()
        .is_some_and(|component| component.eq_ignore_ascii_case("src"))
    {
        components.remove(0);
    }
    if components.is_empty() && !filename.eq_ignore_ascii_case("__init__.py") {
        return None;
    }
    let levels_up = leading_dots.saturating_sub(1);
    if levels_up > 0 && levels_up >= components.len() {
        return None;
    }
    components.truncate(components.len() - levels_up);
    let remainder = &specifier[leading_dots..];
    if !remainder.is_empty() {
        components.extend(remainder.split('.'));
    }
    Some(components.join("."))
}

fn resolution_from_candidates(
    mut candidates: Vec<String>,
    external: Option<String>,
    external_reason: &str,
    ambiguous_reason: &str,
) -> SemanticResolution {
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [target] => SemanticResolution::Resolved {
            target_entity_id: target.clone(),
        },
        [] => external.map_or_else(
            || SemanticResolution::Unresolved {
                reason: external_reason.to_owned(),
            },
            |target| SemanticResolution::External {
                target,
                reason: external_reason.to_owned(),
            },
        ),
        _ => SemanticResolution::Ambiguous {
            candidate_entity_ids: candidates,
            reason: ambiguous_reason.to_owned(),
        },
    }
}

fn resolve_relative_javascript_target<'a>(
    importing_path: &str,
    specifier: &str,
    file_entities: &BTreeMap<&str, &'a str>,
    portable_paths: &BTreeMap<String, Vec<&str>>,
) -> Result<&'a str, RelativeImportFailure> {
    let base = normalize_relative_javascript_path(importing_path, specifier)
        .ok_or(RelativeImportFailure::EscapesRepository)?;
    let mut candidates = BTreeSet::from([base.clone()]);
    if !has_javascript_typescript_extension(&base) {
        for extension in javascript_typescript_extensions() {
            candidates.insert(format!("{base}.{extension}"));
            candidates.insert(format!("{base}/index.{extension}"));
        }
    }

    let mut matches = BTreeSet::new();
    let mut portable_collision = false;
    for candidate in candidates {
        let Some(target) = file_entities.get(candidate.as_str()) else {
            continue;
        };
        portable_collision |= portable_paths
            .get(&candidate.to_lowercase())
            .is_some_and(|paths| paths.len() > 1);
        matches.insert(*target);
    }
    if portable_collision || matches.len() > 1 {
        return Err(RelativeImportFailure::Ambiguous);
    }
    matches
        .into_iter()
        .next()
        .ok_or(RelativeImportFailure::Missing)
}

fn normalize_relative_javascript_path(importing_path: &str, specifier: &str) -> Option<String> {
    let mut components = importing_path.split('/').collect::<Vec<_>>();
    components.pop();
    for component in specifier.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            component => components.push(component),
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn is_relative_javascript_specifier(specifier: &str) -> bool {
    matches!(specifier, "." | "..") || specifier.starts_with("./") || specifier.starts_with("../")
}

fn has_javascript_typescript_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            javascript_typescript_extensions()
                .iter()
                .any(|supported| extension.eq_ignore_ascii_case(supported))
        })
}

const fn javascript_typescript_extensions() -> &'static [&'static str] {
    &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"]
}

const fn relative_import_failure_reason(failure: RelativeImportFailure) -> &'static str {
    match failure {
        RelativeImportFailure::EscapesRepository => {
            "relative JavaScript/TypeScript import escapes the repository root"
        }
        RelativeImportFailure::Missing => {
            "relative JavaScript/TypeScript import does not resolve to a scanned source file"
        }
        RelativeImportFailure::Ambiguous => {
            "relative JavaScript/TypeScript import matches multiple scanned source files"
        }
    }
}

fn discover_files(root: &Path, options: &ScanOptions) -> Result<(Vec<PathBuf>, bool), ScanError> {
    if options.prefer_git
        && let Some(paths) = git_files(root, options)?
    {
        return Ok((paths, true));
    }
    let mut builder = WalkBuilder::new(root);
    let filter_root = root.to_path_buf();
    let excluded_roots = options.excluded_roots.clone();
    builder
        .hidden(!options.include_hidden)
        .follow_links(false)
        .git_ignore(true)
        // External user/global and parent-worktree ignore sources would make
        // the same repository bytes scan differently on another machine.
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .filter_entry(move |entry| {
            entry
                .path()
                .strip_prefix(&filter_root)
                .map_or(true, |relative| {
                    !is_internal_path(relative, &excluded_roots)
                })
        });
    let mut paths = Vec::new();
    for entry in builder.build() {
        let entry = entry.map_err(|error| ScanError::Io {
            path: root.to_path_buf(),
            source: io::Error::other(error.to_string()),
        })?;
        let path = entry.path();
        if path == root {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file() || file_type.is_symlink() {
            paths.push(path.to_path_buf());
        }
    }
    sort_and_dedup_paths(root, &mut paths);
    Ok((paths, false))
}

fn git_files(root: &Path, options: &ScanOptions) -> Result<Option<Vec<PathBuf>>, ScanError> {
    let Ok(git) = which::which_global("git") else {
        return Ok(None);
    };
    let status = Command::new(&git)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=",
            "-C",
        ])
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output();
    let Ok(status) = status else {
        return Ok(None);
    };
    if !status.status.success() || !String::from_utf8_lossy(&status.stdout).trim().eq("true") {
        return Ok(None);
    }

    let output = Command::new(git)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=",
            "-C",
        ])
        .arg(root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            ".",
        ])
        .output()
        .map_err(|source| ScanError::Io {
            path: root.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Ok(None);
    }

    let mut paths = Vec::new();
    for bytes in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
    {
        let relative = path_from_git_bytes(bytes);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, Component::ParentDir))
            || is_internal_path(&relative, &options.excluded_roots)
            || (!options.include_hidden && is_hidden_path(&relative))
        {
            continue;
        }
        let path = root.join(&relative);
        if path.exists() {
            paths.push(path);
        }
    }
    sort_and_dedup_paths(root, &mut paths);
    Ok(Some(paths))
}

#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from(String::from_utf8_lossy(bytes).into_owned()))
}

fn sort_and_dedup_paths(root: &Path, paths: &mut Vec<PathBuf>) {
    paths.sort_by(|left, right| {
        normalize_relative(root, left).cmp(&normalize_relative(root, right))
    });
    paths.dedup();
}

fn is_internal_path(path: &Path, excluded_roots: &BTreeSet<PathBuf>) -> bool {
    if excluded_roots
        .iter()
        .any(|excluded| path == excluded || path.starts_with(excluded))
    {
        return true;
    }
    let Some(first) = path.components().next() else {
        return false;
    };
    let Component::Normal(first) = first else {
        return false;
    };
    matches!(
        first.to_str(),
        Some(".git" | ".repo2okf" | ".okf" | "repo2okf.toml" | "target" | "node_modules")
    )
}

fn is_hidden_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.to_string_lossy().starts_with('.'))
    })
}

fn extract_file(
    root: &RootIdentity,
    path: &Path,
    options: &ScanOptions,
) -> Result<FileExtraction, ScanError> {
    let relative = normalize_relative(&root.path, path);
    let path_metadata = file_path_metadata(&root.path, path)?;
    if is_link_or_reparse_point(&path_metadata) {
        return Ok(excluded_extraction(
            relative,
            path_metadata.len(),
            String::new(),
            ScanStatus::SymlinkSkipped,
            "symbolic links and reparse points are inventoried but never followed",
        ));
    }
    if !path_metadata.is_file() {
        return Ok(excluded_extraction(
            relative,
            path_metadata.len(),
            String::new(),
            ScanStatus::Unsupported,
            "non-file repository entries such as Git submodules are not traversed",
        ));
    }

    let mut opened = open_stable_file(root, path, &path_metadata)?;
    let metadata = opened.metadata().map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let language = Language::from_path(&relative);
    if metadata.len() > options.max_file_bytes {
        let content_hash = hash_reader(&mut opened, path, metadata.len())?;
        verify_stable_file(root, path, &opened, &metadata)?;
        return Ok(excluded_extraction(
            relative,
            metadata.len(),
            content_hash,
            ScanStatus::TooLarge,
            "file exceeds scan.max_file_bytes",
        ));
    }

    let bytes = read_bounded_file(&mut opened, path, metadata.len(), options.max_file_bytes)?;
    verify_stable_file(root, path, &opened, &metadata)?;
    let content_hash = blake3::hash(&bytes).to_hex().to_string();
    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Ok(excluded_extraction(
            relative,
            metadata.len(),
            content_hash,
            ScanStatus::Binary,
            "file is binary or not valid UTF-8",
        ));
    }
    let source = std::str::from_utf8(&bytes).expect("UTF-8 checked above");
    let Some(language) = language else {
        return Ok(unresolved_extraction(
            relative,
            metadata.len(),
            content_hash,
            "no language-aware scanner is available",
        ));
    };
    if !options.languages.contains(&language) {
        return Ok(excluded_extraction(
            relative,
            metadata.len(),
            content_hash,
            ScanStatus::Unsupported,
            "language scanner is disabled by configuration",
        ));
    }

    parsed_extraction(relative, metadata.len(), content_hash, language, source)
}

fn file_path_metadata(root: &Path, path: &Path) -> Result<fs::Metadata, ScanError> {
    reject_linked_ancestors(root, path)?;
    fs::symlink_metadata(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn reject_linked_ancestors(root: &Path, path: &Path) -> Result<(), ScanError> {
    let relative = path.strip_prefix(root).map_err(|_| ScanError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "repository file escaped the canonical scan root",
        ),
    })?;
    let mut current = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let Component::Normal(component) = component else {
            return Err(ScanError::Io {
                path: path.to_path_buf(),
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "repository file path contains a non-normal component",
                ),
            });
        };
        current.push(component);
        // The final entry is checked separately so a leaf link can be
        // inventoried as SymlinkSkipped instead of aborting the whole scan.
        if components.peek().is_none() {
            break;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|source| ScanError::Io {
            path: current.clone(),
            source,
        })?;
        if is_link_or_reparse_point(&metadata) {
            return Err(ScanError::Io {
                path: current,
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "repository path traverses a symbolic link or reparse point",
                ),
            });
        }
    }
    Ok(())
}

fn open_stable_file(
    root: &RootIdentity,
    path: &Path,
    path_metadata: &fs::Metadata,
) -> Result<File, ScanError> {
    root.verify()?;
    let file = File::open(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    root.verify()?;
    let opened_metadata = file.metadata().map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !opened_metadata.is_file()
        || !same_file_identity(path_metadata, &opened_metadata)
        || metadata_changed_during_read(path_metadata, &opened_metadata)
    {
        return Err(changed_file_error(path));
    }
    verify_path_matches_handle(&root.path, path, &opened_metadata)?;
    Ok(file)
}

fn verify_stable_file(
    root: &RootIdentity,
    path: &Path,
    file: &File,
    initial: &fs::Metadata,
) -> Result<(), ScanError> {
    let final_metadata = file.metadata().map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !same_file_identity(initial, &final_metadata)
        || metadata_changed_during_read(initial, &final_metadata)
    {
        return Err(changed_file_error(path));
    }
    root.verify()?;
    verify_path_matches_handle(&root.path, path, &final_metadata)
}

fn verify_path_matches_handle(
    root: &Path,
    path: &Path,
    opened_metadata: &fs::Metadata,
) -> Result<(), ScanError> {
    reject_linked_ancestors(root, path)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|source| ScanError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if is_link_or_reparse_point(&path_metadata)
        || !path_metadata.is_file()
        || !same_file_identity(&path_metadata, opened_metadata)
        || metadata_changed_during_read(&path_metadata, opened_metadata)
    {
        return Err(changed_file_error(path));
    }
    Ok(())
}

fn read_bounded_file(
    file: &mut File,
    path: &Path,
    expected_len: u64,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ScanError> {
    let capacity = usize::try_from(expected_len.min(maximum_bytes)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_len != expected_len || actual_len > maximum_bytes {
        return Err(changed_file_error(path));
    }
    Ok(bytes)
}

fn hash_reader(reader: &mut File, path: &Path, expected_len: u64) -> Result<String, ScanError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut actual_len = 0_u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|source| ScanError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if count == 0 {
            break;
        }
        actual_len = actual_len
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or_else(|| changed_file_error(path))?;
        hasher.update(&buffer[..count]);
    }
    if actual_len != expected_len {
        return Err(changed_file_error(path));
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn changed_file_error(path: &Path) -> ScanError {
    ScanError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            "repository file changed identity, type, or length while being scanned",
        ),
    }
}

fn changed_root_error(path: &Path) -> ScanError {
    ScanError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical repository root changed identity, type, or metadata while being scanned",
        ),
    }
}

fn metadata_changed_during_read(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.created().ok() != after.created().ok()
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(windows)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    left.file_attributes() == right.file_attributes()
        && left.creation_time() == right.creation_time()
        && left.len() == right.len()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
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

fn excluded_extraction(
    path: String,
    size: u64,
    content_hash: String,
    status: ScanStatus,
    reason: &str,
) -> FileExtraction {
    let coverage_id = stable_id("cov", &["file", &path]);
    FileExtraction {
        file: FileRecord {
            path: path.clone(),
            language: Language::from_path(&path),
            size,
            content_hash,
            status,
            evidence_id: None,
        },
        entities: vec![],
        imports: vec![],
        evidence: vec![],
        relationships: vec![],
        claims: vec![],
        coverage: vec![CoverageItem {
            id: coverage_id,
            kind: CoverageKind::File,
            subject: path,
            evidence_ids: vec![],
            disposition: CoverageDisposition::Excluded {
                reason: reason.into(),
            },
        }],
        semantic_references: vec![],
        python_bindings: vec![],
    }
}

fn unresolved_extraction(
    path: String,
    size: u64,
    content_hash: String,
    reason: &str,
) -> FileExtraction {
    let coverage_id = stable_id("cov", &["file", &path]);
    FileExtraction {
        file: FileRecord {
            path: path.clone(),
            language: None,
            size,
            content_hash,
            status: ScanStatus::Unsupported,
            evidence_id: None,
        },
        entities: vec![],
        imports: vec![],
        evidence: vec![],
        relationships: vec![],
        claims: vec![],
        coverage: vec![CoverageItem {
            id: coverage_id,
            kind: CoverageKind::File,
            subject: path,
            evidence_ids: vec![],
            disposition: CoverageDisposition::Unresolved {
                reason: Some(reason.into()),
            },
        }],
        semantic_references: vec![],
        python_bindings: vec![],
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "this function keeps the per-file records, evidence, and coverage construction in one auditable transaction"
)]
fn parsed_extraction(
    path: String,
    size: u64,
    content_hash: String,
    language: Language,
    source: &str,
) -> Result<FileExtraction, ScanError> {
    let file_evidence = make_evidence(
        &path,
        &content_hash,
        0,
        source.len(),
        1,
        u32::try_from(source.lines().count().max(1)).unwrap_or(u32::MAX),
        None,
    );
    let file_entity_id = stable_id("entity", &["file", &path]);
    let concept_id = concept_id_for_path(&path);
    let mut evidence = vec![file_evidence.clone()];
    let file_qualified_name = source_qualified_file_name(&path, language);
    let mut entities = vec![Entity {
        id: file_entity_id.clone(),
        kind: EntityKind::File,
        name: path.rsplit('/').next().unwrap_or(&path).to_owned(),
        qualified_name: if file_qualified_name.is_empty() {
            "__root__".to_owned()
        } else {
            file_qualified_name
        },
        owner_id: None,
        path: path.clone(),
        language: Some(language),
        evidence_id: file_evidence.id.clone(),
    }];
    let parsed = match language {
        Language::Markdown => ParsedFile {
            symbols: parse_markdown(source),
            imports: Vec::new(),
            docstring: None,
            semantic_references: Vec::new(),
            python_bindings: Vec::new(),
        },
        Language::JavaScript
        | Language::TypeScript
        | Language::Go
        | Language::Python
        | Language::Rust => parse_tree_sitter(language, &path, source)?,
    };
    let parsed_semantic_references = parsed.semantic_references.clone();
    let parsed_python_bindings = parsed.python_bindings.clone();

    let mut relationships = Vec::new();
    let mut claims = Vec::new();
    let mut coverage = vec![CoverageItem {
        id: stable_id("cov", &["file", &path]),
        kind: CoverageKind::File,
        subject: path.clone(),
        evidence_ids: vec![file_evidence.id.clone()],
        disposition: CoverageDisposition::Included {
            concept_id: concept_id.clone(),
        },
    }];

    let symbol_ids = parsed
        .symbols
        .iter()
        .map(|symbol| {
            (
                symbol.start_byte,
                stable_id(
                    "entity",
                    &[
                        entity_kind_label(symbol.kind),
                        &path,
                        &symbol.name,
                        &symbol.start_byte.to_string(),
                    ],
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for symbol in parsed.symbols {
        let symbol_evidence = make_evidence(
            &path,
            &content_hash,
            symbol.start_byte,
            symbol.end_byte,
            symbol.start_line,
            symbol.end_line,
            Some(symbol.name.clone()),
        );
        let entity_id = symbol_ids[&symbol.start_byte].clone();
        let owner_id = symbol
            .owner_start_byte
            .and_then(|start| symbol_ids.get(&start))
            .unwrap_or(&file_entity_id)
            .clone();
        let relationship_id = stable_id("rel", &["contains", &owner_id, &entity_id]);
        let claim_id = stable_id("claim", &["declares", &entity_id]);
        entities.push(Entity {
            id: entity_id.clone(),
            kind: symbol.kind,
            name: symbol.name.clone(),
            qualified_name: symbol.qualified_name.clone(),
            owner_id: Some(owner_id.clone()),
            path: path.clone(),
            language: Some(language),
            evidence_id: symbol_evidence.id.clone(),
        });
        relationships.push(Relationship {
            id: relationship_id,
            source: owner_id,
            target: entity_id.clone(),
            kind: RelationshipKind::Contains,
            origin: RelationshipOrigin::ObservedSyntax,
            evidence_ids: vec![symbol_evidence.id.clone()],
        });
        claims.push(Claim {
            id: claim_id,
            text: format!(
                "{} declares {} `{}`.",
                path,
                entity_kind_label(symbol.kind),
                symbol.name
            ),
            evidence_ids: vec![symbol_evidence.id.clone()],
            provenance: ClaimProvenance::Deterministic {
                process: EXTRACTOR_VERSION.into(),
            },
            confidence: Some(100),
        });
        if let Some(docstring) = symbol.docstring {
            let docstring_evidence = make_evidence(
                &path,
                &content_hash,
                docstring.start_byte,
                docstring.end_byte,
                docstring.start_line,
                docstring.end_line,
                Some(format!("{} docstring", symbol.name)),
            );
            claims.push(Claim {
                id: stable_id(
                    "claim",
                    &[
                        "python-docstring",
                        &path,
                        entity_kind_label(symbol.kind),
                        &symbol.name,
                        &docstring.start_byte.to_string(),
                    ],
                ),
                text: format!(
                    "{} declares {} `{}` with a Python docstring.",
                    path,
                    entity_kind_label(symbol.kind),
                    symbol.name
                ),
                evidence_ids: vec![symbol_evidence.id.clone(), docstring_evidence.id.clone()],
                provenance: ClaimProvenance::Deterministic {
                    process: EXTRACTOR_VERSION.into(),
                },
                confidence: Some(100),
            });
            evidence.push(docstring_evidence);
        }
        coverage.push(CoverageItem {
            id: stable_id("cov", &["entity", &entity_id]),
            kind: CoverageKind::Entity,
            subject: format!("{}:{}", path, symbol.name),
            evidence_ids: vec![symbol_evidence.id.clone()],
            disposition: CoverageDisposition::Included {
                concept_id: concept_id.clone(),
            },
        });
        evidence.push(symbol_evidence);
    }

    if let Some(docstring) = parsed.docstring {
        let docstring_evidence = make_evidence(
            &path,
            &content_hash,
            docstring.start_byte,
            docstring.end_byte,
            docstring.start_line,
            docstring.end_line,
            Some("module docstring".to_owned()),
        );
        claims.push(Claim {
            id: stable_id(
                "claim",
                &[
                    "python-module-docstring",
                    &path,
                    &docstring.start_byte.to_string(),
                ],
            ),
            text: format!("{path} has a Python module docstring."),
            evidence_ids: vec![file_evidence.id.clone(), docstring_evidence.id.clone()],
            provenance: ClaimProvenance::Deterministic {
                process: EXTRACTOR_VERSION.into(),
            },
            confidence: Some(100),
        });
        evidence.push(docstring_evidence);
    }

    let mut imports = Vec::new();
    for import in parsed.imports {
        let import_evidence = make_evidence(
            &path,
            &content_hash,
            import.start_byte,
            import.end_byte,
            import.start_line,
            import.end_line,
            None,
        );
        let external_id = stable_id("module", &[&import.specifier]);
        imports.push(ImportRecord {
            path: path.clone(),
            specifier: import.specifier.clone(),
            evidence_id: import_evidence.id.clone(),
        });
        relationships.push(Relationship {
            id: stable_id(
                "rel",
                &[
                    "imports",
                    &file_entity_id,
                    &external_id,
                    &import.start_byte.to_string(),
                ],
            ),
            source: file_entity_id.clone(),
            target: external_id,
            kind: RelationshipKind::Imports,
            origin: RelationshipOrigin::ObservedSyntax,
            evidence_ids: vec![import_evidence.id.clone()],
        });
        coverage.push(CoverageItem {
            id: stable_id(
                "cov",
                &[
                    "import",
                    &path,
                    &import.specifier,
                    &import.start_byte.to_string(),
                ],
            ),
            kind: CoverageKind::Import,
            subject: format!("{} imports {}", path, import.specifier),
            evidence_ids: vec![import_evidence.id.clone()],
            disposition: CoverageDisposition::Included {
                concept_id: concept_id.clone(),
            },
        });
        evidence.push(import_evidence);
    }

    let mut semantic_references = Vec::new();
    let mut python_bindings = Vec::new();
    if language == Language::Python {
        for reference in parsed_semantic_references {
            let initial_resolution = reference.forced_unresolved_reason.map_or_else(
                || SemanticResolution::Unresolved {
                    reason: PENDING_SEMANTIC_RESOLUTION_REASON.to_owned(),
                },
                |reason| SemanticResolution::Unresolved {
                    reason: reason.to_owned(),
                },
            );
            let reference_evidence = make_evidence(
                &path,
                &content_hash,
                reference.span.start_byte,
                reference.span.end_byte,
                reference.span.start_line,
                reference.span.end_line,
                None,
            );
            let scope_id = reference
                .scope_start_byte
                .and_then(|start| symbol_ids.get(&start))
                .unwrap_or(&file_entity_id)
                .clone();
            let source_entity_id = reference
                .source_start_byte
                .and_then(|start| symbol_ids.get(&start))
                .cloned();
            let id = stable_id(
                "ref",
                &[
                    semantic_reference_kind_label(reference.kind),
                    &path,
                    &reference.name,
                    &reference.span.start_byte.to_string(),
                    reference.binding_name.as_deref().unwrap_or(""),
                ],
            );
            semantic_references.push(SemanticReference {
                id,
                kind: reference.kind,
                path: path.clone(),
                scope_id,
                source_entity_id,
                name: reference.name,
                qualifier: reference.qualifier,
                binding_name: reference.binding_name,
                evidence_id: reference_evidence.id.clone(),
                resolution: initial_resolution,
            });
            evidence.push(reference_evidence);
        }
        for binding in parsed_python_bindings {
            python_bindings.push(PythonBinding {
                name: binding.name,
                scope_id: binding
                    .scope_start_byte
                    .and_then(|start| symbol_ids.get(&start))
                    .unwrap_or(&file_entity_id)
                    .clone(),
                kind: binding.kind,
                visible_after_byte: u64::try_from(binding.visible_after_byte).unwrap_or(u64::MAX),
            });
        }
    }

    Ok(FileExtraction {
        file: FileRecord {
            path,
            language: Some(language),
            size,
            content_hash,
            status: ScanStatus::Parsed,
            evidence_id: Some(file_evidence.id),
        },
        entities,
        imports,
        evidence,
        relationships,
        claims,
        coverage,
        semantic_references,
        python_bindings,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "parser setup, normalization and deterministic sort form one extraction transaction"
)]
fn parse_tree_sitter(
    language: Language,
    path: &str,
    source: &str,
) -> Result<ParsedFile, ScanError> {
    let mut parser = Parser::new();
    let grammar = match language {
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if path.to_ascii_lowercase().ends_with(".tsx") => {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Markdown => unreachable!("Markdown has a dedicated parser"),
    };
    parser
        .set_language(&grammar)
        .map_err(|error| ScanError::Parser {
            language: language.as_str(),
            message: error.to_string(),
        })?;
    let Some(tree) = parser.parse(source, None) else {
        return Ok(ParsedFile {
            symbols: Vec::new(),
            imports: Vec::new(),
            docstring: None,
            semantic_references: Vec::new(),
            python_bindings: Vec::new(),
        });
    };
    let file_docstring = (language == Language::Python)
        .then(|| python_docstring_span(tree.root_node(), source))
        .flatten();
    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    walk_syntax(
        tree.root_node(),
        source,
        language,
        path,
        &mut symbols,
        &mut imports,
    );
    symbols.sort_by(|left, right| {
        left.start_byte
            .cmp(&right.start_byte)
            .then_with(|| left.name.cmp(&right.name))
    });
    symbols.dedup_by(|left, right| {
        left.start_byte == right.start_byte
            && left.end_byte == right.end_byte
            && left.kind == right.kind
    });
    imports.sort_by(|left, right| {
        left.start_byte
            .cmp(&right.start_byte)
            .then_with(|| left.specifier.cmp(&right.specifier))
    });
    imports.dedup_by(|left, right| {
        left.start_byte == right.start_byte && left.specifier == right.specifier
    });
    let (mut semantic_references, mut python_bindings) = if language == Language::Python {
        extract_python_semantics(tree.root_node(), source)
    } else {
        (Vec::new(), Vec::new())
    };
    if language == Language::Python {
        for symbol in &symbols {
            python_bindings.push(ParsedPythonBinding {
                name: symbol.name.clone(),
                scope_start_byte: symbol.owner_start_byte,
                kind: if symbol.conditional_binding {
                    PythonBindingKind::ConditionalDeclaration
                } else {
                    PythonBindingKind::Declaration
                },
                visible_after_byte: symbol.end_byte,
            });
        }
        for import in &imports {
            for binding in &import.bindings {
                python_bindings.push(ParsedPythonBinding {
                    name: binding.binding_name.clone(),
                    scope_start_byte: import.scope_start_byte,
                    kind: if import.conditional_binding {
                        PythonBindingKind::ConditionalImport
                    } else {
                        PythonBindingKind::Import
                    },
                    visible_after_byte: import.end_byte,
                });
                semantic_references.push(ParsedSemanticReference {
                    kind: SemanticReferenceKind::ImportBinding,
                    name: binding.imported_name.clone(),
                    qualifier: binding.qualifier.clone(),
                    binding_name: Some(binding.binding_name.clone()),
                    span: ParsedSpan {
                        start_byte: import.start_byte,
                        end_byte: import.end_byte,
                        start_line: import.start_line,
                        end_line: import.end_line,
                    },
                    scope_start_byte: import.scope_start_byte,
                    source_start_byte: import.scope_start_byte,
                    forced_unresolved_reason: import
                        .conditional_binding
                        .then_some(PYTHON_CONDITIONAL_BINDING_RESOLUTION_REASON),
                });
            }
        }
        normalize_python_bindings(&mut python_bindings);
    }
    semantic_references.sort_by(|left, right| {
        left.span
            .start_byte
            .cmp(&right.span.start_byte)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });
    semantic_references.dedup_by(|left, right| {
        left.kind == right.kind
            && left.name == right.name
            && left.binding_name == right.binding_name
            && left.span.start_byte == right.span.start_byte
            && left.span.end_byte == right.span.end_byte
    });
    Ok(ParsedFile {
        symbols,
        imports,
        docstring: file_docstring,
        semantic_references,
        python_bindings,
    })
}

fn walk_syntax(
    node: Node<'_>,
    source: &str,
    language: Language,
    path: &str,
    symbols: &mut Vec<ParsedSymbol>,
    imports: &mut Vec<ParsedImport>,
) {
    if let Some(kind) = entity_kind_for_node(node, language)
        && let Some(name_node) = name_node(node, language)
        && let Ok(name) = name_node.utf8_text(source.as_bytes())
    {
        let name = name.trim();
        if !name.is_empty() {
            let span_node = declaration_span_node(node, language);
            symbols.push(ParsedSymbol {
                kind,
                name: name.to_owned(),
                start_byte: span_node.start_byte(),
                end_byte: span_node.end_byte(),
                start_line: one_based_row(span_node.start_position().row),
                end_line: one_based_row(span_node.end_position().row),
                docstring: (language == Language::Python)
                    .then(|| python_docstring_span(node, source))
                    .flatten(),
                owner_start_byte: lexical_owner_start_byte(node, language),
                qualified_name: qualified_symbol_name(path, language, node, source, name),
                conditional_binding: language == Language::Python
                    && python_binding_is_conditional(node),
            });
        }
    }

    if language == Language::Python {
        append_python_imports(node, source, imports);
    } else if let Some(specifier_node) = import_specifier_node(node, language) {
        append_import(node, specifier_node, source, imports);
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_syntax(child, source, language, path, symbols, imports);
    }
}

fn entity_kind_for_node(node: Node<'_>, language: Language) -> Option<EntityKind> {
    match (language, node.kind()) {
        (Language::JavaScript | Language::TypeScript, "function_declaration") => {
            Some(EntityKind::Function)
        }
        (Language::JavaScript | Language::TypeScript, "method_definition") => {
            Some(EntityKind::Method)
        }
        (Language::JavaScript | Language::TypeScript, "class_declaration")
        | (Language::Rust, "struct_item")
        | (Language::Python, "class_definition") => Some(EntityKind::Class),
        (Language::TypeScript, "interface_declaration") | (Language::Rust, "trait_item") => {
            Some(EntityKind::Interface)
        }
        (Language::TypeScript, "type_alias_declaration")
        | (Language::Go, "type_spec")
        | (Language::Rust, "type_item") => Some(EntityKind::Type),
        (Language::TypeScript, "enum_declaration") | (Language::Rust, "enum_item") => {
            Some(EntityKind::Enum)
        }
        (Language::JavaScript | Language::TypeScript, "variable_declarator")
            if is_module_level_variable(node) =>
        {
            Some(EntityKind::Variable)
        }
        (Language::Go, "function_declaration") => Some(EntityKind::Function),
        (Language::Go, "method_declaration") => Some(EntityKind::Method),
        (Language::Python, "function_definition") => Some(if is_python_method(node) {
            EntityKind::Method
        } else {
            EntityKind::Function
        }),
        (Language::Rust, "function_item" | "function_signature_item") => {
            if is_rust_associated_function(node) {
                Some(EntityKind::Method)
            } else {
                Some(EntityKind::Function)
            }
        }
        (Language::Rust, "const_item" | "static_item") => Some(EntityKind::Variable),
        _ => None,
    }
}

fn declaration_span_node(node: Node<'_>, language: Language) -> Node<'_> {
    if language == Language::Python
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
    {
        node.parent().unwrap_or(node)
    } else {
        node
    }
}

fn is_python_method(node: Node<'_>) -> bool {
    let declaration = declaration_span_node(node, Language::Python);
    declaration
        .parent()
        .filter(|parent| parent.kind() == "block")
        .and_then(|block| block.parent())
        .is_some_and(|parent| parent.kind() == "class_definition")
}

fn lexical_owner_start_byte(node: Node<'_>, language: Language) -> Option<usize> {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if entity_kind_for_node(current, language).is_some() {
            return Some(declaration_span_node(current, language).start_byte());
        }
        ancestor = current.parent();
    }
    None
}

fn qualified_symbol_name(
    path: &str,
    language: Language,
    node: Node<'_>,
    source: &str,
    name: &str,
) -> String {
    let mut owners = Vec::new();
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        if entity_kind_for_node(current, language).is_some()
            && let Some(name_node) = name_node(current, language)
            && let Ok(owner_name) = name_node.utf8_text(source.as_bytes())
            && !owner_name.trim().is_empty()
        {
            owners.push(owner_name.trim().to_owned());
        }
        ancestor = current.parent();
    }
    owners.reverse();
    owners.push(name.to_owned());
    let file_name = source_qualified_file_name(path, language);
    if language == Language::Python {
        std::iter::once(file_name)
            .chain(owners)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        format!("{file_name}::{}", owners.join("::"))
    }
}

fn source_qualified_file_name(path: &str, language: Language) -> String {
    if language != Language::Python {
        return path.to_owned();
    }
    let without_extension = path
        .get(path.len().saturating_sub(3)..)
        .filter(|suffix| suffix.eq_ignore_ascii_case(".py"))
        .and_then(|_| path.get(..path.len().saturating_sub(3)))
        .unwrap_or(path);
    let mut module = without_extension.replace('/', ".");
    if module.eq_ignore_ascii_case("__init__") {
        module.clear();
    } else if module
        .rsplit_once('.')
        .is_some_and(|(_, filename)| filename.eq_ignore_ascii_case("__init__"))
    {
        module.truncate(module.rfind('.').unwrap_or_default());
    }
    if module
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("src."))
    {
        module.drain(..4);
    }
    module
}

fn python_docstring_span(owner: Node<'_>, source: &str) -> Option<ParsedSpan> {
    let body = if owner.kind() == "module" {
        owner
    } else {
        owner.child_by_field_name("body")?
    };
    let mut cursor = body.walk();
    let statement = body
        .named_children(&mut cursor)
        .find(|child| child.kind() != "comment")?;
    if statement.kind() != "expression_statement" {
        return None;
    }
    let literal = statement.named_child(0)?;
    if !is_python_docstring_literal(literal, source) {
        return None;
    }
    Some(ParsedSpan {
        start_byte: literal.start_byte(),
        end_byte: literal.end_byte(),
        start_line: one_based_row(literal.start_position().row),
        end_line: one_based_row(literal.end_position().row),
    })
}

fn is_python_docstring_literal(literal: Node<'_>, source: &str) -> bool {
    match literal.kind() {
        "string" => python_string_is_text_constant(literal, source),
        "concatenated_string" => {
            let mut cursor = literal.walk();
            let strings = literal
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "string")
                .collect::<Vec<_>>();
            !strings.is_empty()
                && strings
                    .into_iter()
                    .all(|string| python_string_is_text_constant(string, source))
        }
        _ => false,
    }
}

fn python_string_is_text_constant(literal: Node<'_>, source: &str) -> bool {
    let Ok(raw) = literal.utf8_text(source.as_bytes()) else {
        return false;
    };
    let prefix = raw
        .find(['\'', '"'])
        .map_or(raw, |quote_index| &raw[..quote_index]);
    prefix
        .bytes()
        .all(|byte| matches!(byte.to_ascii_lowercase(), b'r' | b'u'))
        && !node_contains_kind(literal, "interpolation")
}

fn node_contains_kind(node: Node<'_>, kind: &str) -> bool {
    if node.kind() == kind {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| node_contains_kind(child, kind))
}

fn extract_python_semantics(
    root: Node<'_>,
    source: &str,
) -> (Vec<ParsedSemanticReference>, Vec<ParsedPythonBinding>) {
    let mut references = Vec::new();
    let mut bindings = Vec::new();
    walk_python_semantics(root, source, &mut references, &mut bindings);
    normalize_python_bindings(&mut bindings);
    (references, bindings)
}

fn normalize_python_bindings(bindings: &mut Vec<ParsedPythonBinding>) {
    bindings.sort_by(|left, right| {
        left.scope_start_byte
            .cmp(&right.scope_start_byte)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| {
                python_binding_kind_order(left.kind).cmp(&python_binding_kind_order(right.kind))
            })
            .then_with(|| left.visible_after_byte.cmp(&right.visible_after_byte))
    });
    bindings.dedup_by(|left, right| {
        left.scope_start_byte == right.scope_start_byte
            && left.name == right.name
            && left.kind == right.kind
            && left.visible_after_byte == right.visible_after_byte
    });
}

#[allow(
    clippy::too_many_lines,
    reason = "the Python semantic syntax inventory is intentionally explicit and fail-closed"
)]
fn walk_python_semantics(
    node: Node<'_>,
    source: &str,
    references: &mut Vec<ParsedSemanticReference>,
    bindings: &mut Vec<ParsedPythonBinding>,
) {
    match node.kind() {
        "call" => {
            if let Some(function) = node.child_by_field_name("function") {
                let (scope_start, source_start) = python_call_context(node);
                append_python_named_reference(
                    function,
                    source,
                    SemanticReferenceKind::Call,
                    scope_start,
                    source_start,
                    references,
                );
            }
        }
        "class_definition" => {
            if let Some(superclasses) = node.child_by_field_name("superclasses") {
                let source_start = Some(declaration_span_node(node, Language::Python).start_byte());
                let scope_start = lexical_owner_start_byte(node, Language::Python);
                let mut cursor = superclasses.walk();
                for base in superclasses.named_children(&mut cursor) {
                    if base.kind() != "keyword_argument" {
                        append_python_named_reference(
                            base,
                            source,
                            SemanticReferenceKind::Extends,
                            scope_start,
                            source_start,
                            references,
                        );
                    }
                }
            }
        }
        "decorator" => {
            if let Some(target) = python_decorated_target(node) {
                let expression = node.named_child(0);
                if let Some(expression) = expression {
                    let decorated = decorator_callable(expression);
                    append_python_named_reference(
                        decorated,
                        source,
                        SemanticReferenceKind::Decorator,
                        lexical_owner_start_byte(target, Language::Python),
                        Some(declaration_span_node(target, Language::Python).start_byte()),
                        references,
                    );
                }
            }
        }
        "function_definition" => {
            let source_start = Some(declaration_span_node(node, Language::Python).start_byte());
            let annotation_scope = lexical_owner_start_byte(node, Language::Python);
            if let Some(return_type) = node.child_by_field_name("return_type") {
                append_python_type_references(
                    return_type,
                    source,
                    annotation_scope,
                    source_start,
                    references,
                );
            }
        }
        "typed_parameter" | "typed_default_parameter" => {
            if let Some(annotation) = node.child_by_field_name("type") {
                let function = nearest_python_declaration(node);
                let source_start = function
                    .map(|owner| declaration_span_node(owner, Language::Python).start_byte());
                let annotation_scope =
                    function.and_then(|owner| lexical_owner_start_byte(owner, Language::Python));
                append_python_type_references(
                    annotation,
                    source,
                    annotation_scope,
                    source_start,
                    references,
                );
            }
        }
        "assignment" => {
            if let Some(annotation) = node.child_by_field_name("type") {
                append_python_type_references(
                    annotation,
                    source,
                    nearest_python_scope_start(node),
                    nearest_python_scope_start(node),
                    references,
                );
            }
            if let Some(left) = node.child_by_field_name("left") {
                append_python_local_bindings(
                    left,
                    source,
                    nearest_python_scope_start(node),
                    node.end_byte(),
                    bindings,
                );
            }
        }
        "for_statement" | "for_in_clause" => {
            if !python_comprehension_ancestor(node)
                && let Some(left) = node.child_by_field_name("left")
            {
                append_python_local_bindings(
                    left,
                    source,
                    nearest_python_scope_start(node),
                    left.end_byte(),
                    bindings,
                );
            }
        }
        "except_clause" => {
            if let Some(alias) = node.child_by_field_name("alias") {
                append_python_local_bindings(
                    alias,
                    source,
                    nearest_python_scope_start(node),
                    alias.end_byte(),
                    bindings,
                );
            }
        }
        "with_item" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if Some(child) != node.child_by_field_name("value") {
                    append_python_local_bindings(
                        child,
                        source,
                        nearest_python_scope_start(node),
                        child.end_byte(),
                        bindings,
                    );
                }
            }
        }
        "case_clause" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "case_pattern" {
                    append_python_local_bindings(
                        child,
                        source,
                        nearest_python_scope_start(node),
                        child.end_byte(),
                        bindings,
                    );
                }
            }
        }
        "augmented_assignment" | "named_expression" => {
            if let Some(left) = node
                .child_by_field_name("left")
                .or_else(|| node.child_by_field_name("name"))
            {
                append_python_local_bindings(
                    left,
                    source,
                    nearest_python_scope_start(node),
                    node.end_byte(),
                    bindings,
                );
            }
        }
        "delete_statement" => {
            let mut cursor = node.walk();
            for target in node.named_children(&mut cursor) {
                append_python_bindings(
                    target,
                    source,
                    nearest_python_scope_start(node),
                    PythonBindingKind::Delete,
                    node.end_byte(),
                    bindings,
                );
            }
        }
        "parameters" => {
            let scope_start = node
                .parent()
                .filter(|parent| parent.kind() == "function_definition")
                .map(|function| declaration_span_node(function, Language::Python).start_byte());
            let mut cursor = node.walk();
            for parameter in node.named_children(&mut cursor) {
                if let Some(name) = python_parameter_name_node(parameter) {
                    append_python_local_bindings(
                        name,
                        source,
                        scope_start,
                        name.end_byte(),
                        bindings,
                    );
                }
            }
        }
        "global_statement" | "nonlocal_statement" => {
            let kind = if node.kind() == "global_statement" {
                PythonBindingKind::Global
            } else {
                PythonBindingKind::Nonlocal
            };
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier"
                    && let Ok(name) = child.utf8_text(source.as_bytes())
                {
                    bindings.push(ParsedPythonBinding {
                        name: name.to_owned(),
                        scope_start_byte: nearest_python_scope_start(node),
                        kind,
                        visible_after_byte: node.end_byte(),
                    });
                }
            }
        }
        _ => {}
    }

    if node.kind() == "lambda" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_python_semantics(child, source, references, bindings);
    }
}

fn append_python_type_references(
    annotation: Node<'_>,
    source: &str,
    scope_start: Option<usize>,
    source_start: Option<usize>,
    references: &mut Vec<ParsedSemanticReference>,
) {
    if matches!(
        annotation.kind(),
        "identifier" | "dotted_name" | "attribute"
    ) {
        append_python_named_reference(
            annotation,
            source,
            SemanticReferenceKind::TypeUse,
            scope_start,
            source_start,
            references,
        );
        return;
    }
    let mut cursor = annotation.walk();
    for child in annotation.named_children(&mut cursor) {
        append_python_type_references(child, source, scope_start, source_start, references);
    }
}

fn append_python_named_reference(
    node: Node<'_>,
    source: &str,
    kind: SemanticReferenceKind,
    scope_start_byte: Option<usize>,
    source_start_byte: Option<usize>,
    references: &mut Vec<ParsedSemanticReference>,
) {
    let Ok(name) = node.utf8_text(source.as_bytes()) else {
        return;
    };
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    references.push(ParsedSemanticReference {
        kind,
        name: name.to_owned(),
        qualifier: None,
        binding_name: None,
        span: parsed_span(node),
        scope_start_byte,
        source_start_byte,
        forced_unresolved_reason: python_comprehension_ancestor(node)
            .then_some(PYTHON_COMPREHENSION_RESOLUTION_REASON),
    });
}

fn python_comprehension_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "list_comprehension"
                | "set_comprehension"
                | "dictionary_comprehension"
                | "generator_expression"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

fn python_binding_is_conditional(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "module" | "function_definition" | "class_definition"
        ) {
            return false;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "for_statement"
                | "while_statement"
                | "try_statement"
                | "with_statement"
                | "match_statement"
                | "case_clause"
        ) {
            return true;
        }
        node = parent;
    }
    false
}

fn append_python_local_bindings(
    node: Node<'_>,
    source: &str,
    scope_start_byte: Option<usize>,
    visible_after_byte: usize,
    bindings: &mut Vec<ParsedPythonBinding>,
) {
    append_python_bindings(
        node,
        source,
        scope_start_byte,
        PythonBindingKind::Local,
        visible_after_byte,
        bindings,
    );
}

fn append_python_bindings(
    node: Node<'_>,
    source: &str,
    scope_start_byte: Option<usize>,
    kind: PythonBindingKind,
    visible_after_byte: usize,
    bindings: &mut Vec<ParsedPythonBinding>,
) {
    if node.kind() == "identifier" {
        if let Ok(name) = node.utf8_text(source.as_bytes()) {
            bindings.push(ParsedPythonBinding {
                name: name.to_owned(),
                scope_start_byte,
                kind,
                visible_after_byte,
            });
        }
        return;
    }
    if matches!(node.kind(), "attribute" | "subscript") {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        append_python_bindings(
            child,
            source,
            scope_start_byte,
            kind,
            visible_after_byte,
            bindings,
        );
    }
}

fn python_parameter_name_node(parameter: Node<'_>) -> Option<Node<'_>> {
    match parameter.kind() {
        "identifier" => Some(parameter),
        "typed_parameter" => parameter
            .named_children(&mut parameter.walk())
            .find(|child| {
                matches!(
                    child.kind(),
                    "identifier" | "list_splat_pattern" | "dictionary_splat_pattern"
                )
            }),
        "default_parameter" | "typed_default_parameter" => parameter.child_by_field_name("name"),
        "list_splat" | "dictionary_splat" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            parameter.named_child(0)
        }
        _ => None,
    }
}

fn nearest_python_declaration(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "function_definition" | "class_definition") {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn nearest_python_scope_start(node: Node<'_>) -> Option<usize> {
    nearest_python_declaration(node)
        .map(|owner| declaration_span_node(owner, Language::Python).start_byte())
}

fn python_call_context(node: Node<'_>) -> (Option<usize>, Option<usize>) {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "class_definition") {
            let declaration = declaration_span_node(parent, Language::Python);
            let body_contains_call = parent.child_by_field_name("body").is_some_and(|body| {
                body.start_byte() <= node.start_byte() && node.end_byte() <= body.end_byte()
            });
            if body_contains_call {
                let start = Some(declaration.start_byte());
                return (start, start);
            }
            return (
                lexical_owner_start_byte(parent, Language::Python),
                lexical_owner_start_byte(parent, Language::Python),
            );
        }
        current = parent;
    }
    (None, None)
}

fn python_decorated_target(decorator: Node<'_>) -> Option<Node<'_>> {
    let decorated = decorator.parent()?;
    if decorated.kind() != "decorated_definition" {
        return None;
    }
    let mut cursor = decorated.walk();
    decorated
        .named_children(&mut cursor)
        .find(|child| matches!(child.kind(), "function_definition" | "class_definition"))
}

fn decorator_callable(expression: Node<'_>) -> Node<'_> {
    if expression.kind() == "call" {
        expression
            .child_by_field_name("function")
            .unwrap_or(expression)
    } else {
        expression
    }
}

const fn python_binding_kind_order(kind: PythonBindingKind) -> u8 {
    match kind {
        PythonBindingKind::Local => 0,
        PythonBindingKind::Declaration => 1,
        PythonBindingKind::Import => 2,
        PythonBindingKind::ConditionalDeclaration => 3,
        PythonBindingKind::ConditionalImport => 4,
        PythonBindingKind::Delete => 5,
        PythonBindingKind::Global => 6,
        PythonBindingKind::Nonlocal => 7,
    }
}

fn append_python_imports(node: Node<'_>, source: &str, imports: &mut Vec<ParsedImport>) {
    match node.kind() {
        "import_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if matches!(child.kind(), "aliased_import" | "dotted_name") {
                    append_python_import(node, child, source, imports);
                }
            }
        }
        "import_from_statement" => {
            if let Some(module) = node.child_by_field_name("module_name") {
                // For `from . import util`, `util` may be either a package
                // attribute or an imported submodule at runtime. Preserve the
                // verified dependency on the package (`.`) instead of guessing
                // a `pkg.util` source edge.
                let bindings = python_from_import_bindings(node, source);
                append_import_with_bindings(node, module, source, bindings, imports);
            }
        }
        "future_import_statement" => {
            let bindings = python_from_import_bindings(node, source);
            append_import_specifier_with_bindings(node, "__future__", bindings, imports);
        }
        _ => {}
    }
}

fn append_python_import(
    statement: Node<'_>,
    name_node: Node<'_>,
    source: &str,
    imports: &mut Vec<ParsedImport>,
) {
    let imported_node = if name_node.kind() == "aliased_import" {
        name_node.child_by_field_name("name")
    } else {
        Some(name_node)
    };
    let Some(imported_node) = imported_node else {
        return;
    };
    let Ok(imported_name) = imported_node.utf8_text(source.as_bytes()) else {
        return;
    };
    let imported_name = imported_name.trim();
    if imported_name.is_empty() {
        return;
    }
    let binding_node = name_node
        .child_by_field_name("alias")
        .unwrap_or(imported_node);
    let Ok(binding) = binding_node.utf8_text(source.as_bytes()) else {
        return;
    };
    let binding = if name_node.kind() == "aliased_import" {
        binding.trim()
    } else {
        imported_name.split('.').next().unwrap_or(imported_name)
    };
    let binding = ParsedImportBinding {
        imported_name: imported_name.to_owned(),
        qualifier: None,
        binding_name: binding.to_owned(),
    };
    append_import_with_bindings(statement, imported_node, source, vec![binding], imports);
}

fn python_from_import_bindings(statement: Node<'_>, source: &str) -> Vec<ParsedImportBinding> {
    let mut result = Vec::new();
    let mut cursor = statement.walk();
    for child in statement.named_children(&mut cursor) {
        if Some(child) == statement.child_by_field_name("module_name") {
            continue;
        }
        match child.kind() {
            "aliased_import" | "dotted_name" => {
                let imported_node = child.child_by_field_name("name").unwrap_or(child);
                let binding_node = child.child_by_field_name("alias").unwrap_or(imported_node);
                let (Ok(imported), Ok(binding)) = (
                    imported_node.utf8_text(source.as_bytes()),
                    binding_node.utf8_text(source.as_bytes()),
                ) else {
                    continue;
                };
                let imported = imported.trim();
                let binding = binding.trim();
                if !imported.is_empty() && !binding.is_empty() {
                    result.push(ParsedImportBinding {
                        imported_name: imported.to_owned(),
                        qualifier: statement
                            .child_by_field_name("module_name")
                            .and_then(|module| module.utf8_text(source.as_bytes()).ok())
                            .map(str::trim)
                            .filter(|module| !module.is_empty())
                            .map(str::to_owned)
                            .or_else(|| {
                                (statement.kind() == "future_import_statement")
                                    .then(|| "__future__".to_owned())
                            }),
                        binding_name: binding.to_owned(),
                    });
                }
            }
            "wildcard_import" => result.push(ParsedImportBinding {
                imported_name: "*".to_owned(),
                qualifier: statement
                    .child_by_field_name("module_name")
                    .and_then(|module| module.utf8_text(source.as_bytes()).ok())
                    .map(str::trim)
                    .filter(|module| !module.is_empty())
                    .map(str::to_owned),
                binding_name: "*".to_owned(),
            }),
            _ => {}
        }
    }
    result
}

fn append_import(
    statement: Node<'_>,
    specifier_node: Node<'_>,
    source: &str,
    imports: &mut Vec<ParsedImport>,
) {
    if let Ok(raw) = specifier_node.utf8_text(source.as_bytes()) {
        let specifier = raw.trim().trim_matches(['\'', '"', '`']);
        append_import_specifier(statement, specifier, imports);
    }
}

fn append_import_specifier(statement: Node<'_>, specifier: &str, imports: &mut Vec<ParsedImport>) {
    append_import_specifier_with_bindings(statement, specifier, Vec::new(), imports);
}

fn append_import_with_bindings(
    statement: Node<'_>,
    specifier_node: Node<'_>,
    source: &str,
    bindings: Vec<ParsedImportBinding>,
    imports: &mut Vec<ParsedImport>,
) {
    if let Ok(raw) = specifier_node.utf8_text(source.as_bytes()) {
        let specifier = raw.trim().trim_matches(['\'', '"', '`']);
        append_import_specifier_with_bindings(statement, specifier, bindings, imports);
    }
}

fn append_import_specifier_with_bindings(
    statement: Node<'_>,
    specifier: &str,
    bindings: Vec<ParsedImportBinding>,
    imports: &mut Vec<ParsedImport>,
) {
    if !specifier.is_empty() {
        imports.push(ParsedImport {
            specifier: specifier.to_owned(),
            bindings,
            scope_start_byte: nearest_python_scope_start(statement),
            start_byte: statement.start_byte(),
            end_byte: statement.end_byte(),
            start_line: one_based_row(statement.start_position().row),
            end_line: one_based_row(statement.end_position().row),
            conditional_binding: python_binding_is_conditional(statement),
        });
    }
}

fn parsed_span(node: Node<'_>) -> ParsedSpan {
    ParsedSpan {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: one_based_row(node.start_position().row),
        end_line: one_based_row(node.end_position().row),
    }
}

fn name_node(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    match (language, node.kind()) {
        (Language::JavaScript | Language::TypeScript, "variable_declarator") => {
            node.child_by_field_name("name")
        }
        _ => node.child_by_field_name("name"),
    }
}

fn is_module_level_variable(node: Node<'_>) -> bool {
    let Some(declaration) = node.parent() else {
        return false;
    };
    let Some(parent) = declaration.parent() else {
        return false;
    };
    parent.kind() == "program"
        || (parent.kind() == "export_statement"
            && parent
                .parent()
                .is_some_and(|grandparent| grandparent.kind() == "program"))
}

fn is_rust_associated_function(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(parent) = ancestor {
        match parent.kind() {
            "impl_item" | "trait_item" => return true,
            // An inner function is not a method merely because the enclosing
            // function itself belongs to an impl or trait.
            "function_item" | "function_signature_item" | "source_file" | "mod_item" => {
                return false;
            }
            _ => ancestor = parent.parent(),
        }
    }
    false
}

fn import_specifier_node(node: Node<'_>, language: Language) -> Option<Node<'_>> {
    match (language, node.kind()) {
        (Language::JavaScript | Language::TypeScript, "import_statement") => {
            node.child_by_field_name("source")
        }
        (Language::Go, "import_spec") => node.child_by_field_name("path").or_else(|| {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .find(|child| child.kind() == "interpreted_string_literal")
        }),
        (Language::Rust, "use_declaration") => node.child_by_field_name("argument"),
        _ => None,
    }
}

fn parse_markdown(source: &str) -> Vec<ParsedSymbol> {
    let mut result = Vec::new();
    let mut byte_offset = 0_usize;
    for (index, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim_start();
        let hashes = trimmed.bytes().take_while(|byte| *byte == b'#').count();
        if (1..=6).contains(&hashes)
            && trimmed
                .as_bytes()
                .get(hashes)
                .is_some_and(u8::is_ascii_whitespace)
        {
            let name = trimmed[hashes..].trim().trim_end_matches('#').trim();
            if !name.is_empty() {
                result.push(ParsedSymbol {
                    kind: EntityKind::Heading,
                    name: name.to_owned(),
                    start_byte: byte_offset,
                    end_byte: byte_offset + line.len(),
                    start_line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    end_line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    docstring: None,
                    owner_start_byte: None,
                    qualified_name: name.to_owned(),
                    conditional_binding: false,
                });
            }
        }
        byte_offset += chunk.len();
    }
    result
}

fn make_evidence(
    path: &str,
    content_hash: &str,
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    end_line: u32,
    symbol: Option<String>,
) -> EvidenceRef {
    let id = stable_id(
        "evidence",
        &[
            path,
            content_hash,
            &start_byte.to_string(),
            &end_byte.to_string(),
        ],
    );
    EvidenceRef {
        id,
        path: path.into(),
        start_line,
        end_line: end_line.max(start_line),
        start_byte: u64::try_from(start_byte).unwrap_or(u64::MAX),
        end_byte: u64::try_from(end_byte).unwrap_or(u64::MAX),
        content_hash: content_hash.into(),
        symbol,
        extractor: EXTRACTOR_VERSION.into(),
    }
}

fn git_head(root: &Path) -> Option<String> {
    let git = which::which_global("git").ok()?;
    let output = Command::new(git)
        .args([
            "--no-pager",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=",
            "-C",
        ])
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn normalize_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn concept_id_for_path(path: &str) -> String {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let slug: String = filename
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .take(80)
        .collect();
    let hash = stable_hash(&[path]);
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "file" } else { slug };
    format!("source/{slug}-{}", &hash[..16])
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    format!("{prefix}:{}", &stable_hash(parts)[..24])
}

fn stable_hash(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn one_based_row(row: usize) -> u32 {
    u32::try_from(row).map_or(u32::MAX, |value| value.saturating_add(1))
}

const fn entity_kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::File => "file",
        EntityKind::Function => "function",
        EntityKind::Method => "method",
        EntityKind::Class => "class",
        EntityKind::Interface => "interface",
        EntityKind::Type => "type",
        EntityKind::Enum => "enum",
        EntityKind::Variable => "variable",
        EntityKind::Heading => "heading",
    }
}

const fn semantic_reference_kind_label(kind: SemanticReferenceKind) -> &'static str {
    match kind {
        SemanticReferenceKind::ImportBinding => "import_binding",
        SemanticReferenceKind::Call => "call",
        SemanticReferenceKind::Extends => "extends",
        SemanticReferenceKind::TypeUse => "type_use",
        SemanticReferenceKind::Decorator => "decorator",
    }
}

const fn relationship_kind_for_semantic_reference(kind: SemanticReferenceKind) -> RelationshipKind {
    match kind {
        SemanticReferenceKind::ImportBinding => RelationshipKind::Imports,
        SemanticReferenceKind::Call => RelationshipKind::Calls,
        SemanticReferenceKind::Extends => RelationshipKind::Extends,
        SemanticReferenceKind::TypeUse => RelationshipKind::TypeUses,
        SemanticReferenceKind::Decorator => RelationshipKind::DecoratedBy,
    }
}

#[allow(clippy::too_many_arguments)]
fn fingerprint_ir(
    repository: &RepositoryMetadata,
    files: &[FileRecord],
    entities: &[Entity],
    imports: &[ImportRecord],
    evidence: &[EvidenceRef],
    relationships: &[Relationship],
    semantic_references: &[SemanticReference],
    semantic_coverage: &SemanticCoverage,
    claims: &[Claim],
    coverage: &CoverageReport,
) -> Result<String, serde_json::Error> {
    let deterministic_claims: Vec<&Claim> = claims
        .iter()
        .filter(|claim| matches!(claim.provenance, ClaimProvenance::Deterministic { .. }))
        .collect();
    let value = serde_json::to_vec(&(
        IR_SCHEMA_VERSION,
        repository,
        files,
        entities,
        imports,
        evidence,
        relationships,
        semantic_references,
        semantic_coverage,
        deterministic_claims,
        coverage,
    ))?;
    Ok(blake3::hash(&value).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
    };

    use super::fingerprint_ir;
    use super::{
        RelativeImportFailure, RootIdentity, ScanOptions, concept_id_for_path, file_path_metadata,
        parse_markdown, python_module_case_guard, resolve_relative_javascript_target,
        scan_repository,
    };
    #[cfg(any(unix, windows))]
    use super::{open_stable_file, verify_stable_file};
    use crate::{
        ArchitectureScope, CoverageDisposition, CoverageKind, EntityKind, Language,
        RelationshipKind, RelationshipOrigin, RepositoryIr, ScanStatus, SemanticCoverage,
        SemanticReferenceKind, SemanticResolution,
    };

    #[test]
    fn markdown_headings_have_precise_lines() {
        let headings = parse_markdown("# One\ntext\n## Two\n");
        assert_eq!(headings.len(), 2);
        assert_eq!(headings[0].name, "One");
        assert_eq!(headings[1].start_line, 3);
    }

    #[test]
    fn concept_ids_bound_long_source_components() {
        let filename = format!("{}.rs", "a".repeat(240));
        let id = concept_id_for_path(&format!("deep/{filename}"));
        let component = id.rsplit('/').next().expect("concept filename");
        assert!(component.len() < 120);
        assert_eq!(id, concept_id_for_path(&format!("deep/{filename}")));
    }

    #[test]
    fn scans_typescript_go_and_markdown_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("app.ts"),
            "import {x} from './dep';\nexport function run() { return x; }\n",
        )
        .expect("write TypeScript");
        fs::write(
            temp.path().join("main.go"),
            "package main\nfunc main() {}\n",
        )
        .expect("write Go");
        fs::write(temp.path().join("README.md"), "# Project\n").expect("write Markdown");
        fs::write(temp.path().join("image.bin"), [0, 1, 2]).expect("write binary");

        let first = scan_repository(temp.path(), &ScanOptions::default()).expect("first scan");
        let second = scan_repository(temp.path(), &ScanOptions::default()).expect("second scan");
        assert_eq!(first, second);
        assert!(
            first
                .entities
                .iter()
                .any(|entity| { entity.kind == EntityKind::Function && entity.name == "run" })
        );
        assert!(
            first
                .entities
                .iter()
                .any(|entity| { entity.language == Some(Language::Go) && entity.name == "main" })
        );
        assert!(
            first
                .imports
                .iter()
                .any(|import| import.specifier == "./dep")
        );
        assert!(
            first
                .files
                .iter()
                .any(|file| file.status == ScanStatus::Binary)
        );
        first.validate().expect("IR should validate");
    }

    #[test]
    fn resolves_relative_typescript_imports_by_extension_index_and_normalized_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("src/folder")).expect("source directories");
        fs::write(
            temp.path().join("src/main.ts"),
            concat!(
                "import './feature/../lib';\n",
                "import './folder';\n",
                "import './exact.js';\n",
            ),
        )
        .expect("entrypoint");
        fs::write(temp.path().join("src/lib.ts"), "export const lib = 1;\n")
            .expect("extension target");
        fs::write(
            temp.path().join("src/folder/index.ts"),
            "export const folder = 1;\n",
        )
        .expect("index target");
        fs::write(
            temp.path().join("src/exact.js"),
            "export const exact = 1;\n",
        )
        .expect("exact target");

        let first = scan_repository(temp.path(), &ScanOptions::default()).expect("first scan");
        let second = scan_repository(temp.path(), &ScanOptions::default()).expect("second scan");
        assert_eq!(first, second);
        for (specifier, expected_path) in [
            ("./feature/../lib", "src/lib.ts"),
            ("./folder", "src/folder/index.ts"),
            ("./exact.js", "src/exact.js"),
        ] {
            let import = first
                .imports
                .iter()
                .find(|import| import.specifier == specifier)
                .expect("import record");
            let relationship = first
                .relationships
                .iter()
                .find(|relationship| {
                    relationship.kind == RelationshipKind::Imports
                        && relationship.evidence_ids.contains(&import.evidence_id)
                })
                .expect("resolved import relationship");
            let target = first
                .entities
                .iter()
                .find(|entity| entity.id == relationship.target)
                .expect("target file entity");
            assert_eq!(target.kind, EntityKind::File);
            assert_eq!(target.path, expected_path);
            let coverage = first
                .coverage
                .items
                .iter()
                .find(|item| {
                    item.kind == CoverageKind::Import
                        && item.evidence_ids.contains(&import.evidence_id)
                })
                .expect("import coverage");
            assert!(matches!(
                coverage.disposition,
                CoverageDisposition::Included { .. }
            ));
        }
    }

    #[test]
    fn leaves_ambiguous_missing_case_mismatched_and_escaping_imports_unresolved() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("src")).expect("source directory");
        fs::write(
            temp.path().join("src/main.ts"),
            concat!(
                "import './choice';\n",
                "import './missing';\n",
                "import './Case';\n",
                "import '../../outside';\n",
            ),
        )
        .expect("entrypoint");
        fs::write(temp.path().join("src/choice.ts"), "export const ts = 1;\n")
            .expect("TypeScript candidate");
        fs::write(temp.path().join("src/choice.js"), "export const js = 1;\n")
            .expect("JavaScript candidate");
        fs::write(temp.path().join("src/case.ts"), "export const lower = 1;\n")
            .expect("case-sensitive candidate");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        for specifier in ["./choice", "./missing", "./Case", "../../outside"] {
            let import = ir
                .imports
                .iter()
                .find(|import| import.specifier == specifier)
                .expect("import record");
            assert!(
                ir.relationships.iter().all(|relationship| {
                    relationship.kind != RelationshipKind::Imports
                        || !relationship.evidence_ids.contains(&import.evidence_id)
                }),
                "unresolved relative import must not become an external edge: {specifier}"
            );
            let coverage = ir
                .coverage
                .items
                .iter()
                .find(|item| {
                    item.kind == CoverageKind::Import
                        && item.evidence_ids.contains(&import.evidence_id)
                })
                .expect("import coverage");
            assert!(matches!(
                coverage.disposition,
                CoverageDisposition::Unresolved { .. }
            ));
        }
        ir.validate().expect("IR should validate");
    }

    #[test]
    fn treats_portable_case_collisions_as_ambiguous() {
        let file_entities = std::collections::BTreeMap::from([
            ("src/dep.ts", "entity-lower"),
            ("src/DEP.ts", "entity-upper"),
        ]);
        let portable_paths = std::collections::BTreeMap::from([(
            "src/dep.ts".to_owned(),
            vec!["src/dep.ts", "src/DEP.ts"],
        )]);
        assert_eq!(
            resolve_relative_javascript_target(
                "src/main.ts",
                "./dep.ts",
                &file_entities,
                &portable_paths,
            ),
            Err(RelativeImportFailure::Ambiguous)
        );
    }

    #[test]
    fn scans_rust_entities_imports_and_precise_evidence_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = concat!(
            "use std::{fs, path::Path};\n",
            "\n",
            "pub struct Engine;\n",
            "\n",
            "pub trait Execute {\n",
            "    fn run(&self) -> bool;\n",
            "}\n",
            "\n",
            "pub type EngineResult = Result<(), ()>;\n",
            "pub enum Mode { Fast, Safe }\n",
            "pub const LIMIT: usize = 8;\n",
            "pub static NAME: &str = \"repo2okf\";\n",
            "\n",
            "pub fn build() -> Engine { Engine }\n",
            "\n",
            "impl Engine {\n",
            "    pub fn execute(&self) -> bool { true }\n",
            "}\n",
        );
        fs::write(temp.path().join("lib.rs"), source).expect("write Rust fixture");

        let first = scan_repository(temp.path(), &ScanOptions::default()).expect("first scan");
        let second = scan_repository(temp.path(), &ScanOptions::default()).expect("second scan");
        assert_eq!(first, second);
        assert_eq!(first.files[0].language, Some(Language::Rust));

        let expected = [
            (EntityKind::Class, "Engine"),
            (EntityKind::Interface, "Execute"),
            (EntityKind::Method, "run"),
            (EntityKind::Type, "EngineResult"),
            (EntityKind::Enum, "Mode"),
            (EntityKind::Variable, "LIMIT"),
            (EntityKind::Variable, "NAME"),
            (EntityKind::Function, "build"),
            (EntityKind::Method, "execute"),
        ];
        for (kind, name) in expected {
            assert!(
                first
                    .entities
                    .iter()
                    .any(|entity| entity.kind == kind && entity.name == name),
                "missing {kind:?} {name}"
            );
        }

        let import = first
            .imports
            .iter()
            .find(|import| import.path == "lib.rs")
            .expect("Rust use declaration");
        assert_eq!(import.specifier, "std::{fs, path::Path}");
        let import_evidence = first
            .evidence
            .iter()
            .find(|evidence| evidence.id == import.evidence_id)
            .expect("import evidence");
        assert_eq!(import_evidence.start_line, 1);
        assert_eq!(import_evidence.end_line, 1);
        assert_eq!(
            evidence_source(source, import_evidence),
            "use std::{fs, path::Path};"
        );

        let method = first
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Method && entity.name == "execute")
            .expect("impl method");
        let method_evidence = first
            .evidence
            .iter()
            .find(|evidence| evidence.id == method.evidence_id)
            .expect("method evidence");
        assert_eq!(method_evidence.start_line, 17);
        assert_eq!(method_evidence.end_line, 17);
        assert_eq!(
            evidence_source(source, method_evidence),
            "pub fn execute(&self) -> bool { true }"
        );
        first.validate().expect("Rust IR should validate");
    }

    fn evidence_source<'a>(source: &'a str, evidence: &crate::EvidenceRef) -> &'a str {
        let start = usize::try_from(evidence.start_byte).expect("fixture start offset");
        let end = usize::try_from(evidence.end_byte).expect("fixture end offset");
        &source[start..end]
    }

    #[test]
    fn hashes_and_parses_the_same_small_file_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = "pub fn from_scanned_bytes() -> u8 { 7 }\n";
        fs::write(temp.path().join("lib.rs"), source).expect("fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let file = ir
            .files
            .iter()
            .find(|file| file.path == "lib.rs")
            .expect("scanned file");
        let expected_hash = blake3::hash(source.as_bytes()).to_hex().to_string();
        assert_eq!(file.content_hash, expected_hash);
        assert!(
            ir.entities
                .iter()
                .any(|entity| entity.name == "from_scanned_bytes")
        );
        assert!(
            ir.evidence
                .iter()
                .filter(|evidence| evidence.path == "lib.rs")
                .all(|evidence| evidence.content_hash == expected_hash)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one fixture verifies correlated ownership, references, resolution and edges"
    )]
    fn resolves_conservative_python_semantics_and_preserves_uncertainty() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("pkg")).expect("package");
        fs::write(temp.path().join("pkg/__init__.py"), "").expect("package init");
        fs::write(
            temp.path().join("pkg/models.py"),
            concat!(
                "class Base:\n",
                "    pass\n",
                "\n",
                "class Result:\n",
                "    pass\n",
            ),
        )
        .expect("model fixture");
        fs::write(
            temp.path().join("pkg/service.py"),
            concat!(
                "from .models import Base as Parent, Result\n",
                "\n",
                "def traced(value):\n",
                "    return value\n",
                "\n",
                "@traced\n",
                "class Service(Parent):\n",
                "    def build(self, value: Result) -> Result:\n",
                "        return traced(value)\n",
                "\n",
                "def shadowed(traced):\n",
                "    return traced()\n",
                "\n",
                "def dynamic(obj):\n",
                "    return obj.run()\n",
                "\n",
                "def loop_shadow(values):\n",
                "    for traced in values:\n",
                "        pass\n",
                "    return traced()\n",
                "\n",
                "def match_shadow(value):\n",
                "    match value:\n",
                "        case traced:\n",
                "            pass\n",
                "    return traced()\n",
            ),
        )
        .expect("service fixture");

        let first = scan_repository(temp.path(), &ScanOptions::default()).expect("first scan");
        let second = scan_repository(temp.path(), &ScanOptions::default()).expect("second scan");
        assert_eq!(first, second);
        first.validate().expect("semantic IR");

        let service = first
            .entities
            .iter()
            .find(|entity| entity.name == "Service")
            .expect("Service entity");
        assert_eq!(service.qualified_name, "pkg.service.Service");
        let build = first
            .entities
            .iter()
            .find(|entity| entity.name == "build")
            .expect("build entity");
        assert_eq!(build.qualified_name, "pkg.service.Service.build");
        assert_eq!(build.owner_id.as_deref(), Some(service.id.as_str()));

        let parent_import = first
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("Parent")
            })
            .expect("Parent binding");
        assert_eq!(parent_import.name, "Base");
        assert!(matches!(
            parent_import.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let parent_evidence = first
            .evidence
            .iter()
            .find(|evidence| evidence.id == parent_import.evidence_id)
            .expect("Parent import evidence");
        let service_source =
            fs::read_to_string(temp.path().join("pkg/service.py")).expect("service source");
        assert_eq!(
            evidence_source(&service_source, parent_evidence),
            "from .models import Base as Parent, Result"
        );
        for import in first
            .imports
            .iter()
            .filter(|import| import.path == "pkg/service.py")
        {
            let semantic_bindings = first
                .semantic_references
                .iter()
                .filter(|reference| {
                    reference.kind == SemanticReferenceKind::ImportBinding
                        && reference.path == import.path
                        && (reference.qualifier.as_deref() == Some(import.specifier.as_str())
                            || reference.qualifier.is_none() && reference.name == import.specifier)
                })
                .count();
            assert!(
                semantic_bindings > 0,
                "compatibility import {} lacks semantic bindings",
                import.specifier
            );
        }
        let parent_edge = first
            .relationships
            .iter()
            .find(|relationship| {
                relationship.kind == RelationshipKind::Imports
                    && matches!(
                        &relationship.origin,
                        RelationshipOrigin::SemanticReference { reference_id }
                            if reference_id == &parent_import.id
                    )
            })
            .expect("semantic import-binding edge");
        assert_eq!(
            parent_edge.evidence_ids.as_slice(),
            std::slice::from_ref(&parent_import.evidence_id)
        );

        for (kind, name) in [
            (SemanticReferenceKind::Extends, "Parent"),
            (SemanticReferenceKind::Decorator, "traced"),
            (SemanticReferenceKind::TypeUse, "Result"),
            (SemanticReferenceKind::Call, "traced"),
        ] {
            assert!(
                first.semantic_references.iter().any(|reference| {
                    reference.kind == kind
                        && reference.name == name
                        && matches!(reference.resolution, SemanticResolution::Resolved { .. })
                }),
                "missing resolved {kind:?} {name}; references: {:#?}",
                first.semantic_references
            );
        }
        for kind in [
            RelationshipKind::Calls,
            RelationshipKind::Extends,
            RelationshipKind::TypeUses,
            RelationshipKind::DecoratedBy,
        ] {
            assert!(first.relationships.iter().any(|relationship| {
                relationship.kind == kind
                    && matches!(
                        relationship.origin,
                        RelationshipOrigin::SemanticReference { .. }
                    )
                    && !relationship.evidence_ids.is_empty()
            }));
        }

        let shadowed_call = first
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "traced"
                    && first
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.name == "shadowed")
            })
            .expect("shadowed call");
        assert!(matches!(
            shadowed_call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        let loop_call = first
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "traced"
                    && first
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.name == "loop_shadow")
            })
            .expect("for-target shadowed call");
        assert!(matches!(
            loop_call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        let match_call = first
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "traced"
                    && first
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.name == "match_shadow")
            })
            .expect("match capture shadowed call");
        assert!(matches!(
            match_call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        let member_call = first
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call && reference.name == "obj.run"
            })
            .expect("dynamic member call");
        assert!(matches!(
            member_call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert_eq!(
            first.semantic_coverage.total,
            first.semantic_references.len()
        );
    }

    #[test]
    fn duplicate_python_import_roots_are_ambiguous_instead_of_guessed() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("src/pkg")).expect("src package");
        fs::create_dir_all(temp.path().join("pkg")).expect("root package");
        fs::write(
            temp.path().join("src/pkg/mod.py"),
            "class Value:\n    pass\n",
        )
        .expect("src module");
        fs::write(temp.path().join("pkg/mod.py"), "class Value:\n    pass\n").expect("root module");
        fs::write(
            temp.path().join("consumer.py"),
            "from pkg.mod import Value\n",
        )
        .expect("consumer");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("Value")
            })
            .expect("Value import binding");
        assert!(matches!(
            binding.resolution,
            SemanticResolution::Ambiguous { .. } | SemanticResolution::Unresolved { .. }
        ));
        assert!(ir.relationships.iter().all(|relationship| {
            !matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &binding.id
            )
        }));
        ir.validate().expect("ambiguous semantic IR");
    }

    #[test]
    fn python_definition_header_calls_use_the_enclosing_scope() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("header.py"),
            concat!(
                "def function_scope(value=hidden()):\n",
                "    def hidden():\n",
                "        return 1\n",
                "    return value\n",
                "\n",
                "class ClassScope(hidden()):\n",
                "    def hidden(self):\n",
                "        return 1\n",
            ),
        )
        .expect("header fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let file_id = ir
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::File && entity.path == "header.py")
            .map(|entity| entity.id.as_str())
            .expect("file entity");
        let header_calls = ir
            .semantic_references
            .iter()
            .filter(|reference| {
                reference.kind == SemanticReferenceKind::Call && reference.name == "hidden"
            })
            .collect::<Vec<_>>();
        assert_eq!(header_calls.len(), 2);
        for reference in header_calls {
            assert_eq!(reference.scope_id, file_id);
            assert_eq!(reference.source_entity_id, None);
            assert!(matches!(
                reference.resolution,
                SemanticResolution::Unresolved { .. }
            ));
            assert!(!ir.relationships.iter().any(|relationship| {
                matches!(
                    &relationship.origin,
                    RelationshipOrigin::SemanticReference { reference_id }
                        if reference_id == &reference.id
                )
            }));
        }
    }

    #[test]
    fn nested_class_methods_do_not_resolve_bare_names_from_enclosing_classes() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("nested.py"),
            concat!(
                "class Outer:\n",
                "    def sibling(self):\n",
                "        return 1\n",
                "\n",
                "    class Inner:\n",
                "        def run(self):\n",
                "            return sibling()\n",
            ),
        )
        .expect("nested class fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let call = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call && reference.name == "sibling"
            })
            .expect("bare sibling call");
        assert!(matches!(
            call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert!(!ir.relationships.iter().any(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &call.id
            )
        }));
    }

    #[test]
    fn nested_class_bodies_skip_outer_classes_but_keep_valid_lexical_scopes() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("nested_body.py"),
            concat!(
                "class Outer:\n",
                "    def sibling(self):\n",
                "        return 1\n",
                "\n",
                "    same_class = sibling(None)\n",
                "\n",
                "    class Inner:\n",
                "        value = sibling()\n",
                "\n",
                "def enclosing():\n",
                "    def lexical():\n",
                "        return 1\n",
                "\n",
                "    class Inner:\n",
                "        value = lexical()\n",
                "\n",
                "    return Inner\n",
            ),
        )
        .expect("nested class-body fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let scope_name = |reference: &crate::SemanticReference| {
            ir.entities
                .iter()
                .find(|entity| entity.id == reference.scope_id)
                .map(|entity| entity.qualified_name.as_str())
        };
        let same_class_call = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "sibling"
                    && scope_name(reference) == Some("nested_body.Outer")
            })
            .expect("same-class body call");
        assert!(matches!(
            same_class_call.resolution,
            SemanticResolution::Resolved { .. }
        ));

        let nested_class_call = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "sibling"
                    && scope_name(reference) == Some("nested_body.Outer.Inner")
            })
            .expect("nested class-body call");
        assert!(matches!(
            nested_class_call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert!(!ir.relationships.iter().any(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &nested_class_call.id
            )
        }));

        let enclosing_function_call = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "lexical"
                    && scope_name(reference) == Some("nested_body.enclosing.Inner")
            })
            .expect("enclosing function call");
        assert!(matches!(
            enclosing_function_call.resolution,
            SemanticResolution::Resolved { .. }
        ));
        ir.validate().expect("conservative nested class-body IR");
    }

    #[test]
    fn same_scope_declaration_and_import_collision_remains_unresolved() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("collision.py"),
            concat!(
                "from outside import target\n",
                "\n",
                "def target():\n",
                "    return 1\n",
                "\n",
                "def caller():\n",
                "    return target()\n",
            ),
        )
        .expect("collision fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let call = semantic_call(&ir, "target", "collision.caller");
        assert_unresolved_without_edge(&ir, call);

        fs::write(temp.path().join("models.py"), "class Base:\n    pass\n").expect("model fixture");
        fs::write(
            temp.path().join("extends_collision.py"),
            concat!(
                "from models import Base\n",
                "\n",
                "def Base():\n",
                "    return 1\n",
                "\n",
                "class Child(Base):\n",
                "    pass\n",
            ),
        )
        .expect("extends collision fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("rescan");
        let base = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Extends && reference.name == "Base"
            })
            .expect("conflicting base reference");
        assert_unresolved_without_edge(&ir, base);
    }

    #[test]
    fn ambiguous_import_binding_is_not_narrowed_by_reference_kind() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("pkg")).expect("package");
        fs::write(
            temp.path().join("pkg/__init__.py"),
            "def helper():\n    return 1\n",
        )
        .expect("package fixture");
        fs::write(temp.path().join("pkg/helper.py"), "").expect("module fixture");
        fs::write(
            temp.path().join("consumer.py"),
            "from pkg import helper\n\ndef caller():\n    return helper()\n",
        )
        .expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("helper")
            })
            .expect("ambiguous helper binding");
        assert!(matches!(
            binding.resolution,
            SemanticResolution::Ambiguous { .. }
        ));
        let call = semantic_call(&ir, "helper", "consumer.caller");
        assert_unresolved_without_edge(&ir, call);
    }

    #[test]
    fn wildcard_import_taints_bare_name_resolution() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("wildcard.py"),
            concat!(
                "from plugin import *\n",
                "\n",
                "def known():\n",
                "    return 1\n",
                "\n",
                "def caller():\n",
                "    return known()\n",
            ),
        )
        .expect("wildcard fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let call = semantic_call(&ir, "known", "wildcard.caller");
        assert_unresolved_without_edge(&ir, call);
    }

    #[test]
    fn class_body_resolves_only_same_class_declarations_already_executed() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("ordered.py"),
            concat!(
                "class Ordered:\n",
                "    def early(self):\n",
                "        return 1\n",
                "\n",
                "    first = early(None)\n",
                "    early = object()\n",
                "    after_rebinding = early(None)\n",
                "    second = later(None)\n",
                "\n",
                "    def later(self):\n",
                "        return 2\n",
                "\n",
                "    def current(value=current()):\n",
                "        return value\n",
            ),
        )
        .expect("ordered class fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let early_calls = semantic_calls(&ir, "early", "ordered.Ordered");
        assert_eq!(early_calls.len(), 2);
        assert_eq!(
            early_calls
                .iter()
                .filter(|reference| matches!(
                    reference.resolution,
                    SemanticResolution::Resolved { .. }
                ))
                .count(),
            1
        );
        assert_eq!(
            early_calls
                .iter()
                .filter(|reference| matches!(
                    reference.resolution,
                    SemanticResolution::Unresolved { .. }
                ))
                .count(),
            1
        );
        let later = semantic_call(&ir, "later", "ordered.Ordered");
        assert_unresolved_without_edge(&ir, later);
        let current = semantic_call(&ir, "current", "ordered.Ordered");
        assert_unresolved_without_edge(&ir, current);
    }

    #[test]
    fn module_body_order_is_immediate_but_function_lookup_is_deferred() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("module_order.py"),
            concat!(
                "result = target()\n",
                "\n",
                "def caller():\n",
                "    return target()\n",
                "\n",
                "def target():\n",
                "    return 1\n",
            ),
        )
        .expect("module order fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let module_call = semantic_call(&ir, "target", "module_order");
        assert_unresolved_without_edge(&ir, module_call);
        let function_call = semantic_call(&ir, "target", "module_order.caller");
        assert!(matches!(
            function_call.resolution,
            SemanticResolution::Resolved { .. }
        ));
    }

    #[test]
    fn class_body_preserves_module_order_while_function_lookup_is_deferred() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("evaluation_order.py"),
            concat!(
                "def prior():\n",
                "    return 1\n",
                "\n",
                "class Immediate:\n",
                "    before = prior()\n",
                "    after = later()\n",
                "\n",
                "def deferred():\n",
                "    return later()\n",
                "\n",
                "def later():\n",
                "    return 2\n",
            ),
        )
        .expect("evaluation order fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let prior_class_call = semantic_call(&ir, "prior", "evaluation_order.Immediate");
        assert!(matches!(
            prior_class_call.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let later_class_call = semantic_call(&ir, "later", "evaluation_order.Immediate");
        assert_unresolved_without_edge(&ir, later_class_call);
        let later_function_call = semantic_call(&ir, "later", "evaluation_order.deferred");
        assert!(matches!(
            later_function_call.resolution,
            SemanticResolution::Resolved { .. }
        ));
    }

    #[test]
    fn function_bindings_obey_statement_order_without_falling_back() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("pkg")).expect("package directory");
        fs::write(
            temp.path().join("pkg/__init__.py"),
            "def helper():\n    return 1\n",
        )
        .expect("package fixture");
        fs::write(
            temp.path().join("binding_order.py"),
            concat!(
                "from pkg import helper\n",
                "\n",
                "def import_before_call():\n",
                "    from pkg import helper\n",
                "    return helper()\n",
                "\n",
                "def call_before_import():\n",
                "    value = helper()\n",
                "    from pkg import helper\n",
                "    return value\n",
                "\n",
                "def inner():\n",
                "    return 1\n",
                "\n",
                "def definition_before_call():\n",
                "    def inner():\n",
                "        return 2\n",
                "    return inner()\n",
                "\n",
                "def call_before_definition():\n",
                "    value = inner()\n",
                "    def inner():\n",
                "        return 3\n",
                "    return value\n",
            ),
        )
        .expect("binding order fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let prior_import = semantic_call(&ir, "helper", "binding_order.import_before_call");
        assert!(matches!(
            prior_import.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let later_import = semantic_call(&ir, "helper", "binding_order.call_before_import");
        assert_unresolved_without_edge(&ir, later_import);
        let prior_definition = semantic_call(&ir, "inner", "binding_order.definition_before_call");
        assert!(matches!(
            prior_definition.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let later_definition = semantic_call(&ir, "inner", "binding_order.call_before_definition");
        assert_unresolved_without_edge(&ir, later_definition);
    }

    #[test]
    fn conditional_python_bindings_taint_lookup_without_outer_fallback() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("pkg")).expect("package directory");
        fs::write(
            temp.path().join("pkg/__init__.py"),
            "def helper():\n    return 1\n",
        )
        .expect("package fixture");
        fs::write(
            temp.path().join("conditional_bindings.py"),
            concat!(
                "def helper():\n",
                "    return 0\n",
                "\n",
                "def conditional_if(flag):\n",
                "    if flag:\n",
                "        def helper():\n",
                "            return 1\n",
                "    return helper()\n",
                "\n",
                "def conditional_try():\n",
                "    try:\n",
                "        from pkg import helper\n",
                "    except ImportError:\n",
                "        pass\n",
                "    return helper()\n",
                "\n",
                "def conditional_for(values):\n",
                "    for _ in values:\n",
                "        def helper():\n",
                "            return 2\n",
                "    return helper()\n",
                "\n",
                "def conditional_while(flag):\n",
                "    while flag:\n",
                "        def helper():\n",
                "            return 3\n",
                "    return helper()\n",
                "\n",
                "def conditional_match(value):\n",
                "    match value:\n",
                "        case 1:\n",
                "            from pkg import helper\n",
                "    return helper()\n",
                "\n",
                "def conditional_with(manager):\n",
                "    with manager:\n",
                "        from pkg import helper\n",
                "    return helper()\n",
                "\n",
                "def conditional_class(flag):\n",
                "    if flag:\n",
                "        class helper:\n",
                "            pass\n",
                "    return helper()\n",
                "\n",
                "if FLAG:\n",
                "    class Maybe:\n",
                "        pass\n",
                "\n",
                "class Child(Maybe):\n",
                "    pass\n",
            ),
        )
        .expect("conditional binding fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        for scope in [
            "conditional_bindings.conditional_if",
            "conditional_bindings.conditional_try",
            "conditional_bindings.conditional_for",
            "conditional_bindings.conditional_while",
            "conditional_bindings.conditional_match",
            "conditional_bindings.conditional_with",
            "conditional_bindings.conditional_class",
        ] {
            let call = semantic_call(&ir, "helper", scope);
            assert_unresolved_without_edge(&ir, call);
        }
        let extends = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Extends && reference.name == "Maybe"
            })
            .expect("conditional class base");
        assert_unresolved_without_edge(&ir, extends);
    }

    #[test]
    fn imports_of_conditional_repository_members_stay_unresolved() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("provider.py"),
            concat!(
                "if FLAG:\n",
                "    class Maybe:\n",
                "        def build():\n",
                "            return 1\n",
                "if FLAG:\n",
                "    from pkg import helper as maybe_helper\n",
            ),
        )
        .expect("conditional provider fixture");
        fs::write(
            temp.path().join("consumer.py"),
            concat!(
                "from provider import Maybe\n",
                "from provider.Maybe import build\n",
                "from provider import maybe_helper\n",
                "\n",
                "def caller():\n",
                "    return Maybe(), build(), maybe_helper()\n",
            ),
        )
        .expect("conditional consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        for binding_name in ["Maybe", "build", "maybe_helper"] {
            let binding = ir
                .semantic_references
                .iter()
                .find(|reference| {
                    reference.kind == SemanticReferenceKind::ImportBinding
                        && reference.binding_name.as_deref() == Some(binding_name)
                })
                .expect("conditional import binding");
            assert!(matches!(
                binding.resolution,
                SemanticResolution::Unresolved { .. }
            ));
            assert_unresolved_without_edge(&ir, binding);
            let call = semantic_call(&ir, binding_name, "consumer.caller");
            assert_unresolved_without_edge(&ir, call);
        }
    }

    #[test]
    fn missing_members_of_scanned_python_modules_are_not_external() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("provider.py"),
            "def known():\n    return 1\n",
        )
        .expect("provider fixture");
        fs::write(
            temp.path().join("consumer.py"),
            concat!(
                "from provider import dynamic_name\n",
                "from outside_package import external_name\n",
                "\n",
                "def caller():\n",
                "    return dynamic_name(), external_name()\n",
            ),
        )
        .expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("dynamic_name")
            })
            .expect("dynamic import binding");
        assert!(matches!(
            binding.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert_unresolved_without_edge(&ir, binding);
        let call = semantic_call(&ir, "dynamic_name", "consumer.caller");
        assert_unresolved_without_edge(&ir, call);
        let external_binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("external_name")
            })
            .expect("external import binding");
        assert!(matches!(
            external_binding.resolution,
            SemanticResolution::External { .. }
        ));
        let external_call = semantic_call(&ir, "external_name", "consumer.caller");
        assert!(matches!(
            external_call.resolution,
            SemanticResolution::External { .. }
        ));
    }

    #[test]
    fn uppercase_package_initializer_is_local_for_observed_and_semantic_imports() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("pkg")).expect("package directory");
        fs::write(temp.path().join("pkg/__INIT__.PY"), "").expect("package initializer");
        fs::write(temp.path().join("consumer.py"), "import pkg\n").expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let package = ir
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::File && entity.path == "pkg/__INIT__.PY")
            .expect("package file");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("pkg")
            })
            .expect("package binding");
        assert!(matches!(
            &binding.resolution,
            SemanticResolution::Resolved { target_entity_id }
                if target_entity_id == &package.id
        ));
        assert!(ir.relationships.iter().any(|relationship| {
            relationship.kind == RelationshipKind::Imports && relationship.target == package.id
        }));
    }

    #[test]
    fn class_qualified_imports_do_not_masquerade_as_modules() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("provider.py"),
            concat!(
                "class Service:\n",
                "    def build():\n",
                "        return 1\n",
            ),
        )
        .expect("provider fixture");
        fs::write(
            temp.path().join("consumer.py"),
            concat!(
                "from provider.Service import build\n",
                "\n",
                "def caller():\n",
                "    return build()\n",
            ),
        )
        .expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("build")
            })
            .expect("build binding");
        assert_unresolved_without_edge(&ir, binding);
        let call = semantic_call(&ir, "build", "consumer.caller");
        assert_unresolved_without_edge(&ir, call);
    }

    #[test]
    fn ambiguous_qualifier_modules_are_not_narrowed_by_member_presence() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(temp.path().join("pkg")).expect("root package");
        fs::create_dir_all(temp.path().join("src/pkg")).expect("src package");
        fs::write(temp.path().join("pkg/mod.py"), "class Target:\n    pass\n")
            .expect("root module");
        fs::write(temp.path().join("src/pkg/mod.py"), "").expect("src module");
        fs::write(
            temp.path().join("consumer.py"),
            "from pkg.mod import Target\n",
        )
        .expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("Target")
            })
            .expect("Target binding");
        assert_unresolved_without_edge(&ir, binding);
    }

    #[test]
    fn global_and_nonlocal_mutations_fail_closed_before_redirect() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("redirects.py"),
            concat!(
                "def target():\n",
                "    return 1\n",
                "\n",
                "def global_delete():\n",
                "    global target\n",
                "    del target\n",
                "    return target()\n",
                "\n",
                "def outer():\n",
                "    def target():\n",
                "        return 2\n",
                "    def inner():\n",
                "        nonlocal target\n",
                "        del target\n",
                "        return target()\n",
                "    return inner\n",
            ),
        )
        .expect("redirect fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        for scope in ["redirects.global_delete", "redirects.outer.inner"] {
            let call = semantic_call(&ir, "target", scope);
            assert_unresolved_without_edge(&ir, call);
        }
    }

    #[test]
    fn dotted_python_filenames_are_not_importable_module_identities() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("foo.bar.py"), "class Target:\n    pass\n")
            .expect("dotted filename fixture");
        fs::write(
            temp.path().join("consumer.py"),
            "from foo.bar import Target\n",
        )
        .expect("consumer fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("Target")
            })
            .expect("Target binding");
        assert!(matches!(
            binding.resolution,
            SemanticResolution::External { .. }
        ));
        assert!(!ir.relationships.iter().any(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &binding.id
            )
        }));
    }

    #[test]
    fn portable_python_module_case_guard_rejects_mismatch_and_collision() {
        let exact = BTreeMap::from([("Pkg".to_owned(), vec!["upper".to_owned()])]);
        let portable = BTreeMap::from([("pkg".to_owned(), BTreeSet::from(["Pkg".to_owned()]))]);
        assert!(matches!(
            python_module_case_guard("pkg", &exact, &portable),
            Some(SemanticResolution::Unresolved { .. })
        ));

        let exact = BTreeMap::from([
            ("pkg".to_owned(), vec!["lower".to_owned()]),
            ("Pkg".to_owned(), vec!["upper".to_owned()]),
        ]);
        let portable = BTreeMap::from([(
            "pkg".to_owned(),
            BTreeSet::from(["pkg".to_owned(), "Pkg".to_owned()]),
        )]);
        assert!(matches!(
            python_module_case_guard("pkg", &exact, &portable),
            Some(SemanticResolution::Unresolved { .. })
        ));
    }

    #[test]
    fn deleted_python_bindings_do_not_resolve_to_stale_declarations() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("deleted_bindings.py"),
            concat!(
                "def module_removed():\n",
                "    return 1\n",
                "del module_removed\n",
                "module_value = module_removed()\n",
                "\n",
                "class Removed:\n",
                "    def member():\n",
                "        return 2\n",
                "    del member\n",
                "    value = member()\n",
                "\n",
                "def remove_local():\n",
                "    def inner():\n",
                "        return 3\n",
                "    del inner\n",
                "    return inner()\n",
            ),
        )
        .expect("deleted binding fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        for (name, scope) in [
            ("module_removed", "deleted_bindings"),
            ("member", "deleted_bindings.Removed"),
            ("inner", "deleted_bindings.remove_local"),
        ] {
            let call = semantic_call(&ir, name, scope);
            assert_unresolved_without_edge(&ir, call);
        }
    }

    #[test]
    fn comprehension_calls_are_inventoried_but_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("comprehension.py"),
            concat!(
                "def item():\n",
                "    return 1\n",
                "\n",
                "class Container:\n",
                "    def helper(self):\n",
                "        return 1\n",
                "\n",
                "    list_values = [helper(None) for item in ()]\n",
                "    set_values = {helper(None) for item in ()}\n",
                "    dict_values = {item: helper(None) for item in ()}\n",
                "    generator_values = (helper(None) for item in ())\n",
                "    target_does_not_leak = item()\n",
                "\n",
                "def enclosing():\n",
                "    def helper():\n",
                "        return 1\n",
                "\n",
                "    list_values = [helper() for item in ()]\n",
                "    set_values = {helper() for item in ()}\n",
                "    dict_values = {item: helper() for item in ()}\n",
                "    generator_values = (helper() for item in ())\n",
                "    return helper(), item()\n",
            ),
        )
        .expect("comprehension fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let class_calls = semantic_calls(&ir, "helper", "comprehension.Container");
        assert_eq!(class_calls.len(), 4);
        for call in class_calls {
            assert_unresolved_without_edge(&ir, call);
        }
        let function_calls = ir
            .semantic_references
            .iter()
            .filter(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == "helper"
                    && ir
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.qualified_name == "comprehension.enclosing")
            })
            .collect::<Vec<_>>();
        assert_eq!(function_calls.len(), 5);
        assert_eq!(
            function_calls
                .iter()
                .filter(|reference| matches!(
                    reference.resolution,
                    SemanticResolution::Resolved { .. }
                ))
                .count(),
            1
        );
        let unresolved = function_calls
            .into_iter()
            .filter(|reference| {
                matches!(reference.resolution, SemanticResolution::Unresolved { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(unresolved.len(), 4);
        for call in unresolved {
            assert_unresolved_without_edge(&ir, call);
        }
        for scope in ["comprehension.Container", "comprehension.enclosing"] {
            let item_call = semantic_call(&ir, "item", scope);
            assert!(matches!(
                item_call.resolution,
                SemanticResolution::Resolved { .. }
            ));
        }
    }

    #[test]
    fn match_capture_only_taints_its_name_and_keeps_other_case_calls() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("matching.py"),
            concat!(
                "def known():\n",
                "    return 1\n",
                "\n",
                "def captured():\n",
                "    return 2\n",
                "\n",
                "def dispatch(value):\n",
                "    match value:\n",
                "        case captured:\n",
                "            known()\n",
                "    return captured()\n",
            ),
        )
        .expect("match fixture");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let known = semantic_call(&ir, "known", "matching.dispatch");
        assert!(matches!(
            known.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let captured = semantic_call(&ir, "captured", "matching.dispatch");
        assert_unresolved_without_edge(&ir, captured);
    }

    #[test]
    fn uppercase_python_extensions_share_the_logical_module_inventory() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::create_dir(temp.path().join("pkg")).expect("package");
        fs::write(temp.path().join("pkg/__INIT__.PY"), "").expect("package init");
        fs::write(
            temp.path().join("pkg/helper.PY"),
            "def target():\n    return 1\n",
        )
        .expect("helper module");
        fs::write(
            temp.path().join("pkg/consumer.PY"),
            "from .helper import target\n\ndef caller():\n    return target()\n",
        )
        .expect("consumer module");

        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        assert!(ir.entities.iter().any(|entity| {
            entity.kind == EntityKind::File
                && entity.path == "pkg/__INIT__.PY"
                && entity.qualified_name == "pkg"
        }));
        let binding = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::ImportBinding
                    && reference.binding_name.as_deref() == Some("target")
            })
            .expect("target binding");
        assert!(matches!(
            binding.resolution,
            SemanticResolution::Resolved { .. }
        ));
        let call = semantic_call(&ir, "target", "pkg.consumer.caller");
        assert!(matches!(
            call.resolution,
            SemanticResolution::Resolved { .. }
        ));
    }

    fn semantic_call<'a>(
        ir: &'a RepositoryIr,
        name: &str,
        scope_qualified_name: &str,
    ) -> &'a crate::SemanticReference {
        ir.semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == name
                    && ir
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.qualified_name == scope_qualified_name)
            })
            .expect("semantic call")
    }

    fn semantic_calls<'a>(
        ir: &'a RepositoryIr,
        name: &str,
        scope_qualified_name: &str,
    ) -> Vec<&'a crate::SemanticReference> {
        ir.semantic_references
            .iter()
            .filter(|reference| {
                reference.kind == SemanticReferenceKind::Call
                    && reference.name == name
                    && ir
                        .entities
                        .iter()
                        .find(|entity| entity.id == reference.scope_id)
                        .is_some_and(|entity| entity.qualified_name == scope_qualified_name)
            })
            .collect()
    }

    fn assert_unresolved_without_edge(ir: &RepositoryIr, reference: &crate::SemanticReference) {
        assert!(matches!(
            reference.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert!(!ir.relationships.iter().any(|relationship| {
            matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &reference.id
            )
        }));
    }

    #[test]
    fn architecture_scope_totals_must_match_the_repository_ir() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("scope.py"),
            "def target():\n    pass\n\ndef caller():\n    target()\n",
        )
        .expect("scope fixture");
        let mut ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let semantic_relationships_total = ir
            .relationships
            .iter()
            .filter(|relationship| {
                matches!(
                    relationship.origin,
                    RelationshipOrigin::SemanticReference { .. }
                )
            })
            .count();
        ir.architecture_scope = Some(ArchitectureScope {
            evidence_total: ir.evidence.len(),
            evidence_supplied: ir.evidence.len(),
            coverage_items_total: ir.coverage.items.len(),
            coverage_items_supplied: ir.coverage.items.len(),
            entities_total: ir.entities.len(),
            entities_supplied: ir.entities.len(),
            semantic_references_total: ir.semantic_references.len(),
            semantic_references_supplied: ir.semantic_references.len(),
            semantic_relationships_total,
            semantic_relationships_supplied: semantic_relationships_total,
            complete: true,
        });
        ir.validate().expect("accurate architecture scope");

        let scope = ir.architecture_scope.as_mut().expect("scope");
        scope.semantic_references_total += 1;
        scope.semantic_references_supplied += 1;
        assert!(ir.validate().is_err());
    }

    #[test]
    fn semantic_records_change_the_repository_fingerprint() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(
            temp.path().join("service.py"),
            "def target():\n    pass\n\ndef caller():\n    target()\n",
        )
        .expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let original = ir.fingerprint.clone();
        let mut changed = ir.semantic_references.clone();
        changed[0].resolution = SemanticResolution::Unresolved {
            reason: "test mutation".to_owned(),
        };
        let fingerprint = fingerprint_ir(
            &ir.repository,
            &ir.files,
            &ir.entities,
            &ir.imports,
            &ir.evidence,
            &ir.relationships,
            &changed,
            &SemanticCoverage::from_references(&changed),
            &ir.claims,
            &ir.coverage,
        )
        .expect("fingerprint");
        assert_ne!(original, fingerprint);
    }

    #[test]
    fn validation_rejects_source_evidence_hash_and_span_drift() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("source.py"), "def source():\n    pass\n").expect("fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");

        let mut wrong_hash = ir.clone();
        wrong_hash.evidence[0].content_hash = "wrong".to_owned();
        assert!(wrong_hash.validate().is_err());

        let mut wrong_span = ir;
        wrong_span.evidence[0].end_byte = wrong_span.files[0].size + 1;
        assert!(wrong_span.validate().is_err());
    }

    #[test]
    fn imported_module_alias_called_as_function_remains_unresolved() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("helpers.py"), "def run():\n    pass\n").expect("module");
        fs::write(
            temp.path().join("consumer.py"),
            "import helpers as make\n\ndef consumer():\n    make()\n",
        )
        .expect("consumer");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan");
        let call = ir
            .semantic_references
            .iter()
            .find(|reference| {
                reference.kind == SemanticReferenceKind::Call && reference.name == "make"
            })
            .expect("module alias call");
        assert!(matches!(
            call.resolution,
            SemanticResolution::Unresolved { .. }
        ));
        assert!(ir.relationships.iter().all(|relationship| {
            !matches!(
                &relationship.origin,
                RelationshipOrigin::SemanticReference { reference_id }
                    if reference_id == &call.id
            )
        }));
        ir.validate().expect("conservative module call IR");
    }

    #[test]
    fn hashes_too_large_files_from_the_open_handle() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = b"0123456789abcdef";
        fs::write(temp.path().join("large.rs"), source).expect("fixture");
        let options = ScanOptions {
            max_file_bytes: 8,
            ..ScanOptions::default()
        };

        let ir = scan_repository(temp.path(), &options).expect("scan");
        let file = ir
            .files
            .iter()
            .find(|file| file.path == "large.rs")
            .expect("inventoried large file");
        assert_eq!(file.status, ScanStatus::TooLarge);
        assert_eq!(file.content_hash, blake3::hash(source).to_hex().to_string());
        assert!(ir.entities.iter().all(|entity| entity.path != "large.rs"));
    }

    #[test]
    fn rejects_non_normal_repository_path_components() {
        let root = tempfile::tempdir().expect("root tempdir");
        let escaped = root.path().join("..").join("outside.rs");

        assert!(file_path_metadata(root.path(), &escaped).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn root_identity_rejects_a_root_rename_to_symlink_swap() {
        use std::os::unix::fs::symlink;

        let sandbox = tempfile::tempdir().expect("sandbox");
        let root = sandbox.path().join("repository");
        let moved = sandbox.path().join("repository-original");
        let outside = sandbox.path().join("outside");
        fs::create_dir(&root).expect("repository root");
        fs::create_dir(&outside).expect("outside root");
        fs::write(root.join("source.rs"), "pub fn original() {}\n").expect("source");
        fs::write(outside.join("source.rs"), "pub fn outside() {}\n").expect("outside source");

        let canonical_root = root.canonicalize().expect("canonical root");
        let identity = RootIdentity::capture(canonical_root.clone()).expect("root identity");
        fs::rename(&canonical_root, &moved).expect("move original root");
        symlink(&outside, &canonical_root).expect("replace root with symlink");

        assert!(
            identity.verify().is_err(),
            "the canonical root path must remain bound to its original directory"
        );

        fs::remove_file(&canonical_root).expect("remove root symlink");
        fs::rename(&moved, &canonical_root).expect("restore original root");
    }

    #[cfg(windows)]
    #[test]
    fn root_identity_rejects_a_regular_root_replacement() {
        let sandbox = tempfile::tempdir().expect("sandbox");
        let root = sandbox.path().join("repository");
        let moved = sandbox.path().join("repository-original");
        fs::create_dir(&root).expect("repository root");
        fs::write(root.join("source.rs"), "pub fn original() {}\n").expect("source");

        let canonical_root = root.canonicalize().expect("canonical root");
        let identity = RootIdentity::capture(canonical_root.clone()).expect("root identity");
        fs::rename(&canonical_root, &moved).expect("move original root");
        fs::create_dir(&canonical_root).expect("replacement root");
        fs::write(canonical_root.join("outside.rs"), "pub fn outside() {}\n")
            .expect("replacement source");

        assert!(
            identity.verify().is_err(),
            "the canonical root path must remain bound to its original directory"
        );

        fs::remove_dir_all(&canonical_root).expect("remove replacement root");
        fs::rename(&moved, &canonical_root).expect("restore original root");
    }

    #[cfg(windows)]
    #[test]
    fn root_identity_rejects_a_root_rename_to_symlink_swap_when_permitted() {
        use std::io::ErrorKind;
        use std::os::windows::fs::symlink_dir;

        let sandbox = tempfile::tempdir().expect("sandbox");
        let root = sandbox.path().join("repository");
        let moved = sandbox.path().join("repository-original");
        let outside = sandbox.path().join("outside");
        fs::create_dir(&root).expect("repository root");
        fs::create_dir(&outside).expect("outside root");
        fs::write(root.join("source.rs"), "pub fn original() {}\n").expect("source");
        fs::write(outside.join("source.rs"), "pub fn outside() {}\n").expect("outside source");

        let canonical_root = root.canonicalize().expect("canonical root");
        let identity = RootIdentity::capture(canonical_root.clone()).expect("root identity");
        fs::rename(&canonical_root, &moved).expect("move original root");
        match symlink_dir(&outside, &canonical_root) {
            Ok(()) => {}
            Err(error)
                if error.kind() == ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                fs::rename(&moved, &canonical_root).expect("restore original root");
                return;
            }
            Err(error) => {
                fs::rename(&moved, &canonical_root).expect("restore original root");
                panic!("replace root with symlink: {error}");
            }
        }

        assert!(
            identity.verify().is_err(),
            "the canonical root path must reject a reparse-point replacement"
        );

        fs::remove_dir(&canonical_root).expect("remove root symlink");
        fs::rename(&moved, &canonical_root).expect("restore original root");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_swap_after_opening_the_file() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let canonical_root = temp.path().canonicalize().expect("canonical root");
        let path = canonical_root.join("source.rs");
        let replacement = canonical_root.join("replacement.rs");
        fs::write(&path, "pub fn original() {}\n").expect("original fixture");
        fs::write(&replacement, "pub fn replaced() {}\n").expect("replacement fixture");

        let root = RootIdentity::capture(canonical_root).expect("root identity");
        let path_metadata = file_path_metadata(&root.path, &path).expect("path metadata");
        let file = open_stable_file(&root, &path, &path_metadata).expect("stable open");
        let opened_metadata = file.metadata().expect("handle metadata");
        fs::remove_file(&path).expect("unlink original path");
        symlink(&replacement, &path).expect("replace path with symlink");

        assert!(
            verify_stable_file(&root, &path, &file, &opened_metadata).is_err(),
            "a path swapped to a symlink must not validate against the open handle"
        );
    }

    #[cfg(windows)]
    #[test]
    fn rejects_a_regular_path_replacement_after_opening_the_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let canonical_root = temp.path().canonicalize().expect("canonical root");
        let path = canonical_root.join("source.rs");
        let replacement = canonical_root.join("replacement.rs");
        fs::write(&path, "pub fn original() {}\n").expect("original fixture");
        fs::write(&replacement, "pub fn replacement_with_a_new_size() {}\n")
            .expect("replacement fixture");

        let root = RootIdentity::capture(canonical_root).expect("root identity");
        let path_metadata = file_path_metadata(&root.path, &path).expect("path metadata");
        let file = open_stable_file(&root, &path, &path_metadata).expect("stable open");
        let opened_metadata = file.metadata().expect("handle metadata");
        fs::remove_file(&path).expect("unlink original path");
        fs::rename(&replacement, &path).expect("replace path with another regular file");

        assert!(
            verify_stable_file(&root, &path, &file, &opened_metadata).is_err(),
            "a replaced path must not validate against the original open handle"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_in_a_file_ancestor() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        fs::write(outside.path().join("source.rs"), "pub fn outside() {}\n")
            .expect("outside fixture");
        symlink(outside.path(), root.path().join("linked")).expect("ancestor symlink");

        assert!(
            file_path_metadata(root.path(), &root.path().join("linked/source.rs")).is_err(),
            "linked ancestors must be rejected before a file is opened"
        );
    }

    #[cfg(unix)]
    #[test]
    fn inventories_leaf_symlinks_without_reading_their_targets() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("root tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let target = outside.path().join("external.ts");
        fs::write(&target, "export function externalSecret() { return 1; }\n")
            .expect("outside fixture");
        symlink(&target, root.path().join("linked.ts")).expect("leaf symlink");

        let ir = scan_repository(root.path(), &ScanOptions::default()).expect("scan");
        let link = ir
            .files
            .iter()
            .find(|file| file.path == "linked.ts")
            .expect("inventoried symlink");
        assert_eq!(link.status, ScanStatus::SymlinkSkipped);
        assert!(link.content_hash.is_empty());
        assert!(
            ir.entities
                .iter()
                .all(|entity| entity.name != "externalSecret")
        );
        assert!(
            ir.evidence
                .iter()
                .all(|evidence| evidence.path != "linked.ts")
        );
    }

    #[cfg(windows)]
    #[test]
    fn inventories_leaf_symlinks_without_reading_their_targets_when_permitted() {
        use std::io::ErrorKind;
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().expect("root tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        let target = outside.path().join("external.ts");
        fs::write(&target, "export function externalSecret() { return 1; }\n")
            .expect("outside fixture");
        match symlink_file(&target, root.path().join("linked.ts")) {
            Ok(()) => {}
            Err(error)
                if error.kind() == ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(1314) =>
            {
                return;
            }
            Err(error) => panic!("leaf symlink: {error}"),
        }

        let ir = scan_repository(root.path(), &ScanOptions::default()).expect("scan");
        let link = ir
            .files
            .iter()
            .find(|file| file.path == "linked.ts")
            .expect("inventoried symlink");
        assert_eq!(link.status, ScanStatus::SymlinkSkipped);
        assert!(link.content_hash.is_empty());
        assert!(
            ir.entities
                .iter()
                .all(|entity| entity.name != "externalSecret")
        );
    }
}
