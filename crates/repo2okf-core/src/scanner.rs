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
    ImportRecord, Language, Relationship, RelationshipKind, RepositoryIr, RepositoryMetadata,
    ScanStatus,
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
        let identity = Self { path, metadata };
        identity.verify()?;
        Ok(identity)
    }

    fn verify(&self) -> Result<(), ScanError> {
        let current = fs::symlink_metadata(&self.path).map_err(|source| ScanError::Io {
            path: self.path.clone(),
            source,
        })?;
        if is_link_or_reparse_point(&current)
            || !current.file_type().is_dir()
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
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    end_line: u32,
}

#[derive(Debug)]
struct ParsedFile {
    symbols: Vec<ParsedSymbol>,
    imports: Vec<ParsedImport>,
    docstring: Option<ParsedSpan>,
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
    for extraction in extractions {
        files.push(extraction.file);
        entities.extend(extraction.entities);
        imports.extend(extraction.imports);
        evidence.extend(extraction.evidence);
        relationships.extend(extraction.relationships);
        claims.extend(extraction.claims);
        coverage_items.extend(extraction.coverage);
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
        claims,
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
    let mut entities = vec![Entity {
        id: file_entity_id.clone(),
        kind: EntityKind::File,
        name: path.rsplit('/').next().unwrap_or(&path).to_owned(),
        path: path.clone(),
        language: Some(language),
        evidence_id: file_evidence.id.clone(),
    }];
    let parsed = match language {
        Language::Markdown => ParsedFile {
            symbols: parse_markdown(source),
            imports: Vec::new(),
            docstring: None,
        },
        Language::JavaScript
        | Language::TypeScript
        | Language::Go
        | Language::Python
        | Language::Rust => parse_tree_sitter(language, &path, source)?,
    };

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
        let entity_id = stable_id(
            "entity",
            &[
                entity_kind_label(symbol.kind),
                &path,
                &symbol.name,
                &symbol.start_byte.to_string(),
            ],
        );
        let relationship_id = stable_id("rel", &["contains", &file_entity_id, &entity_id]);
        let claim_id = stable_id("claim", &["declares", &entity_id]);
        entities.push(Entity {
            id: entity_id.clone(),
            kind: symbol.kind,
            name: symbol.name.clone(),
            path: path.clone(),
            language: Some(language),
            evidence_id: symbol_evidence.id.clone(),
        });
        relationships.push(Relationship {
            id: relationship_id,
            source: file_entity_id.clone(),
            target: entity_id.clone(),
            kind: RelationshipKind::Contains,
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
    })
}

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
    Ok(ParsedFile {
        symbols,
        imports,
        docstring: file_docstring,
    })
}

fn walk_syntax(
    node: Node<'_>,
    source: &str,
    language: Language,
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
        walk_syntax(child, source, language, symbols, imports);
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

fn append_python_imports(node: Node<'_>, source: &str, imports: &mut Vec<ParsedImport>) {
    match node.kind() {
        "import_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                let name = if child.kind() == "aliased_import" {
                    child.child_by_field_name("name")
                } else if child.kind() == "dotted_name" {
                    Some(child)
                } else {
                    None
                };
                if let Some(name) = name {
                    append_import(node, name, source, imports);
                }
            }
        }
        "import_from_statement" => {
            if let Some(module) = node.child_by_field_name("module_name") {
                // For `from . import util`, `util` may be either a package
                // attribute or an imported submodule at runtime. Preserve the
                // verified dependency on the package (`.`) instead of guessing
                // a `pkg.util` source edge.
                append_import(node, module, source, imports);
            }
        }
        "future_import_statement" => append_import_specifier(node, "__future__", imports),
        _ => {}
    }
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
    if !specifier.is_empty() {
        imports.push(ParsedImport {
            specifier: specifier.to_owned(),
            start_byte: statement.start_byte(),
            end_byte: statement.end_byte(),
            start_line: one_based_row(statement.start_position().row),
            end_line: one_based_row(statement.end_position().row),
        });
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

#[allow(clippy::too_many_arguments)]
fn fingerprint_ir(
    repository: &RepositoryMetadata,
    files: &[FileRecord],
    entities: &[Entity],
    imports: &[ImportRecord],
    evidence: &[EvidenceRef],
    relationships: &[Relationship],
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
        deterministic_claims,
        coverage,
    ))?;
    Ok(blake3::hash(&value).to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        RelativeImportFailure, RootIdentity, ScanOptions, concept_id_for_path, file_path_metadata,
        parse_markdown, resolve_relative_javascript_target, scan_repository,
    };
    #[cfg(any(unix, windows))]
    use super::{open_stable_file, verify_stable_file};
    use crate::{
        CoverageDisposition, CoverageKind, EntityKind, Language, RelationshipKind, ScanStatus,
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
