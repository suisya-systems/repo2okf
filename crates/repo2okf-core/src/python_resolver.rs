use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CoverageDisposition, CoverageItem, CoverageKind, Entity, EntityKind, FileRecord, ImportRecord,
    Language, Relationship, RelationshipKind, ScanStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PythonImportFailure {
    EscapesRepository,
    Missing,
    Ambiguous,
    CaseMismatch,
}

#[derive(Debug, Eq, PartialEq)]
enum PythonImportResolution {
    Local(String),
    External,
    Failure(PythonImportFailure),
}

/// Resolve Python imports after the complete repository inventory is known.
///
/// Absolute imports remain external unless they uniquely match a scanned
/// Python module or package. Relative imports fail closed when they escape the
/// repository, do not resolve, differ only by case, or are ambiguous.
pub(crate) fn resolve_python_imports(
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
    let (modules, portable_modules) = python_module_inventory(files, &file_entities);
    let mut unresolved_relationships = BTreeSet::new();

    for import in imports {
        if source_languages.get(import.path.as_str()).copied() != Some(Language::Python) {
            continue;
        }
        let Some(source_id) = file_entities.get(import.path.as_str()).copied() else {
            continue;
        };
        let external_id = external_module_id(&import.specifier);
        let resolution =
            resolve_python_target(&import.path, &import.specifier, &modules, &portable_modules);

        match resolution {
            PythonImportResolution::Local(target) => {
                for relationship in relationships.iter_mut().filter(|relationship| {
                    python_import_relationship_matches(
                        relationship,
                        source_id,
                        &external_id,
                        &import.evidence_id,
                    )
                }) {
                    target.clone_into(&mut relationship.target);
                }
            }
            PythonImportResolution::External => {}
            PythonImportResolution::Failure(failure) => {
                unresolved_relationships.insert((
                    source_id.to_owned(),
                    external_id,
                    import.evidence_id.clone(),
                ));
                let subject = format!("{} imports {}", import.path, import.specifier);
                for item in coverage.iter_mut().filter(|item| {
                    item.kind == CoverageKind::Import
                        && item.subject == subject
                        && item.evidence_ids.iter().any(|id| id == &import.evidence_id)
                }) {
                    item.disposition = CoverageDisposition::Unresolved {
                        reason: Some(python_import_failure_reason(failure).to_owned()),
                    };
                }
            }
        }
    }

    relationships.retain(|relationship| {
        !unresolved_relationships
            .iter()
            .any(|(source, target, evidence)| {
                python_import_relationship_matches(relationship, source, target, evidence)
            })
    });
}

fn python_module_inventory(
    files: &[FileRecord],
    file_entities: &BTreeMap<&str, &str>,
) -> (
    BTreeMap<String, Vec<String>>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut modules = BTreeMap::<String, Vec<String>>::new();
    for file in files
        .iter()
        .filter(|file| file.language == Some(Language::Python) && file.status == ScanStatus::Parsed)
    {
        let Some(target) = file_entities.get(file.path.as_str()) else {
            continue;
        };
        for module in python_modules_for_path(&file.path) {
            modules
                .entry(module)
                .or_default()
                .push((*target).to_owned());
        }
    }
    for targets in modules.values_mut() {
        targets.sort();
        targets.dedup();
    }

    let mut portable_modules = BTreeMap::<String, BTreeSet<String>>::new();
    for module in modules.keys() {
        portable_modules
            .entry(module.to_lowercase())
            .or_default()
            .insert(module.clone());
    }
    (modules, portable_modules)
}

fn resolve_python_target(
    importing_path: &str,
    specifier: &str,
    modules: &BTreeMap<String, Vec<String>>,
    portable_modules: &BTreeMap<String, BTreeSet<String>>,
) -> PythonImportResolution {
    // `from __future__ import ...` is a compiler directive. Python does not
    // resolve it through a repository-local `__future__.py`, even if one is
    // present, so it must never become a local source edge.
    if specifier == "__future__" {
        return PythonImportResolution::External;
    }
    let is_relative = specifier.starts_with('.');
    let module = if is_relative {
        match normalize_relative_python_module(importing_path, specifier) {
            Ok(module) => module,
            Err(failure) => return PythonImportResolution::Failure(failure),
        }
    } else {
        specifier.to_owned()
    };

    let portable_matches = portable_modules.get(&module.to_lowercase());
    let Some(targets) = modules.get(&module) else {
        return match portable_matches {
            Some(matches) if matches.len() > 1 => {
                PythonImportResolution::Failure(PythonImportFailure::Ambiguous)
            }
            Some(_) => PythonImportResolution::Failure(PythonImportFailure::CaseMismatch),
            None if is_relative => PythonImportResolution::Failure(PythonImportFailure::Missing),
            None => PythonImportResolution::External,
        };
    };

    if targets.len() != 1 || portable_matches.is_some_and(|matches| matches.len() != 1) {
        return PythonImportResolution::Failure(PythonImportFailure::Ambiguous);
    }
    PythonImportResolution::Local(targets[0].clone())
}

fn normalize_relative_python_module(
    importing_path: &str,
    specifier: &str,
) -> Result<String, PythonImportFailure> {
    let leading_dots = specifier.bytes().take_while(|byte| *byte == b'.').count();
    if leading_dots == 0 {
        return Ok(specifier.to_owned());
    }
    let remainder = &specifier[leading_dots..];
    if remainder.split('.').any(str::is_empty) && !remainder.is_empty() {
        return Err(PythonImportFailure::Missing);
    }

    let mut path_components = importing_path.split('/').collect::<Vec<_>>();
    let filename = path_components
        .pop()
        .ok_or(PythonImportFailure::EscapesRepository)?;
    if path_components.first().copied() == Some("src") {
        path_components.remove(0);
    }
    if path_components.is_empty() && filename != "__init__.py" {
        return Err(PythonImportFailure::EscapesRepository);
    }

    let levels_up = leading_dots.saturating_sub(1);
    if levels_up > 0 && levels_up >= path_components.len() {
        return Err(PythonImportFailure::EscapesRepository);
    }
    path_components.truncate(path_components.len() - levels_up);
    if !remainder.is_empty() {
        path_components.extend(remainder.split('.'));
    }
    Ok(path_components.join("."))
}

fn python_module_for_path(path: &str) -> Option<String> {
    let mut components = path.split('/').collect::<Vec<_>>();
    let filename = components.pop()?;
    if filename.len() <= 3 || !filename[filename.len() - 3..].eq_ignore_ascii_case(".py") {
        return None;
    }
    let stem = &filename[..filename.len() - 3];
    if stem != "__init__" {
        components.push(stem);
    }
    if components
        .iter()
        .any(|component| component.is_empty() || component.contains('.'))
    {
        return None;
    }
    Some(components.join("."))
}

fn python_modules_for_path(path: &str) -> BTreeSet<String> {
    let Some(canonical) = python_module_for_path(path) else {
        return BTreeSet::new();
    };
    let mut modules = BTreeSet::from([canonical.clone()]);
    // `src/` is Python's conventional import root. Indexing both spellings is
    // deterministic, and the resolver still requires exactly one target, so a
    // real top-level collision becomes unresolved rather than guessed.
    if let Some(stripped) = canonical.strip_prefix("src.") {
        if !stripped.is_empty() {
            modules.insert(stripped.to_owned());
        }
    }
    modules
}

fn python_import_relationship_matches(
    relationship: &Relationship,
    source: &str,
    target: &str,
    evidence: &str,
) -> bool {
    relationship.kind == RelationshipKind::Imports
        && relationship.source == source
        && relationship.target == target
        && relationship.evidence_ids.iter().any(|id| id == evidence)
}

fn external_module_id(specifier: &str) -> String {
    format!("module:{}", &stable_hash(&[specifier])[..24])
}

fn stable_hash(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

const fn python_import_failure_reason(failure: PythonImportFailure) -> &'static str {
    match failure {
        PythonImportFailure::EscapesRepository => {
            "relative Python import escapes the repository package root"
        }
        PythonImportFailure::Missing => {
            "relative Python import does not resolve to a scanned Python module or package"
        }
        PythonImportFailure::Ambiguous => {
            "Python import matches multiple scanned modules or packages"
        }
        PythonImportFailure::CaseMismatch => {
            "Python import differs in case from a scanned module or package"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_python_file(path: &str, evidence_id: &str) -> FileRecord {
        FileRecord {
            path: path.to_owned(),
            language: Some(Language::Python),
            size: 1,
            content_hash: "hash".to_owned(),
            status: ScanStatus::Parsed,
            evidence_id: Some(evidence_id.to_owned()),
        }
    }

    fn file_entity(path: &str, id: &str, evidence_id: &str) -> Entity {
        Entity {
            id: id.to_owned(),
            kind: EntityKind::File,
            name: path.rsplit('/').next().unwrap_or(path).to_owned(),
            path: path.to_owned(),
            language: Some(Language::Python),
            evidence_id: evidence_id.to_owned(),
        }
    }

    #[test]
    fn normalizes_relative_modules_from_modules_and_packages() {
        assert_eq!(
            normalize_relative_python_module("pkg/service.py", ".helper"),
            Ok("pkg.helper".to_owned())
        );
        assert_eq!(
            normalize_relative_python_module("pkg/sub/service.py", "..shared.types"),
            Ok("pkg.shared.types".to_owned())
        );
        assert_eq!(
            normalize_relative_python_module("src/pkg/service.py", ".helper"),
            Ok("pkg.helper".to_owned())
        );
        assert_eq!(
            normalize_relative_python_module("pkg/service.py", "..outside"),
            Err(PythonImportFailure::EscapesRepository)
        );
        assert_eq!(
            normalize_relative_python_module("src/pkg/service.py", "..outside"),
            Err(PythonImportFailure::EscapesRepository)
        );
        assert_eq!(
            normalize_relative_python_module("pkg/__init__.py", ".util"),
            Ok("pkg.util".to_owned())
        );
        assert_eq!(
            normalize_relative_python_module("service.py", ".helper"),
            Err(PythonImportFailure::EscapesRepository)
        );
    }

    #[test]
    fn identifies_modules_and_package_initializers() {
        assert_eq!(
            python_module_for_path("service.py").as_deref(),
            Some("service")
        );
        assert_eq!(
            python_module_for_path("pkg/service.py").as_deref(),
            Some("pkg.service")
        );
        assert_eq!(
            python_module_for_path("pkg/__init__.py").as_deref(),
            Some("pkg")
        );
        assert_eq!(python_module_for_path("__init__.py").as_deref(), Some(""));
        assert_eq!(python_module_for_path("bad.dir/module.py"), None);
        assert_eq!(
            python_modules_for_path("src/pkg/service.py"),
            BTreeSet::from(["pkg.service".to_owned(), "src.pkg.service".to_owned()])
        );
    }

    #[test]
    fn distinguishes_local_external_and_ambiguous_absolute_imports() {
        let modules = BTreeMap::from([
            ("pkg".to_owned(), vec!["file:pkg".to_owned()]),
            (
                "ambiguous".to_owned(),
                vec!["file:a".to_owned(), "file:b".to_owned()],
            ),
        ]);
        let portable = BTreeMap::from([
            ("pkg".to_owned(), BTreeSet::from(["pkg".to_owned()])),
            (
                "ambiguous".to_owned(),
                BTreeSet::from(["ambiguous".to_owned()]),
            ),
        ]);

        assert_eq!(
            resolve_python_target("app.py", "pkg", &modules, &portable),
            PythonImportResolution::Local("file:pkg".to_owned())
        );
        assert_eq!(
            resolve_python_target("app.py", "requests", &modules, &portable),
            PythonImportResolution::External
        );
        assert_eq!(
            resolve_python_target("app.py", "Pkg", &modules, &portable),
            PythonImportResolution::Failure(PythonImportFailure::CaseMismatch)
        );
        assert_eq!(
            resolve_python_target("app.py", "ambiguous", &modules, &portable),
            PythonImportResolution::Failure(PythonImportFailure::Ambiguous)
        );
        let shadowed_future =
            BTreeMap::from([("__future__".to_owned(), vec!["file:shadow".to_owned()])]);
        let portable_future = BTreeMap::from([(
            "__future__".to_owned(),
            BTreeSet::from(["__future__".to_owned()]),
        )]);
        assert_eq!(
            resolve_python_target("app.py", "__future__", &shadowed_future, &portable_future),
            PythonImportResolution::External
        );
    }

    #[test]
    fn resolves_and_rejects_individual_imports_that_share_evidence() {
        let files = vec![
            parsed_python_file("pkg/service.py", "ev-service"),
            parsed_python_file("pkg/helpers.py", "ev-helpers"),
        ];
        let entities = vec![
            file_entity("pkg/service.py", "file-service", "ev-service"),
            file_entity("pkg/helpers.py", "file-helpers", "ev-helpers"),
        ];
        let imports = [".helpers", ".missing"]
            .into_iter()
            .map(|specifier| ImportRecord {
                path: "pkg/service.py".to_owned(),
                specifier: specifier.to_owned(),
                evidence_id: "ev-import".to_owned(),
            })
            .collect::<Vec<_>>();
        let mut relationships = imports
            .iter()
            .map(|import| Relationship {
                id: format!("rel-{}", import.specifier),
                source: "file-service".to_owned(),
                target: external_module_id(&import.specifier),
                kind: RelationshipKind::Imports,
                evidence_ids: vec!["ev-import".to_owned()],
            })
            .collect::<Vec<_>>();
        let mut coverage = imports
            .iter()
            .map(|import| CoverageItem {
                id: format!("cov-{}", import.specifier),
                kind: CoverageKind::Import,
                subject: format!("pkg/service.py imports {}", import.specifier),
                evidence_ids: vec!["ev-import".to_owned()],
                disposition: CoverageDisposition::Included {
                    concept_id: "source/service".to_owned(),
                },
            })
            .collect::<Vec<_>>();

        resolve_python_imports(
            &files,
            &entities,
            &imports,
            &mut relationships,
            &mut coverage,
        );

        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].target, "file-helpers");
        assert!(matches!(
            coverage
                .iter()
                .find(|item| item.subject.ends_with(".helpers"))
                .expect("resolved coverage")
                .disposition,
            CoverageDisposition::Included { .. }
        ));
        assert!(matches!(
            coverage
                .iter()
                .find(|item| item.subject.ends_with(".missing"))
                .expect("missing coverage")
                .disposition,
            CoverageDisposition::Unresolved { .. }
        ));
    }

    #[test]
    fn resolves_src_layout_modules_and_keeps_external_imports_external() {
        let files = vec![
            parsed_python_file("src/pkg/service.py", "ev-service"),
            parsed_python_file("src/pkg/helpers.py", "ev-helpers"),
        ];
        let entities = vec![
            file_entity("src/pkg/service.py", "file-service", "ev-service"),
            file_entity("src/pkg/helpers.py", "file-helpers", "ev-helpers"),
        ];
        let imports = [".helpers", "pkg.helpers", "requests"]
            .into_iter()
            .map(|specifier| ImportRecord {
                path: "src/pkg/service.py".to_owned(),
                specifier: specifier.to_owned(),
                evidence_id: format!("ev-{specifier}"),
            })
            .collect::<Vec<_>>();
        let mut relationships = imports
            .iter()
            .map(|import| Relationship {
                id: format!("rel-{}", import.specifier),
                source: "file-service".to_owned(),
                target: external_module_id(&import.specifier),
                kind: RelationshipKind::Imports,
                evidence_ids: vec![import.evidence_id.clone()],
            })
            .collect::<Vec<_>>();
        let mut coverage = imports
            .iter()
            .map(|import| CoverageItem {
                id: format!("cov-{}", import.specifier),
                kind: CoverageKind::Import,
                subject: format!("src/pkg/service.py imports {}", import.specifier),
                evidence_ids: vec![import.evidence_id.clone()],
                disposition: CoverageDisposition::Included {
                    concept_id: "source/service".to_owned(),
                },
            })
            .collect::<Vec<_>>();

        resolve_python_imports(
            &files,
            &entities,
            &imports,
            &mut relationships,
            &mut coverage,
        );

        assert_eq!(
            relationships
                .iter()
                .filter(|relationship| relationship.target == "file-helpers")
                .count(),
            2
        );
        assert!(
            relationships
                .iter()
                .any(|relationship| { relationship.target == external_module_id("requests") })
        );
        assert!(
            coverage
                .iter()
                .all(|item| matches!(item.disposition, CoverageDisposition::Included { .. }))
        );
    }
}
