//! Deterministic conversion from the scanner IR into format-owned documents.

use std::collections::{BTreeMap, BTreeSet};

use repo2okf_core::{
    ArchitectureRelationshipKind, ClaimProvenance, CoverageDisposition, CoverageKind, Entity,
    EntityKind, EvidenceRef, Language, OutputLocale, Relationship, RelationshipKind,
    RelationshipOrigin, RepositoryIr, SemanticResolution,
};

use crate::locale::{
    coverage_description, external_module_description, fallback_claim_description,
    fallback_claim_title, python_description, root_package_title, source_title,
};
use crate::model::{
    ArchitectureScope, CoverageClassification, CoverageItem, EvidenceRecord, Generated,
    OkfArchitectureConcept, OkfClaim, OkfDocument, OkfRelationship, OkfSource,
    ProjectedSemanticRelationship, Repo2OkfMetadata, RepositorySnapshot, SemanticInventory,
};

impl RepositorySnapshot {
    /// Project a repository IR into OKF documents using the requested prose locale.
    #[allow(clippy::too_many_lines)]
    pub fn from_ir_with_locale(ir: &RepositoryIr, output_locale: OutputLocale) -> Self {
        let evidence = ir.evidence.iter().map(EvidenceRecord::from).collect();
        let coverage = ir
            .coverage
            .items
            .iter()
            .map(|item| CoverageItem {
                id: item.id.clone(),
                classification: match &item.disposition {
                    CoverageDisposition::Included { concept_id } => {
                        CoverageClassification::Included {
                            concept_id: concept_id.clone(),
                        }
                    }
                    CoverageDisposition::Excluded { reason } => CoverageClassification::Excluded {
                        reason: reason.clone(),
                    },
                    CoverageDisposition::Unresolved { .. } => CoverageClassification::Unresolved,
                },
            })
            .collect();

        let evidence_by_id = ir
            .evidence
            .iter()
            .map(|record| (record.id.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        let mut evidence_concepts: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let mut documents = BTreeMap::<String, OkfDocument>::new();

        for item in &ir.coverage.items {
            let CoverageDisposition::Included { concept_id } = &item.disposition else {
                continue;
            };
            for evidence_id in &item.evidence_ids {
                evidence_concepts
                    .entry(evidence_id)
                    .or_default()
                    .insert(concept_id.clone());
            }

            let document = documents
                .entry(concept_id.clone())
                .or_insert_with(|| document_for_coverage(ir, item, concept_id, output_locale));
            merge_coverage_metadata(document, ir, item, output_locale);
            for evidence_id in &item.evidence_ids {
                if let Some(record) = evidence_by_id.get(evidence_id.as_str()) {
                    add_source(document, record, output_locale);
                }
            }
        }

        let mut python_concepts_by_path = BTreeMap::new();
        for entity in &ir.entities {
            if !is_python_file(entity) {
                continue;
            }
            let concept_id = python_concept_id(entity);
            let path = normalized_source_path(&entity.path);
            python_concepts_by_path.insert(path, concept_id.clone());
            documents.entry(concept_id.clone()).or_insert_with(|| {
                python_concept_document(ir, entity, &concept_id, &evidence_by_id, output_locale)
            });
        }

        let mut entity_concepts = BTreeMap::new();
        for entity in &ir.entities {
            let python_concept = python_concepts_by_path
                .get(&normalized_source_path(&entity.path))
                .filter(|_| entity.language == Some(Language::Python));
            if let Some(concept_id) = python_concept
                .map(String::as_str)
                .or_else(|| first_concept(&evidence_concepts, &entity.evidence_id))
            {
                entity_concepts.insert(entity.id.as_str(), concept_id.to_owned());
            }
        }

        let mut external_targets = BTreeMap::<&str, String>::new();
        for relationship in &ir.relationships {
            if relationship.kind != RelationshipKind::Imports {
                continue;
            }
            if entity_concepts.contains_key(relationship.target.as_str()) {
                continue;
            }
            let Some(import) = import_for_external_relationship(ir, relationship) else {
                continue;
            };
            let concept_id = external_concept_id(&import.specifier);
            external_targets.insert(relationship.target.as_str(), concept_id.clone());
            let document = documents.entry(concept_id.clone()).or_insert_with(|| {
                external_document(ir, &concept_id, &import.specifier, output_locale)
            });
            if let Some(record) = evidence_by_id.get(import.evidence_id.as_str()) {
                add_source(document, record, output_locale);
            }
        }

        for claim in &ir.claims {
            let mut candidates = BTreeSet::new();
            for evidence_id in &claim.evidence_ids {
                if let Some(concepts) = evidence_concepts.get(evidence_id.as_str()) {
                    candidates.extend(concepts.iter().cloned());
                }
            }
            let concept_id = candidates
                .into_iter()
                .next()
                .unwrap_or_else(|| fallback_claim_concept_id(&claim.id));
            let document = documents.entry(concept_id.clone()).or_insert_with(|| {
                let mut document = OkfDocument::new(&concept_id, "Repository Claim");
                document.metadata.title = Some(fallback_claim_title(output_locale, &claim.id));
                document.metadata.description =
                    Some(fallback_claim_description(output_locale).to_owned());
                document.metadata.generated = Some(generator(ir));
                document
            });
            for evidence_id in &claim.evidence_ids {
                if let Some(record) = evidence_by_id.get(evidence_id.as_str()) {
                    add_source(document, record, output_locale);
                }
            }
            let (agent_provider, agent_reported_model) = match &claim.provenance {
                ClaimProvenance::Agent { provider, model } => {
                    (Some(provider.clone()), model.clone())
                }
                ClaimProvenance::Deterministic { .. } => (None, None),
            };
            if let Some(provider) = agent_provider.as_deref() {
                document.metadata.status = Some(crate::model::OkfStatus::Draft);
                document.metadata.generated = Some(Generated {
                    by: format!("repo2okf-agent/{provider}"),
                    at: None,
                });
            }
            document.claims.push(OkfClaim {
                id: claim.id.clone(),
                text: claim.text_for(output_locale).into_owned(),
                evidence_ids: claim.evidence_ids.clone(),
                ai_generated: agent_provider.is_some(),
                agent_provider,
                agent_reported_model,
            });
        }

        let architecture_concepts = ir
            .architecture_concepts
            .iter()
            .map(|concept| (concept.id.as_str(), architecture_concept_id(&concept.id)))
            .collect::<BTreeMap<_, _>>();
        for concept in &ir.architecture_concepts {
            let concept_id = architecture_concepts[concept.id.as_str()].clone();
            let mut document = OkfDocument::new(&concept_id, "Architecture Component");
            document.metadata.title = Some(concept.title.clone());
            document.metadata.description = Some(concept.responsibility.clone());
            document.metadata.tags.push("architecture".to_owned());
            document.metadata.status = Some(crate::model::OkfStatus::Draft);
            document.metadata.generated = Some(generated_from_provenance(&concept.provenance));
            document.metadata.repo2okf = Some(Repo2OkfMetadata {
                output_locale: Some(output_locale),
                claims: Vec::new(),
                relationships: Vec::new(),
                architecture: Some(OkfArchitectureConcept {
                    source_concept_id: concept.id.clone(),
                    member_entity_ids: concept.member_entity_ids.clone(),
                    supporting_relationship_ids: concept.supporting_relationship_ids.clone(),
                    evidence_ids: concept.evidence_ids.clone(),
                    scope: ir.architecture_scope.as_ref().map(architecture_scope),
                }),
            });
            for evidence_id in &concept.evidence_ids {
                if let Some(record) = evidence_by_id.get(evidence_id.as_str()) {
                    add_source(&mut document, record, output_locale);
                }
            }
            documents.insert(concept_id, document);
        }

        let mut projected_relationships = BTreeMap::new();
        let mut semantic_projection_keys = BTreeSet::new();
        for relationship in &ir.relationships {
            let source = entity_concepts
                .get(relationship.source.as_str())
                .cloned()
                .or_else(|| {
                    first_relationship_concept(&evidence_concepts, &relationship.evidence_ids)
                });
            let target = entity_concepts
                .get(relationship.target.as_str())
                .cloned()
                .or_else(|| external_targets.get(relationship.target.as_str()).cloned());
            let (Some(source), Some(target)) = (source, target) else {
                continue;
            };
            let origin = origin_reference_id(relationship);
            if source == target && origin.is_none() {
                continue;
            }
            let label = documents
                .get(&target)
                .and_then(|document| document.metadata.title.clone());
            let kind = relationship_kind_name(relationship.kind).to_owned();
            let key = (source.clone(), target.clone(), kind.clone());
            merge_projected_relationship(
                &mut projected_relationships,
                source,
                target,
                kind,
                label,
                std::slice::from_ref(&relationship.id),
                origin.clone(),
                relationship.evidence_ids.iter().cloned(),
            );
            if origin.is_some() {
                semantic_projection_keys.insert(key);
            }
        }

        for relationship in &ir.architecture_relationships {
            let (Some(source), Some(target)) = (
                architecture_concepts.get(relationship.source_concept_id.as_str()),
                architecture_concepts.get(relationship.target_concept_id.as_str()),
            ) else {
                continue;
            };
            let label = ir
                .architecture_concepts
                .iter()
                .find(|concept| concept.id == relationship.target_concept_id)
                .map(|concept| concept.title.clone());
            let origins = relationship
                .supporting_relationship_ids
                .iter()
                .filter_map(|id| ir.relationships.iter().find(|edge| edge.id == *id))
                .filter_map(origin_reference_id);
            let kind = match relationship.kind {
                ArchitectureRelationshipKind::DependsOn => "depends_on",
            }
            .to_owned();
            let key = ((*source).clone(), (*target).clone(), kind.clone());
            merge_projected_relationship(
                &mut projected_relationships,
                (*source).clone(),
                (*target).clone(),
                kind,
                label,
                &relationship.supporting_relationship_ids,
                origins,
                relationship.evidence_ids.iter().cloned(),
            );
            semantic_projection_keys.insert(key);
        }

        let projected_semantic_relationships = semantic_projection_keys
            .iter()
            .filter_map(|key| {
                projected_relationships.get(key).map(|relationship| {
                    ProjectedSemanticRelationship::from_okf(&key.0, relationship)
                })
            })
            .collect::<Vec<_>>();

        for ((source, _, _), relationship) in projected_relationships {
            if let Some(document) = documents.get_mut(&source) {
                document.relationships.push(relationship);
            }
        }

        Self {
            repository: ir.repository.name.clone(),
            output_locale,
            documents: documents.into_values().collect(),
            evidence,
            coverage,
            semantic_inventory: Some(semantic_inventory(ir, projected_semantic_relationships)),
        }
    }
}

impl From<&RepositoryIr> for RepositorySnapshot {
    fn from(ir: &RepositoryIr) -> Self {
        Self::from_ir_with_locale(ir, OutputLocale::En)
    }
}

impl From<RepositoryIr> for RepositorySnapshot {
    fn from(ir: RepositoryIr) -> Self {
        Self::from(&ir)
    }
}

impl From<&EvidenceRef> for EvidenceRecord {
    fn from(record: &EvidenceRef) -> Self {
        Self {
            id: record.id.clone(),
            path: record.path.clone(),
            line: Some(record.start_line),
            content_hash: record.content_hash.clone(),
        }
    }
}

fn document_for_coverage(
    ir: &RepositoryIr,
    item: &repo2okf_core::CoverageItem,
    concept_id: &str,
    output_locale: OutputLocale,
) -> OkfDocument {
    let mut document = OkfDocument::new(concept_id, coverage_type(item.kind));
    document.metadata.title = Some(item.subject.clone());
    document.metadata.description = Some(coverage_description(output_locale, &item.subject));
    document.metadata.resource = item
        .evidence_ids
        .iter()
        .find_map(|id| ir.evidence.iter().find(|record| &record.id == id))
        .map(|record| repository_resource(&record.path, None));
    document.metadata.generated = Some(generator(ir));
    document
}

fn is_python_file(entity: &Entity) -> bool {
    entity.kind == EntityKind::File
        && entity.language == Some(Language::Python)
        && normalized_source_path(&entity.path)
            .to_ascii_lowercase()
            .ends_with(".py")
}

fn python_concept_document(
    ir: &RepositoryIr,
    entity: &Entity,
    concept_id: &str,
    evidence_by_id: &BTreeMap<&str, &EvidenceRef>,
    output_locale: OutputLocale,
) -> OkfDocument {
    let package = is_python_package_path(&entity.path);
    let kind = if package {
        "Python Package"
    } else {
        "Python Module"
    };
    let mut document = OkfDocument::new(concept_id, kind);
    document.metadata.title = Some(python_concept_title(entity, package, output_locale));
    document.metadata.description = Some(python_description(
        output_locale,
        &normalized_source_path(&entity.path),
        package,
    ));
    document.metadata.resource = Some(repository_resource(&entity.path, None));
    document.metadata.tags.push("python".to_owned());
    document.metadata.generated = Some(generator(ir));
    if let Some(record) = evidence_by_id.get(entity.evidence_id.as_str()) {
        add_source(&mut document, record, output_locale);
    }
    document
}

fn python_concept_id(entity: &Entity) -> String {
    let package = is_python_package_path(&entity.path);
    let kind = if package { "package" } else { "module" };
    let identity = python_logical_name(entity);
    let slug = portable_slug(&identity, 64);
    let stable_identity = format!(
        "{kind}\0{}\0{identity}",
        normalized_source_path(&entity.path)
    );
    format!("python/{kind}-{slug}-{}", compact_hash(&stable_identity))
}

fn is_python_package_path(path: &str) -> bool {
    normalized_source_path(path)
        .rsplit('/')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("__init__.py"))
}

fn python_concept_title(entity: &Entity, package: bool, output_locale: OutputLocale) -> String {
    let logical = python_logical_name(entity);
    if logical != "__root__" {
        return logical;
    }
    if package {
        root_package_title(output_locale).to_owned()
    } else {
        normalized_source_path(&entity.path)
            .rsplit('/')
            .next()
            .unwrap_or("Python module")
            .to_owned()
    }
}

fn python_logical_name(entity: &Entity) -> String {
    let path = normalized_source_path(&entity.path);
    let mut components = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let Some(filename) = components.pop() else {
        return python_qualified_name_fallback(entity);
    };
    if components
        .first()
        .is_some_and(|component| component.eq_ignore_ascii_case("src"))
    {
        components.remove(0);
    }
    let initializer = filename.eq_ignore_ascii_case("__init__.py");
    if !initializer {
        let stem = filename
            .get(..filename.len().saturating_sub(3))
            .unwrap_or(filename);
        if !stem.is_empty() {
            components.push(stem);
        }
    }
    if components.is_empty() && initializer {
        "__root__".to_owned()
    } else if components.is_empty() {
        python_qualified_name_fallback(entity)
    } else {
        components.join(".")
    }
}

fn python_qualified_name_fallback(entity: &Entity) -> String {
    let qualified = entity.qualified_name.trim();
    if qualified.is_empty() || qualified == "__root__" {
        "__root__".to_owned()
    } else {
        qualified
            .strip_prefix("src.")
            .filter(|name| !name.is_empty())
            .unwrap_or(qualified)
            .to_owned()
    }
}

fn normalized_source_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn portable_slug(value: &str, limit: usize) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            separator = false;
        } else if !separator && !slug.is_empty() {
            slug.push('-');
            separator = true;
        }
        if slug.len() >= limit {
            break;
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() { "root" } else { slug }.to_owned()
}

fn merge_coverage_metadata(
    document: &mut OkfDocument,
    ir: &RepositoryIr,
    item: &repo2okf_core::CoverageItem,
    output_locale: OutputLocale,
) {
    // A file item describes the shared concept more accurately than the
    // declaration and import inventory items folded into the same file concept.
    if item.kind == CoverageKind::File {
        coverage_type(item.kind).clone_into(&mut document.metadata.concept_type);
        document.metadata.title = Some(item.subject.clone());
        document.metadata.description = Some(coverage_description(output_locale, &item.subject));
        document.metadata.resource = Some(repository_resource(&item.subject, None));
        if let Some(language) = ir
            .files
            .iter()
            .find(|file| file.path == item.subject)
            .and_then(|file| file.language)
        {
            document.metadata.tags.push(language.as_str().to_owned());
        }
    }
}

fn external_document(
    ir: &RepositoryIr,
    concept_id: &str,
    specifier: &str,
    output_locale: OutputLocale,
) -> OkfDocument {
    let mut document = OkfDocument::new(concept_id, "External Module");
    document.metadata.title = Some(specifier.to_owned());
    document.metadata.description = Some(external_module_description(output_locale, specifier));
    document.metadata.resource = Some(format!("module:{specifier}"));
    document.metadata.generated = Some(generator(ir));
    document
}

fn generator(ir: &RepositoryIr) -> Generated {
    Generated {
        by: ir.repository.extractor.clone(),
        at: None,
    }
}

fn coverage_type(kind: CoverageKind) -> &'static str {
    match kind {
        CoverageKind::File => "Source File",
        CoverageKind::Entity => "Source Declaration",
        CoverageKind::Import => "Import",
    }
}

fn add_source(document: &mut OkfDocument, record: &EvidenceRef, output_locale: OutputLocale) {
    if document
        .metadata
        .sources
        .iter()
        .any(|source| source.evidence_id.as_deref() == Some(record.id.as_str()))
    {
        return;
    }
    document.metadata.sources.push(OkfSource {
        id: None,
        resource: repository_resource(&record.path, Some(record.start_line)),
        title: Some(source_title(
            output_locale,
            record.symbol.as_deref(),
            &record.path,
        )),
        author: Some(format!("process:{}", record.extractor)),
        usage_count: None,
        last_modified: None,
        usage_window: None,
        evidence_id: Some(record.id.clone()),
        content_hash: Some(record.content_hash.clone()),
    });
}

fn repository_resource(path: &str, line: Option<u32>) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let normalized = path.replace('\\', "/");
    let mut encoded = String::with_capacity(normalized.len());
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    line.map_or_else(
        || format!("repo:{encoded}"),
        |line| format!("repo:{encoded}#L{line}"),
    )
}

fn first_concept<'a>(
    evidence_concepts: &'a BTreeMap<&str, BTreeSet<String>>,
    evidence_id: &str,
) -> Option<&'a str> {
    evidence_concepts
        .get(evidence_id)
        .and_then(|concepts| concepts.first())
        .map(String::as_str)
}

fn first_relationship_concept(
    evidence_concepts: &BTreeMap<&str, BTreeSet<String>>,
    evidence_ids: &[String],
) -> Option<String> {
    evidence_ids
        .iter()
        .filter_map(|id| first_concept(evidence_concepts, id))
        .min()
        .map(str::to_owned)
}

fn import_for_external_relationship<'a>(
    ir: &'a RepositoryIr,
    relationship: &Relationship,
) -> Option<&'a repo2okf_core::ImportRecord> {
    ir.imports.iter().find(|import| {
        relationship.evidence_ids.contains(&import.evidence_id)
            && relationship.target == scanner_external_module_id(&import.specifier)
    })
}

// Keep this in lockstep with the core scanner's stable `module` ID. Matching
// both the evidence and target is necessary for statements such as Python's
// `import a, b`, where several import records share one exact source span.
fn scanner_external_module_id(specifier: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(specifier.len() as u64).to_le_bytes());
    hasher.update(specifier.as_bytes());
    format!("module:{}", &hasher.finalize().to_hex()[..24])
}

fn external_concept_id(specifier: &str) -> String {
    format!("external/module-{}", compact_hash(specifier))
}

fn fallback_claim_concept_id(claim_id: &str) -> String {
    format!("claims/claim-{}", compact_hash(claim_id))
}

fn compact_hash(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex()[..24].to_owned()
}

type ProjectedRelationshipKey = (String, String, String);

#[allow(clippy::too_many_arguments)]
fn merge_projected_relationship<I, E>(
    projected: &mut BTreeMap<ProjectedRelationshipKey, OkfRelationship>,
    source: String,
    target: String,
    kind: String,
    label: Option<String>,
    source_relationship_ids: &[String],
    origin_reference_ids: I,
    evidence_ids: E,
) where
    I: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let key = (source, target.clone(), kind.clone());
    let relationship = projected.entry(key).or_insert_with(|| OkfRelationship {
        target,
        label,
        kind: Some(kind),
        source_relationship_ids: Vec::new(),
        origin_reference_ids: Vec::new(),
        evidence_ids: Vec::new(),
    });
    relationship
        .source_relationship_ids
        .extend(source_relationship_ids.iter().cloned());
    relationship
        .origin_reference_ids
        .extend(origin_reference_ids);
    relationship.evidence_ids.extend(evidence_ids);
    relationship.source_relationship_ids.sort();
    relationship.source_relationship_ids.dedup();
    relationship.origin_reference_ids.sort();
    relationship.origin_reference_ids.dedup();
    relationship.evidence_ids.sort();
    relationship.evidence_ids.dedup();
}

const fn relationship_kind_name(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::Contains => "contains",
        RelationshipKind::Imports => "imports",
        RelationshipKind::Calls => "calls",
        RelationshipKind::Extends => "extends",
        RelationshipKind::TypeUses => "type_uses",
        RelationshipKind::DecoratedBy => "decorated_by",
    }
}

fn origin_reference_id(relationship: &Relationship) -> Option<String> {
    match &relationship.origin {
        RelationshipOrigin::ObservedSyntax => None,
        RelationshipOrigin::SemanticReference { reference_id } => Some(reference_id.clone()),
    }
}

fn architecture_concept_id(source_id: &str) -> String {
    format!("architecture/concept-{}", compact_hash(source_id))
}

fn generated_from_provenance(provenance: &ClaimProvenance) -> Generated {
    match provenance {
        ClaimProvenance::Agent { provider, .. } => Generated {
            by: format!("repo2okf-agent/{provider}"),
            at: None,
        },
        ClaimProvenance::Deterministic { process } => Generated {
            by: process.clone(),
            at: None,
        },
    }
}

fn semantic_inventory(
    ir: &RepositoryIr,
    mut projected_relationships: Vec<ProjectedSemanticRelationship>,
) -> SemanticInventory {
    let mut entity_ids = ir
        .entities
        .iter()
        .map(|entity| entity.id.clone())
        .collect::<Vec<_>>();
    let mut relationship_ids = ir
        .relationships
        .iter()
        .map(|relationship| relationship.id.clone())
        .collect::<Vec<_>>();
    let mut resolved_reference_ids = ir
        .semantic_references
        .iter()
        .filter(|reference| matches!(reference.resolution, SemanticResolution::Resolved { .. }))
        .map(|reference| reference.id.clone())
        .collect::<Vec<_>>();
    let mut architecture_concept_ids = ir
        .architecture_concepts
        .iter()
        .map(|concept| concept.id.clone())
        .collect::<Vec<_>>();
    for ids in [
        &mut entity_ids,
        &mut relationship_ids,
        &mut resolved_reference_ids,
        &mut architecture_concept_ids,
    ] {
        ids.sort();
        ids.dedup();
    }
    projected_relationships.sort();
    projected_relationships.dedup();
    SemanticInventory {
        entity_ids,
        relationship_ids,
        resolved_reference_ids,
        architecture_concept_ids,
        projection_contract_complete: true,
        projected_relationships,
        architecture_scope: ir.architecture_scope.as_ref().map(architecture_scope),
    }
}

fn architecture_scope(scope: &repo2okf_core::ArchitectureScope) -> ArchitectureScope {
    ArchitectureScope {
        evidence_total: scope.evidence_total,
        evidence_supplied: scope.evidence_supplied,
        coverage_items_total: scope.coverage_items_total,
        coverage_items_supplied: scope.coverage_items_supplied,
        entities_total: scope.entities_total,
        entities_supplied: scope.entities_supplied,
        semantic_references_total: scope.semantic_references_total,
        semantic_references_supplied: scope.semantic_references_supplied,
        semantic_relationships_total: scope.semantic_relationships_total,
        semantic_relationships_supplied: scope.semantic_relationships_supplied,
        complete: scope.complete,
    }
}

#[cfg(test)]
mod tests {
    use repo2okf_core::{
        ArchitectureConcept, ArchitectureRelationship, ArchitectureRelationshipKind,
        ArchitectureScope as CoreArchitectureScope, ArchitectureStatus, Claim, ClaimFact,
        ClaimProvenance, CoverageDisposition, CoverageItem, CoverageKind, CoverageReport, Entity,
        EntityKind, EvidenceRef, FileRecord, ImportRecord, Language, OutputLocale, Relationship,
        RelationshipKind, RelationshipOrigin, RepositoryIr, RepositoryMetadata, ScanStatus,
        SemanticCoverage, SemanticReference, SemanticReferenceKind, SemanticResolution,
    };

    use super::{
        RepositorySnapshot, architecture_concept_id, external_concept_id, is_python_file,
        python_concept_document, python_concept_id, python_logical_name,
        scanner_external_module_id,
    };
    use crate::model::concept_path;

    fn ir(provenance: ClaimProvenance) -> RepositoryIr {
        let evidence = EvidenceRef {
            id: "ev-1".into(),
            path: "src/main.ts".into(),
            start_line: 2,
            end_line: 2,
            start_byte: 10,
            end_byte: 20,
            content_hash: "hash".into(),
            symbol: Some("main".into()),
            extractor: "repo2okf-core/0.1.0".into(),
        };
        RepositoryIr {
            schema_version: 2,
            repository: RepositoryMetadata {
                name: "example".into(),
                git_commit: None,
                git_inventory: false,
                extractor: "repo2okf-core/0.1.0".into(),
            },
            files: vec![FileRecord {
                path: "src/main.ts".into(),
                language: Some(Language::TypeScript),
                size: 64,
                content_hash: "hash".into(),
                status: ScanStatus::Parsed,
                evidence_id: Some("ev-1".into()),
            }],
            entities: vec![
                Entity {
                    id: "file-main".into(),
                    kind: EntityKind::File,
                    name: "main.ts".into(),
                    qualified_name: "src.main".into(),
                    owner_id: None,
                    path: "src/main.ts".into(),
                    language: Some(Language::TypeScript),
                    evidence_id: "ev-1".into(),
                },
                Entity {
                    id: "entity-1".into(),
                    kind: EntityKind::Function,
                    name: "main".into(),
                    qualified_name: "src.main.main".into(),
                    owner_id: Some("file-main".into()),
                    path: "src/main.ts".into(),
                    language: Some(Language::TypeScript),
                    evidence_id: "ev-1".into(),
                },
            ],
            imports: vec![],
            evidence: vec![evidence],
            relationships: vec![],
            semantic_references: vec![],
            semantic_coverage: SemanticCoverage::default(),
            claims: vec![Claim {
                id: "claim-1".into(),
                text: "main is declared.".into(),
                fact: None,
                evidence_ids: vec!["ev-1".into()],
                provenance,
                confidence: Some(90),
            }],
            architecture_concepts: vec![],
            architecture_relationships: vec![],
            architecture_scope: None,
            coverage: CoverageReport::from_items(vec![CoverageItem {
                id: "coverage-1".into(),
                kind: CoverageKind::File,
                subject: "src/main.ts".into(),
                evidence_ids: vec!["ev-1".into()],
                disposition: CoverageDisposition::Included {
                    concept_id: "source/main".into(),
                },
            }]),
            fingerprint: "fingerprint".into(),
        }
    }

    #[test]
    fn converts_core_ir_without_promoting_agent_claims_to_verified() {
        let snapshot = RepositorySnapshot::from(&ir(ClaimProvenance::Agent {
            provider: "codex".into(),
            model: Some("gpt".into()),
        }));

        assert_eq!(snapshot.repository, "example");
        assert_eq!(snapshot.documents.len(), 1);
        let document = &snapshot.documents[0];
        assert_eq!(document.id, "source/main");
        assert_eq!(document.metadata.concept_type, "Source File");
        assert_eq!(document.metadata.tags, ["typescript"]);
        assert!(document.metadata.verified.is_empty());
        assert!(document.claims[0].ai_generated);
        assert_eq!(document.claims[0].agent_provider.as_deref(), Some("codex"));
        assert_eq!(
            document.claims[0].agent_reported_model.as_deref(),
            Some("gpt")
        );
        assert_eq!(
            document.metadata.status,
            Some(crate::model::OkfStatus::Draft)
        );
        assert_eq!(
            document
                .metadata
                .generated
                .as_ref()
                .map(|event| event.by.as_str()),
            Some("repo2okf-agent/codex")
        );
        assert_eq!(snapshot.evidence[0].line, Some(2));
    }

    #[test]
    fn deterministic_claim_is_not_mislabeled_as_ai() {
        let snapshot = RepositorySnapshot::from(&ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        }));
        assert!(!snapshot.documents[0].claims[0].ai_generated);
    }

    #[test]
    fn localizes_generated_prose_without_changing_machine_contracts() {
        let mut repository = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        });
        repository.claims[0].fact = Some(ClaimFact::Declaration {
            path: "src/main.ts".into(),
            entity_kind: EntityKind::Function,
            name: "main".into(),
        });

        let english = RepositorySnapshot::from_ir_with_locale(&repository, OutputLocale::En);
        let japanese = RepositorySnapshot::from_ir_with_locale(&repository, OutputLocale::Ja);
        let english_document = &english.documents[0];
        let japanese_document = &japanese.documents[0];

        assert_eq!(english.output_locale, OutputLocale::En);
        assert_eq!(japanese.output_locale, OutputLocale::Ja);
        assert_eq!(english.evidence, japanese.evidence);
        assert_eq!(english.coverage, japanese.coverage);
        assert_eq!(english.semantic_inventory, japanese.semantic_inventory);
        assert_eq!(english_document.id, japanese_document.id);
        assert_eq!(
            english_document.metadata.concept_type,
            japanese_document.metadata.concept_type
        );
        assert_eq!(
            english_document.metadata.resource,
            japanese_document.metadata.resource
        );
        assert_eq!(
            english_document.claims[0].id,
            japanese_document.claims[0].id
        );
        assert_eq!(
            english_document.claims[0].evidence_ids,
            japanese_document.claims[0].evidence_ids
        );
        assert_eq!(
            english_document.metadata.description.as_deref(),
            Some("Repository knowledge extracted from src/main.ts.")
        );
        assert_eq!(
            japanese_document.metadata.description.as_deref(),
            Some("src/main.ts から抽出したリポジトリの情報です。")
        );
        assert_eq!(
            english_document.claims[0].text,
            "src/main.ts declares function `main`."
        );
        assert_eq!(
            japanese_document.claims[0].text,
            "src/main.ts では、関数 `main` が宣言されています。"
        );
        assert_eq!(
            english_document.metadata.sources[0].title.as_deref(),
            Some("main in src/main.ts")
        );
        assert_eq!(
            japanese_document.metadata.sources[0].title.as_deref(),
            Some("src/main.ts 内の main")
        );
    }

    #[test]
    fn python_concept_ids_are_portable_bounded_and_collision_safe() {
        let entity = |path: &str, qualified_name: &str| Entity {
            id: format!("entity:{path}"),
            kind: EntityKind::File,
            name: path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned(),
            qualified_name: qualified_name.to_owned(),
            owner_id: None,
            path: path.to_owned(),
            language: Some(Language::Python),
            evidence_id: "ev-1".to_owned(),
        };
        let src_module = entity("src/pkg/service.PY", "src.pkg.service");
        let portable_src_module = entity("src\\pkg\\service.PY", "src.pkg.service");
        let top_level_collision = entity("pkg/service.PY", "pkg.service");
        let root_package = entity("__INIT__.PY", "");
        let long_module = entity(
            &format!("src/{}.py", "a".repeat(300)),
            &format!("src.{}", "a".repeat(300)),
        );

        assert!(is_python_file(&src_module));
        assert!(is_python_file(&root_package));
        assert_eq!(python_logical_name(&src_module), "pkg.service");
        assert_eq!(python_logical_name(&root_package), "__root__");
        assert_eq!(
            python_concept_id(&src_module),
            python_concept_id(&portable_src_module),
            "path separators must not affect a generated concept ID"
        );
        assert_ne!(
            python_concept_id(&src_module),
            python_concept_id(&top_level_collision),
            "src-layout aliases must remain collision safe"
        );
        for id in [
            python_concept_id(&src_module),
            python_concept_id(&top_level_collision),
            python_concept_id(&root_package),
            python_concept_id(&long_module),
        ] {
            assert!(id.len() <= 112, "concept ID is not bounded: {id}");
            assert!(
                concept_path(&id).is_ok(),
                "concept ID is not portable: {id}"
            );
        }

        let repository = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".to_owned(),
        });
        let evidence = repository
            .evidence
            .iter()
            .map(|record| (record.id.as_str(), record))
            .collect();
        let root_document = python_concept_document(
            &repository,
            &root_package,
            &python_concept_id(&root_package),
            &evidence,
            repo2okf_core::OutputLocale::En,
        );
        assert_eq!(
            root_document.metadata.title.as_deref(),
            Some("Repository root package")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the end-to-end Python projection fixture keeps every graph binding auditable"
    )]
    fn projects_python_module_docs_and_rolls_up_semantic_edges() {
        let mut ir = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".to_owned(),
        });
        let package_path = "src/pkg/__INIT__.PY";
        let module_path = "src/pkg/service.PY";
        ir.files[0].path = package_path.to_owned();
        ir.files[0].language = Some(Language::Python);
        ir.evidence[0].path = package_path.to_owned();
        ir.coverage.items[0].subject = package_path.to_owned();
        for entity in &mut ir.entities {
            entity.path = package_path.to_owned();
            entity.language = Some(Language::Python);
        }
        ir.entities[0].name = "__INIT__.PY".to_owned();
        ir.entities[0].qualified_name = "src.pkg".to_owned();
        ir.entities[1].qualified_name = "src.pkg.initialize".to_owned();
        ir.evidence.extend([
            EvidenceRef {
                id: "ev-module".to_owned(),
                path: module_path.to_owned(),
                start_line: 1,
                end_line: 4,
                start_byte: 0,
                end_byte: 40,
                content_hash: "module-hash".to_owned(),
                symbol: None,
                extractor: "repo2okf-core/0.1.0".to_owned(),
            },
            EvidenceRef {
                id: "ev-python-call".to_owned(),
                path: package_path.to_owned(),
                start_line: 2,
                end_line: 2,
                start_byte: 21,
                end_byte: 30,
                content_hash: "hash".to_owned(),
                symbol: Some("serve".to_owned()),
                extractor: "repo2okf-core/0.1.0".to_owned(),
            },
            EvidenceRef {
                id: "ev-python-self-call".to_owned(),
                path: module_path.to_owned(),
                start_line: 2,
                end_line: 2,
                start_byte: 12,
                end_byte: 19,
                content_hash: "module-hash".to_owned(),
                symbol: Some("serve".to_owned()),
                extractor: "repo2okf-core/0.1.0".to_owned(),
            },
            EvidenceRef {
                id: "ev-python-self-call-2".to_owned(),
                path: module_path.to_owned(),
                start_line: 3,
                end_line: 3,
                start_byte: 22,
                end_byte: 29,
                content_hash: "module-hash".to_owned(),
                symbol: Some("serve".to_owned()),
                extractor: "repo2okf-core/0.1.0".to_owned(),
            },
        ]);
        ir.files.push(FileRecord {
            path: module_path.to_owned(),
            language: Some(Language::Python),
            size: 64,
            content_hash: "module-hash".to_owned(),
            status: ScanStatus::Parsed,
            evidence_id: Some("ev-module".to_owned()),
        });
        ir.entities.extend([
            Entity {
                id: "file-service".to_owned(),
                kind: EntityKind::File,
                name: "service.PY".to_owned(),
                qualified_name: "src.pkg.service".to_owned(),
                owner_id: None,
                path: module_path.to_owned(),
                language: Some(Language::Python),
                evidence_id: "ev-module".to_owned(),
            },
            Entity {
                id: "entity-serve".to_owned(),
                kind: EntityKind::Function,
                name: "serve".to_owned(),
                qualified_name: "src.pkg.service.serve".to_owned(),
                owner_id: Some("file-service".to_owned()),
                path: module_path.to_owned(),
                language: Some(Language::Python),
                evidence_id: "ev-module".to_owned(),
            },
        ]);
        ir.semantic_references = vec![
            SemanticReference {
                id: "ref-python-call".to_owned(),
                kind: SemanticReferenceKind::Call,
                path: package_path.to_owned(),
                scope_id: "entity-1".to_owned(),
                source_entity_id: Some("entity-1".to_owned()),
                name: "serve".to_owned(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-python-call".to_owned(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-serve".to_owned(),
                },
            },
            SemanticReference {
                id: "ref-python-self-call".to_owned(),
                kind: SemanticReferenceKind::Call,
                path: module_path.to_owned(),
                scope_id: "entity-serve".to_owned(),
                source_entity_id: Some("entity-serve".to_owned()),
                name: "serve".to_owned(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-python-self-call".to_owned(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-serve".to_owned(),
                },
            },
            SemanticReference {
                id: "ref-python-self-call-2".to_owned(),
                kind: SemanticReferenceKind::Call,
                path: module_path.to_owned(),
                scope_id: "entity-serve".to_owned(),
                source_entity_id: Some("entity-serve".to_owned()),
                name: "serve".to_owned(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-python-self-call-2".to_owned(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-serve".to_owned(),
                },
            },
        ];
        ir.semantic_coverage = SemanticCoverage::from_references(&ir.semantic_references);
        ir.relationships = vec![
            Relationship {
                id: "edge-python-call".to_owned(),
                source: "entity-1".to_owned(),
                target: "entity-serve".to_owned(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-python-call".to_owned(),
                },
                evidence_ids: vec!["ev-python-call".to_owned()],
            },
            Relationship {
                id: "edge-python-self-call".to_owned(),
                source: "entity-serve".to_owned(),
                target: "entity-serve".to_owned(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-python-self-call".to_owned(),
                },
                evidence_ids: vec!["ev-python-self-call".to_owned()],
            },
            Relationship {
                id: "edge-python-self-call-2".to_owned(),
                source: "entity-serve".to_owned(),
                target: "entity-serve".to_owned(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-python-self-call-2".to_owned(),
                },
                evidence_ids: vec!["ev-python-self-call-2".to_owned()],
            },
            Relationship {
                id: "edge-python-contains".to_owned(),
                source: "file-service".to_owned(),
                target: "entity-serve".to_owned(),
                kind: RelationshipKind::Contains,
                origin: RelationshipOrigin::ObservedSyntax,
                evidence_ids: vec!["ev-module".to_owned()],
            },
        ];
        ir.coverage = CoverageReport::from_items(vec![
            ir.coverage.items[0].clone(),
            CoverageItem {
                id: "coverage-module".to_owned(),
                kind: CoverageKind::File,
                subject: module_path.to_owned(),
                evidence_ids: vec!["ev-module".to_owned()],
                disposition: CoverageDisposition::Included {
                    concept_id: "source/service".to_owned(),
                },
            },
        ]);
        ir.validate().unwrap();

        let snapshot = RepositorySnapshot::from(&ir);
        assert_eq!(snapshot.coverage.len(), 2);
        assert_eq!(snapshot.documents.len(), 4);
        assert!(snapshot.documents.iter().any(|document| {
            document.id == "source/main" && document.metadata.concept_type == "Source File"
        }));
        assert!(snapshot.documents.iter().any(|document| {
            document.id == "source/service" && document.metadata.concept_type == "Source File"
        }));
        let package = snapshot
            .documents
            .iter()
            .find(|document| document.metadata.concept_type == "Python Package")
            .unwrap();
        let module = snapshot
            .documents
            .iter()
            .find(|document| document.metadata.concept_type == "Python Module")
            .unwrap();
        assert_eq!(package.metadata.title.as_deref(), Some("pkg"));
        assert_eq!(module.metadata.title.as_deref(), Some("pkg.service"));
        assert_eq!(
            package.metadata.resource.as_deref(),
            Some("repo:src/pkg/__INIT__.PY")
        );
        assert_eq!(
            module.metadata.resource.as_deref(),
            Some("repo:src/pkg/service.PY")
        );
        assert!(
            package
                .metadata
                .sources
                .iter()
                .any(|source| { source.evidence_id.as_deref() == Some("ev-1") })
        );
        let call = package
            .relationships
            .iter()
            .find(|relationship| relationship.kind.as_deref() == Some("calls"))
            .unwrap();
        assert_eq!(call.target, module.id);
        assert_eq!(call.source_relationship_ids, ["edge-python-call"]);
        assert_eq!(call.origin_reference_ids, ["ref-python-call"]);
        assert_eq!(call.evidence_ids, ["ev-python-call"]);
        let self_call = module
            .relationships
            .iter()
            .find(|relationship| {
                relationship.kind.as_deref() == Some("calls") && relationship.target == module.id
            })
            .unwrap();
        assert_eq!(
            self_call.source_relationship_ids,
            ["edge-python-self-call", "edge-python-self-call-2"]
        );
        assert_eq!(
            self_call.origin_reference_ids,
            ["ref-python-self-call", "ref-python-self-call-2"]
        );
        assert_eq!(
            self_call.evidence_ids,
            ["ev-python-self-call", "ev-python-self-call-2"]
        );
        assert!(
            module
                .relationships
                .iter()
                .all(|relationship| relationship.kind.as_deref() != Some("contains")),
            "observed-syntax self edges must remain omitted"
        );
        assert!(
            snapshot
                .documents
                .iter()
                .filter(|document| document.metadata.concept_type == "Source File")
                .all(|document| document
                    .relationships
                    .iter()
                    .all(|relationship| { relationship.kind.as_deref() != Some("calls") }))
        );
        assert!(
            snapshot
                .documents
                .iter()
                .all(|document| !document.id.contains("entity-"))
        );
        let inventory = snapshot.semantic_inventory.as_ref().unwrap();
        assert!(inventory.projected_relationships.iter().any(|projected| {
            projected.source_concept_id == module.id
                && projected.target_concept_id == module.id
                && projected.kind == "calls"
                && projected.source_relationship_ids
                    == ["edge-python-self-call", "edge-python-self-call-2"]
                && projected.origin_reference_ids
                    == ["ref-python-self-call", "ref-python-self-call-2"]
                && projected.evidence_ids == ["ev-python-self-call", "ev-python-self-call-2"]
        }));

        let mut reordered = ir.clone();
        reordered.entities.reverse();
        reordered.relationships.reverse();
        assert_eq!(snapshot, RepositorySnapshot::from(&reordered));
    }

    #[test]
    fn repository_resources_percent_encode_unsafe_uri_bytes() {
        let mut ir = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        });
        ir.files[0].path = "src/a #b.ts".into();
        ir.entities[0].path = "src/a #b.ts".into();
        ir.evidence[0].path = "src/a #b.ts".into();
        ir.coverage.items[0].subject = "src/a #b.ts".into();
        let snapshot = RepositorySnapshot::from(&ir);
        let document = &snapshot.documents[0];
        assert_eq!(
            document.metadata.resource.as_deref(),
            Some("repo:src/a%20%23b.ts")
        );
        assert_eq!(
            document.metadata.sources[0].resource,
            "repo:src/a%20%23b.ts#L2"
        );
    }

    #[test]
    fn converts_resolved_local_imports_to_source_concept_links() {
        let mut ir = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        });
        ir.evidence.push(EvidenceRef {
            id: "ev-2".into(),
            path: "src/dependency.ts".into(),
            start_line: 1,
            end_line: 1,
            start_byte: 0,
            end_byte: 20,
            content_hash: "dependency-hash".into(),
            symbol: None,
            extractor: "repo2okf-core/0.1.0".into(),
        });
        ir.files.push(FileRecord {
            path: "src/dependency.ts".into(),
            language: Some(Language::TypeScript),
            size: 64,
            content_hash: "dependency-hash".into(),
            status: ScanStatus::Parsed,
            evidence_id: Some("ev-2".into()),
        });
        ir.entities.push(Entity {
            id: "entity-2".into(),
            kind: EntityKind::File,
            name: "dependency.ts".into(),
            qualified_name: "src.dependency".into(),
            owner_id: None,
            path: "src/dependency.ts".into(),
            language: Some(Language::TypeScript),
            evidence_id: "ev-2".into(),
        });
        ir.imports.push(ImportRecord {
            path: "src/main.ts".into(),
            specifier: "./dependency".into(),
            evidence_id: "ev-1".into(),
        });
        ir.relationships.push(Relationship {
            id: "relationship-1".into(),
            source: "entity-1".into(),
            target: "entity-2".into(),
            kind: RelationshipKind::Imports,
            origin: RelationshipOrigin::ObservedSyntax,
            evidence_ids: vec!["ev-1".into()],
        });
        ir.coverage.items.push(CoverageItem {
            id: "coverage-2".into(),
            kind: CoverageKind::File,
            subject: "src/dependency.ts".into(),
            evidence_ids: vec!["ev-2".into()],
            disposition: CoverageDisposition::Included {
                concept_id: "source/dependency".into(),
            },
        });

        let snapshot = RepositorySnapshot::from(&ir);
        assert_eq!(snapshot.documents.len(), 2);
        assert!(
            snapshot
                .documents
                .iter()
                .all(|document| document.metadata.concept_type != "External Module")
        );
        let source = snapshot
            .documents
            .iter()
            .find(|document| document.id == "source/main")
            .expect("source concept");
        assert!(source.relationships.iter().any(|relationship| {
            relationship.target == "source/dependency"
                && relationship.kind.as_deref() == Some("imports")
        }));
    }

    #[test]
    fn distinguishes_external_imports_that_share_one_evidence_span() {
        let mut ir = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        });
        for specifier in ["alpha", "beta"] {
            ir.imports.push(ImportRecord {
                path: "src/main.ts".into(),
                specifier: specifier.into(),
                evidence_id: "ev-1".into(),
            });
            ir.relationships.push(Relationship {
                id: format!("relationship-{specifier}"),
                source: "entity-1".into(),
                target: scanner_external_module_id(specifier),
                kind: RelationshipKind::Imports,
                origin: RelationshipOrigin::ObservedSyntax,
                evidence_ids: vec!["ev-1".into()],
            });
        }

        let snapshot = RepositorySnapshot::from(&ir);
        let source = snapshot
            .documents
            .iter()
            .find(|document| document.id == "source/main")
            .expect("source concept");
        for specifier in ["alpha", "beta"] {
            let target = external_concept_id(specifier);
            assert!(snapshot.documents.iter().any(|document| {
                document.id == target && document.metadata.title.as_deref() == Some(specifier)
            }));
            assert!(source.relationships.iter().any(|relationship| {
                relationship.target == target
                    && relationship.label.as_deref() == Some(specifier)
                    && relationship.kind.as_deref() == Some("imports")
            }));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn rolls_up_semantic_edges_and_projects_draft_architecture_without_symbol_documents() {
        let mut ir = ir(ClaimProvenance::Deterministic {
            process: "repo2okf-core/0.1.0".into(),
        });
        ir.evidence.extend([
            EvidenceRef {
                id: "ev-2".into(),
                path: "src/dependency.ts".into(),
                start_line: 1,
                end_line: 20,
                start_byte: 0,
                end_byte: 200,
                content_hash: "dependency-hash".into(),
                symbol: None,
                extractor: "repo2okf-core/0.1.0".into(),
            },
            EvidenceRef {
                id: "ev-call".into(),
                path: "src/main.ts".into(),
                start_line: 3,
                end_line: 3,
                start_byte: 21,
                end_byte: 32,
                content_hash: "hash".into(),
                symbol: Some("load".into()),
                extractor: "repo2okf-core/0.1.0".into(),
            },
        ]);
        ir.files.push(FileRecord {
            path: "src/dependency.ts".into(),
            language: Some(Language::TypeScript),
            size: 200,
            content_hash: "dependency-hash".into(),
            status: ScanStatus::Parsed,
            evidence_id: Some("ev-2".into()),
        });
        ir.entities.extend([
            Entity {
                id: "entity-source-helper".into(),
                kind: EntityKind::Function,
                name: "helper".into(),
                qualified_name: "src.main.helper".into(),
                owner_id: Some("file-main".into()),
                path: "src/main.ts".into(),
                language: Some(Language::TypeScript),
                evidence_id: "ev-1".into(),
            },
            Entity {
                id: "file-dependency".into(),
                kind: EntityKind::File,
                name: "dependency.ts".into(),
                qualified_name: "src.dependency".into(),
                owner_id: None,
                path: "src/dependency.ts".into(),
                language: Some(Language::TypeScript),
                evidence_id: "ev-2".into(),
            },
            Entity {
                id: "entity-target-load".into(),
                kind: EntityKind::Function,
                name: "load".into(),
                qualified_name: "src.dependency.load".into(),
                owner_id: Some("file-dependency".into()),
                path: "src/dependency.ts".into(),
                language: Some(Language::TypeScript),
                evidence_id: "ev-2".into(),
            },
            Entity {
                id: "entity-target-save".into(),
                kind: EntityKind::Function,
                name: "save".into(),
                qualified_name: "src.dependency.save".into(),
                owner_id: Some("file-dependency".into()),
                path: "src/dependency.ts".into(),
                language: Some(Language::TypeScript),
                evidence_id: "ev-2".into(),
            },
        ]);
        ir.semantic_references = vec![
            SemanticReference {
                id: "ref-cross".into(),
                kind: SemanticReferenceKind::Call,
                path: "src/main.ts".into(),
                scope_id: "file-main".into(),
                source_entity_id: Some("entity-1".into()),
                name: "load".into(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-call".into(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-target-load".into(),
                },
            },
            SemanticReference {
                id: "ref-cross-save".into(),
                kind: SemanticReferenceKind::Call,
                path: "src/main.ts".into(),
                scope_id: "file-main".into(),
                source_entity_id: Some("entity-1".into()),
                name: "save".into(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-call".into(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-target-save".into(),
                },
            },
            SemanticReference {
                id: "ref-source-cohesion".into(),
                kind: SemanticReferenceKind::Call,
                path: "src/main.ts".into(),
                scope_id: "file-main".into(),
                source_entity_id: Some("entity-1".into()),
                name: "helper".into(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-1".into(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-source-helper".into(),
                },
            },
            SemanticReference {
                id: "ref-target-cohesion".into(),
                kind: SemanticReferenceKind::Call,
                path: "src/dependency.ts".into(),
                scope_id: "file-dependency".into(),
                source_entity_id: Some("entity-target-load".into()),
                name: "save".into(),
                qualifier: None,
                binding_name: None,
                evidence_id: "ev-2".into(),
                resolution: SemanticResolution::Resolved {
                    target_entity_id: "entity-target-save".into(),
                },
            },
        ];
        ir.semantic_coverage = SemanticCoverage::from_references(&ir.semantic_references);
        ir.relationships = vec![
            Relationship {
                id: "edge-cross".into(),
                source: "entity-1".into(),
                target: "entity-target-load".into(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-cross".into(),
                },
                evidence_ids: vec!["ev-call".into()],
            },
            Relationship {
                id: "edge-source-cohesion".into(),
                source: "entity-1".into(),
                target: "entity-source-helper".into(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-source-cohesion".into(),
                },
                evidence_ids: vec!["ev-1".into()],
            },
            Relationship {
                id: "edge-cross-save".into(),
                source: "entity-1".into(),
                target: "entity-target-save".into(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-cross-save".into(),
                },
                evidence_ids: vec!["ev-call".into()],
            },
            Relationship {
                id: "edge-target-cohesion".into(),
                source: "entity-target-load".into(),
                target: "entity-target-save".into(),
                kind: RelationshipKind::Calls,
                origin: RelationshipOrigin::SemanticReference {
                    reference_id: "ref-target-cohesion".into(),
                },
                evidence_ids: vec!["ev-2".into()],
            },
        ];
        ir.architecture_concepts = vec![
            ArchitectureConcept {
                id: "architecture:concept:source".into(),
                title: "Request orchestration".into(),
                responsibility: "Coordinates repository requests.".into(),
                member_entity_ids: vec!["entity-1".into(), "entity-source-helper".into()],
                supporting_relationship_ids: vec!["edge-source-cohesion".into()],
                evidence_ids: vec!["ev-1".into()],
                status: ArchitectureStatus::Draft,
                provenance: ClaimProvenance::Agent {
                    provider: "codex".into(),
                    model: Some("gpt".into()),
                },
            },
            ArchitectureConcept {
                id: "architecture:concept:target".into(),
                title: "Data access".into(),
                responsibility: "Loads and saves repository data.".into(),
                member_entity_ids: vec!["entity-target-load".into(), "entity-target-save".into()],
                supporting_relationship_ids: vec!["edge-target-cohesion".into()],
                evidence_ids: vec!["ev-2".into()],
                status: ArchitectureStatus::Draft,
                provenance: ClaimProvenance::Agent {
                    provider: "codex".into(),
                    model: Some("gpt".into()),
                },
            },
        ];
        ir.architecture_relationships = vec![ArchitectureRelationship {
            id: "architecture:relationship:depends".into(),
            source_concept_id: "architecture:concept:source".into(),
            target_concept_id: "architecture:concept:target".into(),
            kind: ArchitectureRelationshipKind::DependsOn,
            supporting_relationship_ids: vec!["edge-cross".into()],
            evidence_ids: vec!["ev-call".into()],
            status: ArchitectureStatus::Draft,
            provenance: ClaimProvenance::Agent {
                provider: "codex".into(),
                model: Some("gpt".into()),
            },
        }];
        ir.coverage = CoverageReport::from_items(vec![
            ir.coverage.items[0].clone(),
            CoverageItem {
                id: "coverage-2".into(),
                kind: CoverageKind::File,
                subject: "src/dependency.ts".into(),
                evidence_ids: vec!["ev-2".into()],
                disposition: CoverageDisposition::Included {
                    concept_id: "source/dependency".into(),
                },
            },
        ]);
        ir.architecture_scope = Some(CoreArchitectureScope {
            evidence_total: ir.evidence.len(),
            evidence_supplied: ir.evidence.len(),
            coverage_items_total: ir.coverage.items.len(),
            coverage_items_supplied: ir.coverage.items.len(),
            entities_total: ir.entities.len(),
            entities_supplied: ir.entities.len(),
            semantic_references_total: ir.semantic_references.len(),
            semantic_references_supplied: ir.semantic_references.len(),
            semantic_relationships_total: ir.relationships.len(),
            semantic_relationships_supplied: ir.relationships.len(),
            complete: true,
        });
        ir.validate().unwrap();

        let snapshot = RepositorySnapshot::from(&ir);
        assert_eq!(snapshot.documents.len(), 4);
        assert!(
            snapshot
                .documents
                .iter()
                .all(|document| !document.id.contains("entity-"))
        );
        let source_file = snapshot
            .documents
            .iter()
            .find(|document| document.id == "source/main")
            .unwrap();
        let call = source_file
            .relationships
            .iter()
            .find(|relationship| relationship.kind.as_deref() == Some("calls"))
            .unwrap();
        assert_eq!(
            call.source_relationship_ids,
            ["edge-cross", "edge-cross-save"]
        );
        assert_eq!(call.origin_reference_ids, ["ref-cross", "ref-cross-save"]);
        assert_eq!(call.evidence_ids, ["ev-call"]);

        let source_id = architecture_concept_id("architecture:concept:source");
        let target_id = architecture_concept_id("architecture:concept:target");
        let source_architecture = snapshot
            .documents
            .iter()
            .find(|document| document.id == source_id)
            .unwrap();
        assert_eq!(
            source_architecture.metadata.status,
            Some(crate::model::OkfStatus::Draft)
        );
        assert!(source_architecture.metadata.verified.is_empty());
        let architecture = source_architecture
            .metadata
            .repo2okf
            .as_ref()
            .and_then(|metadata| metadata.architecture.as_ref())
            .unwrap();
        assert_eq!(
            architecture.member_entity_ids,
            ["entity-1", "entity-source-helper"]
        );
        assert!(
            architecture
                .scope
                .as_ref()
                .is_some_and(|scope| scope.complete)
        );
        assert!(
            snapshot
                .documents
                .iter()
                .filter_map(|document| {
                    document
                        .metadata
                        .repo2okf
                        .as_ref()
                        .and_then(|metadata| metadata.architecture.as_ref())
                })
                .all(|projected| projected.scope == architecture.scope)
        );
        let depends_on = source_architecture
            .relationships
            .iter()
            .find(|relationship| relationship.target == target_id)
            .unwrap();
        assert_eq!(depends_on.kind.as_deref(), Some("depends_on"));
        assert_eq!(depends_on.source_relationship_ids, ["edge-cross"]);
        assert_eq!(depends_on.origin_reference_ids, ["ref-cross"]);
        assert_eq!(depends_on.evidence_ids, ["ev-call"]);
        let inventory = snapshot.semantic_inventory.as_ref().unwrap();
        assert!(inventory.projection_contract_complete);
        assert_eq!(inventory.architecture_scope, architecture.scope);
        assert!(inventory.projected_relationships.iter().any(|projected| {
            projected.source_concept_id == source_id
                && projected.target_concept_id == target_id
                && projected.kind == "depends_on"
        }));
    }
}
