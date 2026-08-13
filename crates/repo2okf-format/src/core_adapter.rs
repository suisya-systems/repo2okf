//! Deterministic conversion from the scanner IR into format-owned documents.

use std::collections::{BTreeMap, BTreeSet};

use repo2okf_core::{
    ClaimProvenance, CoverageDisposition, CoverageKind, EvidenceRef, Relationship,
    RelationshipKind, RepositoryIr,
};

use crate::model::{
    CoverageClassification, CoverageItem, EvidenceRecord, Generated, OkfClaim, OkfDocument,
    OkfRelationship, OkfSource, RepositorySnapshot,
};

impl From<&RepositoryIr> for RepositorySnapshot {
    #[allow(clippy::too_many_lines)]
    fn from(ir: &RepositoryIr) -> Self {
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
                .or_insert_with(|| document_for_coverage(ir, item, concept_id));
            merge_coverage_metadata(document, ir, item);
            for evidence_id in &item.evidence_ids {
                if let Some(record) = evidence_by_id.get(evidence_id.as_str()) {
                    add_source(document, record);
                }
            }
        }

        let mut entity_concepts = BTreeMap::new();
        for entity in &ir.entities {
            if let Some(concept_id) = first_concept(&evidence_concepts, &entity.evidence_id) {
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
            let document = documents
                .entry(concept_id.clone())
                .or_insert_with(|| external_document(ir, &concept_id, &import.specifier));
            if let Some(record) = evidence_by_id.get(import.evidence_id.as_str()) {
                add_source(document, record);
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
                document.metadata.title = Some(format!("Claim {}", claim.id));
                document.metadata.description =
                    Some("Evidence-bound repository knowledge claim.".to_owned());
                document.metadata.generated = Some(generator(ir));
                document
            });
            for evidence_id in &claim.evidence_ids {
                if let Some(record) = evidence_by_id.get(evidence_id.as_str()) {
                    add_source(document, record);
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
                text: claim.text.clone(),
                evidence_ids: claim.evidence_ids.clone(),
                ai_generated: agent_provider.is_some(),
                agent_provider,
                agent_reported_model,
            });
        }

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
            if source == target {
                continue;
            }
            if let Some(document) = documents.get_mut(&source) {
                document.relationships.push(OkfRelationship {
                    target,
                    label: relationship_label(ir, relationship.target.as_str()),
                    kind: Some(
                        match relationship.kind {
                            RelationshipKind::Contains => "contains",
                            RelationshipKind::Imports => "imports",
                        }
                        .to_owned(),
                    ),
                });
            }
        }

        Self {
            repository: ir.repository.name.clone(),
            documents: documents.into_values().collect(),
            evidence,
            coverage,
        }
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
) -> OkfDocument {
    let mut document = OkfDocument::new(concept_id, coverage_type(item.kind));
    document.metadata.title = Some(item.subject.clone());
    document.metadata.description = Some(format!(
        "Repository knowledge extracted from {}.",
        item.subject
    ));
    document.metadata.resource = item
        .evidence_ids
        .iter()
        .find_map(|id| ir.evidence.iter().find(|record| &record.id == id))
        .map(|record| repository_resource(&record.path, None));
    document.metadata.generated = Some(generator(ir));
    document
}

fn merge_coverage_metadata(
    document: &mut OkfDocument,
    ir: &RepositoryIr,
    item: &repo2okf_core::CoverageItem,
) {
    // A file item describes the shared concept more accurately than the
    // declaration and import inventory items folded into the same file concept.
    if item.kind == CoverageKind::File {
        coverage_type(item.kind).clone_into(&mut document.metadata.concept_type);
        document.metadata.title = Some(item.subject.clone());
        document.metadata.description = Some(format!(
            "Repository knowledge extracted from {}.",
            item.subject
        ));
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

fn external_document(ir: &RepositoryIr, concept_id: &str, specifier: &str) -> OkfDocument {
    let mut document = OkfDocument::new(concept_id, "External Module");
    document.metadata.title = Some(specifier.to_owned());
    document.metadata.description = Some(format!("External module imported as {specifier}."));
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

fn add_source(document: &mut OkfDocument, record: &EvidenceRef) {
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
        title: record
            .symbol
            .as_ref()
            .map(|symbol| format!("{} in {}", symbol, record.path))
            .or_else(|| Some(record.path.clone())),
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

fn relationship_label(ir: &RepositoryIr, target: &str) -> Option<String> {
    ir.entities
        .iter()
        .find(|entity| entity.id == target)
        .map(|entity| entity.name.clone())
        .or_else(|| {
            ir.relationships
                .iter()
                .find(|relationship| relationship.target == target)
                .and_then(|relationship| {
                    import_for_external_relationship(ir, relationship)
                        .map(|import| import.specifier.clone())
                })
        })
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

#[cfg(test)]
mod tests {
    use repo2okf_core::{
        Claim, ClaimProvenance, CoverageDisposition, CoverageItem, CoverageKind, CoverageReport,
        Entity, EntityKind, EvidenceRef, FileRecord, ImportRecord, Language, Relationship,
        RelationshipKind, RepositoryIr, RepositoryMetadata, ScanStatus,
    };

    use super::{RepositorySnapshot, external_concept_id, scanner_external_module_id};

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
            schema_version: 1,
            repository: RepositoryMetadata {
                name: "example".into(),
                git_commit: None,
                git_inventory: false,
                extractor: "repo2okf-core/0.1.0".into(),
            },
            files: vec![FileRecord {
                path: "src/main.ts".into(),
                language: Some(Language::TypeScript),
                size: 20,
                content_hash: "hash".into(),
                status: ScanStatus::Parsed,
                evidence_id: Some("ev-1".into()),
            }],
            entities: vec![Entity {
                id: "entity-1".into(),
                kind: EntityKind::Function,
                name: "main".into(),
                path: "src/main.ts".into(),
                language: Some(Language::TypeScript),
                evidence_id: "ev-1".into(),
            }],
            imports: vec![],
            evidence: vec![evidence],
            relationships: vec![],
            claims: vec![Claim {
                id: "claim-1".into(),
                text: "main is declared.".into(),
                evidence_ids: vec!["ev-1".into()],
                provenance,
                confidence: Some(90),
            }],
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
            size: 20,
            content_hash: "dependency-hash".into(),
            status: ScanStatus::Parsed,
            evidence_id: Some("ev-2".into()),
        });
        ir.entities.push(Entity {
            id: "entity-2".into(),
            kind: EntityKind::File,
            name: "dependency.ts".into(),
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
}
