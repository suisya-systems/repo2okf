//! End-to-end emitter and verifier contract tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use repo2okf_format::{
    CoverageClassification, CoverageItem, EmitError, EvidenceRecord, Generated, OkfClaim,
    OkfDocument, OkfRelationship, RepositorySnapshot, Severity, Verification, VerifyOptions,
    concept_path, emit_okf, verify_okf,
};
use tempfile::TempDir;

fn evidence(id: &str, path: &str, hash: &str) -> EvidenceRecord {
    EvidenceRecord {
        id: id.to_owned(),
        path: path.to_owned(),
        line: Some(7),
        content_hash: hash.to_owned(),
    }
}

fn document(id: &str, evidence_id: &str) -> OkfDocument {
    let mut document = OkfDocument::new(id, "Module");
    document.metadata.title = Some("Authentication".to_owned());
    document.metadata.description = Some("Authenticates incoming requests.".to_owned());
    document.metadata.tags = vec!["security".to_owned(), "authentication".to_owned()];
    document
        .body
        .push_str("# Authentication\n\nThe module validates incoming credentials.");
    document.claims.push(OkfClaim {
        id: "validates-credentials".to_owned(),
        text: "The module validates incoming credentials.".to_owned(),
        evidence_ids: vec![evidence_id.to_owned()],
        ai_generated: false,
        agent_provider: None,
        agent_reported_model: None,
    });
    document
}

fn snapshot() -> RepositorySnapshot {
    RepositorySnapshot {
        repository: "demo".to_owned(),
        documents: vec![document("modules/auth", "ev-auth")],
        evidence: vec![evidence("ev-auth", "src/auth.rs", "blake3:auth")],
        coverage: vec![CoverageItem {
            id: "file:src/auth.rs".to_owned(),
            classification: CoverageClassification::Included {
                concept_id: "modules/auth".to_owned(),
            },
        }],
    }
}

#[test]
fn emits_a_valid_evidence_bound_bundle() {
    let temp = TempDir::new().unwrap();
    let snapshot = snapshot();

    let emitted = emit_okf(&snapshot, temp.path()).unwrap();
    assert_eq!(emitted.included, 1);
    assert_eq!(
        emitted.files_written,
        vec![PathBuf::from("index.md"), PathBuf::from("modules/auth.md")]
    );

    let report = verify_okf(
        temp.path(),
        &snapshot.evidence,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!(report.valid, "{:#?}", report.issues);
    assert!((report.coverage - 1.0).abs() < f64::EPSILON);
    assert_eq!(report.concepts, 1);

    let concept = fs::read_to_string(temp.path().join("modules/auth.md")).unwrap();
    assert!(concept.contains("evidence_id: ev-auth"));
    assert!(concept.contains("content_hash: blake3:auth"));
    assert!(concept.contains("[^evidence-65762d61757468]"));
    assert!(!concept.contains("verified:"));
}

#[test]
fn emission_is_deterministic_across_input_order() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    let mut left = snapshot();
    let mut data = document("modules/data", "ev-data");
    data.metadata.title = Some("Data".to_owned());
    data.claims[0].id = "validates-data".to_owned();
    left.documents.push(data.clone());
    left.documents[0].relationships.push(OkfRelationship {
        target: "modules/data".to_owned(),
        label: Some("data module".to_owned()),
        kind: Some("depends-on".to_owned()),
    });
    left.evidence
        .push(evidence("ev-data", "src/data.rs", "blake3:data"));
    left.coverage.push(CoverageItem {
        id: "file:src/data.rs".to_owned(),
        classification: CoverageClassification::Included {
            concept_id: "modules/data".to_owned(),
        },
    });

    let mut right = left.clone();
    right.documents.reverse();
    right.evidence.reverse();
    right.coverage.reverse();
    right.documents.iter_mut().for_each(|document| {
        document.metadata.tags.reverse();
        document.claims.reverse();
    });

    emit_okf(&left, first.path()).unwrap();
    emit_okf(&right, second.path()).unwrap();
    assert_eq!(read_tree(first.path()), read_tree(second.path()));
}

#[test]
fn rejects_portable_duplicate_concept_ids() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.documents.push(document("Modules/Auth", "ev-auth"));

    let error = emit_okf(&snapshot, temp.path()).unwrap_err();
    assert!(matches!(error, EmitError::DuplicateConceptId(_)));
}

#[test]
fn rejects_unknown_or_missing_claim_evidence() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.documents[0].claims[0].evidence_ids = vec!["missing".to_owned()];
    let error = emit_okf(&snapshot, temp.path()).unwrap_err();
    assert!(matches!(error, EmitError::UnknownEvidence { .. }));

    snapshot.documents[0].claims[0].evidence_ids.clear();
    let error = emit_okf(&snapshot, temp.path()).unwrap_err();
    assert!(matches!(error, EmitError::ClaimWithoutEvidence { .. }));
}

#[test]
fn evidence_binding_does_not_make_an_ai_claim_verified() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.documents[0].claims[0].ai_generated = true;

    emit_okf(&snapshot, temp.path()).unwrap();
    let concept = fs::read_to_string(temp.path().join("modules/auth.md")).unwrap();
    assert!(!concept.contains("verified:"));

    snapshot.documents[0].metadata.verified.push(Verification {
        by: "repo2okf-agent/codex".to_owned(),
        at: "2026-08-13T00:00:00Z".parse::<DateTime<Utc>>().unwrap(),
    });
    let error = emit_okf(&snapshot, temp.path()).unwrap_err();
    assert!(matches!(error, EmitError::AiOnlyVerification(_)));

    snapshot.documents[0].metadata.verified.push(Verification {
        by: "process:repo2okf-evidence-check".to_owned(),
        at: "2026-08-13T00:01:00Z".parse::<DateTime<Utc>>().unwrap(),
    });
    emit_okf(&snapshot, temp.path()).unwrap();
}

#[test]
fn detects_stale_evidence_hashes() {
    let temp = TempDir::new().unwrap();
    let snapshot = snapshot();
    emit_okf(&snapshot, temp.path()).unwrap();

    let current = vec![evidence("ev-auth", "src/auth.rs", "blake3:changed")];
    let report = verify_okf(
        temp.path(),
        &current,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!(!report.valid);
    assert!(report.has_code("stale-evidence-hash"));
}

#[test]
fn detects_path_traversal_and_broken_links() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "concepts/auth.md",
        "---\ntype: Module\n---\n\n[escape](../../secret.md)\n[missing](missing.md)\n",
    );

    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(!report.valid);
    assert!(report.has_code("path-traversal"));
    assert!(report.has_code("broken-link"));
}

#[test]
fn broken_links_are_only_warnings_in_spec_compatible_mode() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\n---\n\n[future](future.md)\n",
    );
    let options = VerifyOptions {
        broken_links_are_errors: false,
        ..VerifyOptions::default()
    };

    let report = verify_okf(temp.path(), &[], &[], &options);
    assert!(report.valid, "{:#?}", report.issues);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.code == "broken-link" && issue.severity == Severity::Warning)
    );
}

#[test]
fn enforces_classified_coverage_threshold_and_exclusion_reasons() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.coverage.push(CoverageItem {
        id: "file:src/unmapped.rs".to_owned(),
        classification: CoverageClassification::Unresolved,
    });
    emit_okf(&snapshot, temp.path()).unwrap();

    let report = verify_okf(
        temp.path(),
        &snapshot.evidence,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!((report.coverage - 0.5).abs() < f64::EPSILON);
    assert!(report.has_code("coverage-below-threshold"));

    snapshot.coverage[1].classification = CoverageClassification::Excluded {
        reason: String::new(),
    };
    let error = emit_okf(&snapshot, temp.path()).unwrap_err();
    assert!(matches!(error, EmitError::EmptyExclusionReason(_)));
}

#[test]
fn accepts_the_v02_bare_verified_mapping() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\nverified: { by: 'human:reviewer', at: 2026-08-13T00:00:00Z }\n---\n\n# Auth\n",
    );

    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(report.valid, "{:#?}", report.issues);
}

#[test]
fn reports_stale_after_without_conflating_it_with_hash_staleness() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\nstale_after: 2026-08-12\n---\n\n# Auth\n",
    );
    let options = VerifyOptions {
        today: NaiveDate::from_ymd_opt(2026, 8, 13).unwrap(),
        ..VerifyOptions::default()
    };

    let report = verify_okf(temp.path(), &[], &[], &options);
    assert!(report.valid);
    assert!(report.has_code("stale-document"));
    assert!(!report.has_code("stale-evidence-hash"));
}

#[test]
fn concept_ids_cannot_escape_or_use_reserved_names() {
    assert_eq!(
        concept_path("modules/auth").unwrap(),
        PathBuf::from("modules/auth.md")
    );
    assert!(concept_path("../auth").is_err());
    assert!(concept_path("/auth").is_err());
    assert!(concept_path("modules/index").is_err());
    assert!(concept_path("modules/log.md").is_err());
    assert!(concept_path("C:/auth").is_err());
    assert!(concept_path("modules/NUL").is_err());
    assert!(concept_path("modules/auth. ").is_err());
}

#[test]
fn coverage_ratio_matches_core_and_ignores_exclusions() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.coverage.push(CoverageItem {
        id: "excluded".to_owned(),
        classification: CoverageClassification::Excluded {
            reason: "generated fixture".to_owned(),
        },
    });
    emit_okf(&snapshot, temp.path()).unwrap();
    let report = verify_okf(
        temp.path(),
        &snapshot.evidence,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!((report.coverage - 1.0).abs() < f64::EPSILON);
    assert!(report.valid, "{:#?}", report.issues);
}

#[test]
fn rejects_duplicate_coverage_and_markdown_injection() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.coverage.push(snapshot.coverage[0].clone());
    assert!(matches!(
        emit_okf(&snapshot, temp.path()).unwrap_err(),
        EmitError::DuplicateCoverageId(_)
    ));

    snapshot.coverage.pop();
    snapshot.documents[0].claims[0].text = "claim\n[^forged]: injected".to_owned();
    assert!(matches!(
        emit_okf(&snapshot, temp.path()).unwrap_err(),
        EmitError::InvalidClaim { .. }
    ));
}

#[test]
fn escapes_raw_html_and_active_markdown_from_generated_text() {
    let temp = TempDir::new().unwrap();
    let mut snapshot = snapshot();
    snapshot.documents[0].claims[0].text =
        "<script>alert(1)</script> [click](javascript:alert(1)) ![image](x)".to_owned();
    snapshot.documents[0].metadata.title = Some("<img src=x onerror=alert(1)>".to_owned());
    emit_okf(&snapshot, temp.path()).unwrap();
    let concept = fs::read_to_string(temp.path().join("modules/auth.md")).unwrap();
    let index = fs::read_to_string(temp.path().join("index.md")).unwrap();
    let body = concept.splitn(3, "---").nth(2).unwrap();
    assert!(!body.contains("<script>"));
    assert!(!body.contains("[click](javascript:"));
    assert!(!body.contains("![image](x)"));
    assert!(!index.contains("<img"));
}

#[test]
fn validates_evidence_records_and_displayed_resource() {
    let temp = TempDir::new().unwrap();
    let snapshot = snapshot();
    emit_okf(&snapshot, temp.path()).unwrap();
    let concept_path = temp.path().join("modules/auth.md");
    let concept = fs::read_to_string(&concept_path)
        .unwrap()
        .replace("repo:src/auth.rs#L7", "repo:src/other.rs#L9");
    fs::write(concept_path, concept).unwrap();
    let report = verify_okf(
        temp.path(),
        &snapshot.evidence,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!(report.has_code("evidence-resource-mismatch"));
    assert!(report.has_code("evidence-line-mismatch"));

    let malformed = vec![EvidenceRecord {
        id: "ev-auth".to_owned(),
        path: String::new(),
        line: Some(0),
        content_hash: String::new(),
    }];
    let report = verify_okf(
        temp.path(),
        &malformed,
        &snapshot.coverage,
        &VerifyOptions::default(),
    );
    assert!(report.has_code("unsafe-evidence-path"));
    assert!(report.has_code("invalid-evidence-line"));
    assert!(report.has_code("empty-evidence-hash"));
}

#[test]
fn rejects_encoded_repository_traversal() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\nresource: repo:%2e%2e/secret\n---\n",
    );
    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(report.has_code("path-traversal"));
}

#[test]
fn rejects_traversal_in_attested_computation_paths() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "metrics/revenue.md",
        "---\ntype: Attested Computation\ncomputation: ../../outside.sql\nexecutor: { resource: '../../run.md' }\nattester: { resource: '../../attest.py' }\n---\n",
    );
    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(!report.valid);
    assert!(
        report
            .issues
            .iter()
            .filter(|issue| issue.code == "path-traversal")
            .count()
            >= 3
    );
}

#[test]
fn agent_document_cannot_self_verify_without_structured_claims() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\ngenerated: { by: 'repo2okf-agent/codex' }\nverified: { by: 'repo2okf-agent/codex', at: 2026-08-13T00:00:00Z }\n---\n",
    );
    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(report.has_code("ai-only-verification"));

    let mut snapshot = snapshot();
    snapshot.documents[0].claims.clear();
    snapshot.documents[0].metadata.generated = Some(Generated {
        by: "repo2okf-agent/claude".to_owned(),
        at: None,
    });
    snapshot.documents[0].metadata.verified.push(Verification {
        by: "process:".to_owned(),
        at: "2026-08-13T00:00:00Z".parse().unwrap(),
    });
    assert!(matches!(
        emit_okf(&snapshot, temp.path()).unwrap_err(),
        EmitError::InvalidMetadata { .. }
    ));
}

#[test]
fn actor_convention_requires_a_nonempty_identity() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\ngenerated: { by: 'not-an-actor' }\nsources:\n  - resource: repo:src/auth.rs\n    author: 'human:'\n---\n",
    );
    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(report.has_code("empty-generated-actor"));
    assert!(report.has_code("invalid-source-author"));
}

#[test]
fn checks_assets_and_ignores_links_inside_code_fences() {
    let temp = TempDir::new().unwrap();
    write_bundle(
        temp.path(),
        "auth.md",
        "---\ntype: Module\n---\n\n![diagram](assets/diagram.png)\n\n```md\n[not a link](missing.md)\n```\n",
    );
    fs::create_dir_all(temp.path().join("assets")).unwrap();
    fs::write(temp.path().join("assets/diagram.png"), b"png").unwrap();
    let report = verify_okf(temp.path(), &[], &[], &VerifyOptions::default());
    assert!(report.valid, "{:#?}", report.issues);
}

#[test]
fn emitted_bundle_matches_golden_files() {
    let temp = TempDir::new().unwrap();
    emit_okf(&snapshot(), temp.path()).unwrap();
    assert_eq!(
        fs::read_to_string(temp.path().join("index.md")).unwrap(),
        include_str!("golden/index.md")
    );
    assert_eq!(
        fs::read_to_string(temp.path().join("modules/auth.md")).unwrap(),
        include_str!("golden/modules_auth.md")
    );
}

fn write_bundle(root: &Path, concept: &str, contents: &str) {
    fs::write(
        root.join("index.md"),
        "---\nokf_version: '0.2'\n---\n\n# Test\n",
    )
    .unwrap();
    let path = root.join(concept);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

fn read_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, directory: &Path, output: &mut BTreeMap<String, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if entry.file_type().unwrap().is_dir() {
                walk(root, &entry.path(), output);
            } else {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                output.insert(relative, fs::read(entry.path()).unwrap());
            }
        }
    }

    let mut output = BTreeMap::new();
    walk(root, root, &mut output);
    output
}
