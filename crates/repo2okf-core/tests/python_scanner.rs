//! End-to-end tests for deterministic Python syntax extraction.

use std::fs;

use repo2okf_core::{
    ClaimProvenance, EntityKind, EvidenceRef, Language, ScanOptions, ScanStatus, scan_repository,
};

#[test]
fn python_is_a_default_case_insensitive_language_and_can_be_disabled() {
    assert_eq!(Language::from_path("src/MODULE.PY"), Some(Language::Python));
    assert_eq!(Language::Python.as_str(), "python");
    assert!(ScanOptions::default().languages.contains(&Language::Python));

    let repository = tempfile::tempdir().expect("repository");
    fs::write(
        repository.path().join("disabled.py"),
        "def hidden():\n    pass\n",
    )
    .expect("Python fixture");
    let mut options = ScanOptions::default();
    options.languages.remove(&Language::Python);
    let ir = scan_repository(repository.path(), &options).expect("scan");
    let file = ir.files.first().expect("inventoried Python file");
    assert_eq!(file.language, Some(Language::Python));
    assert_eq!(file.status, ScanStatus::Unsupported);
    assert!(ir.entities.is_empty());
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture verifies the correlated Python entities, imports, spans, and claims"
)]
fn extracts_python_entities_imports_decorators_and_docstrings_deterministically() {
    let repository = tempfile::tempdir().expect("repository");
    let source = concat!(
        "r\"\"\"Module docs.\"\"\"\n",
        "from __future__ import annotations\n",
        "import os, pkg.mod as pm\n",
        "from package.api import (Client as ApiClient, helper)\n",
        "from .helpers import greet as hello\n",
        "from ..shared import VALUE\n",
        "from . import util, helper as h\n",
        "\n",
        "@module_decorator\n",
        "async def top(value):\n",
        "    \"\"\"Top docs.\"\"\"\n",
        "    def nested():\n",
        "        r\"\"\"Nested docs.\"\"\"\n",
        "        import local.dynamic as dynamic\n",
        "        return value\n",
        "    return nested()\n",
        "\n",
        "@class_decorator\n",
        "class Greeter:\n",
        "    \"\"\"Class docs.\"\"\"\n",
        "    @method_decorator\n",
        "    def welcome(self):\n",
        "        \"\"\"Welcome docs.\"\"\"\n",
        "        return \"hello\"\n",
    );
    fs::write(repository.path().join("fixture.py"), source).expect("Python fixture");

    let first = scan_repository(repository.path(), &ScanOptions::default()).expect("first scan");
    let second = scan_repository(repository.path(), &ScanOptions::default()).expect("second scan");
    assert_eq!(first, second);
    first.validate().expect("Python IR");

    let file = first.files.first().expect("Python file");
    assert_eq!(file.path, "fixture.py");
    assert_eq!(file.language, Some(Language::Python));
    assert_eq!(file.status, ScanStatus::Parsed);
    assert_eq!(
        file.content_hash,
        blake3::hash(source.as_bytes()).to_hex().to_string()
    );

    let expected_entities = [
        ("top", EntityKind::Function),
        ("nested", EntityKind::Function),
        ("Greeter", EntityKind::Class),
        ("welcome", EntityKind::Method),
    ];
    for (name, kind) in expected_entities {
        let matches = first
            .entities
            .iter()
            .filter(|entity| entity.name == name && entity.kind == kind)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "unexpected entity count for {name}");
    }

    let top_evidence = entity_evidence(&first, "top");
    assert_eq!(top_evidence.start_line, 9);
    assert!(evidence_source(source, top_evidence).starts_with("@module_decorator\nasync def top"));
    let class_evidence = entity_evidence(&first, "Greeter");
    assert_eq!(class_evidence.start_line, 18);
    assert!(evidence_source(source, class_evidence).starts_with("@class_decorator\nclass Greeter"));
    let method_evidence = entity_evidence(&first, "welcome");
    assert_eq!(method_evidence.start_line, 21);
    assert!(
        evidence_source(source, method_evidence).starts_with("@method_decorator\n    def welcome")
    );
    assert_eq!(entity_evidence(&first, "nested").start_line, 12);

    let expected_imports = [
        ".",
        "..shared",
        ".helpers",
        "__future__",
        "local.dynamic",
        "os",
        "package.api",
        "pkg.mod",
    ];
    assert_eq!(
        first
            .imports
            .iter()
            .map(|import| import.specifier.as_str())
            .collect::<Vec<_>>(),
        expected_imports
    );
    let os = first
        .imports
        .iter()
        .find(|import| import.specifier == "os")
        .expect("os import");
    let pkg = first
        .imports
        .iter()
        .find(|import| import.specifier == "pkg.mod")
        .expect("package import");
    assert_eq!(os.evidence_id, pkg.evidence_id);
    assert_eq!(
        evidence_source(source, evidence(&first, &os.evidence_id)),
        "import os, pkg.mod as pm"
    );
    let relative = first
        .imports
        .iter()
        .find(|import| import.specifier == ".")
        .expect("relative import");
    assert_eq!(
        evidence_source(source, evidence(&first, &relative.evidence_id)),
        "from . import util, helper as h"
    );

    let expected_docstrings = [
        ("module docstring", "r\"\"\"Module docs.\"\"\""),
        ("top docstring", "\"\"\"Top docs.\"\"\""),
        ("nested docstring", "r\"\"\"Nested docs.\"\"\""),
        ("Greeter docstring", "\"\"\"Class docs.\"\"\""),
        ("welcome docstring", "\"\"\"Welcome docs.\"\"\""),
    ];
    for (symbol, literal) in expected_docstrings {
        let record = first
            .evidence
            .iter()
            .find(|record| record.symbol.as_deref() == Some(symbol))
            .unwrap_or_else(|| panic!("missing {symbol}"));
        assert_eq!(evidence_source(source, record), literal);
        assert_eq!(record.content_hash, file.content_hash);
    }

    let welcome_claim = first
        .claims
        .iter()
        .find(|claim| claim.text.contains("`welcome` with a Python docstring"))
        .expect("welcome docstring claim");
    assert_eq!(
        welcome_claim.text,
        "fixture.py declares method `welcome` with a Python docstring."
    );
    assert_eq!(welcome_claim.evidence_ids.len(), 2);
    assert!(matches!(
        welcome_claim.provenance,
        ClaimProvenance::Deterministic { .. }
    ));
    assert_eq!(welcome_claim.confidence, Some(100));
    assert!(!welcome_claim.text.contains("Welcome docs."));
    assert!(
        first
            .claims
            .iter()
            .any(|claim| claim.text == "fixture.py has a Python module docstring.")
    );
}

#[test]
fn only_constant_text_first_statements_become_python_docstrings() {
    let repository = tempfile::tempdir().expect("repository");
    let source = concat!(
        "def bytes_first():\n",
        "    b\"not a docstring\"\n",
        "    return None\n",
        "\n",
        "def fstring_first(value):\n",
        "    f\"not a docstring: {value}\"\n",
        "    return None\n",
        "\n",
        "def after_statement():\n",
        "    value = 1\n",
        "    \"too late\"\n",
        "\n",
        "def concatenated():\n",
        "    r\"valid \" \"docstring\"\n",
        "    return None\n",
    );
    fs::write(repository.path().join("docstrings.py"), source).expect("Python fixture");

    let ir = scan_repository(repository.path(), &ScanOptions::default()).expect("scan");
    for name in ["bytes_first", "fstring_first", "after_statement"] {
        let symbol = format!("{name} docstring");
        assert!(
            ir.evidence
                .iter()
                .all(|evidence| evidence.symbol.as_deref() != Some(symbol.as_str())),
            "{name} must not have docstring evidence"
        );
    }
    let concatenated = ir
        .evidence
        .iter()
        .find(|evidence| evidence.symbol.as_deref() == Some("concatenated docstring"))
        .expect("concatenated docstring evidence");
    assert_eq!(
        evidence_source(source, concatenated),
        "r\"valid \" \"docstring\""
    );
    ir.validate().expect("valid IR");
}

#[test]
fn leading_comments_do_not_hide_python_docstrings() {
    let repository = tempfile::tempdir().expect("repository");
    let source = concat!(
        "#!/usr/bin/env python3\n",
        "# module comment\n",
        "\"\"\"Module after comments.\"\"\"\n",
        "\n",
        "class Commented:\n",
        "    # class comment\n",
        "    \"\"\"Class after comment.\"\"\"\n",
        "\n",
        "    def method(self):\n",
        "        # method comment\n",
        "        \"\"\"Method after comment.\"\"\"\n",
        "        return None\n",
    );
    fs::write(repository.path().join("comments.py"), source).expect("Python fixture");

    let ir = scan_repository(repository.path(), &ScanOptions::default()).expect("scan");
    for (symbol, literal) in [
        ("module docstring", "\"\"\"Module after comments.\"\"\""),
        ("Commented docstring", "\"\"\"Class after comment.\"\"\""),
        ("method docstring", "\"\"\"Method after comment.\"\"\""),
    ] {
        let record = ir
            .evidence
            .iter()
            .find(|evidence| evidence.symbol.as_deref() == Some(symbol))
            .unwrap_or_else(|| panic!("missing {symbol}"));
        assert_eq!(evidence_source(source, record), literal);
    }
    ir.validate().expect("valid IR");
}

#[test]
fn future_directives_never_resolve_to_a_shadowing_local_module() {
    let repository = tempfile::tempdir().expect("repository");
    fs::write(repository.path().join("__future__.py"), "SHADOW = True\n")
        .expect("shadow module fixture");
    fs::write(
        repository.path().join("main.py"),
        "from __future__ import annotations\n",
    )
    .expect("future import fixture");

    let ir = scan_repository(repository.path(), &ScanOptions::default()).expect("scan");
    let shadow = ir
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::File && entity.path == "__future__.py")
        .expect("shadow file entity");
    let import = ir
        .imports
        .iter()
        .find(|import| import.specifier == "__future__")
        .expect("future directive record");
    let relationship = ir
        .relationships
        .iter()
        .find(|relationship| {
            relationship.kind == repo2okf_core::RelationshipKind::Imports
                && relationship.evidence_ids.contains(&import.evidence_id)
        })
        .expect("future directive relationship");
    assert_ne!(relationship.target, shadow.id);
    assert!(relationship.target.starts_with("module:"));
    ir.validate().expect("valid IR");
}

#[test]
fn dots_only_from_import_resolves_to_the_package_not_a_guessed_submodule() {
    let repository = tempfile::tempdir().expect("repository");
    fs::create_dir(repository.path().join("pkg")).expect("package directory");
    fs::write(repository.path().join("pkg/__init__.py"), "util = 1\n")
        .expect("package attribute fixture");
    fs::write(repository.path().join("pkg/util.py"), "VALUE = 2\n")
        .expect("same-named submodule fixture");
    fs::write(
        repository.path().join("pkg/consumer.py"),
        "from . import util\n",
    )
    .expect("dots-only import fixture");

    let ir = scan_repository(repository.path(), &ScanOptions::default()).expect("scan");
    let package = ir
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::File && entity.path == "pkg/__init__.py")
        .expect("package initializer entity");
    let submodule = ir
        .entities
        .iter()
        .find(|entity| entity.kind == EntityKind::File && entity.path == "pkg/util.py")
        .expect("submodule entity");
    let import = ir
        .imports
        .iter()
        .find(|import| import.path == "pkg/consumer.py")
        .expect("dots-only import record");
    assert_eq!(import.specifier, ".");
    let relationship = ir
        .relationships
        .iter()
        .find(|relationship| {
            relationship.kind == repo2okf_core::RelationshipKind::Imports
                && relationship.evidence_ids.contains(&import.evidence_id)
        })
        .expect("package import relationship");
    assert_eq!(relationship.target, package.id);
    assert_ne!(relationship.target, submodule.id);
    ir.validate().expect("valid IR");
}

fn entity_evidence<'a>(ir: &'a repo2okf_core::RepositoryIr, name: &str) -> &'a EvidenceRef {
    let entity = ir
        .entities
        .iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("missing entity {name}"));
    evidence(ir, &entity.evidence_id)
}

fn evidence<'a>(ir: &'a repo2okf_core::RepositoryIr, id: &str) -> &'a EvidenceRef {
    ir.evidence
        .iter()
        .find(|evidence| evidence.id == id)
        .unwrap_or_else(|| panic!("missing evidence {id}"))
}

fn evidence_source<'a>(source: &'a str, evidence: &EvidenceRef) -> &'a str {
    let start = usize::try_from(evidence.start_byte).expect("fixture start offset");
    let end = usize::try_from(evidence.end_byte).expect("fixture end offset");
    &source[start..end]
}
