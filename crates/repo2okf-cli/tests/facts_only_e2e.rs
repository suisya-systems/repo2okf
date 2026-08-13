//! Cross-platform black-box tests for the credential-free CLI workflow.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

fn repo2okf(repository: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_repo2okf"))
        .arg("--repository")
        .arg(repository)
        .args(arguments)
        .output()
        .expect("repo2okf process should start")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("CLI stdout should be UTF-8")
}

fn bundle_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .expect("read bundle directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read bundle entries");
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                collect(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root)
                        .expect("bundle-relative path")
                        .to_owned(),
                    fs::read(path).expect("read bundle file"),
                );
            }
        }
    }

    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario intentionally proves the full incremental state sequence"
)]
fn facts_only_compile_verify_coverage_and_incremental_update() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    let root = fixture.path();
    fs::create_dir(root.join("src")).expect("create source directory");
    fs::write(
        root.join("README.md"),
        "# Example service\n\nA small deterministic fixture.\n",
    )
    .expect("write README fixture");
    fs::write(
        root.join("src/main.ts"),
        "export function greet(name: string): string { return `hello ${name}`; }\n",
    )
    .expect("write TypeScript fixture");

    let compile = repo2okf(root, &["compile", "--facts-only"]);
    assert_success(&compile, "facts-only compile");
    assert!(root.join(".okf/index.md").is_file());
    assert!(root.join(".repo2okf/ir.json").is_file());
    assert!(root.join(".repo2okf/state.json").is_file());

    let verify = repo2okf(root, &["verify", "--json"]);
    assert_success(&verify, "verification");
    let verification: Value =
        serde_json::from_slice(&verify.stdout).expect("verification should emit JSON");
    assert_eq!(verification["valid"], true);
    assert_eq!(verification["errors"], 0);
    assert!(verification["concepts"].as_u64().unwrap_or_default() > 0);

    fs::write(
        root.join("src/main.ts"),
        "export function replaced(): string { return 'changed after compile'; }\n",
    )
    .expect("mutate evidence after compile");
    let stale = repo2okf(root, &["verify", "--json"]);
    assert!(
        !stale.status.success(),
        "verification must fail after source evidence changes"
    );
    let stale_report: Value =
        serde_json::from_slice(&stale.stdout).expect("failed verification should emit JSON");
    assert_eq!(stale_report["valid"], false);
    fs::write(
        root.join("src/main.ts"),
        "export function greet(name: string): string { return `hello ${name}`; }\n",
    )
    .expect("restore compiled evidence");

    fs::write(root.join("src/new.ts"), "export const added = 1;\n")
        .expect("add new inventory after compile");
    let added = repo2okf(root, &["verify", "--json"]);
    assert!(
        !added.status.success(),
        "verification must fail after repository inventory grows"
    );
    let added_report: Value =
        serde_json::from_slice(&added.stdout).expect("stale inventory should emit JSON");
    assert!(added_report["issues"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "repository-ir-stale")
    }));
    fs::remove_file(root.join("src/new.ts")).expect("remove new inventory fixture");

    fs::write(root.join(".okf/stale.md"), "---\ntype: Extra\n---\n")
        .expect("add stale concept fixture");
    let stale_bundle = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&stale_bundle, "repair bundle containing a stale concept");
    assert!(
        !root.join(".okf/stale.md").exists(),
        "incremental update must remove unexpected concept files"
    );

    let concept = root.join(".okf").join(
        bundle_bytes(&root.join(".okf"))
            .keys()
            .find(|path| {
                path.extension().is_some_and(|extension| extension == "md")
                    && path.file_name().is_some_and(|name| name != "index.md")
            })
            .expect("generated concept"),
    );
    fs::OpenOptions::new()
        .append(true)
        .open(&concept)
        .expect("open concept for tampering")
        .write_all(b"\nUNSOURCED MALICIOUS ASSERTION\n")
        .expect("tamper concept fixture");
    let tampered = repo2okf(root, &["verify", "--json"]);
    assert!(
        !tampered.status.success(),
        "verification must reject a modified compiler-owned concept"
    );
    let tampered_report: Value =
        serde_json::from_slice(&tampered.stdout).expect("tampered bundle verification JSON");
    assert!(tampered_report["issues"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "generated-bundle-stale")
    }));
    let repaired = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&repaired, "repair modified compiler-owned concept");
    assert!(
        !fs::read_to_string(concept)
            .expect("repaired concept")
            .contains("MALICIOUS")
    );

    let coverage = repo2okf(root, &["coverage", "--json"]);
    assert_success(&coverage, "coverage report");
    let coverage: Value =
        serde_json::from_slice(&coverage.stdout).expect("coverage should emit JSON");
    assert!(coverage["included"].as_u64().unwrap_or_default() > 0);
    assert!(
        coverage["items"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let unchanged = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&unchanged, "unchanged incremental update");
    assert!(
        stdout(&unchanged).contains("up to date"),
        "unchanged update should take the incremental fast path"
    );

    let mut persisted_ir: Value =
        serde_json::from_slice(&fs::read(root.join(".repo2okf/ir.json")).expect("persisted IR"))
            .expect("valid persisted IR");
    persisted_ir["repository"]["name"] = Value::String("tampered-cache".into());
    fs::write(
        root.join(".repo2okf/ir.json"),
        serde_json::to_vec_pretty(&persisted_ir).expect("tampered IR JSON"),
    )
    .expect("tamper persisted IR");
    let repaired_cache = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&repaired_cache, "reject tampered persisted IR cache");
    assert!(
        !stdout(&repaired_cache).contains("up to date"),
        "tampered persisted IR must not take the fast path"
    );
    let repaired_ir: Value = serde_json::from_slice(
        &fs::read(root.join(".repo2okf/ir.json")).expect("repaired persisted IR"),
    )
    .expect("valid repaired IR");
    assert_ne!(repaired_ir["repository"]["name"], "tampered-cache");

    fs::write(
        root.join("src/main.ts"),
        concat!(
            "export function greet(name: string): string { return `hello ${name}`; }\n",
            "export function farewell(name: string): string { return `bye ${name}`; }\n",
        ),
    )
    .expect("modify TypeScript fixture");

    let changed = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&changed, "changed incremental update");
    let changed_stdout = stdout(&changed);
    assert!(changed_stdout.contains("changes:"));
    assert!(changed_stdout.contains("~1"));
    assert!(changed_stdout.contains("compiled"));

    let incremental_bundle = bundle_bytes(&root.join(".okf"));

    let verify_after_update = repo2okf(root, &["verify", "--json"]);
    assert_success(
        &verify_after_update,
        "verification after incremental update",
    );
    let verification: Value = serde_json::from_slice(&verify_after_update.stdout)
        .expect("post-update verification should emit JSON");
    assert_eq!(verification["valid"], true);
    assert_eq!(verification["errors"], 0);

    fs::remove_dir_all(root.join(".okf")).expect("remove generated bundle fixture");
    fs::remove_dir_all(root.join(".repo2okf")).expect("remove generated state fixture");
    let clean = repo2okf(root, &["compile", "--facts-only"]);
    assert_success(&clean, "clean rebuild after incremental update");
    assert_eq!(
        incremental_bundle,
        bundle_bytes(&root.join(".okf")),
        "incremental output must be byte-equivalent to a clean build"
    );
}

#[test]
fn rejects_output_override_over_source_tree() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::write(fixture.path().join("README.md"), "# Fixture\n").expect("write fixture");
    let output = repo2okf(
        fixture.path(),
        &["compile", "--facts-only", "--output", "docs"],
    );
    assert!(!output.status.success());
    assert!(!fixture.path().join("docs").exists());

    let scan = repo2okf(fixture.path(), &["scan", "--output", "README.md"]);
    assert!(!scan.status.success());
    assert_eq!(
        fs::read_to_string(fixture.path().join("README.md")).expect("source preserved"),
        "# Fixture\n"
    );
}

#[test]
fn refuses_to_replace_unowned_reserved_output() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::write(fixture.path().join("README.md"), "# Fixture\n").expect("write fixture");
    fs::create_dir(fixture.path().join(".okf")).expect("create unowned output");
    fs::write(fixture.path().join(".okf/precious.md"), "keep me").expect("write protected fixture");
    let output = repo2okf(fixture.path(), &["compile", "--facts-only"]);
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(fixture.path().join(".okf/precious.md")).expect("protected file"),
        "keep me"
    );
}

#[test]
fn refuses_to_replace_unowned_reserved_cache() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::write(fixture.path().join("README.md"), "# Fixture\n").expect("write fixture");
    fs::create_dir(fixture.path().join(".repo2okf")).expect("create unowned cache");
    fs::write(fixture.path().join(".repo2okf/precious.txt"), "keep me")
        .expect("write protected cache fixture");

    let compile = repo2okf(fixture.path(), &["compile", "--facts-only"]);
    assert!(!compile.status.success());
    assert_eq!(
        fs::read_to_string(fixture.path().join(".repo2okf/precious.txt"))
            .expect("protected cache file"),
        "keep me"
    );

    let scan = repo2okf(fixture.path(), &["scan"]);
    assert!(!scan.status.success());
    assert_eq!(
        fs::read_to_string(fixture.path().join(".repo2okf/precious.txt"))
            .expect("protected cache file after scan"),
        "keep me"
    );
}

#[test]
fn scan_replaces_the_whole_owned_cache() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::write(fixture.path().join("README.md"), "# Fixture\n").expect("write fixture");
    assert_success(&repo2okf(fixture.path(), &["scan"]), "initial scan");
    fs::write(fixture.path().join(".repo2okf/stale.txt"), "stale").expect("stale cache fixture");
    assert_success(&repo2okf(fixture.path(), &["scan"]), "replacement scan");
    assert!(!fixture.path().join(".repo2okf/stale.txt").exists());
    assert!(fixture.path().join(".repo2okf/.repo2okf-owned").is_file());
}

#[test]
fn starter_config_compiles_a_small_python_repository() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::create_dir(fixture.path().join("example")).expect("create Python package");
    fs::write(
        fixture.path().join("example/helpers.py"),
        "def greet(name: str) -> str:\n    return f'hello {name}'\n",
    )
    .expect("write Python helper fixture");
    let service_source = concat!(
        "from .helpers import greet\n\n",
        "class Greeter:\n",
        "    \"\"\"Format a friendly welcome without side effects.\"\"\"\n",
        "    def welcome(self, name: str) -> str:\n",
        "        \"\"\"Return a greeting for the supplied name.\"\"\"\n",
        "        return greet(name)\n",
    );
    fs::write(fixture.path().join("example/service.py"), service_source)
        .expect("write Python service fixture");
    assert_success(&repo2okf(fixture.path(), &["init"]), "initialize config");
    let starter = fs::read_to_string(fixture.path().join("repo2okf.toml"))
        .expect("read starter configuration");
    assert!(starter.contains("\"python\""));
    assert_success(
        &repo2okf(fixture.path(), &["compile", "--facts-only"]),
        "compile with starter config",
    );
    let ir: Value = serde_json::from_slice(
        &fs::read(fixture.path().join(".repo2okf/ir.json")).expect("read generated IR"),
    )
    .expect("valid IR JSON");
    assert!(ir["entities"].as_array().is_some_and(|entities| {
        ["greet", "Greeter", "welcome"]
            .iter()
            .all(|expected| entities.iter().any(|entity| entity["name"] == *expected))
    }));
    assert!(ir["imports"].as_array().is_some_and(|imports| {
        imports.iter().any(|import| {
            import["path"] == "example/service.py" && import["specifier"] == ".helpers"
        })
    }));
    let entities = ir["entities"].as_array().expect("IR entities");
    let service = entities
        .iter()
        .find(|entity| entity["kind"] == "file" && entity["path"] == "example/service.py")
        .and_then(|entity| entity["id"].as_str())
        .expect("service file entity");
    let helpers = entities
        .iter()
        .find(|entity| entity["kind"] == "file" && entity["path"] == "example/helpers.py")
        .and_then(|entity| entity["id"].as_str())
        .expect("helpers file entity");
    assert!(ir["relationships"].as_array().is_some_and(|relationships| {
        relationships.iter().any(|relationship| {
            relationship["kind"] == "imports"
                && relationship["source"] == service
                && relationship["target"] == helpers
        })
    }));
    let claims = ir["claims"].as_array().expect("IR claims");
    let docstring_claim = claims
        .iter()
        .find(|claim| {
            claim["text"]
                .as_str()
                .is_some_and(|text| text.contains("`welcome` with a Python docstring."))
        })
        .expect("facts-only docstring presence claim");
    let docstring_evidence_ids = docstring_claim["evidence_ids"]
        .as_array()
        .expect("docstring claim evidence IDs");
    let docstring_evidence = ir["evidence"]
        .as_array()
        .and_then(|evidence| {
            evidence.iter().find(|evidence| {
                evidence["symbol"] == "welcome docstring"
                    && docstring_evidence_ids
                        .iter()
                        .any(|id| id == &evidence["id"])
            })
        })
        .expect("docstring evidence record");
    assert_eq!(docstring_evidence["path"], "example/service.py");
    assert_eq!(docstring_evidence["symbol"], "welcome docstring");
    let start = usize::try_from(
        docstring_evidence["start_byte"]
            .as_u64()
            .expect("start byte"),
    )
    .expect("start byte fits usize");
    let end = usize::try_from(docstring_evidence["end_byte"].as_u64().expect("end byte"))
        .expect("end byte fits usize");
    assert_eq!(
        &service_source.as_bytes()[start..end],
        b"\"\"\"Return a greeting for the supplied name.\"\"\""
    );
    assert!(claims.iter().all(|claim| {
        !claim["text"]
            .as_str()
            .is_some_and(|text| text.contains("Return a greeting for the supplied name."))
    }));
}
