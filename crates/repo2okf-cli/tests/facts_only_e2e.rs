//! Cross-platform black-box tests for the credential-free CLI workflow.

use std::{
    collections::BTreeMap,
    env, fs,
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

fn repo2okf_with_fake_bin(repository: &Path, arguments: &[&str], fake_bin: &Path) -> Output {
    #[cfg(unix)]
    let search_path = env::join_paths([fake_bin]).expect("fake Unix PATH");
    #[cfg(windows)]
    let search_path = {
        let system_root = env::var_os("SystemRoot")
            .map(PathBuf::from)
            .expect("Windows has SystemRoot");
        env::join_paths([fake_bin.to_path_buf(), system_root.join("System32")])
            .expect("fake Windows PATH")
    };

    let mut command = Command::new(env!("CARGO_BIN_EXE_repo2okf"));
    command
        .arg("--repository")
        .arg(repository)
        .args(arguments)
        .env("PATH", search_path);
    #[cfg(windows)]
    command.env("PATHEXT", ".COM;.EXE;.BAT;.CMD");
    command.output().expect("repo2okf process should start")
}

#[cfg(unix)]
fn write_fake_claude(fake_bin: &Path, response: &Value) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir(fake_bin).expect("create fake agent bin");
    let response = serde_json::to_string(response)
        .expect("serialize fake Claude response")
        .replace('\'', "'\"'\"'");
    let executable = fake_bin.join("claude");
    let script = format!(
        r#"#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then
  printf '%s\n' 'claude-code 9.9.9'
  exit 0
fi
if [ "$#" -eq 1 ] && [ "$1" = "--help" ]; then
  printf '%s\n' '--print -p stream-json --json-schema --tools --disallowedTools --safe-mode'
  exit 0
fi
if [ "$#" -eq 2 ] && [ "$1" = "auth" ] && [ "$2" = "status" ]; then
  printf '%s\n' '{{"loggedIn":true}}'
  exit 0
fi
while IFS= read -r _line; do :; done
printf '%s' '{response}'
"#
    );
    fs::write(&executable, script).expect("write fake Claude executable");
    let mut permissions = fs::metadata(&executable)
        .expect("fake Claude metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(executable, permissions).expect("make fake Claude executable");
}

#[cfg(windows)]
fn write_fake_claude(fake_bin: &Path, response: &Value) {
    fs::create_dir(fake_bin).expect("create fake agent bin");
    fs::write(
        fake_bin.join("response.json"),
        serde_json::to_vec(response).expect("serialize fake Claude response"),
    )
    .expect("write fake Claude response");
    fs::write(
        fake_bin.join("claude.cmd"),
        concat!(
            "@echo off\r\n",
            "if \"%~1\"==\"--version\" goto version\r\n",
            "if \"%~1\"==\"--help\" goto help\r\n",
            "if \"%~1\"==\"auth\" goto auth\r\n",
            "type \"%~dp0response.json\"\r\n",
            "exit /b 0\r\n",
            ":version\r\n",
            "echo claude-code 9.9.9\r\n",
            "exit /b 0\r\n",
            ":help\r\n",
            "echo --print -p stream-json --json-schema --tools --disallowedTools --safe-mode\r\n",
            "exit /b 0\r\n",
            ":auth\r\n",
            "echo {\"loggedIn\":true}\r\n",
            "exit /b 0\r\n",
        ),
    )
    .expect("write fake Claude executable");
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

fn write_output_locale_config(root: &Path, locale: &str) {
    fs::write(
        root.join("repo2okf.toml"),
        format!(
            concat!(
                "schema = 1\n\n",
                "[output]\n",
                "directory = \".okf\"\n",
                "ir_file = \".repo2okf/ir.json\"\n",
                "state_file = \".repo2okf/state.json\"\n",
                "locale = \"{}\"\n",
            ),
            locale,
        ),
    )
    .expect("write output locale config");
}

#[test]
fn output_locale_rerenders_prose_without_changing_repository_ir() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    let root = fixture.path();
    fs::write(
        root.join("service.py"),
        "\"\"\"Greeting service.\"\"\"\n\ndef greet(name: str) -> str:\n    \"\"\"Return a greeting.\"\"\"\n    return f\"Hello {name}\"\n",
    )
    .expect("write Python fixture");

    write_output_locale_config(root, "en");
    let english = repo2okf(root, &["compile", "--facts-only"]);
    assert_success(&english, "English facts-only compile");
    let english_ir: Value = serde_json::from_slice(
        &fs::read(root.join(".repo2okf/ir.json")).expect("English IR bytes"),
    )
    .expect("English IR JSON");
    let english_bundle = bundle_bytes(&root.join(".okf"));
    let english_text = english_bundle
        .values()
        .filter_map(|bytes| std::str::from_utf8(bytes).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(english_text.contains("output_locale: en"));
    assert!(english_text.contains("Evidence-bound claims"));

    write_output_locale_config(root, "ja");
    let japanese = repo2okf(root, &["update", "--facts-only"]);
    assert_success(&japanese, "Japanese facts-only update");
    assert!(!stdout(&japanese).contains("up to date:"));
    let japanese_ir: Value = serde_json::from_slice(
        &fs::read(root.join(".repo2okf/ir.json")).expect("Japanese IR bytes"),
    )
    .expect("Japanese IR JSON");
    let japanese_bundle = bundle_bytes(&root.join(".okf"));
    let japanese_text = japanese_bundle
        .values()
        .filter_map(|bytes| std::str::from_utf8(bytes).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(japanese_text.contains("output_locale: ja"));
    assert!(japanese_text.contains("証拠に紐づく主張"));
    assert!(japanese_text.contains("宣言されています"));
    assert_ne!(english_bundle, japanese_bundle);

    for field in [
        "fingerprint",
        "files",
        "entities",
        "evidence",
        "relationships",
        "semantic_references",
        "semantic_coverage",
        "coverage",
    ] {
        assert_eq!(
            english_ir[field], japanese_ir[field],
            "locale changed deterministic IR field {field}"
        );
    }
    assert_eq!(english_ir["claims"], japanese_ir["claims"]);

    let verify = repo2okf(root, &["verify", "--strict", "--json"]);
    assert_success(&verify, "Japanese strict verification");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("verification JSON");
    assert_eq!(verification["valid"], true);
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
    assert!(coverage["semantic"].is_object());
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
#[allow(
    clippy::too_many_lines,
    reason = "one black-box scenario follows semantic evidence from source through IR and OKF"
)]
fn starter_config_compiles_a_small_python_repository() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    fs::create_dir(fixture.path().join("example")).expect("create Python package");
    fs::write(fixture.path().join("example/__init__.py"), "")
        .expect("write Python package fixture");
    fs::write(
        fixture.path().join("example/helpers.py"),
        "def greet(name: str) -> str:\n    return f'hello {name}'\n",
    )
    .expect("write Python helper fixture");
    let service_source = concat!(
        "from .helpers import greet as friendly_greet\n\n",
        "class Greeter:\n",
        "    \"\"\"Format a friendly welcome without side effects.\"\"\"\n",
        "    def welcome(self, name: str) -> str:\n",
        "        \"\"\"Return a greeting for the supplied name.\"\"\"\n",
        "        return friendly_greet(name)\n",
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
    let entities = ir["entities"].as_array().expect("IR entities");
    let greet = entities
        .iter()
        .find(|entity| entity["name"] == "greet")
        .expect("greet entity");
    let greeter = entities
        .iter()
        .find(|entity| entity["name"] == "Greeter")
        .expect("Greeter entity");
    let welcome = entities
        .iter()
        .find(|entity| entity["name"] == "welcome")
        .expect("welcome entity");
    assert_eq!(greet["qualified_name"], "example.helpers.greet");
    assert_eq!(greeter["qualified_name"], "example.service.Greeter");
    assert_eq!(welcome["qualified_name"], "example.service.Greeter.welcome");
    assert_eq!(welcome["owner_id"], greeter["id"]);
    assert!(ir["imports"].as_array().is_some_and(|imports| {
        imports.iter().any(|import| {
            import["path"] == "example/service.py" && import["specifier"] == ".helpers"
        })
    }));
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

    let semantic_references = ir["semantic_references"]
        .as_array()
        .expect("semantic references");
    let import_binding = semantic_references
        .iter()
        .find(|reference| {
            reference["kind"] == "import_binding"
                && reference["path"] == "example/service.py"
                && reference["name"] == "greet"
                && reference["qualifier"] == ".helpers"
                && reference["binding_name"] == "friendly_greet"
        })
        .expect("aliased local import binding");
    assert_eq!(import_binding["resolution"]["status"], "resolved");
    assert_eq!(
        import_binding["resolution"]["target_entity_id"],
        greet["id"]
    );

    let direct_call = semantic_references
        .iter()
        .find(|reference| {
            reference["kind"] == "call"
                && reference["path"] == "example/service.py"
                && reference["name"] == "friendly_greet"
        })
        .expect("direct call through imported alias");
    assert_eq!(direct_call["scope_id"], welcome["id"]);
    assert_eq!(direct_call["source_entity_id"], welcome["id"]);
    assert_eq!(direct_call["resolution"]["status"], "resolved");
    assert_eq!(direct_call["resolution"]["target_entity_id"], greet["id"]);

    let semantic_coverage = &ir["semantic_coverage"];
    let classified = ["resolved", "external", "ambiguous", "unresolved"]
        .iter()
        .map(|field| semantic_coverage[*field].as_u64().expect("semantic count"))
        .sum::<u64>();
    assert_eq!(
        semantic_coverage["total"].as_u64(),
        Some(u64::try_from(semantic_references.len()).expect("reference count fits u64"))
    );
    assert_eq!(semantic_coverage["total"].as_u64(), Some(classified));

    let coverage_items = ir["coverage"]["items"]
        .as_array()
        .expect("source coverage items");
    let file_concept_ids = coverage_items
        .iter()
        .filter(|item| item["kind"] == "file" && item["disposition"]["status"] == "included")
        .filter_map(|item| item["disposition"]["concept_id"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(file_concept_ids.len(), 3);
    let entity_coverage = coverage_items
        .iter()
        .filter(|item| item["kind"] == "entity")
        .collect::<Vec<_>>();
    assert_eq!(entity_coverage.len(), 3);
    assert!(entity_coverage.iter().all(|item| {
        item["disposition"]["status"] == "included"
            && item["disposition"]["concept_id"]
                .as_str()
                .is_some_and(|concept_id| file_concept_ids.contains(&concept_id))
    }));

    let direct_call_relationship = ir["relationships"]
        .as_array()
        .and_then(|relationships| {
            relationships.iter().find(|relationship| {
                relationship["kind"] == "calls"
                    && relationship["source"] == welcome["id"]
                    && relationship["target"] == greet["id"]
                    && relationship["origin"]["kind"] == "semantic_reference"
                    && relationship["origin"]["reference_id"] == direct_call["id"]
            })
        })
        .expect("resolved call relationship");
    assert_eq!(
        direct_call_relationship["evidence_ids"],
        Value::Array(vec![direct_call["evidence_id"].clone()])
    );
    let call_evidence = ir["evidence"]
        .as_array()
        .and_then(|evidence| {
            evidence
                .iter()
                .find(|evidence| evidence["id"] == direct_call["evidence_id"])
        })
        .expect("call evidence record");
    assert_eq!(call_evidence["path"], "example/service.py");
    let call_start = usize::try_from(call_evidence["start_byte"].as_u64().expect("start byte"))
        .expect("start byte fits usize");
    let call_end = usize::try_from(call_evidence["end_byte"].as_u64().expect("end byte"))
        .expect("end byte fits usize");
    assert_eq!(
        &service_source.as_bytes()[call_start..call_end],
        b"friendly_greet"
    );

    let claims = ir["claims"].as_array().expect("IR claims");
    assert!(
        claims
            .iter()
            .all(|claim| claim["provenance"]["kind"] == "deterministic"),
        "facts-only must not persist agent provenance"
    );
    assert!(
        ir["architecture_concepts"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert!(
        ir["architecture_relationships"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );

    let okf_root = fixture.path().join(".okf");
    let concepts = bundle_bytes(&okf_root)
        .into_iter()
        .filter(|(path, _)| {
            path.extension().is_some_and(|extension| extension == "md")
                && path != Path::new("index.md")
        })
        .map(|(path, bytes)| {
            (
                path,
                String::from_utf8(bytes).expect("generated concept should be UTF-8"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        concepts.len(),
        6,
        "three source files, one package and two logical modules are expected"
    );
    assert_eq!(
        concepts
            .iter()
            .filter(|(_, contents)| contents.contains("type: Source File\n"))
            .count(),
        3
    );
    assert_eq!(
        concepts
            .iter()
            .filter(|(_, contents)| contents.contains("type: Python Module\n"))
            .count(),
        2
    );
    assert_eq!(
        concepts
            .iter()
            .filter(|(_, contents)| contents.contains("type: Python Package\n"))
            .count(),
        1
    );
    assert!(concepts.iter().all(|(_, contents)| {
        !contents.contains("type: Source Declaration\n") && !contents.contains("type: Import\n")
    }));
    assert!(concepts.iter().any(|(_, contents)| {
        contents.contains("type: Python Package\n") && contents.contains("repo:example/__init__.py")
    }));
    assert!(concepts.iter().all(|(_, contents)| {
        !contents.contains("repo2okf-agent/")
            && !contents.contains("agent_provider:")
            && !contents.contains("ai_generated: true")
    }));
    let (helper_concept_path, _) = concepts
        .iter()
        .find(|(_, contents)| {
            contents.contains("type: Python Module\n")
                && contents.contains("repo:example/helpers.py")
        })
        .expect("helper module concept");
    let (_, service_concept) = concepts
        .iter()
        .find(|(_, contents)| {
            contents.contains("type: Python Module\n")
                && contents.contains("repo:example/service.py")
        })
        .expect("service module concept");
    let helper_link = helper_concept_path.to_string_lossy().replace('\\', "/");
    assert!(service_concept.contains(&format!("](/{helper_link})")));
    for retained_id in [
        direct_call_relationship["id"]
            .as_str()
            .expect("relationship ID"),
        direct_call["id"].as_str().expect("reference ID"),
        direct_call["evidence_id"].as_str().expect("evidence ID"),
    ] {
        assert!(
            service_concept.contains(retained_id),
            "cross-concept call must retain {retained_id}"
        );
    }
    assert!(service_concept.contains("kind: calls"));

    let coverage = repo2okf(fixture.path(), &["coverage", "--json"]);
    assert_success(&coverage, "Python semantic coverage report");
    let coverage: Value =
        serde_json::from_slice(&coverage.stdout).expect("coverage should emit JSON");
    assert_eq!(coverage["semantic"], ir["semantic_coverage"]);

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

    fs::write(
        fixture.path().join("example/service.py"),
        service_source.replace(
            "return friendly_greet(name)",
            "return friendly_greet(name.upper())",
        ),
    )
    .expect("change a source occurrence cited by the call relationship");
    let stale = repo2okf(fixture.path(), &["verify", "--json"]);
    assert!(
        !stale.status.success(),
        "changing cited semantic source must stale the saved OKF"
    );
    let stale_report: Value =
        serde_json::from_slice(&stale.stdout).expect("stale verification should emit JSON");
    assert_eq!(stale_report["valid"], false);
    assert!(stale_report["issues"].as_array().is_some_and(|issues| {
        issues
            .iter()
            .any(|issue| issue["code"] == "repository-ir-stale")
    }));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one process-boundary scenario follows an accepted agent candidate into persisted OKF"
)]
fn fake_claude_candidate_becomes_a_scoped_draft_okf_concept() {
    let fixture = tempfile::tempdir().expect("temporary repository");
    let root = fixture.path();
    fs::create_dir(root.join("example")).expect("create Python package");
    fs::write(root.join("example/__init__.py"), "").expect("write Python package fixture");
    fs::write(
        root.join("example/helpers.py"),
        "def greet(name: str) -> str:\n    return f'hello {name}'\n",
    )
    .expect("write helper fixture");
    fs::write(
        root.join("example/service.py"),
        concat!(
            "from .helpers import greet as friendly_greet\n\n",
            "def welcome(name: str) -> str:\n",
            "    return friendly_greet(name)\n",
        ),
    )
    .expect("write service fixture");
    write_output_locale_config(root, "ja");

    assert_success(&repo2okf(root, &["scan"]), "seed deterministic IR");
    let seed_ir: Value =
        serde_json::from_slice(&fs::read(root.join(".repo2okf/ir.json")).expect("seed IR bytes"))
            .expect("valid seed IR");
    let entities = seed_ir["entities"].as_array().expect("seed entities");
    let greet_id = entities
        .iter()
        .find(|entity| entity["qualified_name"] == "example.helpers.greet")
        .and_then(|entity| entity["id"].as_str())
        .expect("greet entity")
        .to_owned();
    let welcome_id = entities
        .iter()
        .find(|entity| entity["qualified_name"] == "example.service.welcome")
        .and_then(|entity| entity["id"].as_str())
        .expect("welcome entity")
        .to_owned();
    let greet_evidence_id = entities
        .iter()
        .find(|entity| entity["qualified_name"] == "example.helpers.greet")
        .and_then(|entity| entity["evidence_id"].as_str())
        .expect("greet declaration evidence")
        .to_owned();
    let welcome_evidence_id = entities
        .iter()
        .find(|entity| entity["qualified_name"] == "example.service.welcome")
        .and_then(|entity| entity["evidence_id"].as_str())
        .expect("welcome declaration evidence")
        .to_owned();
    let call = seed_ir["relationships"]
        .as_array()
        .and_then(|relationships| {
            relationships.iter().find(|relationship| {
                relationship["kind"] == "calls"
                    && relationship["source"] == welcome_id
                    && relationship["target"] == greet_id
                    && relationship["origin"]["kind"] == "semantic_reference"
            })
        })
        .expect("resolved semantic call");
    let call_id = call["id"]
        .as_str()
        .expect("call relationship ID")
        .to_owned();
    let call_evidence_id = call["evidence_ids"]
        .as_array()
        .and_then(|ids| ids.first())
        .and_then(Value::as_str)
        .expect("call evidence ID")
        .to_owned();
    let mut concept_evidence_ids = vec![
        call_evidence_id.clone(),
        greet_evidence_id,
        welcome_evidence_id,
    ];
    concept_evidence_ids.sort();
    concept_evidence_ids.dedup();

    let response = serde_json::json!({
        "type": "result",
        "structured_output": {
            "claims": [],
            "repository_summary": null,
            "summary_evidence_ids": [],
            "concept_candidates": [{
                "candidate_key": "greeting-flow",
                "title": "挨拶フロー",
                "responsibility": "挨拶の入口をローカルヘルパーへ接続します。",
                "member_entity_ids": [welcome_id, greet_id],
                "supporting_edge_ids": [call_id],
                "evidence_ids": concept_evidence_ids.clone()
            }],
            "relationship_candidates": []
        }
    });
    let fake_agent = tempfile::tempdir().expect("fake agent directory");
    let fake_bin = fake_agent.path().join("bin");
    write_fake_claude(&fake_bin, &response);
    let compile = repo2okf_with_fake_bin(
        root,
        &["compile", "--agent", "claude", "--reuse-agent-cache"],
        &fake_bin,
    );
    assert_success(&compile, "compile through fake Claude process boundary");
    assert!(stdout(&compile).contains("claude enrichment accepted after 1 attempt(s)"));

    let ir: Value = serde_json::from_slice(
        &fs::read(root.join(".repo2okf/ir.json")).expect("agent-enriched IR bytes"),
    )
    .expect("valid agent-enriched IR");
    let architecture = ir["architecture_concepts"]
        .as_array()
        .and_then(|concepts| concepts.first())
        .expect("accepted architecture concept");
    assert_eq!(
        ir["architecture_concepts"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(architecture["title"], "挨拶フロー");
    assert_eq!(
        architecture["responsibility"],
        "挨拶の入口をローカルヘルパーへ接続します。"
    );
    assert_eq!(architecture["status"], "draft");
    assert_eq!(architecture["provenance"]["kind"], "agent");
    assert_eq!(architecture["provenance"]["provider"], "claude");
    assert_ne!(architecture["id"], "greeting-flow");
    let members = architecture["member_entity_ids"]
        .as_array()
        .expect("architecture members");
    assert!(members.iter().any(|member| member == &welcome_id));
    assert!(members.iter().any(|member| member == &greet_id));
    assert!(
        architecture["supporting_relationship_ids"]
            .as_array()
            .is_some_and(|ids| ids.len() == 1 && ids[0] == call_id)
    );
    assert_eq!(
        architecture["evidence_ids"],
        serde_json::to_value(&concept_evidence_ids).expect("candidate evidence JSON")
    );
    assert!(
        ir["architecture_relationships"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );

    let scope = &ir["architecture_scope"];
    assert_eq!(scope["complete"], true);
    for (supplied, total) in [
        ("evidence_supplied", "evidence_total"),
        ("coverage_items_supplied", "coverage_items_total"),
        ("entities_supplied", "entities_total"),
        ("semantic_references_supplied", "semantic_references_total"),
        (
            "semantic_relationships_supplied",
            "semantic_relationships_total",
        ),
    ] {
        assert_eq!(scope[supplied], scope[total], "incomplete {total}");
        assert!(scope[total].as_u64().is_some_and(|count| count > 0));
    }

    let coverage_json = repo2okf(root, &["coverage", "--json"]);
    assert_success(&coverage_json, "scoped JSON coverage");
    let coverage_json: Value =
        serde_json::from_slice(&coverage_json.stdout).expect("coverage JSON");
    assert_eq!(
        coverage_json["architecture_scope"],
        ir["architecture_scope"]
    );
    let coverage_text = repo2okf(root, &["coverage"]);
    assert_success(&coverage_text, "scoped text coverage");
    let coverage_text = stdout(&coverage_text);
    assert!(coverage_text.contains("architecture input: complete"));
    for label in [
        "evidence:",
        "coverage items:",
        "entities:",
        "references:",
        "relationships:",
    ] {
        assert!(coverage_text.contains(label), "missing scope label {label}");
    }

    let architecture_documents = bundle_bytes(&root.join(".okf"))
        .into_values()
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .filter(|contents| contents.contains("type: Architecture Component\n"))
        .collect::<Vec<_>>();
    assert_eq!(architecture_documents.len(), 1);
    let document = &architecture_documents[0];
    assert!(document.contains("status: draft"));
    assert!(document.contains("output_locale: ja"));
    assert!(document.contains("title: 挨拶フロー"));
    assert!(document.contains("挨拶の入口をローカルヘルパーへ接続します。"));
    assert!(document.contains("repo2okf-agent/claude"));
    assert!(!document.contains("verified:"));
    for retained_id in [
        architecture["id"].as_str().expect("architecture ID"),
        welcome_id.as_str(),
        greet_id.as_str(),
        call_id.as_str(),
        call_evidence_id.as_str(),
    ] {
        assert!(
            document.contains(retained_id),
            "draft architecture document must retain {retained_id}"
        );
    }
    assert!(document.contains("complete: true"));

    let verify = repo2okf(root, &["verify", "--json"]);
    assert_success(&verify, "verify agent draft bundle");
    let verification: Value = serde_json::from_slice(&verify.stdout).expect("verification JSON");
    assert_eq!(verification["valid"], true);

    write_output_locale_config(root, "en");
    let english_response = serde_json::json!({
        "type": "result",
        "structured_output": {
            "claims": [],
            "repository_summary": null,
            "summary_evidence_ids": [],
            "concept_candidates": [{
                "candidate_key": "greeting-flow",
                "title": "Greeting flow",
                "responsibility": "Connects the greeting entry point to its local helper.",
                "member_entity_ids": [welcome_id, greet_id],
                "supporting_edge_ids": [call_id],
                "evidence_ids": concept_evidence_ids
            }],
            "relationship_candidates": []
        }
    });
    let english_agent = tempfile::tempdir().expect("English fake agent directory");
    let english_bin = english_agent.path().join("bin");
    write_fake_claude(&english_bin, &english_response);
    let update = repo2okf_with_fake_bin(
        root,
        &["update", "--agent", "claude", "--reuse-agent-cache"],
        &english_bin,
    );
    assert_success(&update, "locale-changing agent update");
    assert!(
        stdout(&update).contains("claude enrichment accepted after 1 attempt(s)"),
        "a locale change must not reuse prose from the prior locale"
    );
    let english_documents = bundle_bytes(&root.join(".okf"))
        .into_values()
        .filter_map(|bytes| String::from_utf8(bytes).ok())
        .filter(|contents| contents.contains("type: Architecture Component\n"))
        .collect::<Vec<_>>();
    assert_eq!(english_documents.len(), 1);
    assert!(english_documents[0].contains("output_locale: en"));
    assert!(english_documents[0].contains("title: Greeting flow"));
    assert!(!english_documents[0].contains("挨拶フロー"));
}
