//! `Repo2OKF` command-line entry point.

mod args;
mod config;
mod io;

use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use args::{
    AgentSelection, Cli, Command, CompileArgs, CoverageArgs, DoctorArgs, ScanArgs, VerifyArgs,
};
use clap::Parser;
use config::Config;
use repo2okf_agent::{
    AGENT_CONTRACT_VERSION, AgentDriver, AgentKind, AgentProbe, ClaudeDriver, CodexDriver,
    ProcessConfig, RepairOptions, enrich_with_repair,
};
use repo2okf_core::{
    BuildState, ClaimProvenance, Language, RepositoryIr, ScanOptions, compute_changes,
    scan_repository,
};
use repo2okf_format::{
    EmissionReport, FreshnessMismatch, RepositorySnapshot, Severity, VerificationReport,
    VerifyOptions, emit_okf, verify_okf,
};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

const OWNERSHIP_MARKER_FILE: &str = ".repo2okf-owned";
const OWNERSHIP_MARKER_CONTENT: &[u8] = b"repo2okf bundle v1\n";
const CACHE_DIRECTORY: &str = ".repo2okf";
const CACHE_OWNERSHIP_MARKER_CONTENT: &[u8] = b"repo2okf cache v1\n";

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let repository = cli
        .repository
        .canonicalize()
        .with_context(|| format!("repository does not exist: {}", cli.repository.display()))?;
    if !repository.is_dir() {
        bail!(
            "repository path is not a directory: {}",
            repository.display()
        );
    }
    let repository = io::RepositoryGuard::capture(&repository)?;

    match cli.command {
        Command::Init(args) => {
            repository.verify()?;
            let path = Config::write_starter(repository.path(), args.force)?;
            repository.verify()?;
            println!("created {}", path.display());
        }
        command => {
            repository.verify()?;
            let config = Config::load(repository.path(), cli.config.as_deref())?;
            repository.verify()?;
            dispatch(&repository, &config, command)?;
        }
    }
    repository.verify()?;
    Ok(())
}

fn dispatch(repository: &io::RepositoryGuard, config: &Config, command: Command) -> Result<()> {
    repository.verify()?;
    let result = match command {
        Command::Init(_) => unreachable!("init is dispatched before loading configuration"),
        Command::Doctor(args) => doctor(repository, config, &args),
        Command::Scan(args) => scan(repository, config, &args),
        Command::Compile(args) => compile(repository, config, &args, false),
        Command::Update(args) => compile(repository, config, &args, true),
        Command::Verify(args) => verify(repository, config, &args),
        Command::Coverage(args) => coverage(repository, config, &args),
    };
    repository.verify()?;
    result
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    repository: String,
    git: ToolStatus,
    codex: AgentProbe,
    claude: AgentProbe,
    facts_only_ready: bool,
}

#[derive(Debug, Serialize)]
struct ToolStatus {
    found: bool,
    path: Option<String>,
    version: Option<String>,
}

fn doctor(repository: &io::RepositoryGuard, config: &Config, args: &DoctorArgs) -> Result<()> {
    repository.verify()?;
    let process = process_config(repository.path(), config, false);
    let report = DoctorReport {
        repository: repository.path().display().to_string(),
        git: tool_status("git", &["--version"]),
        codex: CodexDriver::new().probe(&process),
        claude: ClaudeDriver::new().probe(&process),
        facts_only_ready: true,
    };
    repository.verify()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("repository: {}", report.repository);
        print_tool("git", &report.git);
        print_agent(&report.codex, true);
        print_agent(&report.claude, true);
        println!("facts-only: ready");
    }
    Ok(())
}

fn tool_status(command: &str, version_args: &[&str]) -> ToolStatus {
    let path = which::which_global(command).ok();
    let version = path.as_ref().and_then(|path| {
        std::process::Command::new(path)
            .args(version_args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if stdout.is_empty() {
                    String::from_utf8_lossy(&output.stderr).trim().to_owned()
                } else {
                    stdout
                }
            })
    });
    ToolStatus {
        found: path.is_some(),
        path: path.map(|path| path.display().to_string()),
        version,
    }
}

fn print_tool(label: &str, tool: &ToolStatus) {
    if tool.found {
        println!(
            "{label}: found ({}){}",
            tool.path.as_deref().unwrap_or("unknown path"),
            tool.version
                .as_deref()
                .map_or_else(String::new, |version| format!(" — {version}"))
        );
    } else {
        println!("{label}: not found");
    }
}

fn print_agent(probe: &AgentProbe, hermetic: bool) {
    let label = probe.kind.command_name();
    let state = if probe.ready(hermetic) {
        "ready"
    } else if probe.executable.is_some() && probe.authenticated.is_none() {
        "installed; authentication will be checked on first run"
    } else if probe.executable.is_some() {
        "installed but not ready"
    } else {
        "not found"
    };
    println!("{label}: {state}");
    if let Some(version) = &probe.version {
        println!("  version: {version}");
    }
    for diagnostic in &probe.diagnostics {
        println!("  note: {diagnostic}");
    }
}

fn scan(repository: &io::RepositoryGuard, config: &Config, args: &ScanArgs) -> Result<()> {
    repository.verify()?;
    let ir = build_ir(repository, config)?;
    if args.stdout {
        println!("{}", serde_json::to_string_pretty(&ir)?);
    } else {
        let ir_path = &config.output.ir_file;
        if !config::is_reserved_state_path(ir_path) {
            bail!("scan output must be a file inside the reserved `.repo2okf` directory");
        }
        if ir_path == &config.output.state_file {
            bail!("scan output must differ from output.state_file");
        }
        let state = BuildState::from_ir(&ir, config_fingerprint(config)?)
            .with_persisted_ir_hash(persisted_ir_hash(&ir)?);
        publish_cache(repository, ir_path, &config.output.state_file, &ir, &state)?;
        let displayed_path = repository.path().join(ir_path);
        println!(
            "scanned {} files, {} entities, {} imports -> {}",
            ir.files.len(),
            ir.entities.len(),
            ir.imports.len(),
            displayed_path.display()
        );
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "compile keeps the transactional pipeline and its failure ordering visible"
)]
fn compile(
    repository: &io::RepositoryGuard,
    config: &Config,
    args: &CompileArgs,
    incremental: bool,
) -> Result<()> {
    repository.verify()?;
    let repository_path = repository.path();
    if args.agent == Some(AgentSelection::Off)
        && (args.allow_agent_filesystem || args.reuse_agent_cache)
    {
        bail!("agent trust flags require --agent auto, codex, or claude");
    }
    let mut ir = build_ir(repository, config)?;
    let selection = effective_agent(args);
    let build_fingerprint = build_fingerprint(repository_path, config, args)?;
    let new_state = BuildState::from_ir(&ir, build_fingerprint.clone());
    let state_path = if incremental {
        Some(io::resolve_beneath(
            repository_path,
            &config.output.state_file,
        )?)
    } else {
        None
    };
    if let Some(state_path) = state_path.as_ref().filter(|path| path.is_file()) {
        let old_state: BuildState = io::read_json(state_path)?;
        let changes = compute_changes(&old_state, &new_state);
        let may_reuse_output = selection == AgentSelection::Off || args.reuse_agent_cache;
        if changes.is_empty() && may_reuse_output {
            let output = output_directory(repository_path, config, args.output.as_deref())?;
            if output.is_dir() {
                let saved_ir = io::resolve_beneath(repository_path, &config.output.ir_file)
                    .ok()
                    .filter(|path| path.is_file())
                    .and_then(|path| io::read_json::<RepositoryIr>(&path).ok())
                    .filter(|saved| {
                        !old_state.persisted_ir_hash.is_empty()
                            && persisted_ir_hash(saved).ok().as_deref()
                                == Some(&old_state.persisted_ir_hash)
                    })
                    .filter(|saved| saved.fingerprint == ir.fingerprint)
                    .filter(|saved| deterministic_ir_matches(saved, &ir))
                    .filter(|saved| selection != AgentSelection::Off || saved.claims == ir.claims)
                    .filter(|saved| saved.validate().is_ok());
                let snapshot = if selection == AgentSelection::Off {
                    RepositorySnapshot::from_ir_with_locale(&ir, config.output.locale)
                } else {
                    saved_ir.as_ref().map_or_else(
                        || RepositorySnapshot::from_ir_with_locale(&ir, config.output.locale),
                        |saved| {
                            RepositorySnapshot::from_ir_with_locale(saved, config.output.locale)
                        },
                    )
                };
                let report = verify_snapshot(&output, &snapshot, config, args.strict);
                if saved_ir.is_some()
                    && report.valid
                    && (!args.strict || report.warnings == 0)
                    && bundle_matches_fresh_emission(&output, &snapshot)?
                {
                    repository.verify()?;
                    println!("up to date: no repository or scanner configuration changes");
                    return Ok(());
                }
                println!("generated bundle is incomplete or stale; rebuilding");
            }
        } else {
            println!(
                "changes: +{} ~{} -{} ({} prior entities invalidated)",
                changes.added.len(),
                changes.modified.len(),
                changes.removed.len(),
                changes.invalidated_entities.len()
            );
        }
    }

    if selection == AgentSelection::Off
        && args
            .review_with
            .is_some_and(|review| review != AgentSelection::Off)
    {
        bail!("--review-with requires a primary agent other than off");
    }
    if matches!(
        (selection, args.review_with),
        (AgentSelection::Codex, Some(AgentSelection::Codex))
            | (AgentSelection::Claude, Some(AgentSelection::Claude))
    ) {
        bail!("the review agent must differ from the primary agent");
    }
    if selection != AgentSelection::Off {
        let driver = select_driver(
            selection,
            repository_path,
            config,
            None,
            args.allow_agent_filesystem,
        )?;
        let process = process_config(repository_path, config, args.allow_agent_filesystem);
        repository.verify()?;
        let (response, stats) = enrich_with_repair(
            driver.as_ref(),
            &ir,
            &process,
            config.output.locale,
            RepairOptions {
                max_repair_attempts: config.agent.max_repair_attempts,
            },
        )?;
        repository.verify()?;
        let (concepts, relationships) = response.accepted_architecture(driver.kind());
        ir.set_architecture_with_scope(concepts, relationships, stats.architecture_scope.clone())
            .map_err(anyhow::Error::msg)?;
        ir.extend_claims(response.claims)
            .map_err(anyhow::Error::msg)?;
        println!(
            "{} enrichment accepted after {} attempt(s)",
            driver.kind().command_name(),
            stats.attempts
        );

        if let Some(review_selection) = args
            .review_with
            .filter(|selection| *selection != AgentSelection::Off)
        {
            let reviewer = select_driver(
                review_selection,
                repository_path,
                config,
                Some(driver.kind()),
                args.allow_agent_filesystem,
            )?;
            repository.verify()?;
            let (review_response, review_stats) = enrich_with_repair(
                reviewer.as_ref(),
                &ir,
                &process,
                config.output.locale,
                RepairOptions {
                    max_repair_attempts: config.agent.max_repair_attempts,
                },
            )?;
            repository.verify()?;
            ir.claims
                .retain(|claim| matches!(claim.provenance, ClaimProvenance::Deterministic { .. }));
            let (concepts, relationships) = review_response.accepted_architecture(reviewer.kind());
            ir.set_architecture_with_scope(
                concepts,
                relationships,
                review_stats.architecture_scope.clone(),
            )
            .map_err(anyhow::Error::msg)?;
            ir.extend_claims(review_response.claims)
                .map_err(anyhow::Error::msg)?;
            println!(
                "{} review accepted after {} attempt(s)",
                reviewer.kind().command_name(),
                review_stats.attempts
            );
        }
    }

    repository.verify()?;
    ir.validate().map_err(anyhow::Error::msg)?;
    let snapshot = RepositorySnapshot::from_ir_with_locale(&ir, config.output.locale);
    let output = output_directory(repository_path, config, args.output.as_deref())?;
    let persisted_state =
        BuildState::from_ir(&ir, build_fingerprint).with_persisted_ir_hash(persisted_ir_hash(&ir)?);
    let (emission, report) = publish_compilation(
        repository,
        &snapshot,
        &ir,
        &persisted_state,
        &output,
        config,
        args.strict,
    )?;
    println!(
        "compiled {} OKF concepts to {} (coverage {:.1}%, {} warning(s))",
        emission.files_written.len().saturating_sub(1),
        output.display(),
        report.coverage * 100.0,
        report.warnings
    );
    Ok(())
}

fn bundle_matches_fresh_emission(existing: &Path, snapshot: &RepositorySnapshot) -> Result<bool> {
    let parent = existing
        .parent()
        .context("output directory has no parent")?;
    let temporary = tempfile::Builder::new()
        .prefix(".repo2okf-compare-")
        .tempdir_in(parent)?;
    let fresh = temporary.path().join("bundle");
    emit_okf(snapshot, &fresh)?;
    fs::write(fresh.join(OWNERSHIP_MARKER_FILE), OWNERSHIP_MARKER_CONTENT)?;
    Ok(bundle_tree(&fresh)? == bundle_tree(existing)?)
}

fn bundle_tree(root: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    fn visit(
        root: &Path,
        directory: &Path,
        output: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<()> {
        let mut entries = fs::read_dir(directory)
            .with_context(|| format!("failed to read bundle directory {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type()?;
            let linked = file_type.is_symlink()
                || fs::symlink_metadata(entry.path())
                    .is_ok_and(|metadata| io::is_link_or_reparse_point(&metadata));
            if linked {
                bail!(
                    "bundle contains a symbolic link: {}",
                    entry.path().display()
                );
            }
            if file_type.is_dir() {
                visit(root, &entry.path(), output)?;
            } else if file_type.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .expect("walked path is below bundle root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let mut file = fs::File::open(entry.path())?;
                let mut hasher = blake3::Hasher::new();
                let mut buffer = vec![0_u8; 64 * 1024];
                loop {
                    let count = file.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hasher.update(&buffer[..count]);
                }
                let hash = hasher.finalize().to_hex().to_string();
                output.insert(relative, hash);
            }
        }
        Ok(())
    }

    let mut output = std::collections::BTreeMap::new();
    visit(root, root, &mut output)?;
    Ok(output)
}

fn verify(repository: &io::RepositoryGuard, config: &Config, args: &VerifyArgs) -> Result<()> {
    repository.verify()?;
    let repository_path = repository.path();
    let ir_path = io::resolve_beneath(repository_path, &config.output.ir_file)?;
    let saved_ir: RepositoryIr = io::read_json(&ir_path).with_context(|| {
        format!(
            "run `repo2okf scan` or `repo2okf compile` first ({})",
            ir_path.display()
        )
    })?;
    repository.verify()?;
    saved_ir.validate().map_err(anyhow::Error::msg)?;
    let state_path = io::resolve_beneath(repository_path, &config.output.state_file)?;
    let saved_state: BuildState = io::read_json(&state_path)
        .with_context(|| format!("run `repo2okf compile` first ({})", state_path.display()))?;
    repository.verify()?;
    let persisted_ir_is_authentic = !saved_state.persisted_ir_hash.is_empty()
        && persisted_ir_hash(&saved_ir)? == saved_state.persisted_ir_hash;
    let current_ir = build_ir(repository, config).context("failed to rescan current repository")?;
    repository.verify()?;
    let current_evidence = current_ir
        .evidence
        .iter()
        .map(repo2okf_format::EvidenceRecord::from)
        .collect::<Vec<_>>();
    let snapshot = RepositorySnapshot::from_ir_with_locale(&saved_ir, config.output.locale);
    let target = args.target.as_deref().unwrap_or(&config.output.directory);
    let target = io::resolve_beneath(repository_path, target)?;
    if !target.is_dir() {
        bail!(
            "verification target is not a bundle directory: {}",
            target.display()
        );
    }
    let generated_bundle_changed = !bundle_matches_fresh_emission(&target, &snapshot)?;
    repository.verify()?;
    let report = verify_okf(
        &target,
        &current_evidence,
        &snapshot.coverage,
        &verification_options(
            config,
            args.strict,
            Some(&snapshot),
            !persisted_ir_is_authentic
                || saved_ir.fingerprint != current_ir.fingerprint
                || !deterministic_ir_matches(&saved_ir, &current_ir),
            generated_bundle_changed,
        ),
    );
    repository.verify()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_verification(&report);
    }
    if args.json {
        ensure_verification_quiet(&report, args.strict)
    } else {
        ensure_verification(&report, args.strict)
    }
}

fn coverage(repository: &io::RepositoryGuard, config: &Config, args: &CoverageArgs) -> Result<()> {
    #[derive(Serialize)]
    struct CoverageOutput<'a> {
        #[serde(flatten)]
        source: &'a repo2okf_core::CoverageReport,
        semantic: &'a repo2okf_core::SemanticCoverage,
        #[serde(skip_serializing_if = "Option::is_none")]
        architecture_scope: Option<&'a repo2okf_core::ArchitectureScope>,
    }

    repository.verify()?;
    let path = io::resolve_beneath(repository.path(), &config.output.ir_file)?;
    let ir: RepositoryIr = io::read_json(&path).with_context(|| {
        format!(
            "run `repo2okf scan` or `repo2okf compile` first ({})",
            path.display()
        )
    })?;
    repository.verify()?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&CoverageOutput {
                source: &ir.coverage,
                semantic: &ir.semantic_coverage,
                architecture_scope: ir.architecture_scope.as_ref(),
            })?
        );
    } else {
        println!("included:   {}", ir.coverage.included);
        println!("excluded:   {}", ir.coverage.excluded);
        println!("unresolved: {}", ir.coverage.unresolved);
        println!("coverage:   {:.1}%", ir.coverage.ratio() * 100.0);
        println!("semantic references: {}", ir.semantic_coverage.total);
        println!("  resolved:   {}", ir.semantic_coverage.resolved);
        println!("  external:   {}", ir.semantic_coverage.external_);
        println!("  ambiguous:  {}", ir.semantic_coverage.ambiguous);
        println!("  unresolved: {}", ir.semantic_coverage.unresolved);
        if let Some(scope) = &ir.architecture_scope {
            println!(
                "architecture input: {}",
                if scope.complete {
                    "complete"
                } else {
                    "partial"
                }
            );
            println!(
                "  evidence:      {}/{}",
                scope.evidence_supplied, scope.evidence_total
            );
            println!(
                "  coverage items: {}/{}",
                scope.coverage_items_supplied, scope.coverage_items_total
            );
            println!(
                "  entities:      {}/{}",
                scope.entities_supplied, scope.entities_total
            );
            println!(
                "  references:    {}/{}",
                scope.semantic_references_supplied, scope.semantic_references_total
            );
            println!(
                "  relationships: {}/{}",
                scope.semantic_relationships_supplied, scope.semantic_relationships_total
            );
        }
        for item in &ir.coverage.items {
            if matches!(
                item.disposition,
                repo2okf_core::CoverageDisposition::Unresolved { .. }
            ) {
                println!("  unresolved: {}", item.subject);
            }
        }
    }
    Ok(())
}

fn build_ir(repository: &io::RepositoryGuard, config: &Config) -> Result<RepositoryIr> {
    repository.verify()?;
    let languages = config
        .scan
        .languages
        .iter()
        .map(|language| parse_language(language))
        .collect::<Result<BTreeSet<_>>>()?;
    let excluded_roots = [
        &config.output.directory,
        &config.output.ir_file,
        &config.output.state_file,
    ]
    .into_iter()
    .filter_map(|path| first_relative_component(path.as_path()))
    .collect();
    let options = ScanOptions {
        include_hidden: config.scan.include_hidden,
        max_file_bytes: config.scan.max_file_bytes,
        languages,
        // Never execute repository-controlled Git configuration during the
        // default untrusted scan path (for example core.fsmonitor hooks).
        prefer_git: false,
        excluded_roots,
    };
    let ir = scan_repository(repository.path(), &options).context("repository scan failed")?;
    repository.verify()?;
    Ok(ir)
}

fn first_relative_component(path: &Path) -> Option<PathBuf> {
    match path.components().next()? {
        std::path::Component::Normal(component) => Some(PathBuf::from(component)),
        _ => None,
    }
}

fn parse_language(language: &str) -> Result<Language> {
    match language.to_ascii_lowercase().as_str() {
        "javascript" | "js" => Ok(Language::JavaScript),
        "typescript" | "ts" => Ok(Language::TypeScript),
        "python" | "py" => Ok(Language::Python),
        "go" | "golang" => Ok(Language::Go),
        "rust" | "rs" => Ok(Language::Rust),
        "markdown" | "md" => Ok(Language::Markdown),
        _ => bail!("unsupported scan language `{language}`"),
    }
}

fn effective_agent(args: &CompileArgs) -> AgentSelection {
    if args.facts_only {
        return AgentSelection::Off;
    }
    args.agent.unwrap_or(AgentSelection::Off)
}

fn select_driver(
    selection: AgentSelection,
    repository: &Path,
    config: &Config,
    exclude: Option<AgentKind>,
    allow_agent_filesystem: bool,
) -> Result<Box<dyn AgentDriver>> {
    let process = process_config(repository, config, allow_agent_filesystem);
    let codex = CodexDriver::new();
    let claude = ClaudeDriver::new();
    let codex_probe = codex.probe(&process);
    let claude_probe = claude.probe(&process);
    let chosen = choose_agent_kind(
        selection,
        &codex_probe,
        &claude_probe,
        exclude,
        allow_agent_filesystem,
    );

    match (selection, chosen) {
        (_, Some(AgentKind::Codex)) => Ok(Box::new(codex)),
        (_, Some(AgentKind::Claude)) => Ok(Box::new(claude)),
        (AgentSelection::Off, None) => bail!("agent selection is off"),
        (AgentSelection::Codex, None) if !allow_agent_filesystem => bail!(
            "Codex read-only sandbox still permits repository reads; pass --allow-agent-filesystem to opt in explicitly"
        ),
        (AgentSelection::Auto, None) => bail!(
            "no safe, supported agent CLI is available; run `repo2okf doctor` or use --facts-only"
        ),
        (AgentSelection::Codex, None) => bail!(
            "Codex CLI is missing, unsupported, or already used as the primary agent; run `repo2okf doctor`"
        ),
        (AgentSelection::Claude, None) => bail!(
            "Claude Code CLI is missing, unauthenticated, unsupported, or already used as the primary agent; run `repo2okf doctor`"
        ),
    }
}

fn safe_agent_probe(probe: &AgentProbe) -> bool {
    let authentication_ready = match probe.kind {
        AgentKind::Codex => probe.authenticated != Some(false),
        AgentKind::Claude => probe.authenticated == Some(true),
    };
    probe.executable.is_some()
        && authentication_ready
        && probe.capabilities.non_interactive
        && probe.capabilities.output_schema
        && probe.capabilities.read_only
        && probe.capabilities.hermetic
}

fn choose_agent_kind(
    selection: AgentSelection,
    codex: &AgentProbe,
    claude: &AgentProbe,
    exclude: Option<AgentKind>,
    allow_agent_filesystem: bool,
) -> Option<AgentKind> {
    let codex_ready =
        allow_agent_filesystem && exclude != Some(AgentKind::Codex) && safe_agent_probe(codex);
    let claude_ready = exclude != Some(AgentKind::Claude) && safe_agent_probe(claude);
    match selection {
        AgentSelection::Codex => codex_ready.then_some(AgentKind::Codex),
        AgentSelection::Claude => claude_ready.then_some(AgentKind::Claude),
        AgentSelection::Auto if claude_ready => Some(AgentKind::Claude),
        AgentSelection::Auto if codex_ready => Some(AgentKind::Codex),
        AgentSelection::Off | AgentSelection::Auto => None,
    }
}

fn process_config(
    repository: &Path,
    config: &Config,
    allow_agent_filesystem: bool,
) -> ProcessConfig {
    let mut process = ProcessConfig::new(repository.to_path_buf());
    process.timeout = Duration::from_secs(config.agent.timeout_seconds);
    // Repository configuration cannot weaken this trust boundary.
    process.hermetic = true;
    process.allow_repository_access = allow_agent_filesystem;
    process
}

fn output_directory(
    repository: &Path,
    config: &Config,
    override_path: Option<&Path>,
) -> Result<PathBuf> {
    let path = override_path.unwrap_or(&config.output.directory);
    ensure_generated_directory(path)?;
    io::resolve_beneath(repository, path)
}

fn ensure_generated_directory(path: &Path) -> Result<()> {
    if path != Path::new(".okf") {
        bail!("generated output is reserved and must be `.okf`");
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the publication transaction explicitly names its artifacts and policy inputs"
)]
fn publish_compilation(
    repository: &io::RepositoryGuard,
    snapshot: &RepositorySnapshot,
    ir: &RepositoryIr,
    state: &BuildState,
    bundle_destination: &Path,
    config: &Config,
    strict: bool,
) -> Result<(EmissionReport, VerificationReport)> {
    if bundle_destination == Path::new("") {
        bail!("output destination must not be empty");
    }
    ensure_replaceable_bundle(bundle_destination)?;

    repository.verify()?;
    let mut publication = io::PublishPlan::new(repository)?;
    let staging = publication.staging_path("bundle")?;
    let staged_cache = publication.staging_path("cache")?;
    let report = emit_okf(snapshot, &staging)?;
    fs::write(
        staging.join(OWNERSHIP_MARKER_FILE),
        OWNERSHIP_MARKER_CONTENT,
    )?;
    let verification = verify_snapshot(&staging, snapshot, config, strict);
    ensure_verification(&verification, strict)?;
    stage_cache_artifacts(
        &staged_cache,
        &config.output.ir_file,
        &config.output.state_file,
        ir,
        state,
    )?;

    publication.add_owned_directory(
        staging,
        bundle_destination.to_path_buf(),
        Path::new(OWNERSHIP_MARKER_FILE),
        OWNERSHIP_MARKER_CONTENT,
    )?;
    publication.add_owned_directory(
        staged_cache,
        repository.path().join(CACHE_DIRECTORY),
        Path::new(OWNERSHIP_MARKER_FILE),
        CACHE_OWNERSHIP_MARKER_CONTENT,
    )?;
    // Re-check after the potentially expensive emission and verification so
    // an output replaced during staging does not silently lose ownership.
    ensure_replaceable_bundle(bundle_destination)?;
    publication.commit()?;
    Ok((
        EmissionReport {
            output_dir: bundle_destination.to_path_buf(),
            ..report
        },
        verification,
    ))
}

fn publish_cache(
    repository: &io::RepositoryGuard,
    ir_path: &Path,
    state_path: &Path,
    ir: &RepositoryIr,
    state: &BuildState,
) -> Result<()> {
    repository.verify()?;
    let mut publication = io::PublishPlan::new(repository)?;
    let staged_cache = publication.staging_path("cache")?;
    stage_cache_artifacts(&staged_cache, ir_path, state_path, ir, state)?;
    publication.add_owned_directory(
        staged_cache,
        repository.path().join(CACHE_DIRECTORY),
        Path::new(OWNERSHIP_MARKER_FILE),
        CACHE_OWNERSHIP_MARKER_CONTENT,
    )?;
    publication.commit()
}

fn stage_cache_artifacts(
    staged_cache: &Path,
    ir_path: &Path,
    state_path: &Path,
    ir: &RepositoryIr,
    state: &BuildState,
) -> Result<()> {
    let staged_ir = staged_cache_path(staged_cache, ir_path)?;
    let staged_state = staged_cache_path(staged_cache, state_path)?;
    if staged_ir == staged_state {
        bail!("staged IR and build state paths must differ");
    }
    fs::create_dir(staged_cache).with_context(|| {
        format!(
            "failed to create staged cache directory {}",
            staged_cache.display()
        )
    })?;
    fs::write(
        staged_cache.join(OWNERSHIP_MARKER_FILE),
        CACHE_OWNERSHIP_MARKER_CONTENT,
    )?;
    io::write_json(&staged_ir, ir)?;
    io::write_json(&staged_state, state)?;
    let staged_ir_round_trip: RepositoryIr = io::read_json(&staged_ir)?;
    staged_ir_round_trip
        .validate()
        .map_err(anyhow::Error::msg)?;
    if staged_ir_round_trip != *ir {
        bail!("staged persisted IR did not round-trip exactly");
    }
    let staged_state_round_trip: BuildState = io::read_json(&staged_state)?;
    if staged_state_round_trip != *state {
        bail!("staged build state did not round-trip exactly");
    }
    if persisted_ir_hash(&staged_ir_round_trip)? != staged_state_round_trip.persisted_ir_hash {
        bail!("staged build state does not authenticate the staged persisted IR");
    }
    Ok(())
}

fn staged_cache_path(staged_cache: &Path, configured: &Path) -> Result<PathBuf> {
    if !config::is_reserved_state_path(configured) {
        bail!(
            "cache artifact must be inside the reserved `.repo2okf` directory: {}",
            configured.display()
        );
    }
    let relative = configured
        .strip_prefix(Path::new(CACHE_DIRECTORY))
        .with_context(|| format!("invalid cache artifact path {}", configured.display()))?;
    Ok(staged_cache.join(relative))
}

fn ensure_replaceable_bundle(destination: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect output bundle {}", destination.display())
            });
        }
    };
    if io::is_link_or_reparse_point(&metadata) {
        bail!(
            "refusing to replace link-like output: {}",
            destination.display()
        );
    }
    if !metadata.is_dir() {
        bail!(
            "output exists and is not a directory: {}",
            destination.display()
        );
    }
    let ownership_marker = destination.join(OWNERSHIP_MARKER_FILE);
    let owned =
        io::matches_fixed_file(&ownership_marker, OWNERSHIP_MARKER_CONTENT).with_context(|| {
            format!(
                "failed to validate output ownership marker {}",
                ownership_marker.display()
            )
        })?;
    if !owned {
        bail!(
            "refusing to replace an unowned output directory: {}; remove it or choose the reserved `.okf` path after preserving its contents",
            destination.display()
        );
    }
    Ok(())
}

fn verify_snapshot(
    output: &Path,
    snapshot: &RepositorySnapshot,
    config: &Config,
    strict: bool,
) -> VerificationReport {
    verify_okf(
        output,
        &snapshot.evidence,
        &snapshot.coverage,
        &verification_options(config, strict, Some(snapshot), false, false),
    )
}

fn verification_options(
    config: &Config,
    strict: bool,
    snapshot: Option<&RepositorySnapshot>,
    repository_changed: bool,
    generated_bundle_changed: bool,
) -> VerifyOptions {
    let mut freshness_mismatches = BTreeSet::new();
    if repository_changed {
        freshness_mismatches.insert(FreshnessMismatch::Repository);
    }
    if generated_bundle_changed {
        freshness_mismatches.insert(FreshnessMismatch::GeneratedBundle);
    }
    VerifyOptions {
        minimum_coverage: if strict {
            config.verify.minimum_coverage.max(1.0)
        } else {
            config.verify.minimum_coverage
        },
        broken_links_are_errors: strict,
        stale_documents_are_errors: strict,
        expected_concepts: snapshot.map(|snapshot| {
            snapshot
                .documents
                .iter()
                .map(|document| document.id.clone())
                .collect()
        }),
        semantic_inventory: snapshot.and_then(|snapshot| snapshot.semantic_inventory.clone()),
        expected_output_locale: Some(config.output.locale),
        freshness_mismatches,
        ..VerifyOptions::default()
    }
}

fn ensure_verification(report: &VerificationReport, strict: bool) -> Result<()> {
    if !report.valid || (strict && report.warnings > 0) {
        print_verification(report);
        return verification_failure(report);
    }
    Ok(())
}

fn ensure_verification_quiet(report: &VerificationReport, strict: bool) -> Result<()> {
    if !report.valid || (strict && report.warnings > 0) {
        return verification_failure(report);
    }
    Ok(())
}

fn verification_failure(report: &VerificationReport) -> Result<()> {
    bail!(
        "OKF verification failed with {} error(s) and {} warning(s)",
        report.errors,
        report.warnings
    )
}

fn print_verification(report: &VerificationReport) {
    println!(
        "verification: {} concept(s), {:.1}% coverage, {} error(s), {} warning(s)",
        report.concepts,
        report.coverage * 100.0,
        report.errors,
        report.warnings
    );
    for issue in &report.issues {
        let severity = match issue.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        let document = issue
            .document
            .as_deref()
            .map_or_else(String::new, |path| format!(" {path}"));
        println!("  {severity} [{}]{document}: {}", issue.code, issue.message);
    }
}

fn persisted_ir_hash(ir: &RepositoryIr) -> Result<String> {
    let bytes = serde_json::to_vec(ir)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn deterministic_ir_matches(saved: &RepositoryIr, current: &RepositoryIr) -> bool {
    saved.schema_version == current.schema_version
        && saved.repository == current.repository
        && saved.files == current.files
        && saved.entities == current.entities
        && saved.imports == current.imports
        && saved.evidence == current.evidence
        && saved.relationships == current.relationships
        && saved.semantic_references == current.semantic_references
        && saved.semantic_coverage == current.semantic_coverage
        && saved.coverage == current.coverage
        && saved
            .claims
            .iter()
            .filter(|claim| matches!(claim.provenance, ClaimProvenance::Deterministic { .. }))
            .eq(current.claims.iter())
}

fn config_fingerprint(config: &Config) -> Result<String> {
    let serialized = toml::to_string(config)?;
    Ok(blake3::hash(serialized.as_bytes()).to_hex().to_string())
}

fn build_fingerprint(repository: &Path, config: &Config, args: &CompileArgs) -> Result<String> {
    #[derive(Serialize)]
    struct BuildInputs<'a> {
        config: &'a Config,
        agent: AgentSelection,
        review_with: Option<AgentSelection>,
        strict: bool,
        agent_contract_version: &'static str,
        agent_runtime: Vec<String>,
        allow_agent_filesystem: bool,
        reuse_agent_cache: bool,
    }

    let process = process_config(repository, config, args.allow_agent_filesystem);
    let mut agent_runtime = Vec::new();
    let selection = effective_agent(args);
    let mut primary_kind = None;
    if selection != AgentSelection::Off {
        let (identity, kind) =
            probed_identity(selection, &process, None, args.allow_agent_filesystem);
        agent_runtime.push(identity);
        primary_kind = kind;
    }
    if let Some(review) = args
        .review_with
        .filter(|value| *value != AgentSelection::Off)
    {
        agent_runtime
            .push(probed_identity(review, &process, primary_kind, args.allow_agent_filesystem).0);
    }
    let serialized = serde_json::to_vec(&BuildInputs {
        config,
        agent: effective_agent(args),
        review_with: args.review_with,
        strict: args.strict,
        agent_contract_version: AGENT_CONTRACT_VERSION,
        agent_runtime,
        allow_agent_filesystem: args.allow_agent_filesystem,
        reuse_agent_cache: args.reuse_agent_cache,
    })?;
    Ok(blake3::hash(&serialized).to_hex().to_string())
}

fn probed_identity(
    selection: AgentSelection,
    process: &ProcessConfig,
    exclude: Option<AgentKind>,
    allow_agent_filesystem: bool,
) -> (String, Option<AgentKind>) {
    let codex = CodexDriver::new().probe(process);
    let claude = ClaudeDriver::new().probe(process);
    let chosen = choose_agent_kind(selection, &codex, &claude, exclude, allow_agent_filesystem);
    let identity = chosen.map_or_else(
        || format!("unavailable:{selection:?}"),
        |kind| {
            let probe = if kind == AgentKind::Codex {
                &codex
            } else {
                &claude
            };
            format!(
                "{}@{}",
                kind.command_name(),
                probe.version.as_deref().unwrap_or("unknown")
            )
        },
    );
    (identity, chosen)
}

fn init_tracing(verbosity: u8) {
    let default_level = match verbosity {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[cfg(test)]
mod tests {
    use repo2okf_core::Language;

    use super::parse_language;

    #[test]
    fn parses_python_language_names() {
        assert_eq!(
            parse_language("python").expect("python language"),
            Language::Python
        );
        assert_eq!(
            parse_language("py").expect("python alias"),
            Language::Python
        );
        assert_eq!(
            parse_language("Py").expect("case-insensitive alias"),
            Language::Python
        );
    }
}
