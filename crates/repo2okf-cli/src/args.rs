//! Command-line argument definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Evidence-bound repository-to-OKF compiler.
#[derive(Debug, Parser)]
#[command(name = "repo2okf", version, about, propagate_version = true)]
pub struct Cli {
    /// Repository to process. Defaults to the current directory.
    #[arg(long, global = true, value_name = "PATH", default_value = ".")]
    pub repository: PathBuf,

    /// Explicit configuration file.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Increase diagnostic verbosity (-v or -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a documented starter configuration.
    Init(InitArgs),
    /// Diagnose repository and agent CLI readiness.
    Doctor(DoctorArgs),
    /// Build deterministic repository IR without invoking an agent.
    Scan(ScanArgs),
    /// Compile the repository to OKF v0.2.
    Compile(CompileArgs),
    /// Rebuild changed repositories and skip byte-identical builds.
    Update(CompileArgs),
    /// Verify generated OKF and its source evidence.
    Verify(VerifyArgs),
    /// Report inventory coverage from the last scan.
    Coverage(CoverageArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Replace an existing configuration.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit a stable JSON report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Emit the IR to stdout instead of a file.
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, ValueEnum)]
pub enum AgentSelection {
    /// Use no semantic agent.
    Off,
    /// Select the first supported, authenticated agent CLI.
    Auto,
    /// Use Codex CLI and its existing login.
    Codex,
    /// Use Claude Code CLI and its existing login.
    Claude,
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CLI switches are clearer than wrapper enums at the argument boundary"
)]
pub struct CompileArgs {
    /// Agent used for semantic enrichment.
    #[arg(long, value_enum)]
    pub agent: Option<AgentSelection>,

    /// Disable all agent calls, even when configured.
    #[arg(long, conflicts_with = "agent")]
    pub facts_only: bool,

    /// Optionally review generated claims with the other agent.
    #[arg(
        long,
        value_enum,
        value_name = "AGENT",
        conflicts_with = "facts_only",
        requires = "agent"
    )]
    pub review_with: Option<AgentSelection>,

    /// Allow agent CLIs that cannot prevent repository filesystem reads.
    #[arg(long, conflicts_with = "facts_only", requires = "agent")]
    pub allow_agent_filesystem: bool,

    /// Trust and reuse agent claims from compiler-owned local state.
    #[arg(long, conflicts_with = "facts_only", requires = "agent")]
    pub reuse_agent_cache: bool,

    /// Output directory for OKF documents.
    #[arg(long, value_name = "DIRECTORY")]
    pub output: Option<PathBuf>,

    /// Fail when verification warnings or unresolved coverage remain.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// OKF bundle directory to verify.
    #[arg(value_name = "PATH")]
    pub target: Option<PathBuf>,

    /// Treat warnings and insufficient coverage as errors.
    #[arg(long)]
    pub strict: bool,

    /// Emit a stable JSON report.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct CoverageArgs {
    /// Emit a stable JSON report.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{AgentSelection, Cli, Command};

    #[test]
    fn parses_facts_only_compile() {
        let cli = Cli::try_parse_from(["repo2okf", "compile", "--facts-only", "--strict"])
            .expect("arguments should parse");
        let Command::Compile(args) = cli.command else {
            panic!("expected compile command");
        };
        assert!(args.facts_only);
        assert!(args.strict);
    }

    #[test]
    fn parses_explicit_agent() {
        let cli = Cli::try_parse_from(["repo2okf", "compile", "--agent", "claude"])
            .expect("arguments should parse");
        let Command::Compile(args) = cli.command else {
            panic!("expected compile command");
        };
        assert_eq!(args.agent, Some(AgentSelection::Claude));
    }

    #[test]
    fn facts_only_conflicts_with_agent() {
        let error =
            Cli::try_parse_from(["repo2okf", "compile", "--facts-only", "--agent", "codex"])
                .expect_err("conflicting arguments should fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn review_requires_primary_agent() {
        let error = Cli::try_parse_from(["repo2okf", "compile", "--review-with", "claude"])
            .expect_err("review without a primary agent should fail");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn agent_cache_reuse_requires_explicit_agent() {
        let error = Cli::try_parse_from(["repo2okf", "update", "--reuse-agent-cache"])
            .expect_err("cache trust must accompany an explicit agent selection");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );

        let cli = Cli::try_parse_from([
            "repo2okf",
            "update",
            "--agent",
            "claude",
            "--reuse-agent-cache",
        ])
        .expect("explicit cache trust should parse");
        assert!(matches!(cli.command, Command::Update(_)));
    }

    #[test]
    fn agent_filesystem_opt_in_requires_explicit_agent() {
        let error = Cli::try_parse_from(["repo2okf", "compile", "--allow-agent-filesystem"])
            .expect_err("filesystem trust must accompany an explicit agent selection");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn scan_output_is_configured_only() {
        let error = Cli::try_parse_from(["repo2okf", "scan", "--output", ".repo2okf/custom.json"])
            .expect_err("scan output overrides would break the cache path contract");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
