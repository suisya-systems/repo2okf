//! Serializable agent requests, responses and capability reports.

use std::path::PathBuf;

use repo2okf_core::{Claim, CoverageItem, EvidenceRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Supported vendor agent driver.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    /// `OpenAI Codex` CLI.
    Codex,
    /// Anthropic `Claude Code` CLI.
    Claude,
}

impl AgentKind {
    /// Expected command name.
    pub const fn command_name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

/// CLI features required or detected by an adapter.
#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent booleans mirror vendor CLI capability probes"
)]
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AgentCapabilities {
    /// Non-interactive execution is available.
    pub non_interactive: bool,
    /// JSONL event output is available.
    pub jsonl: bool,
    /// Final response JSON Schema enforcement is available.
    pub output_schema: bool,
    /// Read-only tool/sandbox restriction is available.
    pub read_only: bool,
    /// User/project customization can be suppressed.
    pub hermetic: bool,
    /// Authentication status can be probed without reading token files.
    pub auth_status: bool,
}

/// Read-only result of probing an installed vendor CLI.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct AgentProbe {
    /// Vendor kind.
    pub kind: AgentKind,
    /// Resolved executable or script path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<PathBuf>,
    /// Reported version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// True only when the vendor CLI positively confirms authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    /// Detected capabilities.
    pub capabilities: AgentCapabilities,
    /// Non-secret diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

impl AgentProbe {
    /// Whether this CLI can satisfy `Repo2OKF`'s safe enrichment contract.
    pub fn ready(&self, hermetic: bool) -> bool {
        self.executable.is_some()
            && self.authenticated.unwrap_or(false)
            && self.capabilities.non_interactive
            && self.capabilities.output_schema
            && self.capabilities.read_only
            && (!hermetic || self.capabilities.hermetic)
    }
}

/// Bounded semantic-enrichment task sent to a vendor CLI.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct EnrichmentRequest {
    /// Repository display name.
    pub repository: String,
    /// Deterministic IR fingerprint.
    pub ir_fingerprint: String,
    /// Complete evidence catalog available to claims.
    pub evidence: Vec<EvidenceRef>,
    /// Host-verified, bounded source text corresponding to evidence records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_excerpts: Vec<EvidenceExcerpt>,
    /// Items that still benefit from semantic explanation.
    pub coverage: Vec<CoverageItem>,
    /// Agent-generated claims supplied to an optional review pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub existing_agent_claims: Vec<Claim>,
    /// Previously rejected output diagnostics during a repair attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_issues: Vec<ValidationIssue>,
}

/// A bounded excerpt read and verified by the host before agent invocation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExcerpt {
    /// Evidence record this text was derived from.
    pub evidence_id: String,
    /// Normalized repository-relative source path.
    pub path: String,
    /// One-based inclusive starting line of the original evidence span.
    pub start_line: u32,
    /// One-based inclusive ending line of the original evidence span.
    pub end_line: u32,
    /// UTF-8 source text, capped by the host policy.
    pub text: String,
    /// Whether the evidence span exceeded the per-excerpt byte limit.
    pub truncated: bool,
}

/// Schema-constrained result returned by a vendor CLI.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichmentResponse {
    /// Evidence-bound semantic claims.
    #[serde(default)]
    pub claims: Vec<Claim>,
    /// Evidence-backed summary suitable for an OKF bundle index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_summary: Option<String>,
    /// Evidence IDs supporting the repository summary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summary_evidence_ids: Vec<String>,
}

/// A machine-readable response validation issue.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ValidationIssue {
    /// Stable issue code.
    pub code: String,
    /// Owning claim or response field.
    pub subject: String,
    /// Human-readable repair guidance.
    pub message: String,
}

/// Usage and repair metadata from an enrichment run.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct EnrichmentStats {
    /// Number of vendor CLI invocations.
    pub attempts: usize,
    /// Number of validation issues returned to the agent.
    pub repaired_issues: usize,
    /// Reported input token count when present in vendor output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Reported output token count when present in vendor output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
}
