//! Configuration loading, defaults and validation.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use repo2okf_core::OutputLocale;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_FILE: &str = "repo2okf.toml";
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub scan: ScanConfig,
    pub output: OutputConfig,
    pub agent: AgentConfig,
    pub verify: VerifyConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema: 1,
            scan: ScanConfig::default(),
            output: OutputConfig::default(),
            agent: AgentConfig::default(),
            verify: VerifyConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub include_hidden: bool,
    pub max_file_bytes: u64,
    pub languages: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_hidden: false,
            max_file_bytes: 2 * 1024 * 1024,
            languages: vec![
                "typescript".into(),
                "javascript".into(),
                "python".into(),
                "go".into(),
                "rust".into(),
                "markdown".into(),
            ],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    pub directory: PathBuf,
    pub ir_file: PathBuf,
    pub state_file: PathBuf,
    pub locale: OutputLocale,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(".okf"),
            ir_file: PathBuf::from(".repo2okf/ir.json"),
            state_file: PathBuf::from(".repo2okf/state.json"),
            locale: OutputLocale::En,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub max_repair_attempts: usize,
    pub timeout_seconds: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_repair_attempts: 2,
            timeout_seconds: 600,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VerifyConfig {
    pub minimum_coverage: f64,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            minimum_coverage: 0.0,
        }
    }
}

impl Config {
    pub fn load(repository: &Path, explicit: Option<&Path>) -> Result<Self> {
        let path = match explicit {
            Some(path) if path.is_absolute() => path.to_path_buf(),
            Some(path) => crate::io::resolve_beneath(repository, path)?,
            None => crate::io::resolve_beneath(repository, Path::new(DEFAULT_CONFIG_FILE))?,
        };
        let required = explicit.is_some();

        match fs::symlink_metadata(&path) {
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                config.validate()?;
                return Ok(config);
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect configuration {}", path.display())
                });
            }
            Ok(_) => {}
        }
        let (file, length) = crate::io::open_regular_file(&path)
            .with_context(|| format!("failed to load configuration {}", path.display()))?;
        if length > MAX_CONFIG_BYTES {
            bail!(
                "configuration exceeds the 1 MiB safety limit: {}",
                path.display()
            );
        }
        let capacity = usize::try_from(length).unwrap_or(usize::MAX);
        let mut bytes = Vec::with_capacity(capacity);
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read configuration {}", path.display()))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
            bail!(
                "configuration exceeds the 1 MiB safety limit: {}",
                path.display()
            );
        }
        let source = String::from_utf8(bytes)
            .with_context(|| format!("configuration is not UTF-8: {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("invalid configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn write_starter(repository: &Path, force: bool) -> Result<PathBuf> {
        let path = crate::io::resolve_beneath(repository, Path::new(DEFAULT_CONFIG_FILE))?;
        if path.exists() && !force {
            bail!(
                "configuration already exists at {}; pass --force to replace it",
                path.display()
            );
        }
        let rendered = toml::to_string_pretty(&Self::default())
            .context("failed to serialize starter configuration")?;
        crate::io::write_bytes(&path, rendered.as_bytes())
            .with_context(|| format!("failed to write configuration {}", path.display()))?;
        Ok(path)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            bail!(
                "unsupported configuration schema {}; expected 1",
                self.schema
            );
        }
        if self.scan.max_file_bytes == 0 {
            bail!("scan.max_file_bytes must be greater than zero");
        }
        if self.scan.max_file_bytes > 64 * 1024 * 1024 {
            bail!("scan.max_file_bytes must not exceed 67108864 bytes");
        }
        if self.scan.languages.is_empty() {
            bail!("scan.languages must contain at least one language");
        }
        if self.output.directory.as_os_str().is_empty()
            || self.output.ir_file.as_os_str().is_empty()
            || self.output.state_file.as_os_str().is_empty()
        {
            bail!("output paths must not be empty");
        }
        if self.output.directory != Path::new(".okf") {
            bail!("output.directory is reserved and must be `.okf`");
        }
        for (name, path) in [
            ("output.ir_file", &self.output.ir_file),
            ("output.state_file", &self.output.state_file),
        ] {
            if !is_reserved_state_path(path) {
                bail!("{name} must be inside the reserved `.repo2okf` directory");
            }
        }
        let ir_portable = self.output.ir_file.to_string_lossy().to_ascii_lowercase();
        let state_portable = self
            .output
            .state_file
            .to_string_lossy()
            .to_ascii_lowercase();
        if self.output.ir_file == self.output.state_file
            || self.output.ir_file.starts_with(&self.output.state_file)
            || self.output.state_file.starts_with(&self.output.ir_file)
            || ir_portable == state_portable
            || ir_portable.starts_with(&(state_portable.clone() + "/"))
            || state_portable.starts_with(&(ir_portable + "/"))
        {
            bail!("output.ir_file and output.state_file must be distinct, non-nested files");
        }
        if self.agent.max_repair_attempts > 5 {
            bail!("agent.max_repair_attempts must not exceed 5");
        }
        if self.agent.timeout_seconds == 0 {
            bail!("agent.timeout_seconds must be greater than zero");
        }
        if self.agent.timeout_seconds > 3600 {
            bail!("agent.timeout_seconds must not exceed 3600");
        }
        if !(0.0..=1.0).contains(&self.verify.minimum_coverage) {
            bail!("verify.minimum_coverage must be between 0 and 1");
        }
        Ok(())
    }
}

/// Return whether a path is a file below the reserved state directory.
pub(crate) fn is_reserved_state_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(std::path::Component::Normal(value)) if value == ".repo2okf")
        && components.next().is_some()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use repo2okf_core::OutputLocale;

    use super::{Config, MAX_CONFIG_BYTES};

    #[test]
    fn defaults_are_valid_and_round_trip() {
        let config = Config::default();
        config.validate().expect("default should be valid");
        assert!(config.scan.languages.iter().any(|value| value == "python"));
        let encoded = toml::to_string(&config).expect("serialize config");
        assert!(encoded.contains("locale = \"en\""));
        let decoded: Config = toml::from_str(&encoded).expect("deserialize config");
        decoded.validate().expect("round-trip should be valid");
        assert_eq!(decoded.output.locale, OutputLocale::En);
    }

    #[test]
    fn rejects_unknown_fields() {
        let error = toml::from_str::<Config>("schema = 1\nunknown = true")
            .expect_err("unknown field should fail");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn accepts_supported_output_locales_and_rejects_unknown_values() {
        let japanese: Config =
            toml::from_str("[output]\nlocale = \"ja\"\n").expect("Japanese locale");
        assert_eq!(japanese.output.locale, OutputLocale::Ja);

        let error = toml::from_str::<Config>("[output]\nlocale = \"fr\"\n")
            .expect_err("unsupported locale should fail");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn rejects_output_over_source_tree() {
        let mut config = Config::default();
        config.output.directory = "docs".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_protected_dot_directory() {
        let mut config = Config::default();
        config.output.directory = ".git".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn starter_does_not_overwrite_by_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = Config::write_starter(temp.path(), false).expect("write starter");
        fs::write(&path, "custom").expect("replace fixture");
        assert!(Config::write_starter(temp.path(), false).is_err());
        assert_eq!(fs::read_to_string(path).expect("read fixture"), "custom");
    }

    #[test]
    fn resolves_explicit_relative_config_from_repository() {
        let repository = tempfile::tempdir().expect("repository");
        fs::create_dir(repository.path().join("settings")).expect("settings directory");
        fs::write(
            repository.path().join("settings/custom.toml"),
            "[verify]\nminimum_coverage = 0.42\n",
        )
        .expect("write config");

        let config = Config::load(repository.path(), Some(Path::new("settings/custom.toml")))
            .expect("load repository-relative config");
        assert!((config.verify.minimum_coverage - 0.42).abs() < f64::EPSILON);
    }

    #[test]
    fn preserves_explicit_absolute_config_path() {
        let repository = tempfile::tempdir().expect("repository");
        let external = tempfile::tempdir().expect("external config directory");
        let path = external.path().join("custom.toml");
        fs::write(&path, "[verify]\nminimum_coverage = 0.75\n").expect("write config");

        let config = Config::load(repository.path(), Some(&path)).expect("load absolute config");
        assert!((config.verify.minimum_coverage - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn explicit_missing_or_non_regular_config_fails_closed() {
        let repository = tempfile::tempdir().expect("repository");
        assert!(Config::load(repository.path(), Some(Path::new("missing.toml"))).is_err());
        fs::create_dir(repository.path().join("directory.toml")).expect("directory fixture");
        assert!(Config::load(repository.path(), Some(Path::new("directory.toml"))).is_err());
    }

    #[test]
    fn enforces_config_size_at_the_exact_boundary() {
        let repository = tempfile::tempdir().expect("repository");
        let path = repository.path().join("bounded.toml");
        let mut exact = b"schema = 1\n#".to_vec();
        exact.resize(
            usize::try_from(MAX_CONFIG_BYTES).expect("config limit fits usize"),
            b'x',
        );
        fs::write(&path, &exact).expect("write exact-limit config");
        Config::load(repository.path(), Some(&path)).expect("exact limit should load");

        exact.push(b'x');
        fs::write(&path, exact).expect("write oversized config");
        let error =
            Config::load(repository.path(), Some(&path)).expect_err("oversized config should fail");
        assert!(error.to_string().contains("1 MiB safety limit"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_config() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().expect("repository");
        fs::write(repository.path().join("real.toml"), "schema = 1\n").expect("real config");
        symlink(
            repository.path().join("real.toml"),
            repository.path().join("linked.toml"),
        )
        .expect("config symlink");
        assert!(Config::load(repository.path(), Some(Path::new("linked.toml"))).is_err());
    }
}
