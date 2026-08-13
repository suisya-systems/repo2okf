//! Cross-platform, shell-free process launch helpers.

use std::{
    ffi::OsString,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

const MAX_EXIT_STDERR_CHARS: usize = 4000;
const STDERR_TRUNCATED_MARKER: &str = "[... stderr prefix truncated ...]\n";

/// Process execution policy shared by both vendor adapters.
#[derive(Clone, Debug)]
pub struct ProcessConfig {
    /// Repository working directory.
    pub repository: PathBuf,
    /// Maximum wall-clock duration. Process-tree cancellation is platform-specific.
    pub timeout: Duration,
    /// Maximum captured bytes per stream.
    pub max_output_bytes: usize,
    /// Suppress user/project customizations where the CLI supports it.
    pub hermetic: bool,
    /// Explicitly permit an adapter to expose the repository filesystem.
    ///
    /// The default is false. This is currently required by `Codex`, whose
    /// read-only sandbox prevents writes but still permits repository reads.
    pub allow_repository_access: bool,
}

impl ProcessConfig {
    /// Conservative defaults for a trusted local repository.
    pub fn new(repository: PathBuf) -> Self {
        Self {
            repository,
            timeout: Duration::from_secs(600),
            max_output_bytes: 16 * 1024 * 1024,
            hermetic: false,
            allow_repository_access: false,
        }
    }
}

/// Agent discovery, invocation or response failure.
#[derive(Debug, Error)]
pub enum AgentError {
    /// Vendor command was not found.
    #[error("{0} CLI was not found on PATH")]
    NotFound(&'static str),
    /// Process creation or I/O failed.
    #[error("could not run {program}: {source}")]
    Process {
        /// Vendor command label.
        program: &'static str,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Vendor CLI exited unsuccessfully.
    #[error("{program} exited unsuccessfully ({status}): {stderr}")]
    Exit {
        /// Vendor command label.
        program: &'static str,
        /// Numeric or platform status.
        status: String,
        /// Bounded stderr excerpt.
        stderr: String,
    },
    /// Vendor stdout exceeded the configured bound.
    #[error("{0} output exceeded the configured byte limit")]
    OutputTooLarge(&'static str),
    /// Vendor CLI exceeded its wall-clock budget and was terminated.
    #[error("{program} exceeded its {seconds}s timeout")]
    Timeout {
        /// Vendor command label.
        program: &'static str,
        /// Configured timeout in seconds.
        seconds: u64,
    },
    /// The installed vendor CLI predates the minimum safe adapter contract.
    #[error("{program} CLI version {found} is unsupported; version {minimum} or newer is required")]
    UnsupportedVersion {
        /// Vendor command label.
        program: &'static str,
        /// Reported version, or `unknown` when it could not be parsed.
        found: String,
        /// Minimum supported semantic version.
        minimum: &'static str,
    },
    /// Vendor output could not be decoded.
    #[error("invalid {program} output: {message}")]
    InvalidOutput {
        /// Vendor command label.
        program: &'static str,
        /// Safe parsing diagnostic.
        message: String,
    },
    /// Response failed evidence validation after the repair budget.
    #[error("agent response remained invalid after {attempts} attempt(s): {issues:?}")]
    InvalidClaims {
        /// CLI invocation count.
        attempts: usize,
        /// Final validation diagnostics.
        issues: Vec<crate::ValidationIssue>,
    },
    /// The adapter cannot guarantee that repository files remain inaccessible.
    #[error(
        "{program} cannot guarantee a no-filesystem agent boundary; explicitly opt in to repository access"
    )]
    RepositoryAccessRequired {
        /// Vendor command label.
        program: &'static str,
    },
}

pub(crate) fn resolve_command(name: &'static str) -> Result<PathBuf, AgentError> {
    // Do not consider the current repository directory during executable
    // lookup: on Windows that could select a repository-controlled shim.
    which::which_global(name).map_err(|_| AgentError::NotFound(name))
}

pub(crate) fn run_with_stdin(
    program: &'static str,
    executable: &Path,
    arguments: &[OsString],
    stdin: &[u8],
    config: &ProcessConfig,
) -> Result<Output, AgentError> {
    let mut command = command_for_executable(executable, arguments)
        .map_err(|source| AgentError::Process { program, source })?;
    configure_process_group(&mut command);
    let mut child = command
        .current_dir(&config.repository)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| AgentError::Process { program, source })?;
    let child_stdout = child.stdout.take().expect("stdout was configured as piped");
    let child_stderr = child.stderr.take().expect("stderr was configured as piped");
    let maximum = config.max_output_bytes;
    let stdout_reader = thread::spawn(move || read_bounded(child_stdout, maximum));
    let stderr_reader = thread::spawn(move || read_bounded(child_stderr, maximum));
    let prompt = stdin.to_vec();
    let stdin_writer = child
        .stdin
        .take()
        .map(|mut child_stdin| thread::spawn(move || child_stdin.write_all(&prompt)));

    let status = match wait_until(&mut child, config.timeout) {
        Ok(status) => status,
        Err(source) => {
            terminate_process_tree(&mut child);
            return Err(AgentError::Process { program, source });
        }
    };
    if status.is_none() {
        terminate_process_tree(&mut child);
        let _ = child.wait();
        return Err(AgentError::Timeout {
            program,
            seconds: config.timeout.as_secs(),
        });
    }
    join_writer(stdin_writer).map_err(|source| AgentError::Process { program, source })?;
    let (stdout, stdout_overflow) =
        join_reader(stdout_reader).map_err(|source| AgentError::Process { program, source })?;
    let (stderr, stderr_overflow) =
        join_reader(stderr_reader).map_err(|source| AgentError::Process { program, source })?;
    if stdout_overflow || stderr_overflow {
        return Err(AgentError::OutputTooLarge(program));
    }
    let output = Output {
        status: status.expect("status is present after timeout branch"),
        stdout,
        stderr,
    };
    if !output.status.success() {
        return Err(AgentError::Exit {
            program,
            status: output.status.to_string(),
            stderr: bounded_stderr_tail(&output.stderr),
        });
    }
    Ok(output)
}

fn bounded_stderr_tail(bytes: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(bytes);
    let character_count = decoded.chars().count();
    if character_count <= MAX_EXIT_STDERR_CHARS {
        return decoded.into_owned();
    }

    let marker_characters = STDERR_TRUNCATED_MARKER.chars().count();
    let retained_characters = MAX_EXIT_STDERR_CHARS.saturating_sub(marker_characters);
    let skipped_characters = character_count.saturating_sub(retained_characters);
    let start = decoded
        .char_indices()
        .nth(skipped_characters)
        .map_or(decoded.len(), |(index, _)| index);
    format!("{STDERR_TRUNCATED_MARKER}{}", &decoded[start..])
}

fn wait_until(child: &mut Child, timeout: Duration) -> std::io::Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(20).min(timeout.saturating_sub(started.elapsed())));
    }
}

fn read_bounded(mut reader: impl Read, maximum: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    let mut buffer = [0_u8; 16 * 1024];
    let mut overflow = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&buffer[..retained]);
        overflow |= retained != count;
    }
    Ok((bytes, overflow))
}

fn join_reader(
    handle: thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
) -> std::io::Result<(Vec<u8>, bool)> {
    handle
        .join()
        .map_err(|_| std::io::Error::other("output reader thread panicked"))?
}

fn join_writer(handle: Option<thread::JoinHandle<std::io::Result<()>>>) -> std::io::Result<()> {
    handle.map_or(Ok(()), |handle| {
        handle
            .join()
            .map_err(|_| std::io::Error::other("stdin writer thread panicked"))?
    })
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_process_tree(child: &mut Child) {
    let process_group = format!("-{}", child.id());
    let Some(kill) = which::which_global("kill").ok() else {
        let _ = child.kill();
        return;
    };
    let _ = Command::new(kill)
        .args(["-TERM", &process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for _ in 0..10 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
}

#[cfg(windows)]
fn terminate_process_tree(child: &mut Child) {
    if let Ok(taskkill) = which::which_global("taskkill.exe") {
        let _ = Command::new(taskkill)
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

pub(crate) fn probe_output(
    program: &'static str,
    executable: &Path,
    arguments: &[&str],
    config: &ProcessConfig,
) -> Result<Output, AgentError> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    let mut probe_config = config.clone();
    probe_config.timeout = config.timeout.min(Duration::from_secs(10));
    probe_config.max_output_bytes = config.max_output_bytes.min(1024 * 1024);
    run_with_stdin(program, executable, &arguments, b"", &probe_config)
}

fn command_for_executable(executable: &Path, arguments: &[OsString]) -> std::io::Result<Command> {
    let executable = if executable.is_absolute() {
        executable.to_path_buf()
    } else {
        which::which_global(executable)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()))?
    };
    #[cfg(windows)]
    {
        use std::ffi::OsStr;

        let extension = executable.extension().and_then(OsStr::to_str).unwrap_or("");
        if extension.eq_ignore_ascii_case("ps1") {
            let powershell = which::which_global("powershell.exe").map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string())
            })?;
            let mut command = Command::new(powershell);
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$tool = [Environment]::GetEnvironmentVariable('REPO2OKF_PS1_PATH', 'Process'); $count = [int][Environment]::GetEnvironmentVariable('REPO2OKF_PS1_ARG_COUNT', 'Process'); $toolArgs = @(); for ($index = 0; $index -lt $count; $index++) { $toolArgs += [Environment]::GetEnvironmentVariable(('REPO2OKF_PS1_ARG_' + $index), 'Process') }; & $tool @toolArgs; if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }",
            ]);
            command.env("REPO2OKF_PS1_PATH", executable);
            command.env("REPO2OKF_PS1_ARG_COUNT", arguments.len().to_string());
            for (index, argument) in arguments.iter().enumerate() {
                command.env(format!("REPO2OKF_PS1_ARG_{index}"), argument);
            }
            return Ok(command);
        }
        if extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat") {
            // `cmd.exe /d /s /c` is needed for npm shims. All arguments are
            // tool-owned; repository content and prompts stay on stdin.
            let cmd = which::which_global("cmd.exe").map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string())
            })?;
            let mut command = Command::new(cmd);
            command.args(["/d", "/s", "/c"]);
            command.arg(executable);
            command.args(arguments);
            return Ok(command);
        }
    }
    let mut command = Command::new(&executable);
    command.args(arguments);
    Ok(command)
}

pub(crate) fn os(value: &str) -> OsString {
    OsString::from(value)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use super::{
        AgentError, MAX_EXIT_STDERR_CHARS, ProcessConfig, STDERR_TRUNCATED_MARKER, run_with_stdin,
    };

    fn fixture_config() -> (tempfile::TempDir, ProcessConfig) {
        let repository = tempfile::tempdir().expect("tempdir");
        let mut config = ProcessConfig::new(repository.path().to_path_buf());
        config.timeout = Duration::from_secs(3);
        config.max_output_bytes = 1024;
        (repository, config)
    }

    #[test]
    fn passes_prompt_over_stdin() {
        let (_repository, config) = fixture_config();
        let (executable, arguments) = echo_command();
        let output = run_with_stdin(
            "fixture",
            &executable,
            &arguments,
            b"prompt, not shell syntax: $(exit 9)",
            &config,
        )
        .expect("fixture should echo stdin");
        assert_eq!(output.stdout, b"prompt, not shell syntax: $(exit 9)");
    }

    #[test]
    fn enforces_wall_clock_timeout() {
        let (_repository, mut config) = fixture_config();
        config.timeout = Duration::from_millis(100);
        let (executable, arguments) = sleep_command();
        let started = Instant::now();
        let error = run_with_stdin("fixture", &executable, &arguments, b"", &config)
            .expect_err("fixture should time out");
        assert!(matches!(error, AgentError::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn reports_failed_exit_with_bounded_stderr() {
        let (_repository, config) = fixture_config();
        let (executable, arguments) = failure_command();
        let error = run_with_stdin("fixture", &executable, &arguments, b"prompt", &config)
            .expect_err("fixture should fail");
        match error {
            AgentError::Exit {
                program, stderr, ..
            } => {
                assert_eq!(program, "fixture");
                assert!(stderr.contains("intentional fixture failure"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn failed_exit_retains_utf8_safe_terminal_error_instead_of_prompt_echo() {
        let (_repository, mut config) = fixture_config();
        config.max_output_bytes = 64 * 1024;
        let (executable, arguments) = echoed_failure_command();
        let prompt = format!("SENSITIVE_PROMPT_PREFIX:{}", "界".repeat(4500));
        let error = run_with_stdin(
            "fixture",
            &executable,
            &arguments,
            prompt.as_bytes(),
            &config,
        )
        .expect_err("fixture should fail after echoing a long prompt");

        match error {
            AgentError::Exit { stderr, .. } => {
                assert!(stderr.starts_with(STDERR_TRUNCATED_MARKER));
                assert!(stderr.ends_with("terminal failure: 終端エラー"));
                assert!(!stderr.contains("SENSITIVE_PROMPT_PREFIX"));
                assert!(stderr.chars().count() <= MAX_EXIT_STDERR_CHARS);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_output_beyond_configured_limit() {
        let (_repository, config) = fixture_config();
        let (executable, arguments) = oversized_output_command();
        let error = run_with_stdin("fixture", &executable, &arguments, b"", &config)
            .expect_err("fixture output should exceed its bound");
        assert!(matches!(error, AgentError::OutputTooLarge("fixture")));
    }

    #[cfg(unix)]
    fn echo_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("/bin/sh"),
            vec![OsString::from("-c"), OsString::from("cat")],
        )
    }

    #[cfg(windows)]
    fn echo_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from("[Console]::Out.Write([Console]::In.ReadToEnd())"),
            ],
        )
    }

    #[cfg(unix)]
    fn sleep_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("/bin/sh"),
            vec![OsString::from("-c"), OsString::from("sleep 5")],
        )
    }

    #[cfg(windows)]
    fn sleep_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from("Start-Sleep -Seconds 5"),
            ],
        )
    }

    #[cfg(unix)]
    fn failure_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("/bin/sh"),
            vec![
                OsString::from("-c"),
                OsString::from(
                    "cat >/dev/null; printf '%s' 'intentional fixture failure' >&2; exit 23",
                ),
            ],
        )
    }

    #[cfg(unix)]
    fn echoed_failure_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("/bin/sh"),
            vec![
                OsString::from("-c"),
                OsString::from("cat >&2; printf '%s' 'terminal failure: 終端エラー' >&2; exit 23"),
            ],
        )
    }

    #[cfg(windows)]
    fn failure_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from(
                    "$null = [Console]::In.ReadToEnd(); [Console]::Error.Write('intentional fixture failure'); exit 23",
                ),
            ],
        )
    }

    #[cfg(windows)]
    fn echoed_failure_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from(
                    "$prompt = [Console]::In.ReadToEnd(); [Console]::Error.Write($prompt); [Console]::Error.Write('terminal failure: 終端エラー'); exit 23",
                ),
            ],
        )
    }

    #[cfg(unix)]
    fn oversized_output_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("/bin/sh"),
            vec![
                OsString::from("-c"),
                OsString::from(
                    "cat >/dev/null; index=0; while [ $index -lt 2048 ]; do printf x; index=$((index + 1)); done",
                ),
            ],
        )
    }

    #[cfg(windows)]
    fn oversized_output_command() -> (PathBuf, Vec<OsString>) {
        (
            PathBuf::from("powershell.exe"),
            vec![
                OsString::from("-NoLogo"),
                OsString::from("-NoProfile"),
                OsString::from("-NonInteractive"),
                OsString::from("-Command"),
                OsString::from(
                    "$null = [Console]::In.ReadToEnd(); [Console]::Out.Write(('x' * 2048))",
                ),
            ],
        )
    }
}
