//! Safe repository-relative path resolution and atomic output helpers.

use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};

const MAX_JSON_INPUT_BYTES: u64 = 256 * 1024 * 1024;

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};

/// Pins the canonical repository directory for the lifetime of one CLI run.
#[derive(Debug)]
pub(crate) struct RepositoryGuard {
    path: PathBuf,
    identity: EntryIdentity,
}

impl RepositoryGuard {
    /// Capture the non-link repository directory and keep its OS handle open.
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        let identity = EntryIdentity::capture_directory(path)
            .context("failed to capture repository root identity")?;
        let guard = Self {
            path: path.to_path_buf(),
            identity,
        };
        guard.verify()?;
        Ok(guard)
    }

    /// Repository path originally captured by this guard.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Fail if the repository pathname no longer refers to the captured root.
    pub(crate) fn verify(&self) -> Result<()> {
        let current = EntryIdentity::capture_directory(&self.path)?;
        if current != self.identity {
            bail!(
                "repository root identity changed during command execution: {}",
                self.path.display()
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PublishItem {
    staged: PathBuf,
    destination: PathBuf,
    required_marker: Option<RequiredMarker>,
}

#[derive(Debug)]
struct RequiredMarker {
    relative_path: PathBuf,
    expected: Vec<u8>,
}

/// A set of staged filesystem entries committed as one rollback-safe unit.
///
/// Runtime failures are transactional: either every destination is replaced,
/// or all destinations are returned to their pre-commit state. This does not
/// claim atomic visibility to concurrent readers or crash consistency across
/// an operating-system failure.
pub(crate) struct PublishPlan<'guard> {
    guard: &'guard RepositoryGuard,
    repository: PathBuf,
    staging_identity: EntryIdentity,
    staging_root: tempfile::TempDir,
    items: Vec<PublishItem>,
}

impl<'guard> PublishPlan<'guard> {
    /// Create staging on the repository filesystem.
    pub(crate) fn new(repository: &'guard RepositoryGuard) -> Result<Self> {
        repository.verify()?;
        let repository_path = repository.path();
        let staging_root = tempfile::Builder::new()
            .prefix(".repo2okf-publish-")
            .tempdir_in(repository_path)
            .with_context(|| {
                format!(
                    "failed to create publication staging in {}",
                    repository_path.display()
                )
            })?;
        repository.verify()?;
        let staging_identity = EntryIdentity::capture_directory(staging_root.path())
            .context("failed to capture publication staging identity")?;
        let plan = Self {
            guard: repository,
            repository: repository_path.to_path_buf(),
            staging_identity,
            staging_root,
            items: Vec::new(),
        };
        plan.validate_repository_identity()?;
        plan.validate_staging_root_identity()?;
        Ok(plan)
    }

    /// Return a unique, direct child of the private staging directory.
    pub(crate) fn staging_path(&self, name: &str) -> Result<PathBuf> {
        self.validate_repository_identity()?;
        self.validate_staging_root_identity()?;
        let path = Path::new(name);
        if path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            bail!("invalid publication staging name `{name}`");
        }
        Ok(self.staging_root.path().join(path))
    }

    /// Add a staged directory whose existing destination must carry an exact
    /// compiler ownership marker before it may be retired.
    pub(crate) fn add_owned_directory(
        &mut self,
        staged: PathBuf,
        destination: PathBuf,
        marker_relative_path: &Path,
        marker_content: &[u8],
    ) -> Result<()> {
        if marker_relative_path.as_os_str().is_empty()
            || !marker_relative_path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            bail!(
                "ownership marker must be a safe relative path: {}",
                marker_relative_path.display()
            );
        }
        self.add(
            staged,
            destination,
            Some(RequiredMarker {
                relative_path: marker_relative_path.to_path_buf(),
                expected: marker_content.to_vec(),
            }),
        )
    }

    fn add(
        &mut self,
        staged: PathBuf,
        destination: PathBuf,
        required_marker: Option<RequiredMarker>,
    ) -> Result<()> {
        if self.items.iter().any(|item| item.staged == staged) {
            bail!("duplicate staged publication path: {}", staged.display());
        }
        if self
            .items
            .iter()
            .any(|item| item.destination == destination)
        {
            bail!(
                "duplicate publication destination: {}",
                destination.display()
            );
        }
        let relative = staged
            .strip_prefix(self.staging_root.path())
            .with_context(|| {
                format!(
                    "staged publication path is outside its private root: {}",
                    staged.display()
                )
            })?;
        if relative.components().count() != 1 {
            bail!(
                "staged publication path must be a direct child of its private root: {}",
                staged.display()
            );
        }
        if destination.parent() != Some(self.repository.as_path()) {
            bail!(
                "publication destination must be a direct child of the repository: {}",
                destination.display()
            );
        }
        self.items.push(PublishItem {
            staged,
            destination,
            required_marker,
        });
        Ok(())
    }

    /// Commit every staged entry, rolling all destinations back on failure.
    pub(crate) fn commit(self) -> Result<()> {
        let mut renamer = FilesystemRenamer;
        self.commit_with(&mut renamer)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "publication ordering and its rollback journal are reviewed together"
    )]
    fn commit_with(self, renamer: &mut impl RenameEntry) -> Result<()> {
        self.prepare()?;
        let backups = self.staging_root.path().join("backups");
        let displaced = self.staging_root.path().join("rollback-new");
        self.validate_publication_roots()?;
        fs::create_dir(&backups).context("failed to create publication backup directory")?;
        self.validate_publication_roots()?;
        fs::create_dir(&displaced).context("failed to create publication rollback directory")?;
        self.validate_publication_roots()?;
        self.write_recovery_manifest()?;
        self.validate_publication_roots()?;

        let mut backed_up = vec![false; self.items.len()];
        let mut published = vec![false; self.items.len()];
        let mut published_identities = (0..self.items.len()).map(|_| None).collect::<Vec<_>>();
        let staged_identities = self
            .items
            .iter()
            .map(|item| EntryIdentity::capture_directory(&item.staged))
            .collect::<Result<Vec<_>>>()?;
        for index in 0..self.items.len() {
            if let Err(error) = self.validate_publication_roots() {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    error.context("repository changed before target backup"),
                );
            }
            let exists = match validated_target_exists(&self.items[index]) {
                Ok(exists) => exists,
                Err(error) => {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        error.context("failed final publication target validation"),
                    );
                }
            };
            if exists {
                let backup = backups.join(index.to_string());
                if let Err(error) = self.validate_publication_roots() {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        error.context("publication roots changed before target backup"),
                    );
                }
                if let Err(error) = renamer.rename(&self.items[index].destination, &backup) {
                    let destination = self.items[index].destination.display().to_string();
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        anyhow::Error::new(error).context(format!(
                            "failed to back up publication target {destination}"
                        )),
                    );
                }
                backed_up[index] = true;
                if let Err(error) = self.validate_publication_roots() {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        error.context("repository changed after target backup"),
                    );
                }
                if let Err(error) = validate_retired_directory(&backup, &self.items[index]) {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        error.context("backed-up output directory is unsafe to retire"),
                    );
                }
            }
        }

        for index in 0..self.items.len() {
            if let Err(error) = self.validate_publication_roots() {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    error.context("repository changed before target publication"),
                );
            }
            if let Err(error) =
                validate_directory(&self.items[index].staged, "staged publication entry")
            {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    error.context("staged target changed before publication"),
                );
            }
            if !EntryIdentity::capture_directory(&self.items[index].staged)?
                .same_entry_after_rename(&staged_identities[index])
            {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    anyhow::anyhow!("staged target identity changed before publication"),
                );
            }
            if let Err(error) =
                renamer.rename(&self.items[index].staged, &self.items[index].destination)
            {
                let destination = self.items[index].destination.display().to_string();
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    anyhow::Error::new(error)
                        .context(format!("failed to publish staged target {destination}")),
                );
            }
            if let Err(error) = self.validate_publication_roots() {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    error.context("publication roots changed after target publication"),
                );
            }
            match EntryIdentity::capture_directory(&self.items[index].destination) {
                Ok(identity) if identity.same_entry_after_rename(&staged_identities[index]) => {
                    published[index] = true;
                    published_identities[index] = Some(identity);
                }
                Ok(_) => {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        anyhow::anyhow!("published target identity differs from staged target"),
                    );
                }
                Err(error) => {
                    return self.fail_and_rollback(
                        renamer,
                        &backups,
                        &displaced,
                        &backed_up,
                        &published,
                        &published_identities,
                        error.context("failed to capture published target identity"),
                    );
                }
            }
            if let Err(error) = self.validate_publication_roots() {
                return self.fail_and_rollback(
                    renamer,
                    &backups,
                    &displaced,
                    &backed_up,
                    &published,
                    &published_identities,
                    error.context("repository changed during publication"),
                );
            }
        }
        if let Err(error) = self.validate_publication_roots() {
            return self.fail_and_rollback(
                renamer,
                &backups,
                &displaced,
                &backed_up,
                &published,
                &published_identities,
                error.context("repository changed after publication"),
            );
        }
        Ok(())
    }

    fn prepare(&self) -> Result<()> {
        self.validate_repository_identity()?;
        self.validate_staging_root_identity()?;
        if self.items.is_empty() {
            bail!("publication plan contains no entries");
        }
        for item in &self.items {
            let destination_parent = item
                .destination
                .parent()
                .context("publication destination has no parent")?;
            if destination_parent != self.repository {
                bail!(
                    "publication destination parent is not the repository: {}",
                    item.destination.display()
                );
            }
            reject_linked_ancestors(&self.repository, &item.destination)?;
            validate_directory(&item.staged, "staged publication entry")?;
            match fs::symlink_metadata(&item.destination) {
                Ok(metadata) => {
                    if is_link_or_reparse_point(&metadata) {
                        bail!(
                            "refusing to replace link-like publication target: {}",
                            item.destination.display()
                        );
                    }
                    validate_directory_metadata(
                        &metadata,
                        &item.destination,
                        "publication target",
                    )?;
                    validate_required_marker(&item.destination, item)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect publication target {}",
                            item.destination.display()
                        )
                    });
                }
            }
            if !same_filesystem(&item.staged, destination_parent)? {
                bail!(
                    "staged entry and publication target are on different filesystems: {}",
                    item.destination.display()
                );
            }
        }
        Ok(())
    }

    fn validate_repository_identity(&self) -> Result<()> {
        self.guard.verify()
    }

    fn validate_publication_roots(&self) -> Result<()> {
        self.validate_repository_identity()?;
        self.validate_staging_root_identity()
    }

    fn validate_staging_root_identity(&self) -> Result<()> {
        let root = self.staging_root.path();
        let current = EntryIdentity::capture_directory(root)?;
        if current != self.staging_identity {
            bail!(
                "publication staging root identity changed: {}",
                root.display()
            );
        }
        Ok(())
    }

    fn write_recovery_manifest(&self) -> Result<()> {
        let mut manifest = String::from(
            "Repo2OKF interrupted publication recovery map.\n\
             backups/<n> contains the prior destination when present.\n\
             rollback-new/<n> contains a displaced new entry when present.\n\n",
        );
        for (index, item) in self.items.iter().enumerate() {
            writeln!(manifest, "{index}: {}", item.destination.display())
                .expect("writing to a String cannot fail");
        }
        write_bytes(
            &self.staging_root.path().join("RECOVERY.txt"),
            manifest.as_bytes(),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "rollback needs the complete publication journal"
    )]
    fn fail_and_rollback(
        self,
        renamer: &mut impl RenameEntry,
        backups: &Path,
        displaced: &Path,
        backed_up: &[bool],
        published: &[bool],
        published_identities: &[Option<EntryIdentity>],
        publication_error: anyhow::Error,
    ) -> Result<()> {
        fn roots_are_unchanged(plan: &PublishPlan, errors: &mut Vec<String>) -> bool {
            match plan.validate_publication_roots() {
                Ok(()) => true,
                Err(error) => {
                    errors.push(format!(
                        "repository identity changed; stopping rollback mutations: {error:#}"
                    ));
                    false
                }
            }
        }

        let mut rollback_errors = Vec::new();
        let mut safe_to_restore = vec![true; self.items.len()];

        if !roots_are_unchanged(&self, &mut rollback_errors) {
            let recovery = self.staging_root.keep();
            bail!(
                "publication failed ({publication_error:#}); rollback was not attempted ({}); recovery data was preserved at {}",
                rollback_errors.join("; "),
                recovery.display()
            );
        }

        for (index, item) in self.items.iter().enumerate().rev() {
            if !roots_are_unchanged(&self, &mut rollback_errors) {
                break;
            }
            if published[index] {
                let identity_matches = published_identities[index].as_ref().and_then(|expected| {
                    EntryIdentity::capture_directory(&item.destination)
                        .ok()
                        .map(|actual| actual == *expected)
                }) == Some(true);
                if !identity_matches {
                    safe_to_restore[index] = false;
                    rollback_errors.push(format!(
                        "published target identity changed; refusing to move {}",
                        item.destination.display()
                    ));
                    continue;
                }
                if let Err(error) =
                    renamer.rename(&item.destination, &displaced.join(index.to_string()))
                {
                    safe_to_restore[index] = false;
                    rollback_errors.push(format!(
                        "failed to remove new target {}: {error}",
                        item.destination.display()
                    ));
                } else if !roots_are_unchanged(&self, &mut rollback_errors) {
                    safe_to_restore[index] = false;
                    break;
                }
            }
        }
        for (index, item) in self.items.iter().enumerate().rev() {
            if !roots_are_unchanged(&self, &mut rollback_errors) {
                break;
            }
            if backed_up[index] && safe_to_restore[index] {
                match fs::symlink_metadata(&item.destination) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Ok(_) => {
                        rollback_errors.push(format!(
                            "publication destination is occupied; refusing to restore over {}",
                            item.destination.display()
                        ));
                        continue;
                    }
                    Err(error) => {
                        rollback_errors.push(format!(
                            "failed to inspect destination before restore {}: {error}",
                            item.destination.display()
                        ));
                        continue;
                    }
                }
                if let Err(error) =
                    renamer.rename(&backups.join(index.to_string()), &item.destination)
                {
                    rollback_errors.push(format!(
                        "failed to restore prior target {}: {error}",
                        item.destination.display()
                    ));
                } else if !roots_are_unchanged(&self, &mut rollback_errors) {
                    break;
                }
            }
        }

        if rollback_errors.is_empty() {
            return Err(publication_error
                .context("publication failed; every destination was restored to its prior state"));
        }

        let recovery = self.staging_root.keep();
        bail!(
            "publication failed ({publication_error:#}); rollback was incomplete ({}); recovery data was preserved at {}",
            rollback_errors.join("; "),
            recovery.display()
        )
    }
}

#[derive(Debug)]
struct EntryIdentity {
    handle: same_file::Handle,
    #[cfg(any(windows, not(any(unix, windows))))]
    canonical_path: PathBuf,
}

impl EntryIdentity {
    fn capture_directory(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect directory identity {}", path.display()))?;
        if is_link_or_reparse_point(&metadata) || !metadata.file_type().is_dir() {
            bail!(
                "directory identity is link-like or not a directory: {}",
                path.display()
            );
        }
        let handle = same_file::Handle::from_path(path)
            .with_context(|| format!("failed to open directory identity {}", path.display()))?;
        let after = fs::symlink_metadata(path).with_context(|| {
            format!("failed to re-inspect directory identity {}", path.display())
        })?;
        if is_link_or_reparse_point(&after) || !after.file_type().is_dir() {
            bail!(
                "directory identity changed while opening: {}",
                path.display()
            );
        }
        let confirmation = same_file::Handle::from_path(path)
            .with_context(|| format!("failed to confirm directory identity {}", path.display()))?;
        if handle != confirmation {
            bail!(
                "directory identity changed while opening: {}",
                path.display()
            );
        }
        Ok(Self {
            handle,
            #[cfg(any(windows, not(any(unix, windows))))]
            canonical_path: path.canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize directory identity {}",
                    path.display()
                )
            })?,
        })
    }

    fn same_entry_after_rename(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl PartialEq for EntryIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle && {
            #[cfg(any(windows, not(any(unix, windows))))]
            {
                self.canonical_path == other.canonical_path
            }
            #[cfg(unix)]
            {
                true
            }
        }
    }
}

impl Eq for EntryIdentity {}

trait RenameEntry {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()>;
}

struct FilesystemRenamer;

impl RenameEntry for FilesystemRenamer {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(source, destination)
    }
}

fn validate_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if is_link_or_reparse_point(&metadata) {
        bail!("refusing {label} through a link: {}", path.display());
    }
    validate_directory_metadata(&metadata, path, label)?;
    validate_directory_tree(path)
}

fn validate_directory_metadata(metadata: &fs::Metadata, path: &Path, label: &str) -> Result<()> {
    if !metadata.file_type().is_dir() {
        bail!("{label} is not a directory: {}", path.display());
    }
    Ok(())
}

fn validated_target_exists(item: &PublishItem) -> Result<bool> {
    match fs::symlink_metadata(&item.destination) {
        Ok(metadata) => {
            if is_link_or_reparse_point(&metadata) {
                bail!(
                    "refusing to replace link-like publication target: {}",
                    item.destination.display()
                );
            }
            validate_directory_metadata(&metadata, &item.destination, "publication target")?;
            validate_required_marker(&item.destination, item)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect publication target {}",
                item.destination.display()
            )
        }),
    }
}

fn validate_required_marker(directory: &Path, item: &PublishItem) -> Result<()> {
    let Some(marker) = &item.required_marker else {
        return Ok(());
    };
    let path = directory.join(&marker.relative_path);
    if !matches_fixed_file(&path, &marker.expected)? {
        bail!(
            "refusing to replace an unowned publication directory: {}",
            directory.display()
        );
    }
    Ok(())
}

fn validate_retired_directory(directory: &Path, item: &PublishItem) -> Result<()> {
    validate_directory(directory, "backed-up publication directory")?;
    validate_required_marker(directory, item)
}

fn validate_directory_tree(root: &Path) -> Result<()> {
    fn visit(directory: &Path) -> Result<()> {
        let mut entries = fs::read_dir(directory)
            .with_context(|| format!("failed to inspect directory tree {}", directory.display()))?
            .collect::<io::Result<Vec<_>>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("failed to inspect directory entry {}", path.display()))?;
            if is_link_or_reparse_point(&metadata) {
                bail!(
                    "refusing publication directory containing a link-like entry: {}",
                    path.display()
                );
            }
            if metadata.file_type().is_dir() {
                visit(&path)?;
            } else if !metadata.file_type().is_file() {
                bail!(
                    "refusing publication directory containing a special entry: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("failed to inspect directory tree root {}", root.display()))?;
    if is_link_or_reparse_point(&root_metadata) || !root_metadata.file_type().is_dir() {
        bail!(
            "refusing link-like or non-directory tree root: {}",
            root.display()
        );
    }

    visit(root)
}

#[cfg(unix)]
fn same_filesystem(source: &Path, destination_parent: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let source = fs::metadata(source)
        .with_context(|| format!("failed to inspect staged entry {}", source.display()))?;
    let destination = fs::metadata(destination_parent).with_context(|| {
        format!(
            "failed to inspect publication parent {}",
            destination_parent.display()
        )
    })?;
    Ok(source.dev() == destination.dev())
}

#[cfg(windows)]
fn same_filesystem(source: &Path, destination_parent: &Path) -> Result<bool> {
    use std::path::Prefix;

    fn volume(path: &Path) -> Result<String> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", path.display()))?;
        match canonical.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                    Ok(char::from(letter).to_ascii_uppercase().to_string())
                }
                other => Ok(format!("{other:?}").to_ascii_lowercase()),
            },
            _ => bail!("path has no Windows volume prefix: {}", canonical.display()),
        }
    }

    Ok(volume(source)? == volume(destination_parent)?)
}

#[cfg(not(any(unix, windows)))]
fn same_filesystem(_source: &Path, _destination_parent: &Path) -> Result<bool> {
    // The rename calls still fail safely before publication can complete on
    // platforms without a stable filesystem identity API in std.
    Ok(true)
}

/// Resolve a configured path while preventing escape from the repository root.
pub fn resolve_beneath(repository: &Path, configured: &Path) -> Result<PathBuf> {
    let relative = if configured.is_absolute() {
        configured.strip_prefix(repository).with_context(|| {
            format!(
                "output path {} is outside repository {}",
                configured.display(),
                repository.display()
            )
        })?
    } else {
        configured
    };

    let mut clean = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() {
                    bail!("path escapes repository: {}", configured.display());
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                bail!("invalid repository-relative path: {}", configured.display());
            }
        }
    }
    if clean.as_os_str().is_empty() {
        bail!("path must not resolve to the repository root");
    }
    let resolved = repository.join(clean);
    reject_linked_ancestors(repository, &resolved)?;
    Ok(resolved)
}

fn reject_linked_ancestors(repository: &Path, resolved: &Path) -> Result<()> {
    let relative = resolved
        .strip_prefix(repository)
        .context("resolved path escaped repository during validation")?;
    let mut current = repository.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_link_or_reparse_point(&metadata) => {
                bail!("refusing output path through a link: {}", current.display());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect output path {}", current.display())
                });
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
/// Return whether metadata represents a link-like Windows reparse point.
pub fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
/// Return whether metadata represents a symbolic link.
pub fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

/// Open an existing regular file without accepting a direct symbolic link or
/// Windows reparse point. The returned length belongs to the opened handle.
pub(crate) fn open_regular_file(path: &Path) -> Result<(File, u64)> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if is_link_or_reparse_point(&before) {
        bail!("refusing to read through a link: {}", path.display());
    }
    if !before.file_type().is_file() {
        bail!("input is not a regular file: {}", path.display());
    }

    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    if !opened.is_file() {
        bail!("input is not a regular file: {}", path.display());
    }

    // Inspect the directory entry again after opening. This catches a path
    // swapped to a link during the check/open window before any bytes are read.
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect {}", path.display()))?;
    if is_link_or_reparse_point(&after) || !after.file_type().is_file() {
        bail!(
            "input changed or became a link while opening: {}",
            path.display()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
        {
            bail!("input changed while opening: {}", path.display());
        }
    }

    Ok((file, opened.len()))
}

/// Serialize a value as pretty JSON and atomically replace the destination.
pub fn write_json<T: Serialize>(destination: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).context("failed to serialize JSON output")?;
    write_bytes(destination, &bytes)
}

/// Atomically replace a destination with the supplied bytes.
pub fn write_bytes(destination: &Path, bytes: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .context("destination has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary output in {}", parent.display()))?;
    temporary.write_all(bytes).with_context(|| {
        format!(
            "failed to write temporary output for {}",
            destination.display()
        )
    })?;
    temporary.as_file().sync_all().with_context(|| {
        format!(
            "failed to flush temporary output for {}",
            destination.display()
        )
    })?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "failed to atomically replace output {}",
                destination.display()
            )
        })?;
    Ok(())
}

/// Deserialize JSON from disk without loading it twice.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    read_json_with_limit(path, MAX_JSON_INPUT_BYTES)
}

fn read_json_with_limit<T: DeserializeOwned>(path: &Path, maximum_bytes: u64) -> Result<T> {
    let (file, length) = open_regular_file(path)?;
    if length > maximum_bytes {
        bail!(
            "JSON input exceeds the {}-byte safety limit: {}",
            maximum_bytes,
            path.display()
        );
    }

    let reader = BoundedReader::new(file, maximum_bytes);
    serde_json::from_reader(BufReader::new(reader))
        .with_context(|| format!("invalid JSON in {}", path.display()))
}

/// Compare a small ownership marker without ever allocating or reading more
/// than its fixed expected length.
pub(crate) fn matches_fixed_file(path: &Path, expected: &[u8]) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if is_link_or_reparse_point(&metadata) {
        bail!(
            "refusing ownership marker through a link: {}",
            path.display()
        );
    }
    if !metadata.file_type().is_file() {
        bail!("ownership marker is not a regular file: {}", path.display());
    }
    if metadata.len() != expected.len() as u64 {
        return Ok(false);
    }

    let (mut file, length) = open_regular_file(path)?;
    if length != expected.len() as u64 {
        return Ok(false);
    }
    let mut actual = vec![0_u8; expected.len()];
    file.read_exact(&mut actual)
        .with_context(|| format!("failed to read ownership marker {}", path.display()))?;
    let mut extra = [0_u8; 1];
    Ok(actual == expected && file.read(&mut extra)? == 0)
}

struct BoundedReader<R> {
    inner: R,
    maximum_bytes: u64,
    bytes_read: u64,
}

impl<R> BoundedReader<R> {
    const fn new(inner: R, maximum_bytes: u64) -> Self {
        Self {
            inner,
            maximum_bytes,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let remaining = self.maximum_bytes.saturating_sub(self.bytes_read);
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "JSON input exceeds the {}-byte safety limit",
                        self.maximum_bytes
                    ),
                )),
            };
        }

        let allowed = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = self.inner.read(&mut buffer[..allowed])?;
        self.bytes_read += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        io::Read as _,
        path::{Path, PathBuf},
    };

    use serde::{Deserialize, Serialize};

    use super::{
        BoundedReader, MAX_JSON_INPUT_BYTES, PublishPlan, RenameEntry, RepositoryGuard,
        matches_fixed_file, read_json, read_json_with_limit, resolve_beneath, write_json,
    };

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct Fixture {
        value: u32,
    }

    const TEST_MARKER: &[u8] = b"owned\n";

    #[derive(Default)]
    struct FaultRenamer {
        calls: usize,
        fail_at: BTreeSet<usize>,
        replace_after: Option<(usize, PathBuf)>,
    }

    impl FaultRenamer {
        fn failing_at(indices: impl IntoIterator<Item = usize>) -> Self {
            Self {
                calls: 0,
                fail_at: indices.into_iter().collect(),
                replace_after: None,
            }
        }

        fn replacing_after(call: usize, destination: PathBuf) -> Self {
            Self {
                calls: 0,
                fail_at: BTreeSet::new(),
                replace_after: Some((call, destination)),
            }
        }
    }

    impl RenameEntry for FaultRenamer {
        fn rename(&mut self, source: &Path, destination: &Path) -> std::io::Result<()> {
            let call = self.calls;
            self.calls += 1;
            if self.fail_at.remove(&call) {
                return Err(std::io::Error::other(format!(
                    "injected rename failure at call {call}"
                )));
            }
            fs::rename(source, destination)?;
            if self
                .replace_after
                .as_ref()
                .is_some_and(|(target_call, _)| *target_call == call)
            {
                let (_, replacement) = self.replace_after.take().expect("replacement fixture");
                fs::rename(destination, destination.with_extension("published-away"))?;
                fs::create_dir(&replacement)?;
                fs::write(replacement.join("third-party.txt"), "do not delete")?;
                return Err(std::io::Error::other(
                    "injected failure after destination replacement",
                ));
            }
            Ok(())
        }
    }

    fn compilation_plan(repository: &RepositoryGuard, previous: bool) -> PublishPlan<'_> {
        let repository_path = repository.path();
        let bundle = repository_path.join(".okf");
        let cache = repository_path.join(".repo2okf");
        if previous {
            fs::create_dir_all(&bundle).expect("prior bundle directory");
            fs::write(bundle.join("version"), "old bundle").expect("prior bundle");
            fs::write(bundle.join("owned"), TEST_MARKER).expect("prior ownership marker");
            fs::create_dir_all(&cache).expect("prior state directory");
            fs::write(cache.join("ir.json"), "old IR").expect("prior IR");
            fs::write(cache.join("state.json"), "old state").expect("prior state");
            fs::write(cache.join("owned"), TEST_MARKER).expect("prior cache marker");
        }

        let mut plan = PublishPlan::new(repository).expect("publication plan");
        let staged_bundle = plan.staging_path("bundle").expect("staged bundle path");
        let staged_cache = plan.staging_path("cache").expect("staged cache path");
        fs::create_dir(&staged_bundle).expect("staged bundle directory");
        fs::create_dir(&staged_cache).expect("staged cache directory");
        fs::write(staged_bundle.join("version"), "new bundle").expect("staged bundle");
        fs::write(staged_bundle.join("owned"), TEST_MARKER).expect("staged marker");
        fs::write(staged_cache.join("ir.json"), "new IR").expect("staged IR");
        fs::write(staged_cache.join("state.json"), "new state").expect("staged state");
        fs::write(staged_cache.join("owned"), TEST_MARKER).expect("staged cache marker");
        plan.add_owned_directory(staged_bundle, bundle, Path::new("owned"), TEST_MARKER)
            .expect("add owned bundle");
        plan.add_owned_directory(staged_cache, cache, Path::new("owned"), TEST_MARKER)
            .expect("add owned cache");
        plan
    }

    fn assert_compilation(repository: &Path, version: &str) {
        assert_eq!(
            fs::read_to_string(repository.join(".okf/version")).expect("bundle version"),
            format!("{version} bundle")
        );
        assert_eq!(
            fs::read_to_string(repository.join(".repo2okf/ir.json")).expect("IR version"),
            format!("{version} IR")
        );
        assert_eq!(
            fs::read_to_string(repository.join(".repo2okf/state.json")).expect("state version"),
            format!("{version} state")
        );
    }

    fn assert_compilation_absent(repository: &Path) {
        assert!(!repository.join(".okf").exists());
        assert!(!repository.join(".repo2okf").exists());
    }

    #[test]
    fn resolves_normalized_relative_path() {
        let root = Path::new("/repo");
        assert_eq!(
            resolve_beneath(root, Path::new(".repo2okf/../.okf/index.md"))
                .expect("path should resolve"),
            root.join(".okf/index.md")
        );
    }

    #[test]
    fn rejects_escape() {
        assert!(resolve_beneath(Path::new("/repo"), Path::new("../outside")).is_err());
    }

    #[test]
    fn atomically_replaces_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("nested/state.json");
        write_json(&path, &Fixture { value: 1 }).expect("first write");
        write_json(&path, &Fixture { value: 2 }).expect("replacement write");
        assert_eq!(
            read_json::<Fixture>(&path).expect("read output"),
            Fixture { value: 2 }
        );
    }

    #[test]
    fn entry_identity_survives_an_actual_directory_rename() {
        let repository = tempfile::tempdir().expect("repository");
        let source = repository.path().join("source");
        let destination = repository.path().join("destination");
        fs::create_dir(&source).expect("source directory");
        let before = super::EntryIdentity::capture_directory(&source).expect("source identity");
        fs::rename(&source, &destination).expect("rename directory");
        let after =
            super::EntryIdentity::capture_directory(&destination).expect("destination identity");
        assert!(before.same_entry_after_rename(&after));
    }

    #[test]
    fn repository_guard_rejects_same_path_regular_directory_replacement() {
        let container = tempfile::tempdir().expect("container");
        let repository = container.path().join("repository");
        let original = container.path().join("original");
        fs::create_dir(&repository).expect("repository");
        let guard = RepositoryGuard::capture(&repository).expect("repository guard");
        fs::rename(&repository, &original).expect("move original repository");
        fs::create_dir(&repository).expect("replacement repository");
        fs::write(repository.join("third-party.txt"), "untouched").expect("replacement data");
        assert!(guard.verify().is_err());
        assert!(PublishPlan::new(&guard).is_err());
        assert_eq!(
            fs::read_to_string(repository.join("third-party.txt")).expect("replacement data"),
            "untouched"
        );
    }

    #[test]
    fn publication_commits_bundle_and_whole_cache_together() {
        let repository = tempfile::tempdir().expect("repository");
        let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
        let plan = compilation_plan(&guard, true);
        plan.commit().expect("commit publication");
        assert_compilation(repository.path(), "new");
    }

    #[test]
    fn every_existing_publication_boundary_rolls_back_both_targets() {
        // Two backup renames followed by two publication renames.
        for failure in 0..4 {
            let repository = tempfile::tempdir().expect("repository");
            let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
            let plan = compilation_plan(&guard, true);
            let mut renamer = FaultRenamer::failing_at([failure]);
            let error = plan
                .commit_with(&mut renamer)
                .expect_err("injected publication failure");
            assert!(error.to_string().contains("restored to its prior state"));
            assert_compilation(repository.path(), "old");
        }
    }

    #[test]
    fn every_initial_publication_boundary_leaves_both_targets_absent() {
        // With no prior targets, the only forward renames are publications.
        for failure in 0..2 {
            let repository = tempfile::tempdir().expect("repository");
            let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
            let plan = compilation_plan(&guard, false);
            let mut renamer = FaultRenamer::failing_at([failure]);
            plan.commit_with(&mut renamer)
                .expect_err("injected initial publication failure");
            assert_compilation_absent(repository.path());
        }
    }

    #[test]
    fn incomplete_rollback_preserves_a_recovery_directory_and_manifest() {
        let repository = tempfile::tempdir().expect("repository");
        let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
        let plan = compilation_plan(&guard, true);
        // Fail the first publish, then the first old-target restoration.
        let mut renamer = FaultRenamer::failing_at([2, 3]);
        let error = plan
            .commit_with(&mut renamer)
            .expect_err("rollback should be incomplete");
        assert!(error.to_string().contains("recovery data was preserved"));

        let recovery = fs::read_dir(repository.path())
            .expect("repository entries")
            .map(|entry| entry.expect("repository entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".repo2okf-publish-"))
            })
            .expect("preserved recovery directory");
        let manifest =
            fs::read_to_string(recovery.join("RECOVERY.txt")).expect("recovery manifest");
        assert!(manifest.contains(".okf"));
        assert!(manifest.contains(".repo2okf"));
        fs::remove_dir_all(recovery).expect("clean recovery fixture");
    }

    #[test]
    fn rollback_never_overwrites_or_moves_a_replaced_destination() {
        let repository = tempfile::tempdir().expect("repository");
        let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
        let plan = compilation_plan(&guard, true);
        // Backups are calls 0 and 1; publish `.okf` is call 2. Replace that
        // destination immediately after publication and force rollback.
        let bundle = repository.path().join(".okf");
        let mut renamer = FaultRenamer::replacing_after(2, bundle.clone());
        let error = plan
            .commit_with(&mut renamer)
            .expect_err("replacement race must fail closed");
        assert!(error.to_string().contains("recovery data was preserved"));
        assert_eq!(
            fs::read_to_string(bundle.join("third-party.txt")).expect("third-party data"),
            "do not delete"
        );
        let recovery = fs::read_dir(repository.path())
            .expect("repository entries")
            .map(|entry| entry.expect("repository entry").path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".repo2okf-publish-"))
            })
            .expect("preserved recovery directory");
        assert!(recovery.join("backups/0/version").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn owned_output_with_nested_link_is_restored_and_refused() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().expect("repository");
        let guard = RepositoryGuard::capture(repository.path()).expect("repository guard");
        let plan = compilation_plan(&guard, true);
        symlink(
            repository.path().join("README.md"),
            repository.path().join(".okf/linked"),
        )
        .expect("nested output symlink");
        let error = plan
            .commit()
            .expect_err("link-like old output must be refused");
        assert!(error.to_string().contains("restored to its prior state"));
        assert_compilation(repository.path(), "old");
        assert!(
            fs::symlink_metadata(repository.path().join(".okf/linked"))
                .expect("restored nested symlink")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn enforces_json_limit_at_the_exact_boundary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("fixture.json");
        let json = br#"{"value": 7}"#;
        fs::write(&path, json).expect("write JSON");
        let exact = u64::try_from(json.len()).expect("fixture length fits u64");
        assert_eq!(
            read_json_with_limit::<Fixture>(&path, exact).expect("exact boundary should load"),
            Fixture { value: 7 }
        );
        assert!(read_json_with_limit::<Fixture>(&path, exact - 1).is_err());
    }

    #[test]
    fn bounded_reader_detects_growth_past_limit() {
        let input = std::io::Cursor::new(b"abc");
        let mut reader = BoundedReader::new(input, 2);
        let mut output = Vec::new();
        let error = reader
            .read_to_end(&mut output)
            .expect_err("third byte must exceed limit");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(output, b"ab");
    }

    #[test]
    fn public_json_limit_rejects_oversized_sparse_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("oversized.json");
        let file = fs::File::create(&path).expect("create sparse fixture");
        file.set_len(MAX_JSON_INPUT_BYTES + 1)
            .expect("size sparse fixture");
        let error = read_json::<Fixture>(&path).expect_err("oversized JSON should fail");
        assert!(error.to_string().contains("safety limit"));
    }

    #[test]
    fn rejects_non_regular_json_input() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("directory.json");
        fs::create_dir(&path).expect("directory fixture");
        assert!(read_json::<Fixture>(&path).is_err());
    }

    #[test]
    fn fixed_file_comparison_is_exact_and_bounded() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("marker");
        let expected = b"owned\n";
        assert!(!matches_fixed_file(&path, expected).expect("missing is not owned"));
        fs::write(&path, expected).expect("write marker");
        assert!(matches_fixed_file(&path, expected).expect("exact marker"));
        fs::write(&path, b"owned\nextra").expect("write oversized marker");
        assert!(!matches_fixed_file(&path, expected).expect("oversized is not owned"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_ancestor() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().expect("repository");
        let outside = tempfile::tempdir().expect("outside");
        symlink(outside.path(), repository.path().join("linked")).expect("symlink fixture");
        assert!(resolve_beneath(repository.path(), Path::new("linked/output.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link_json_and_marker() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        fs::write(&target, br#"{"value": 1}"#).expect("target");
        let linked_json = temp.path().join("linked.json");
        symlink(&target, &linked_json).expect("JSON symlink");
        assert!(read_json::<Fixture>(&linked_json).is_err());

        let linked_marker = temp.path().join("linked.marker");
        symlink(&target, &linked_marker).expect("marker symlink");
        assert!(matches_fixed_file(&linked_marker, b"owned\n").is_err());
    }
}
