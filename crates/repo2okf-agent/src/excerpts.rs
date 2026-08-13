//! Host-side construction of bounded, content-verified evidence excerpts.

use std::{
    fs::{self, File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

use repo2okf_core::EvidenceRef;

use crate::model::EvidenceExcerpt;

const MAX_EXCERPT_BYTES: usize = 8 * 1024;
const MAX_TOTAL_EXCERPT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EXCERPTS: usize = 512;
const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn verified_excerpts(root: &Path, evidence: &[EvidenceRef]) -> Vec<EvidenceExcerpt> {
    let Ok(canonical_root) = root.canonicalize() else {
        return Vec::new();
    };
    let mut ordered = evidence.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.start_byte.cmp(&right.start_byte))
            .then_with(|| left.end_byte.cmp(&right.end_byte))
            .then_with(|| left.id.cmp(&right.id))
    });
    ordered.truncate(MAX_EXCERPTS);

    let mut cached_path: Option<&str> = None;
    let mut cached_bytes: Option<Vec<u8>> = None;
    let mut source_bytes_read = 0_u64;
    let mut excerpts = Vec::new();
    let mut total = 0_usize;
    for record in ordered {
        if cached_path != Some(record.path.as_str()) {
            cached_path = Some(record.path.as_str());
            let remaining = MAX_TOTAL_SOURCE_BYTES.saturating_sub(source_bytes_read);
            cached_bytes = read_verified_file(&canonical_root, record, remaining).ok();
            if let Some(bytes) = &cached_bytes {
                source_bytes_read = source_bytes_read
                    .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
            }
        }
        let Some(bytes) = cached_bytes.as_deref() else {
            continue;
        };
        let Ok(start) = usize::try_from(record.start_byte) else {
            continue;
        };
        let Ok(end) = usize::try_from(record.end_byte) else {
            continue;
        };
        if start > end || end > bytes.len() || total >= MAX_TOTAL_EXCERPT_BYTES {
            continue;
        }
        let available = MAX_TOTAL_EXCERPT_BYTES - total;
        let limit = MAX_EXCERPT_BYTES.min(available);
        let proposed_end = end.min(start.saturating_add(limit));
        let mut excerpt_end = proposed_end;
        while excerpt_end > start && std::str::from_utf8(&bytes[start..excerpt_end]).is_err() {
            excerpt_end -= 1;
        }
        let Ok(text) = std::str::from_utf8(&bytes[start..excerpt_end]) else {
            continue;
        };
        total += text.len();
        excerpts.push(EvidenceExcerpt {
            evidence_id: record.id.clone(),
            path: record.path.clone(),
            start_line: record.start_line,
            end_line: record.end_line,
            text: text.to_owned(),
            truncated: excerpt_end < end,
        });
    }
    excerpts
}

fn read_verified_file(
    root: &Path,
    evidence: &EvidenceRef,
    remaining_total_bytes: u64,
) -> Result<Vec<u8>, ()> {
    let relative = safe_relative_path(&evidence.path).ok_or(())?;
    let candidate = root.join(relative);
    reject_reparse_components(root, &candidate)?;
    let before = fs::symlink_metadata(&candidate).map_err(|_| ())?;
    let maximum = MAX_SOURCE_FILE_BYTES.min(remaining_total_bytes);
    if !is_plain_regular_file(&before) || before.len() > maximum {
        return Err(());
    }
    let canonical = candidate.canonicalize().map_err(|_| ())?;
    if !canonical.starts_with(root) {
        return Err(());
    }

    let mut file = File::open(&candidate).map_err(|_| ())?;
    let opened = file.metadata().map_err(|_| ())?;
    if !is_plain_regular_file(&opened)
        || !same_file_snapshot(&before, &opened)
        || opened.len() > maximum
    {
        return Err(());
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if u64::try_from(bytes.len()).map_err(|_| ())? != opened.len()
        || blake3::hash(&bytes).to_hex().as_str() != evidence.content_hash
    {
        return Err(());
    }
    let after = fs::symlink_metadata(&candidate).map_err(|_| ())?;
    if !is_plain_regular_file(&after) || !same_file_snapshot(&before, &after) {
        return Err(());
    }
    Ok(bytes)
}

fn safe_relative_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() || value.contains('\\') || value.contains('\0') {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(path.to_path_buf())
}

fn reject_reparse_components(root: &Path, candidate: &Path) -> Result<(), ()> {
    let relative = candidate.strip_prefix(root).map_err(|_| ())?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(());
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| ())?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(());
        }
    }
    Ok(())
}

fn is_plain_regular_file(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && !is_windows_reparse_point(metadata)
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_windows_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(windows)]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    left.file_size() == right.file_size()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_attributes() == right.file_attributes()
}

#[cfg(not(any(unix, windows)))]
fn same_file_snapshot(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use repo2okf_core::{EvidenceRef, ScanOptions, scan_repository};

    use super::{MAX_EXCERPT_BYTES, MAX_EXCERPTS, verified_excerpts};

    fn evidence(id: usize, path: &str, bytes: &[u8], start: usize, end: usize) -> EvidenceRef {
        EvidenceRef {
            id: format!("ev:{id:04}"),
            path: path.into(),
            start_line: 1,
            end_line: 1,
            start_byte: u64::try_from(start).expect("start"),
            end_byte: u64::try_from(end).expect("end"),
            content_hash: blake3::hash(bytes).to_hex().to_string(),
            symbol: None,
            extractor: "fixture".into(),
        }
    }

    #[test]
    fn returns_hash_verified_precise_utf8_excerpt() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bytes = "zero\nこんにちは world\n".as_bytes();
        fs::write(temp.path().join("source.rs"), bytes).expect("fixture");
        let start = "zero\n".len();
        let record = evidence(1, "source.rs", bytes, start, bytes.len() - 1);
        let excerpts = verified_excerpts(temp.path(), &[record]);
        assert_eq!(excerpts.len(), 1);
        assert_eq!(excerpts[0].text, "こんにちは world");
        assert!(!excerpts[0].truncated);
    }

    #[test]
    fn supplies_exact_python_docstring_evidence_to_the_agent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = concat!(
            "def authorize(user: str) -> bool:\n",
            "    \"\"\"Reject users without an active grant.\"\"\"\n",
            "    return bool(user)\n",
        );
        fs::write(temp.path().join("policy.py"), source).expect("Python fixture");
        let ir = scan_repository(temp.path(), &ScanOptions::default()).expect("scan Python");
        let docstring = ir
            .evidence
            .iter()
            .find(|record| record.symbol.as_deref() == Some("authorize docstring"))
            .expect("exact docstring evidence");

        let excerpts = verified_excerpts(temp.path(), std::slice::from_ref(docstring));
        assert_eq!(excerpts.len(), 1);
        assert_eq!(
            excerpts[0].text,
            "\"\"\"Reject users without an active grant.\"\"\""
        );
        assert!(!excerpts[0].truncated);
    }

    #[test]
    fn skips_tampered_file_and_unsafe_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let original = b"trusted";
        fs::write(temp.path().join("source.rs"), b"tampered").expect("fixture");
        let records = [
            evidence(1, "source.rs", original, 0, original.len()),
            evidence(2, "../outside.rs", original, 0, original.len()),
        ];
        assert!(verified_excerpts(temp.path(), &records).is_empty());
    }

    #[test]
    fn enforces_count_and_per_excerpt_limits_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bytes = vec![b'x'; MAX_EXCERPT_BYTES + 20];
        fs::write(temp.path().join("source.rs"), &bytes).expect("fixture");
        let records = (0..MAX_EXCERPTS + 20)
            .rev()
            .map(|id| evidence(id, "source.rs", &bytes, 0, bytes.len()))
            .collect::<Vec<_>>();
        let excerpts = verified_excerpts(temp.path(), &records);
        assert!(excerpts.len() <= MAX_EXCERPTS);
        assert_eq!(excerpts[0].evidence_id, "ev:0000");
        assert!(
            excerpts
                .iter()
                .all(|excerpt| excerpt.text.len() <= MAX_EXCERPT_BYTES)
        );
        assert!(excerpts.iter().all(|excerpt| excerpt.truncated));
        assert!(
            excerpts
                .iter()
                .map(|excerpt| excerpt.text.len())
                .sum::<usize>()
                <= 2 * 1024 * 1024
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_source() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::NamedTempFile::new().expect("outside");
        fs::write(outside.path(), b"secret").expect("outside fixture");
        symlink(outside.path(), temp.path().join("source.rs")).expect("symlink");
        let record = evidence(1, "source.rs", b"secret", 0, 6);
        assert!(verified_excerpts(temp.path(), &[record]).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_symlink_source_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temp = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::NamedTempFile::new().expect("outside");
        fs::write(outside.path(), b"secret").expect("outside fixture");
        if symlink_file(outside.path(), temp.path().join("source.rs")).is_err() {
            return;
        }
        let record = evidence(1, "source.rs", b"secret", 0, 6);
        assert!(verified_excerpts(temp.path(), &[record]).is_empty());
    }
}
