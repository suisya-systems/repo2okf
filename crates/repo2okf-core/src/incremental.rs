//! Persistable build fingerprints and deterministic change classification.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{EXTRACTOR_VERSION, RepositoryIr};

/// Persisted state used to classify a subsequent scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildState {
    /// State schema version.
    pub schema_version: u32,
    /// Extractor that produced the state.
    pub extractor: String,
    /// Fingerprint of scan-affecting configuration.
    pub config_fingerprint: String,
    /// Last complete IR fingerprint, retained for freshness checks. It is not
    /// itself a rebuild key because metadata-only changes may alter it while
    /// file inventory and extractor inputs remain identical.
    pub ir_fingerprint: String,
    /// BLAKE3 hash of the complete persisted IR, including agent claims.
    /// Empty values are accepted only for state files written by an older
    /// pre-release build and force a cache miss in callers.
    #[serde(default)]
    pub persisted_ir_hash: String,
    /// File content hashes keyed by normalized path.
    pub files: BTreeMap<String, String>,
    /// Entity IDs keyed by their evidence-bearing file.
    pub entities_by_file: BTreeMap<String, Vec<String>>,
}

impl BuildState {
    /// Build persistable state from a complete validated IR.
    pub fn from_ir(ir: &RepositoryIr, config_fingerprint: impl Into<String>) -> Self {
        let files = ir
            .files
            .iter()
            .map(|file| (file.path.clone(), file.content_hash.clone()))
            .collect();
        let mut entities_by_file: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entity in &ir.entities {
            entities_by_file
                .entry(entity.path.clone())
                .or_default()
                .push(entity.id.clone());
        }
        for entities in entities_by_file.values_mut() {
            entities.sort();
            entities.dedup();
        }
        Self {
            schema_version: 1,
            extractor: EXTRACTOR_VERSION.into(),
            config_fingerprint: config_fingerprint.into(),
            ir_fingerprint: ir.fingerprint.clone(),
            persisted_ir_hash: String::new(),
            files,
            entities_by_file,
        }
    }

    /// Bind this state to the exact serialized IR persisted beside it.
    #[must_use]
    pub fn with_persisted_ir_hash(mut self, hash: impl Into<String>) -> Self {
        self.persisted_ir_hash = hash.into();
        self
    }
}

/// Deterministic differences between two build states.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChangeSet {
    /// Paths only present in the new state.
    pub added: Vec<String>,
    /// Paths whose byte hash changed.
    pub modified: Vec<String>,
    /// Paths no longer present.
    pub removed: Vec<String>,
    /// Paths with an identical byte hash.
    pub unchanged: Vec<String>,
    /// Prior entity IDs invalidated by a modified or removed file.
    pub invalidated_entities: Vec<String>,
    /// True when extractor or configuration compatibility is lost.
    pub requires_full_rebuild: bool,
}

impl ChangeSet {
    /// Whether repository bytes and scan configuration are unchanged.
    pub fn is_empty(&self) -> bool {
        !self.requires_full_rebuild
            && self.added.is_empty()
            && self.modified.is_empty()
            && self.removed.is_empty()
    }
}

/// Compare two persistable states without reading the repository.
pub fn compute_changes(old: &BuildState, new: &BuildState) -> ChangeSet {
    let requires_full_rebuild = old.schema_version != new.schema_version
        || old.extractor != new.extractor
        || old.config_fingerprint != new.config_fingerprint;

    let old_paths: BTreeSet<&str> = old.files.keys().map(String::as_str).collect();
    let new_paths: BTreeSet<&str> = new.files.keys().map(String::as_str).collect();
    let mut changes = ChangeSet {
        requires_full_rebuild,
        ..ChangeSet::default()
    };

    for path in new_paths.difference(&old_paths) {
        changes.added.push((*path).to_owned());
    }
    for path in old_paths.difference(&new_paths) {
        changes.removed.push((*path).to_owned());
    }
    for path in old_paths.intersection(&new_paths) {
        if old.files[*path] == new.files[*path] {
            changes.unchanged.push((*path).to_owned());
        } else {
            changes.modified.push((*path).to_owned());
        }
    }

    let invalidated_files: BTreeSet<&str> = changes
        .modified
        .iter()
        .chain(&changes.removed)
        .map(String::as_str)
        .collect();
    let mut invalidated = BTreeSet::new();
    for path in invalidated_files {
        if let Some(entities) = old.entities_by_file.get(path) {
            invalidated.extend(entities.iter().cloned());
        }
    }
    if requires_full_rebuild {
        invalidated.extend(old.entities_by_file.values().flatten().cloned());
    }
    changes.invalidated_entities = invalidated.into_iter().collect();
    changes
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{BuildState, compute_changes};

    fn state(files: &[(&str, &str)]) -> BuildState {
        BuildState {
            schema_version: 1,
            extractor: "scanner/1".into(),
            config_fingerprint: "cfg".into(),
            ir_fingerprint: "ir".into(),
            persisted_ir_hash: String::new(),
            files: files
                .iter()
                .map(|(path, hash)| ((*path).into(), (*hash).into()))
                .collect(),
            entities_by_file: BTreeMap::from([("changed.ts".into(), vec!["entity:a".into()])]),
        }
    }

    #[test]
    fn classifies_paths_and_invalidates_old_entities() {
        let old = state(&[("changed.ts", "1"), ("removed.ts", "1"), ("same.ts", "1")]);
        let new = state(&[("added.ts", "2"), ("changed.ts", "2"), ("same.ts", "1")]);
        let changes = compute_changes(&old, &new);
        assert_eq!(changes.added, ["added.ts"]);
        assert_eq!(changes.modified, ["changed.ts"]);
        assert_eq!(changes.removed, ["removed.ts"]);
        assert_eq!(changes.unchanged, ["same.ts"]);
        assert_eq!(changes.invalidated_entities, ["entity:a"]);
    }

    #[test]
    fn an_ir_fingerprint_change_without_inventory_changes_is_not_a_rebuild() {
        let old = state(&[("same.ts", "1")]);
        let mut new = old.clone();
        new.ir_fingerprint = "metadata-only-change".into();
        assert!(compute_changes(&old, &new).is_empty());
    }
}
