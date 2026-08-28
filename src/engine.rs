//! Orchestration: read both sides, ask [`crate::plan`] what to do, carry it out, push.

use crate::blob::{Blob, BlobError};
use crate::config::{Config, ConfigError, Root};
use crate::crypto::{Cipher, CryptoError, blob_name};
use crate::model::{ContentHash, FileState, ObjectKey, Snapshot};
use crate::plan::{Action, Inputs, Side, plan};
use crate::state::{self, StateError};
use crate::store::{GitRunner, GitStore, StoreError};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Errors raised by a synchronisation run.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Configuration was missing or invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// Encryption or key handling failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The store could not be read, written, or pushed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Local state could not be read or written.
    #[error(transparent)]
    State(#[from] StateError),
    /// A stored object could not be decoded.
    #[error("object {name} is corrupt: {source}")]
    Blob {
        /// Name of the offending object.
        name: String,
        /// Underlying decode error.
        source: BlobError,
    },
    /// A local file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The store has no salt, so object names cannot be derived.
    #[error("the store is not initialised; run `memsync init` on the first machine")]
    Uninitialised,
    /// Too many machines pushed at the same time.
    #[error("gave up after {0} attempts because the store kept changing under us")]
    Contention(usize),
}

/// Reads wall-clock time. Injected so runs are reproducible in tests.
pub trait Clock {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        to_millis(std::time::SystemTime::now())
    }
}

/// What a run changed, for reporting to the user.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Files sent to the store.
    pub uploaded: usize,
    /// Files written locally.
    pub downloaded: usize,
    /// Files removed locally because another machine deleted them.
    pub deleted_locally: usize,
    /// Deletions recorded in the store.
    pub tombstoned: usize,
    /// Divergent edits that were preserved side by side.
    pub conflicts: Vec<ObjectKey>,
    /// Objects belonging to roots this machine does not have, left untouched.
    pub ignored: usize,
    /// Whether anything was pushed.
    pub pushed: bool,
}

impl Report {
    /// Whether the run changed anything at all.
    pub fn is_empty(&self) -> bool {
        self.uploaded == 0
            && self.downloaded == 0
            && self.deleted_locally == 0
            && self.tombstoned == 0
            && self.conflicts.is_empty()
    }
}

/// How often the whole cycle is retried when another machine pushes first.
const SYNC_ATTEMPTS: usize = 3;

/// Drives one synchronisation run.
pub struct Engine<'a, G: GitRunner, C: Cipher, K: Clock> {
    config: &'a Config,
    store: &'a GitStore<G>,
    cipher: &'a C,
    clock: &'a K,
    salt: [u8; 32],
    state_path: PathBuf,
}

impl<'a, G: GitRunner, C: Cipher, K: Clock> Engine<'a, G, C, K> {
    /// Builds an engine. `salt` comes from the store and keys the object naming.
    pub fn new(
        config: &'a Config,
        store: &'a GitStore<G>,
        cipher: &'a C,
        clock: &'a K,
        salt: [u8; 32],
        state_path: PathBuf,
    ) -> Self {
        Self {
            config,
            store,
            cipher,
            clock,
            salt,
            state_path,
        }
    }

    /// Runs until the store and this machine agree, retrying if another machine pushes
    /// first. Each attempt re-reads the store, so a lost race costs work but never
    /// correctness.
    pub fn sync(&self) -> Result<Report, EngineError> {
        let mut last_error = None;
        for attempt in 1..=SYNC_ATTEMPTS {
            match self.sync_once() {
                Ok(report) => return Ok(report),
                Err(EngineError::Store(StoreError::PushContention(_))) => {
                    tracing::warn!(attempt, "push rejected, re-planning against the new store");
                    last_error = Some(EngineError::Contention(SYNC_ATTEMPTS));
                }
                Err(other) => return Err(other),
            }
        }
        Err(last_error.unwrap_or(EngineError::Contention(SYNC_ATTEMPTS)))
    }

    fn sync_once(&self) -> Result<Report, EngineError> {
        self.store.pull()?;

        let base = self.only_known_roots(state::load(&self.state_path)?);
        let local = self.read_local()?;

        // Objects under a root this machine has not configured are none of its business:
        // there is no local directory to compare them against, so including them would make
        // every one of them look locally deleted and produce tombstones that destroy another
        // machine's memories. They stay in the store, untouched and unrecorded.
        let mut ignored = 0usize;
        let remote: BTreeMap<ObjectKey, Blob> = self
            .read_remote()?
            .into_iter()
            .filter(|(key, _)| {
                let known = self.config.root(&key.root).is_some();
                ignored += usize::from(!known);
                known
            })
            .collect();
        if ignored > 0 {
            tracing::info!(
                count = ignored,
                "ignoring objects from roots not configured here"
            );
        }

        let local_snapshot = local
            .iter()
            .map(|(k, v)| (k.clone(), v.state.clone()))
            .collect();
        let remote_snapshot: Snapshot = remote
            .iter()
            .map(|(k, v)| (k.clone(), state_of(v)))
            .collect();

        let actions = plan(&Inputs {
            local: &local_snapshot,
            remote: &remote_snapshot,
            base: &base,
            label: &self.config.label,
        });

        let mut report = Report {
            ignored,
            ..Report::default()
        };
        for action in &actions {
            self.apply(action, &local, &remote, &mut report)?;
        }

        if actions.is_empty() {
            state::save(&self.state_path, &remote_snapshot)?;
            return Ok(report);
        }

        report.pushed = self.store.commit_and_push(&self.commit_message(&report))?;

        // Re-read the store from disk so the recorded base is exactly what was pushed,
        // rather than what we believe we pushed — filtered, so an unknown root never
        // enters the snapshot and cannot look deleted on the next run.
        let settled = self.only_known_roots(
            self.read_remote()?
                .iter()
                .map(|(k, v)| (k.clone(), state_of(v)))
                .collect(),
        );
        state::save(&self.state_path, &settled)?;
        Ok(report)
    }

    /// Drops every entry whose root this machine does not have configured.
    ///
    /// Applied to the loaded snapshot as well as the one written back, so a machine that
    /// synchronises a subset of the roots neither acts on the rest nor records them.
    fn only_known_roots(&self, snapshot: Snapshot) -> Snapshot {
        snapshot
            .into_iter()
            .filter(|(key, _)| self.config.root(&key.root).is_some())
            .collect()
    }

    fn commit_message(&self, report: &Report) -> String {
        let mut parts = Vec::new();
        if report.uploaded > 0 {
            parts.push(format!("{} updated", report.uploaded));
        }
        if report.tombstoned > 0 {
            parts.push(format!("{} deleted", report.tombstoned));
        }
        if !report.conflicts.is_empty() {
            parts.push(format!("{} conflicted", report.conflicts.len()));
        }
        let summary = if parts.is_empty() {
            "no changes".to_string()
        } else {
            parts.join(", ")
        };
        format!("sync from {}: {}", self.config.label, summary)
    }

    // ---- reading both sides -------------------------------------------------------------

    fn read_local(&self) -> Result<BTreeMap<ObjectKey, LocalFile>, EngineError> {
        let mut files = BTreeMap::new();
        for root in &self.config.roots {
            self.read_root(root, &mut files)?;
        }
        Ok(files)
    }

    fn read_root(
        &self,
        root: &Root,
        into: &mut BTreeMap<ObjectKey, LocalFile>,
    ) -> Result<(), EngineError> {
        if !root.path.is_dir() {
            tracing::warn!(root = %root.id, path = %root.path.display(),
                "root directory is missing; skipping it rather than deleting its files");
            return Ok(());
        }
        for entry in walkdir::WalkDir::new(&root.path).follow_links(false) {
            let entry = entry.map_err(|e| EngineError::Io {
                path: root.path.clone(),
                source: e.into(),
            })?;
            if !entry.file_type().is_file() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&root.path)
                .expect("walkdir yields paths under the root")
                .to_string_lossy()
                .replace('\\', "/");
            if is_ignored(&relative) {
                continue;
            }
            let content = std::fs::read(entry.path()).map_err(|source| EngineError::Io {
                path: entry.path().to_path_buf(),
                source,
            })?;
            let modified_ms = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map_or_else(|| self.clock.now_ms(), to_millis);
            let key = ObjectKey::new(root.id.clone(), relative);
            into.insert(
                key,
                LocalFile {
                    path: entry.path().to_path_buf(),
                    state: FileState::Present {
                        hash: ContentHash::of(&content),
                        modified_ms,
                    },
                    content,
                },
            );
        }
        Ok(())
    }

    /// Decrypts and decodes every object in the store, including roots this machine has
    /// not configured. Used by the listing command; the sync path filters afterwards.
    pub fn read_remote(&self) -> Result<BTreeMap<ObjectKey, Blob>, EngineError> {
        let mut objects = BTreeMap::new();
        for name in self.store.blob_names()? {
            let Some(ciphertext) = self.store.read_blob(&name)? else {
                continue;
            };
            let plaintext = self.cipher.decrypt(&ciphertext)?;
            let blob = Blob::decode(&plaintext).map_err(|source| EngineError::Blob {
                name: name.clone(),
                source,
            })?;
            objects.insert(blob.key.clone(), blob);
        }
        Ok(objects)
    }

    // ---- carrying out the plan ----------------------------------------------------------

    fn apply(
        &self,
        action: &Action,
        local: &BTreeMap<ObjectKey, LocalFile>,
        remote: &BTreeMap<ObjectKey, Blob>,
        report: &mut Report,
    ) -> Result<(), EngineError> {
        match action {
            Action::UploadLocal(key) => {
                self.upload_local(key, local)?;
                report.uploaded += 1;
            }
            Action::UploadTombstone(key) => {
                self.put(&Blob::tombstone(key.clone(), self.clock.now_ms()))?;
                report.tombstoned += 1;
            }
            Action::DownloadRemote(key) => {
                self.write_local(key, content_of(remote, key))?;
                report.downloaded += 1;
            }
            Action::DeleteLocal(key) => {
                self.delete_local(key)?;
                report.deleted_locally += 1;
            }
            Action::Resolve {
                key,
                winner,
                rename_to,
            } => {
                self.resolve(key, *winner, rename_to, local, remote, report)?;
            }
        }
        Ok(())
    }

    fn resolve(
        &self,
        key: &ObjectKey,
        winner: Side,
        rename_to: &ObjectKey,
        local: &BTreeMap<ObjectKey, LocalFile>,
        remote: &BTreeMap<ObjectKey, Blob>,
        report: &mut Report,
    ) -> Result<(), EngineError> {
        let losing_copy_needed = rename_to != key;
        match winner {
            Side::Local => {
                if losing_copy_needed {
                    let content = content_of(remote, key).to_vec();
                    self.write_local(rename_to, &content)?;
                    self.put(&Blob::file(rename_to.clone(), self.clock.now_ms(), content))?;
                }
                self.upload_local(key, local)?;
            }
            Side::Remote => {
                if losing_copy_needed {
                    let content = local
                        .get(key)
                        .map(|f| f.content.clone())
                        .unwrap_or_default();
                    self.write_local(rename_to, &content)?;
                    self.put(&Blob::file(rename_to.clone(), self.clock.now_ms(), content))?;
                }
                self.write_local(key, content_of(remote, key))?;
            }
        }
        report.uploaded += 1;
        if losing_copy_needed {
            report.conflicts.push(key.clone());
        }
        Ok(())
    }

    fn upload_local(
        &self,
        key: &ObjectKey,
        local: &BTreeMap<ObjectKey, LocalFile>,
    ) -> Result<(), EngineError> {
        let Some(file) = local.get(key) else {
            // The planner only asks to upload files it saw on disk.
            return Ok(());
        };
        let modified_ms = file
            .state
            .modified_ms()
            .unwrap_or_else(|| self.clock.now_ms());
        self.put(&Blob::file(key.clone(), modified_ms, file.content.clone()))
    }

    fn put(&self, blob: &Blob) -> Result<(), EngineError> {
        let ciphertext = self.cipher.encrypt(&blob.encode())?;
        self.store
            .write_blob(&blob_name(&self.salt, &blob.key), &ciphertext)?;
        Ok(())
    }

    fn local_path(&self, key: &ObjectKey) -> Result<PathBuf, EngineError> {
        let root = self
            .config
            .root(&key.root)
            .ok_or_else(|| ConfigError::DuplicateRoot(key.root.clone()))?;
        Ok(root
            .path
            .join(key.path.replace('/', std::path::MAIN_SEPARATOR_STR)))
    }

    /// Writes a file by renaming a temporary file into place, so a reader never observes a
    /// partially written memory file.
    fn write_local(&self, key: &ObjectKey, content: &[u8]) -> Result<(), EngineError> {
        let Ok(path) = self.local_path(key) else {
            tracing::warn!(key = %key, "no root configured for this object; skipping it");
            return Ok(());
        };
        let io = |path: &Path| {
            let path = path.to_path_buf();
            move |source| EngineError::Io {
                path: path.clone(),
                source,
            }
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io(parent))?;
        }
        let temp = path.with_extension("memsync-tmp");
        std::fs::write(&temp, content).map_err(io(&temp))?;
        std::fs::rename(&temp, &path).map_err(io(&path))
    }

    fn delete_local(&self, key: &ObjectKey) -> Result<(), EngineError> {
        let Ok(path) = self.local_path(key) else {
            return Ok(());
        };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(EngineError::Io { path, source }),
        }
    }
}

/// What one root contributes to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSummary {
    /// The logical root id, as stored.
    pub id: String,
    /// Objects that still hold a file.
    pub files: usize,
    /// Objects that record a deletion.
    pub tombstones: usize,
}

/// Groups decoded store objects by root, most populated first.
///
/// Pure: the caller does the decrypting, this only counts. Ties are broken by id so the
/// listing is stable between runs.
pub fn summarise_roots<'a>(blobs: impl IntoIterator<Item = &'a Blob>) -> Vec<RootSummary> {
    let mut by_root: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for blob in blobs {
        let entry = by_root.entry(blob.key.root.as_str()).or_default();
        if blob.deleted {
            entry.1 += 1;
        } else {
            entry.0 += 1;
        }
    }
    let mut out: Vec<RootSummary> = by_root
        .into_iter()
        .map(|(id, (files, tombstones))| RootSummary {
            id: id.to_string(),
            files,
            tombstones,
        })
        .collect();
    out.sort_by(|a, b| b.files.cmp(&a.files).then_with(|| a.id.cmp(&b.id)));
    out
}

struct LocalFile {
    #[allow(dead_code)]
    path: PathBuf,
    state: FileState,
    content: Vec<u8>,
}

fn state_of(blob: &Blob) -> FileState {
    if blob.deleted {
        FileState::Deleted {
            modified_ms: blob.modified_ms,
        }
    } else {
        FileState::Present {
            hash: ContentHash::of(&blob.content),
            modified_ms: blob.modified_ms,
        }
    }
}

fn content_of<'b>(remote: &'b BTreeMap<ObjectKey, Blob>, key: &ObjectKey) -> &'b [u8] {
    remote.get(key).map_or(&[][..], |b| b.content.as_slice())
}

/// Files memsync never synchronises: git metadata, its own temporary files, and the
/// version history other sync tools leave behind.
fn is_ignored(relative: &str) -> bool {
    relative.starts_with(".git/")
        || relative.starts_with(".stversions/")
        || relative.ends_with(".memsync-tmp")
        || relative.ends_with('~')
}

fn to_millis(time: std::time::SystemTime) -> i64 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        // A timestamp before 1970 is nonsense on a memory file; clamp rather than panic.
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_git_metadata_and_temporary_files() {
        assert!(is_ignored(".git/config"));
        assert!(is_ignored(".stversions/a.md"));
        assert!(is_ignored("notes.md.memsync-tmp"));
        assert!(is_ignored("notes.md~"));
        assert!(!is_ignored("notes.md"));
        assert!(!is_ignored("sub/dir/notes.md"));
    }

    #[test]
    fn timestamps_before_the_epoch_clamp_instead_of_panicking() {
        let before = std::time::UNIX_EPOCH - std::time::Duration::from_secs(60);
        assert_eq!(to_millis(before), 0);
    }

    #[test]
    fn a_tombstone_reads_back_as_a_deletion() {
        let blob = Blob::tombstone(ObjectKey::new("r", "a.md"), 42);
        assert_eq!(state_of(&blob), FileState::Deleted { modified_ms: 42 });
    }

    #[test]
    fn summarising_groups_by_root_and_orders_by_size() {
        let blobs = vec![
            Blob::file(ObjectKey::new("small", "a.md"), 1, b"x".to_vec()),
            Blob::file(ObjectKey::new("big", "a.md"), 1, b"x".to_vec()),
            Blob::file(ObjectKey::new("big", "b.md"), 1, b"x".to_vec()),
            Blob::tombstone(ObjectKey::new("big", "gone.md"), 2),
        ];
        let summary = summarise_roots(&blobs);

        assert_eq!(summary.len(), 2);
        assert_eq!(
            summary[0],
            RootSummary {
                id: "big".into(),
                files: 2,
                tombstones: 1
            }
        );
        assert_eq!(
            summary[1],
            RootSummary {
                id: "small".into(),
                files: 1,
                tombstones: 0
            }
        );
    }

    #[test]
    fn summarising_an_empty_store_yields_nothing() {
        assert!(summarise_roots(&[]).is_empty());
    }

    #[test]
    fn an_empty_report_is_recognised() {
        assert!(Report::default().is_empty());
        assert!(
            !Report {
                uploaded: 1,
                ..Report::default()
            }
            .is_empty()
        );
    }
}
