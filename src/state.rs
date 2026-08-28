//! The snapshot recorded after each successful run, and the lock that keeps two runs apart.
//!
//! Without a base snapshot, "absent here, present there" is ambiguous: it could be a file
//! this machine deleted or one the other machine created. The snapshot is what makes
//! deletions converge instead of resurrecting.

use crate::model::{FileState, ObjectKey, Snapshot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Errors raised while reading or writing local state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// The state file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The state file was not valid JSON.
    #[error("malformed state file at {path}: {source}")]
    Malformed {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying parse error.
        source: serde_json::Error,
    },
    /// Another run holds the lock.
    #[error("another memsync run is in progress (lock held at {0})")]
    Locked(PathBuf),
}

/// Current state file version.
const STATE_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Entry {
    key: ObjectKey,
    #[serde(flatten)]
    state: FileState,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    version: u32,
    entries: Vec<Entry>,
}

/// Reads the previous snapshot. A missing or unreadable-version file yields an empty
/// snapshot, which is the correct conservative starting point: everything looks new, so
/// both sides are merged rather than deleted.
pub fn load(path: &Path) -> Result<Snapshot, StateError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Snapshot::new()),
        Err(source) => {
            return Err(StateError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let parsed: StateFile = serde_json::from_str(&raw).map_err(|source| StateError::Malformed {
        path: path.to_path_buf(),
        source,
    })?;
    if parsed.version != STATE_VERSION {
        return Ok(Snapshot::new());
    }
    Ok(parsed
        .entries
        .into_iter()
        .map(|e| (e.key, e.state))
        .collect())
}

/// Writes the snapshot atomically, so an interrupted write cannot corrupt it.
///
/// # Panics
///
/// Panics only if the snapshot cannot be rendered as JSON, which its field types rule out.
pub fn save(path: &Path, snapshot: &Snapshot) -> Result<(), StateError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| StateError::Io {
            path: path.clone(),
            source,
        }
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    let file = StateFile {
        version: STATE_VERSION,
        entries: snapshot
            .iter()
            .map(|(key, state)| Entry {
                key: key.clone(),
                state: state.clone(),
            })
            .collect(),
    };
    let rendered = serde_json::to_string_pretty(&file).expect("state is serialisable");
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, rendered).map_err(io(&temp))?;
    std::fs::rename(&temp, path).map_err(io(path))
}

/// How long a lock file is honoured before it is treated as abandoned.
const LOCK_STALE_SECONDS: u64 = 600;

/// A best-effort exclusive lock, released when dropped.
///
/// Claude Code can run several sessions at once; two engines writing the same store clone
/// would interleave their commits.
#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
}

impl Lock {
    /// Acquires the lock, stealing it if the holder left it behind more than ten minutes ago.
    pub fn acquire(path: &Path) -> Result<Self, StateError> {
        let io = |source| StateError::Io {
            path: path.to_path_buf(),
            source,
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        if let Ok(metadata) = std::fs::metadata(path) {
            let stale = metadata
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > LOCK_STALE_SECONDS);
            if stale {
                tracing::warn!(lock = %path.display(), "removing a stale lock");
                let _ = std::fs::remove_file(path);
            }
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(_) => Ok(Self {
                path: path.to_path_buf(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(StateError::Locked(path.to_path_buf()))
            }
            Err(source) => Err(StateError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ContentHash;

    #[test]
    fn round_trips_a_snapshot_including_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let mut snapshot = Snapshot::new();
        snapshot.insert(
            ObjectKey::new("r", "a.md"),
            FileState::Present {
                hash: ContentHash::of(b"x"),
                modified_ms: 5,
            },
        );
        snapshot.insert(
            ObjectKey::new("r", "b.md"),
            FileState::Deleted { modified_ms: 9 },
        );

        save(&path, &snapshot).unwrap();
        assert_eq!(load(&path).unwrap(), snapshot);
    }

    #[test]
    fn a_missing_state_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("nothing.json")).unwrap().is_empty());
    }

    #[test]
    fn a_future_version_reads_as_empty_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, r#"{"version":99,"entries":[]}"#).unwrap();
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn corrupt_state_is_reported_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, "{{{").unwrap();
        assert!(matches!(load(&path), Err(StateError::Malformed { .. })));
    }

    #[test]
    fn the_lock_excludes_a_second_run_and_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");

        let held = Lock::acquire(&path).unwrap();
        assert!(matches!(Lock::acquire(&path), Err(StateError::Locked(_))));
        drop(held);

        Lock::acquire(&path).expect("the lock must be free again once the holder is gone");
    }
}
