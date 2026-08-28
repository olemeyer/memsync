//! Core value types shared by every layer.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Identifies one synchronised file, independently of where any machine stores it.
///
/// `root` is a stable logical name (see [`crate::config::Root`]); `path` is relative to that
/// root and always uses `/` as separator, so a store written on one platform stays readable
/// on another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectKey {
    /// Logical root identifier, e.g. `home-memory`.
    pub root: String,
    /// Slash-separated path relative to the root.
    pub path: String,
}

impl ObjectKey {
    /// Creates a key from a root id and a relative path.
    pub fn new(root: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            path: path.into(),
        }
    }

    /// Bytes hashed to derive the blob name. The NUL separator cannot occur in either
    /// component, so distinct keys cannot collide by concatenation.
    pub fn naming_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.root.len() + self.path.len() + 1);
        out.extend_from_slice(self.root.as_bytes());
        out.push(0);
        out.extend_from_slice(self.path.as_bytes());
        out
    }

    /// Derives the key a conflicting copy is stored under, e.g.
    /// `notes.md` -> `notes.conflict-thinkpad-1756412345678.md`.
    #[must_use]
    pub fn conflict_variant(&self, label: &str, modified_ms: i64) -> Self {
        let (dir, file) = match self.path.rsplit_once('/') {
            Some((d, f)) => (Some(d), f),
            None => (None, self.path.as_str()),
        };
        let (stem, ext) = match file.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
            _ => (file, String::new()),
        };
        let sanitised: String = label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let name = format!("{stem}.conflict-{sanitised}-{modified_ms}{ext}");
        let path = match dir {
            Some(d) => format!("{d}/{name}"),
            None => name,
        };
        Self {
            root: self.root.clone(),
            path,
        }
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.root, self.path)
    }
}

/// Content digest of a file, hex-encoded BLAKE3.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentHash(pub String);

impl ContentHash {
    /// Hashes file content.
    pub fn of(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }
}

/// What is known about one key on one side (local disk, store, or the previous snapshot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum FileState {
    /// The file does not exist and no deletion has been recorded.
    Missing,
    /// The file exists with the given content and modification time.
    Present {
        /// Digest of the file content.
        hash: ContentHash,
        /// Modification time in milliseconds since the Unix epoch.
        modified_ms: i64,
    },
    /// The file was deleted; the store keeps a tombstone so the deletion converges.
    Deleted {
        /// When the deletion was recorded, in milliseconds since the Unix epoch.
        modified_ms: i64,
    },
}

impl FileState {
    /// Whether this state carries content.
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// The digest, if the file exists.
    pub fn hash(&self) -> Option<&ContentHash> {
        match self {
            Self::Present { hash, .. } => Some(hash),
            _ => None,
        }
    }

    /// Modification (or deletion) time, if known.
    pub fn modified_ms(&self) -> Option<i64> {
        match self {
            Self::Present { modified_ms, .. } | Self::Deleted { modified_ms } => Some(*modified_ms),
            Self::Missing => None,
        }
    }

    /// Two states are equivalent when they lead to the same file on disk. `Missing` and
    /// `Deleted` differ only in whether a tombstone exists, which does not affect the
    /// working tree.
    pub fn same_effect(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Present { hash: a, .. }, Self::Present { hash: b, .. }) => a == b,
            (Self::Present { .. }, _) | (_, Self::Present { .. }) => false,
            _ => true,
        }
    }
}

/// The state of every known key on one side.
pub type Snapshot = std::collections::BTreeMap<ObjectKey, FileState>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_variant_keeps_extension_and_directory() {
        let key = ObjectKey::new("root", "notes/db.md");
        let c = key.conflict_variant("thinkpad-t14s", 1_756_412_345_678);
        assert_eq!(c.path, "notes/db.conflict-thinkpad-t14s-1756412345678.md");
        assert_eq!(c.root, "root");
    }

    #[test]
    fn conflict_variant_handles_missing_extension_and_dotfiles() {
        assert_eq!(
            ObjectKey::new("r", "README").conflict_variant("m", 1).path,
            "README.conflict-m-1"
        );
        // A leading dot is part of the name, not an extension separator.
        assert_eq!(
            ObjectKey::new("r", ".env").conflict_variant("m", 1).path,
            ".env.conflict-m-1"
        );
    }

    #[test]
    fn conflict_variant_sanitises_the_label() {
        let c = ObjectKey::new("r", "a.md").conflict_variant("my machine/../etc", 7);
        assert_eq!(c.path, "a.conflict-my-machine----etc-7.md");
        assert!(!c.path.contains('/'));
    }

    #[test]
    fn naming_bytes_cannot_collide_across_component_boundaries() {
        let a = ObjectKey::new("ab", "c").naming_bytes();
        let b = ObjectKey::new("a", "bc").naming_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn same_effect_ignores_tombstone_versus_absence() {
        assert!(FileState::Missing.same_effect(&FileState::Deleted { modified_ms: 5 }));
        let p = FileState::Present {
            hash: ContentHash::of(b"x"),
            modified_ms: 1,
        };
        // Modification time does not change the resulting file.
        let q = FileState::Present {
            hash: ContentHash::of(b"x"),
            modified_ms: 99,
        };
        assert!(p.same_effect(&q));
        assert!(!p.same_effect(&FileState::Missing));
    }
}
