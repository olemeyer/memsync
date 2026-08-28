//! Encoding of a synchronised file into the plaintext that goes inside an age envelope.
//!
//! Everything that identifies a file — its root, its path, whether it still exists — lives
//! inside the envelope. The store therefore reveals neither names nor deletions.

use crate::model::ObjectKey;
use serde::{Deserialize, Serialize};

/// Errors produced while decoding a blob.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    /// The plaintext did not contain the newline that terminates the header.
    #[error("blob is missing its header terminator")]
    MissingHeader,
    /// The header was not valid JSON of the expected shape.
    #[error("blob header is malformed: {0}")]
    MalformedHeader(#[from] serde_json::Error),
    /// The blob was written by a newer, incompatible format version.
    #[error("unsupported blob format version {0}")]
    UnsupportedVersion(u32),
}

/// Current blob format version. Bumped only for changes that older readers cannot handle.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct Header {
    version: u32,
    root: String,
    path: String,
    modified_ms: i64,
    #[serde(default)]
    deleted: bool,
}

/// A decoded store object: one file, or a tombstone standing in for a deleted one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    /// Which file this object describes.
    pub key: ObjectKey,
    /// Modification time, or deletion time for a tombstone.
    pub modified_ms: i64,
    /// Whether this object records a deletion.
    pub deleted: bool,
    /// File content; empty for a tombstone.
    pub content: Vec<u8>,
}

impl Blob {
    /// Builds an object for an existing file.
    pub fn file(key: ObjectKey, modified_ms: i64, content: Vec<u8>) -> Self {
        Self {
            key,
            modified_ms,
            deleted: false,
            content,
        }
    }

    /// Builds a tombstone.
    pub fn tombstone(key: ObjectKey, modified_ms: i64) -> Self {
        Self {
            key,
            modified_ms,
            deleted: true,
            content: Vec::new(),
        }
    }

    /// Serialises to the plaintext that is handed to the cipher.
    ///
    /// # Panics
    ///
    /// Panics only if serialising a struct of owned strings and integers fails, which
    /// `serde_json` does not do.
    pub fn encode(&self) -> Vec<u8> {
        let header = Header {
            version: FORMAT_VERSION,
            root: self.key.root.clone(),
            path: self.key.path.clone(),
            modified_ms: self.modified_ms,
            deleted: self.deleted,
        };
        // Serialising a struct of owned strings and integers cannot fail.
        let mut out = serde_json::to_vec(&header).expect("header is serialisable");
        out.push(b'\n');
        out.extend_from_slice(&self.content);
        out
    }

    /// Parses the plaintext produced by [`Blob::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, BlobError> {
        let split = bytes
            .iter()
            .position(|b| *b == b'\n')
            .ok_or(BlobError::MissingHeader)?;
        let header: Header = serde_json::from_slice(&bytes[..split])?;
        if header.version > FORMAT_VERSION {
            return Err(BlobError::UnsupportedVersion(header.version));
        }
        Ok(Self {
            key: ObjectKey::new(header.root, header.path),
            modified_ms: header.modified_ms,
            deleted: header.deleted,
            content: bytes[split + 1..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_text() {
        let blob = Blob::file(ObjectKey::new("r", "a/b.md"), 42, b"hello\nworld".to_vec());
        assert_eq!(Blob::decode(&blob.encode()).unwrap(), blob);
    }

    #[test]
    fn round_trips_binary_content_including_newlines_and_nul() {
        let content = vec![0u8, 10, 255, 10, 0, 7];
        let blob = Blob::file(ObjectKey::new("r", "bin"), 1, content);
        assert_eq!(Blob::decode(&blob.encode()).unwrap(), blob);
    }

    #[test]
    fn round_trips_non_ascii_paths() {
        let blob = Blob::file(
            ObjectKey::new("wurzel", "notizen/größe.md"),
            7,
            b"x".to_vec(),
        );
        assert_eq!(Blob::decode(&blob.encode()).unwrap(), blob);
    }

    #[test]
    fn round_trips_a_tombstone() {
        let blob = Blob::tombstone(ObjectKey::new("r", "gone.md"), 99);
        let decoded = Blob::decode(&blob.encode()).unwrap();
        assert!(decoded.deleted);
        assert!(decoded.content.is_empty());
        assert_eq!(decoded.modified_ms, 99);
    }

    #[test]
    fn rejects_plaintext_without_a_header() {
        assert!(matches!(
            Blob::decode(b"no newline here"),
            Err(BlobError::MissingHeader)
        ));
    }

    #[test]
    fn rejects_a_future_format_version() {
        let bytes = br#"{"version":99,"root":"r","path":"p","modified_ms":0,"deleted":false}
body"#;
        assert!(matches!(
            Blob::decode(bytes),
            Err(BlobError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn rejects_a_malformed_header() {
        assert!(matches!(
            Blob::decode(b"{not json}\nbody"),
            Err(BlobError::MalformedHeader(_))
        ));
    }
}
