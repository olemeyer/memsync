//! Key handling, envelope encryption, and privacy-preserving object naming.

use crate::model::ObjectKey;
use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

/// Errors raised by key handling and encryption.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The identity file could not be read or written.
    #[error("cannot access the identity file at {path}: {source}")]
    IdentityIo {
        /// Path that was being accessed.
        path: String,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The identity file did not contain a usable age key.
    #[error("the identity file at {path} does not contain a valid age key: {reason}")]
    MalformedIdentity {
        /// Path that was being parsed.
        path: String,
        /// Why parsing failed.
        reason: String,
    },
    /// A recipient string was not a valid age public key.
    #[error("`{value}` is not a valid age public key (expected an `age1...` string)")]
    MalformedRecipient {
        /// The rejected value.
        value: String,
    },
    /// No recipient was configured, so nothing could be encrypted.
    #[error("no recipients configured; run `memsync key add` first")]
    NoRecipients,
    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
    /// Decryption failed — most often because this machine's key is not a recipient.
    #[error("decryption failed (is this machine authorised?): {0}")]
    Decrypt(#[from] age::DecryptError),
    /// An IO error while streaming through the cipher.
    #[error("cipher stream failed: {0}")]
    Stream(#[from] std::io::Error),
}

/// Encrypts to a fixed recipient set and decrypts with this machine's key.
pub trait Cipher {
    /// Encrypts `plaintext` to every configured recipient.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Decrypts `ciphertext` with this machine's identity.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// An [`age`]-backed cipher: X25519 key agreement, ChaCha20-Poly1305 payloads, ASCII armour.
///
/// Armour costs about a third in size and buys readable `git diff` output and a store that
/// survives any tool that assumes text files.
pub struct AgeCipher {
    identity: Identity,
    recipients: Vec<Recipient>,
}

impl AgeCipher {
    /// Builds a cipher from this machine's identity and the authorised recipient set.
    pub fn new(identity: Identity, recipients: Vec<Recipient>) -> Self {
        Self {
            identity,
            recipients,
        }
    }

    /// Loads the identity at `path`, creating a new key pair if the file does not exist.
    ///
    /// The file is written with mode `0600`; the private key never leaves the machine.
    pub fn load_or_create_identity(path: &Path) -> Result<Identity, CryptoError> {
        let io_err = |source: std::io::Error| CryptoError::IdentityIo {
            path: path.display().to_string(),
            source,
        };

        if path.exists() {
            let raw = std::fs::read_to_string(path).map_err(io_err)?;
            let line = raw
                .lines()
                .map(str::trim)
                .find(|l| l.starts_with("AGE-SECRET-KEY-"))
                .ok_or_else(|| CryptoError::MalformedIdentity {
                    path: path.display().to_string(),
                    reason: "no AGE-SECRET-KEY- line found".to_string(),
                })?;
            return Identity::from_str(line).map_err(|reason| CryptoError::MalformedIdentity {
                path: path.display().to_string(),
                reason: reason.to_string(),
            });
        }

        let identity = Identity::generate();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io_err)?;
        }
        let contents = format!(
            "# memsync identity — private key, never copy this to another machine.\n\
             # public key: {}\n{}\n",
            identity.to_public(),
            identity.to_string().expose_secret()
        );
        write_private(path, contents.as_bytes()).map_err(io_err)?;
        Ok(identity)
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // Other platforms rely on the user's profile directory being private.
    std::fs::write(path, bytes)
}

impl Cipher for AgeCipher {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.recipients.is_empty() {
            return Err(CryptoError::NoRecipients);
        }
        let encryptor = age::Encryptor::with_recipients(
            self.recipients.iter().map(|r| r as &dyn age::Recipient),
        )?;
        let mut ciphertext = Vec::new();
        let armor = age::armor::ArmoredWriter::wrap_output(
            &mut ciphertext,
            age::armor::Format::AsciiArmor,
        )?;
        let mut writer = encryptor.wrap_output(armor)?;
        writer.write_all(plaintext)?;
        writer.finish()?.finish()?;
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(ciphertext))?;
        let mut reader =
            decryptor.decrypt(std::iter::once(&self.identity as &dyn age::Identity))?;
        let mut plaintext = Vec::new();
        reader.read_to_end(&mut plaintext)?;
        Ok(plaintext)
    }
}

/// One authorised machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientEntry {
    /// Human-readable machine name.
    pub label: String,
    /// The machine's age public key.
    pub key: String,
}

/// The authorised recipient set, stored unencrypted in the store.
///
/// Public keys are not secret, and a machine that has just been added must be able to read
/// this file before it can decrypt anything.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipientSet {
    /// Every machine allowed to read the store.
    #[serde(default, rename = "recipient")]
    pub recipients: Vec<RecipientEntry>,
}

impl RecipientSet {
    /// Parses the on-disk representation.
    pub fn parse(raw: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(raw)
    }

    /// Renders the on-disk representation.
    ///
    /// # Panics
    ///
    /// Panics only if the recipient set cannot be rendered as TOML, which its field types
    /// rule out.
    pub fn render(&self) -> String {
        toml::to_string_pretty(self).expect("recipient set is serialisable")
    }

    /// Adds a recipient, replacing any entry with the same key or label.
    pub fn upsert(&mut self, label: &str, key: &str) {
        self.recipients.retain(|r| r.key != key && r.label != label);
        self.recipients.push(RecipientEntry {
            label: label.to_string(),
            key: key.to_string(),
        });
        self.recipients.sort_by(|a, b| a.label.cmp(&b.label));
    }

    /// Removes a recipient by label, reporting whether anything was removed.
    pub fn remove(&mut self, label: &str) -> bool {
        let before = self.recipients.len();
        self.recipients.retain(|r| r.label != label);
        before != self.recipients.len()
    }

    /// Parses every entry into an age recipient.
    pub fn to_age(&self) -> Result<Vec<Recipient>, CryptoError> {
        self.recipients
            .iter()
            .map(|r| {
                Recipient::from_str(&r.key).map_err(|_| CryptoError::MalformedRecipient {
                    value: r.key.clone(),
                })
            })
            .collect()
    }
}

/// Derives the store file name for a key.
///
/// This is a *keyed* hash: memory file names come from a small, guessable space, so a plain
/// digest would let anyone with read access to the store confirm that a given file exists by
/// hashing candidate names. The key is the store salt, which is itself only available in
/// encrypted form.
pub fn blob_name(salt: &[u8; 32], key: &ObjectKey) -> String {
    let digest = blake3::keyed_hash(salt, &key.naming_bytes());
    format!("{}.age", digest.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cipher_for(identity: &Identity, recipients: &[&Identity]) -> AgeCipher {
        AgeCipher::new(
            identity.clone(),
            recipients.iter().map(|i| i.to_public()).collect(),
        )
    }

    #[test]
    fn round_trips_through_the_envelope() {
        let id = Identity::generate();
        let cipher = cipher_for(&id, &[&id]);
        let ciphertext = cipher.encrypt(b"secret").unwrap();
        assert_ne!(ciphertext, b"secret");
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), b"secret");
    }

    #[test]
    fn output_is_ascii_armoured_so_git_sees_a_text_file() {
        let id = Identity::generate();
        let ciphertext = cipher_for(&id, &[&id]).encrypt(b"secret").unwrap();
        let text = String::from_utf8(ciphertext).expect("armoured output is ASCII");
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    }

    #[test]
    fn every_recipient_can_read_the_same_ciphertext() {
        let a = Identity::generate();
        let b = Identity::generate();
        let ciphertext = cipher_for(&a, &[&a, &b]).encrypt(b"shared").unwrap();
        assert_eq!(
            cipher_for(&b, &[&a, &b]).decrypt(&ciphertext).unwrap(),
            b"shared"
        );
    }

    #[test]
    fn an_unauthorised_key_cannot_read() {
        let a = Identity::generate();
        let outsider = Identity::generate();
        let ciphertext = cipher_for(&a, &[&a]).encrypt(b"shared").unwrap();
        assert!(cipher_for(&outsider, &[&a]).decrypt(&ciphertext).is_err());
    }

    #[test]
    fn encrypting_without_recipients_is_an_error_not_a_plaintext_write() {
        let id = Identity::generate();
        let cipher = AgeCipher::new(id, Vec::new());
        assert!(matches!(
            cipher.encrypt(b"x"),
            Err(CryptoError::NoRecipients)
        ));
    }

    #[test]
    fn identity_is_created_once_and_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        let first = AgeCipher::load_or_create_identity(&path).unwrap();
        let second = AgeCipher::load_or_create_identity(&path).unwrap();
        assert_eq!(
            first.to_public().to_string(),
            second.to_public().to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn identity_file_is_not_group_or_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        AgeCipher::load_or_create_identity(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "identity file must be private, got {mode:o}"
        );
    }

    #[test]
    fn blob_names_are_stable_and_key_dependent() {
        let salt = [7u8; 32];
        let a = ObjectKey::new("r", "a.md");
        assert_eq!(blob_name(&salt, &a), blob_name(&salt, &a));
        assert_ne!(
            blob_name(&salt, &a),
            blob_name(&salt, &ObjectKey::new("r", "b.md"))
        );
    }

    #[test]
    fn blob_names_depend_on_the_salt_so_they_cannot_be_guessed() {
        let key = ObjectKey::new("home-memory", "tailscale-api-key.md");
        assert_ne!(blob_name(&[1u8; 32], &key), blob_name(&[2u8; 32], &key));
    }

    #[test]
    fn recipient_set_round_trips_and_deduplicates() {
        let mut set = RecipientSet::default();
        let id = Identity::generate();
        set.upsert("thinkpad", &id.to_public().to_string());
        set.upsert("thinkpad", &id.to_public().to_string());
        assert_eq!(set.recipients.len(), 1);

        let parsed = RecipientSet::parse(&set.render()).unwrap();
        assert_eq!(parsed.recipients, set.recipients);
        assert_eq!(parsed.to_age().unwrap().len(), 1);

        assert!(set.remove("thinkpad"));
        assert!(!set.remove("thinkpad"));
    }
}
