//! Command implementations: the glue between the CLI and the layers below it.

use crate::blob::Blob;
use crate::config::{self, Config};
use crate::crypto::{AgeCipher, Cipher, RecipientSet};
use crate::engine::{Engine, Report, SystemClock};
use crate::hooks;
use crate::store::{GitStore, SystemGit};
use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail};
use std::path::{Path, PathBuf};

/// Filesystem locations this process works with. Grouped so tests can redirect them.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Machine configuration.
    pub config: PathBuf,
    /// This machine's private key.
    pub identity: PathBuf,
    /// Last-synchronised snapshot.
    pub state: PathBuf,
    /// Run lock.
    pub lock: PathBuf,
    /// Claude Code settings file to install hooks into.
    pub settings: PathBuf,
}

impl Paths {
    /// Standard locations for the current user.
    pub fn for_user() -> Result<Self> {
        let config_dir = config::config_dir()?;
        let state = config::state_path()?;
        let home = dirs::home_dir().context("cannot determine the home directory")?;
        Ok(Self {
            config: config_dir.join("config.toml"),
            identity: config_dir.join("identity.txt"),
            lock: state.with_file_name("memsync.lock"),
            state,
            settings: hooks::default_settings_path(&home),
        })
    }
}

/// Creates the identity, the configuration, and — on the first machine — the store itself.
pub fn init(
    paths: &Paths,
    remote: &str,
    label: Option<String>,
    store_path: Option<PathBuf>,
    discover: bool,
) -> Result<()> {
    let identity = AgeCipher::load_or_create_identity(&paths.identity)?;
    let public_key = identity.to_public().to_string();
    let label = label.unwrap_or_else(default_label);

    let store_path = match store_path {
        Some(path) => config::expand(&path)?,
        None => config::default_store_path()?,
    };

    let mut config = match Config::load_from(&paths.config) {
        Ok(mut existing) => {
            existing.store_remote = remote.to_string();
            existing.store_path.clone_from(&store_path);
            existing.label.clone_from(&label);
            existing
        }
        Err(config::ConfigError::Missing(_)) => Config {
            store_remote: remote.to_string(),
            store_path: store_path.clone(),
            label: label.clone(),
            roots: Vec::new(),
        },
        Err(other) => return Err(other.into()),
    };

    if discover {
        for root in config::discover_claude_roots()? {
            config.set_root(&root.id, &root.path)?;
            println!("root {} -> {}", root.id, root.path.display());
        }
        if config.roots.is_empty() {
            println!("no Claude Code memory directories found; add one with `memsync root add`");
        }
    }
    config.save_to(&paths.config)?;

    let store = GitStore::open_or_clone(&store_path, remote, SystemGit)?;
    store.pull()?;

    let mut recipients = match store.read_recipients()? {
        Some(raw) => RecipientSet::parse(&raw).context("the store's recipient list is corrupt")?,
        None => RecipientSet::default(),
    };

    let known = recipients.recipients.iter().any(|r| r.key == public_key);
    if known {
        println!("this machine is already authorised as `{label}`");
    } else if recipients.recipients.is_empty() {
        // First machine: it bootstraps the store, so it may authorise itself.
        recipients.upsert(&label, &public_key);
        store.write_recipients(&recipients.render())?;

        let cipher = AgeCipher::new(identity, recipients.to_age()?);
        let salt = random_salt();
        store.write_salt(&cipher.encrypt(hex::encode(salt).as_bytes())?)?;
        store.commit_and_push(&format!("initialise store from {label}"))?;
        println!("store initialised and this machine authorised as `{label}`");
    } else {
        // A store already exists and this key is not on it. Adding ourselves would be
        // pointless — we cannot encrypt to a salt we cannot read — and dishonest, since only
        // an existing machine can grant access.
        println!("configuration written, but this machine is not authorised yet.");
        println!();
        println!("Run this on a machine that already has access:");
        println!("    memsync key add {public_key} --label {label}");
        return Ok(());
    }

    println!("public key: {public_key}");
    Ok(())
}

/// Prints this machine's public key.
pub fn key_show(paths: &Paths) -> Result<()> {
    let identity = AgeCipher::load_or_create_identity(&paths.identity)?;
    let label = Config::load_from(&paths.config).map_or_else(|_| default_label(), |c| c.label);
    println!("{label}\t{}", identity.to_public());
    Ok(())
}

/// Lists the authorised machines.
pub fn key_list(paths: &Paths) -> Result<()> {
    let (config, _, store) = open(paths)?;
    let recipients = load_recipients(&store)?;
    let identity = AgeCipher::load_or_create_identity(&paths.identity)?;
    let mine = identity.to_public().to_string();

    for entry in &recipients.recipients {
        let marker = if entry.key == mine {
            " (this machine)"
        } else {
            ""
        };
        println!("{}\t{}{}", entry.label, entry.key, marker);
    }
    if recipients.recipients.is_empty() {
        println!("no machines authorised yet for {}", config.store_remote);
    }
    Ok(())
}

/// Authorises another machine and re-encrypts the whole store to the extended set.
pub fn key_add(paths: &Paths, key: &str, label: &str) -> Result<()> {
    let (config, identity, store) = open(paths)?;
    store.pull()?;

    let mut recipients = load_recipients(&store)?;
    if recipients.recipients.iter().any(|r| r.key == key) {
        println!("`{key}` is already authorised");
        return Ok(());
    }
    recipients.upsert(label, key);
    // Reject a malformed key before rewriting anything.
    let age_recipients = recipients.to_age()?;

    let old_cipher = AgeCipher::new(identity.clone(), Vec::new());
    let new_cipher = AgeCipher::new(identity, age_recipients);

    let salt = read_salt(&store, &old_cipher)?;
    store.write_salt(&new_cipher.encrypt(hex::encode(salt).as_bytes())?)?;
    store.write_recipients(&recipients.render())?;

    let mut rewritten = 0usize;
    for name in store.blob_names()? {
        let Some(ciphertext) = store.read_blob(&name)? else {
            continue;
        };
        let plaintext = old_cipher.decrypt(&ciphertext)?;
        store.write_blob(&name, &new_cipher.encrypt(&plaintext)?)?;
        rewritten += 1;
    }

    store.commit_and_push(&format!("authorise {label} (from {})", config.label))?;
    println!("authorised `{label}`; re-encrypted {rewritten} object(s)");
    Ok(())
}

/// Revokes a machine and re-encrypts so it cannot read future updates.
pub fn key_remove(paths: &Paths, label: &str) -> Result<()> {
    let (config, identity, store) = open(paths)?;
    store.pull()?;

    let mut recipients = load_recipients(&store)?;
    if !recipients.remove(label) {
        bail!("no machine named `{label}` is authorised");
    }
    if recipients.recipients.is_empty() {
        bail!("refusing to remove the last machine: the store would become unreadable");
    }
    let age_recipients = recipients.to_age()?;

    let old_cipher = AgeCipher::new(identity.clone(), Vec::new());
    let new_cipher = AgeCipher::new(identity, age_recipients);

    let salt = read_salt(&store, &old_cipher)?;
    store.write_salt(&new_cipher.encrypt(hex::encode(salt).as_bytes())?)?;
    store.write_recipients(&recipients.render())?;
    for name in store.blob_names()? {
        let Some(ciphertext) = store.read_blob(&name)? else {
            continue;
        };
        let plaintext = old_cipher.decrypt(&ciphertext)?;
        store.write_blob(&name, &new_cipher.encrypt(&plaintext)?)?;
    }
    store.commit_and_push(&format!("revoke {label} (from {})", config.label))?;

    println!("revoked `{label}` and re-encrypted the store.");
    println!(
        "note: that machine still holds every copy it read before now. Rotate any credential \
         it could have seen."
    );
    Ok(())
}

/// Lists the configured roots.
pub fn root_list(paths: &Paths) -> Result<()> {
    let config = Config::load_from(&paths.config)?;
    if config.roots.is_empty() {
        println!("no roots configured; add one with `memsync root add <id> <path>`");
    }
    for root in &config.roots {
        let marker = if root.path.is_dir() {
            ""
        } else {
            "  (missing)"
        };
        println!("{}\t{}{}", root.id, root.path.display(), marker);
    }
    Ok(())
}

/// Adds a root, or points an existing one at a new directory.
///
/// # Panics
///
/// Panics if the root cannot be read back immediately after being written, which would mean
/// the in-memory configuration is inconsistent with itself.
pub fn root_set(paths: &Paths, id: &str, path: &Path) -> Result<()> {
    let mut config = Config::load_from(&paths.config)?;
    let previous = config.root(id).map(|r| r.path.clone());
    config.set_root(id, path)?;
    config.save_to(&paths.config)?;

    let now = &config.root(id).expect("the root was just written").path;
    match previous {
        Some(old) if old != *now => println!("root {id}: {} -> {}", old.display(), now.display()),
        Some(_) => println!("root {id} unchanged"),
        None => println!("root {id} -> {}", now.display()),
    }
    Ok(())
}

/// Removes a root. Stored objects are left untouched.
pub fn root_remove(paths: &Paths, id: &str) -> Result<()> {
    let mut config = Config::load_from(&paths.config)?;
    if !config.remove_root(id) {
        bail!("no root named `{id}`");
    }
    config.save_to(&paths.config)?;
    println!("removed root {id} (its objects remain in the store)");
    Ok(())
}

/// Runs a synchronisation.
pub fn sync(paths: &Paths, quiet: bool) -> Result<()> {
    let _lock = crate::state::Lock::acquire(&paths.lock)?;
    let (config, identity, store) = open(paths)?;
    store.pull()?;

    let recipients = load_recipients(&store)?;
    let public_key = identity.to_public().to_string();
    if !recipients.recipients.iter().any(|r| r.key == public_key) {
        bail!(
            "this machine is not authorised yet. Run on an authorised machine:\n    \
             memsync key add {public_key} --label {}",
            config.label
        );
    }

    let cipher = AgeCipher::new(identity, recipients.to_age()?);
    let salt = read_salt(&store, &cipher)?;
    let clock = SystemClock;
    let engine = Engine::new(&config, &store, &cipher, &clock, salt, paths.state.clone());

    let report = engine.sync()?;
    if !quiet {
        print_report(&report);
    }
    Ok(())
}

/// Reports what a synchronisation would do, without changing anything.
pub fn status(paths: &Paths) -> Result<()> {
    let (config, identity, store) = open(paths)?;
    store.pull()?;
    let recipients = load_recipients(&store)?;
    let cipher = AgeCipher::new(identity, recipients.to_age()?);
    let salt = read_salt(&store, &cipher)?;

    println!("remote:    {}", config.store_remote);
    println!("machine:   {}", config.label);
    println!("roots:     {}", config.roots.len());
    println!("objects:   {}", store.blob_names()?.len());
    println!("machines:  {}", recipients.recipients.len());

    let mut decodable = 0usize;
    for name in store.blob_names()? {
        if let Some(ciphertext) = store.read_blob(&name)?
            && let Ok(plaintext) = cipher.decrypt(&ciphertext)
            && Blob::decode(&plaintext).is_ok()
        {
            decodable += 1;
        }
    }
    println!("readable:  {decodable}");
    // Proves the salt decrypted and names derive as expected.
    println!("naming:    keyed, salt {}…", &hex::encode(salt)[..8]);
    Ok(())
}

/// Installs the Claude Code session hooks.
pub fn install_hooks(paths: &Paths, command: Option<String>) -> Result<()> {
    let command = if let Some(command) = command {
        command
    } else {
        let exe = std::env::current_exe().context("cannot determine this executable")?;
        format!("{} sync --quiet", exe.display())
    };
    if hooks::install(&paths.settings, &command)? {
        println!(
            "installed SessionStart and SessionEnd hooks in {}",
            paths.settings.display()
        );
        println!("command: {command}");
    } else {
        println!("hooks already installed in {}", paths.settings.display());
    }
    Ok(())
}

/// Removes the Claude Code session hooks.
pub fn uninstall_hooks(paths: &Paths) -> Result<()> {
    if hooks::uninstall(&paths.settings)? {
        println!("removed memsync hooks from {}", paths.settings.display());
    } else {
        println!("no memsync hooks found in {}", paths.settings.display());
    }
    Ok(())
}

// ---- shared helpers ---------------------------------------------------------------------

fn open(paths: &Paths) -> Result<(Config, age::x25519::Identity, GitStore<SystemGit>)> {
    let config = Config::load_from(&paths.config)?;
    let identity = AgeCipher::load_or_create_identity(&paths.identity)?;
    let store = GitStore::open_or_clone(&config.store_path, &config.store_remote, SystemGit)?;
    Ok((config, identity, store))
}

fn load_recipients(store: &GitStore<SystemGit>) -> Result<RecipientSet> {
    match store.read_recipients()? {
        Some(raw) => RecipientSet::parse(&raw).context("the store's recipient list is corrupt"),
        None => Ok(RecipientSet::default()),
    }
}

fn read_salt(store: &GitStore<SystemGit>, cipher: &AgeCipher) -> Result<[u8; 32]> {
    let ciphertext = store
        .read_salt()?
        .ok_or_else(|| anyhow!("the store has no salt; run `memsync init` on the first machine"))?;
    let plaintext = cipher.decrypt(&ciphertext)?;
    let decoded = hex::decode(String::from_utf8_lossy(&plaintext).trim())
        .context("the store's salt is not valid hex")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("the store's salt has the wrong length"))
}

/// Generates the store's naming salt.
///
/// `rand::fill` draws from the thread RNG, a ChaCha-based CSPRNG seeded from the operating
/// system — appropriate for a value whose only job is to make object names unguessable.
fn random_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::fill(&mut salt);
    salt
}

fn print_report(report: &Report) {
    if report.is_empty() {
        if report.ignored > 0 {
            println!(
                "already in sync ({} object(s) belong to roots not configured here)",
                report.ignored
            );
        } else {
            println!("already in sync");
        }
        return;
    }
    let mut parts = Vec::new();
    if report.uploaded > 0 {
        parts.push(format!("{} uploaded", report.uploaded));
    }
    if report.downloaded > 0 {
        parts.push(format!("{} downloaded", report.downloaded));
    }
    if report.deleted_locally > 0 {
        parts.push(format!("{} removed locally", report.deleted_locally));
    }
    if report.tombstoned > 0 {
        parts.push(format!("{} deletions recorded", report.tombstoned));
    }
    println!("{}", parts.join(", "));

    if report.ignored > 0 {
        println!(
            "{} object(s) belong to roots not configured here and were left alone",
            report.ignored
        );
    }

    for key in &report.conflicts {
        println!("conflict: {key} — both versions kept, the older one renamed");
    }
}

/// This machine's name, used when the user does not supply one.
fn default_label() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "machine".to_string())
}

/// Exposes the private key for backup. Deliberately explicit rather than a flag on `key show`.
pub fn key_export(paths: &Paths) -> Result<()> {
    let identity = AgeCipher::load_or_create_identity(&paths.identity)?;
    eprintln!("This is the private key for this machine. Store it in a password manager.");
    println!("{}", identity.to_string().expose_secret());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_label_is_always_produced() {
        assert!(!default_label().is_empty());
    }

    #[test]
    fn salts_are_random() {
        assert_ne!(random_salt(), random_salt());
    }

    #[test]
    fn blob_names_derive_from_the_salt_and_key() {
        let salt = random_salt();
        let key = crate::model::ObjectKey::new("r", "a.md");
        assert!(
            std::path::Path::new(&crate::crypto::blob_name(&salt, &key))
                .extension()
                .is_some_and(|e| e == "age")
        );
    }
}
