//! Command-line surface. Kept declarative: every command body lives in [`crate::app`].

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// End-to-end encrypted synchronisation of Claude Code memories across machines.
#[derive(Debug, Parser)]
#[command(name = "memsync", version, about, long_about = None)]
pub struct Cli {
    /// Log more detail. Repeat for debug output.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create this machine's key and connect it to a store.
    Init {
        /// Git remote of the encrypted store, e.g. `git@github.com:you/claude-memory-store.git`.
        #[arg(long)]
        remote: String,
        /// Name for this machine (defaults to the hostname).
        #[arg(long)]
        label: Option<String>,
        /// Where to keep the local clone of the store.
        #[arg(long)]
        store_path: Option<PathBuf>,
        /// Do not look for Claude Code memory directories.
        #[arg(long)]
        no_discover: bool,
    },

    /// Synchronise now.
    Sync {
        /// Print nothing on success. Intended for session hooks.
        #[arg(long)]
        quiet: bool,
    },

    /// Show what the store holds and whether this machine can read it.
    Status,

    /// Manage the machines authorised to read the store.
    Key {
        /// Which key operation to perform.
        #[command(subcommand)]
        command: KeyCommand,
    },

    /// Manage the directories that are synchronised.
    Root {
        /// Which root operation to perform.
        #[command(subcommand)]
        command: RootCommand,
    },

    /// Install the Claude Code session hooks that run `memsync sync`.
    InstallHooks {
        /// Command to run from the hook (defaults to this executable).
        #[arg(long)]
        command: Option<String>,
    },

    /// Remove the Claude Code session hooks.
    UninstallHooks,
}

/// Operations on the recipient set.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Print this machine's public key.
    Show,
    /// List the authorised machines.
    List,
    /// Authorise another machine and re-encrypt the store for it.
    Add {
        /// The other machine's age public key (`age1...`).
        key: String,
        /// Name for that machine.
        #[arg(long)]
        label: String,
    },
    /// Revoke a machine and re-encrypt the store without it.
    Remove {
        /// The machine's label, as shown by `memsync key list`.
        label: String,
    },
    /// Print this machine's private key so it can be backed up.
    Export,
}

/// Operations on the root mapping.
#[derive(Debug, Subcommand)]
pub enum RootCommand {
    /// List the roots configured on this machine.
    List,
    /// List every root the store contains, mapped or not.
    Store,
    /// Add a directory under a new logical id.
    Add {
        /// Logical id, identical on every machine.
        id: String,
        /// Local directory.
        path: PathBuf,
    },
    /// Point an existing id at a different local directory.
    ///
    /// Use this after moving a memory directory: the store is untouched.
    Map {
        /// Logical id to repoint.
        id: String,
        /// New local directory.
        path: PathBuf,
    },
    /// Stop synchronising a root. Stored objects are kept.
    Remove {
        /// Logical id to drop.
        id: String,
    },
}
