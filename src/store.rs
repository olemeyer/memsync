//! The encrypted store: an ordinary git repository whose working tree holds only ciphertext.
//!
//! Git is reached through the [`GitRunner`] trait so that the store can be exercised against
//! a stub, and so that the one place that shells out is easy to audit.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Errors raised while operating on the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A git invocation failed.
    #[error("git {args} failed in {repo}: {stderr}")]
    Git {
        /// The arguments passed to git.
        args: String,
        /// The repository the command ran in.
        repo: String,
        /// Captured standard error.
        stderr: String,
    },
    /// Git could not be executed at all.
    #[error("cannot execute git: {0}")]
    GitUnavailable(#[source] std::io::Error),
    /// A store file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The push was rejected repeatedly because another machine kept winning the race.
    #[error("could not push after {0} attempts; another machine is pushing continuously")]
    PushContention(usize),
}

/// Runs git commands. Implemented by [`SystemGit`] in production.
pub trait GitRunner {
    /// Runs git in `repo` and returns standard output.
    fn run(&self, repo: &Path, args: &[&str]) -> Result<String, StoreError>;

    /// Runs git and reports success instead of failing, for commands whose non-zero exit is
    /// meaningful rather than exceptional (`diff --quiet`, `push` under contention).
    fn try_run(&self, repo: &Path, args: &[&str]) -> Result<bool, StoreError>;
}

/// Executes the `git` binary found on `PATH`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemGit;

impl SystemGit {
    fn command(repo: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(repo).args(args);
        // Never block a session hook on an interactive credential prompt.
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        cmd.env("GIT_ADVICE", "0");
        cmd
    }
}

impl GitRunner for SystemGit {
    fn run(&self, repo: &Path, args: &[&str]) -> Result<String, StoreError> {
        let output = Self::command(repo, args)
            .output()
            .map_err(StoreError::GitUnavailable)?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(StoreError::Git {
                args: args.join(" "),
                repo: repo.display().to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            })
        }
    }

    fn try_run(&self, repo: &Path, args: &[&str]) -> Result<bool, StoreError> {
        let output = Self::command(repo, args)
            .output()
            .map_err(StoreError::GitUnavailable)?;
        Ok(output.status.success())
    }
}

/// Directory inside the store holding encrypted objects.
pub const BLOB_DIR: &str = "blobs";
/// File listing the authorised machines, in the clear.
pub const RECIPIENTS_FILE: &str = "recipients.toml";
/// Encrypted naming salt.
pub const SALT_FILE: &str = "salt.age";

/// How many times a rejected push is retried before giving up.
const PUSH_ATTEMPTS: usize = 5;

/// A local clone of the encrypted store.
pub struct GitStore<G: GitRunner> {
    path: PathBuf,
    branch: String,
    git: G,
}

impl<G: GitRunner> GitStore<G> {
    /// Opens the clone at `path`, creating and wiring it to `remote` if it does not exist.
    pub fn open_or_clone(path: &Path, remote: &str, git: G) -> Result<Self, StoreError> {
        let store = Self {
            path: path.to_path_buf(),
            branch: "main".to_string(),
            git,
        };
        if !path.join(".git").is_dir() {
            std::fs::create_dir_all(path).map_err(|source| StoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            store
                .git
                .run(path, &["init", "--initial-branch", &store.branch])?;
            store.git.run(path, &["remote", "add", "origin", remote])?;
            store.ensure_committer_identity()?;
            std::fs::create_dir_all(path.join(BLOB_DIR)).map_err(|source| StoreError::Io {
                path: path.join(BLOB_DIR),
                source,
            })?;
        }
        Ok(store)
    }

    /// The clone's location on disk.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gives the store repository a committer identity when the machine has no global one.
    ///
    /// Without this, `git commit` fails on a freshly provisioned machine or CI runner. A
    /// configured identity is left alone: commits should carry the user's own name where
    /// there is one.
    fn ensure_committer_identity(&self) -> Result<(), StoreError> {
        if self
            .git
            .try_run(&self.path, &["config", "--get", "user.email"])?
        {
            return Ok(());
        }
        self.git
            .run(&self.path, &["config", "user.name", "memsync"])?;
        self.git
            .run(&self.path, &["config", "user.email", "memsync@localhost"])?;
        Ok(())
    }

    /// Brings the working tree to exactly the remote's state, discarding anything local.
    ///
    /// The clone is a cache: the authoritative copies are the remote and this machine's own
    /// files. Resetting rather than merging means a failed run can never leave a half-written
    /// object behind to be pushed later.
    pub fn pull(&self) -> Result<(), StoreError> {
        self.git.run(&self.path, &["fetch", "--quiet", "origin"])?;
        let remote_ref = format!("origin/{}", self.branch);
        if self.git.try_run(
            &self.path,
            &["rev-parse", "--verify", "--quiet", &remote_ref],
        )? {
            self.git
                .run(&self.path, &["reset", "--hard", "--quiet", &remote_ref])?;
            self.git.run(&self.path, &["clean", "-fdq"])?;
        }
        std::fs::create_dir_all(self.path.join(BLOB_DIR)).map_err(|source| StoreError::Io {
            path: self.path.join(BLOB_DIR),
            source,
        })?;
        Ok(())
    }

    /// Commits the working tree and pushes it.
    ///
    /// Returns `false` when there was nothing to commit. A rejected push means another
    /// machine pushed first; the caller must re-plan against the new remote state rather than
    /// forcing, so contention is reported instead of resolved here.
    pub fn commit_and_push(&self, message: &str) -> Result<bool, StoreError> {
        self.git.run(&self.path, &["add", "--all"])?;
        if self
            .git
            .try_run(&self.path, &["diff", "--cached", "--quiet"])?
        {
            return Ok(false);
        }
        self.git
            .run(&self.path, &["commit", "--quiet", "--message", message])?;
        let refspec = format!("HEAD:{}", self.branch);
        if self
            .git
            .try_run(&self.path, &["push", "--quiet", "origin", &refspec])?
        {
            Ok(true)
        } else {
            Err(StoreError::PushContention(PUSH_ATTEMPTS))
        }
    }

    /// Lists the names of every object in the store.
    pub fn blob_names(&self) -> Result<Vec<String>, StoreError> {
        let dir = self.path.join(BLOB_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => return Err(StoreError::Io { path: dir, source }),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| StoreError::Io {
                path: dir.clone(),
                source,
            })?;
            if entry.path().extension().is_some_and(|e| e == "age") {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Reads an object, or `None` if it does not exist.
    pub fn read_blob(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Self::read_optional(&self.path.join(BLOB_DIR).join(name))
    }

    /// Writes an object.
    pub fn write_blob(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.path.join(BLOB_DIR).join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| StoreError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        std::fs::write(&path, bytes).map_err(|source| StoreError::Io { path, source })
    }

    /// Reads the recipient file, or `None` in an empty store.
    pub fn read_recipients(&self) -> Result<Option<String>, StoreError> {
        Ok(Self::read_optional(&self.path.join(RECIPIENTS_FILE))?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// Writes the recipient file.
    pub fn write_recipients(&self, contents: &str) -> Result<(), StoreError> {
        let path = self.path.join(RECIPIENTS_FILE);
        std::fs::write(&path, contents).map_err(|source| StoreError::Io { path, source })
    }

    /// Reads the encrypted salt, or `None` in an empty store.
    pub fn read_salt(&self) -> Result<Option<Vec<u8>>, StoreError> {
        Self::read_optional(&self.path.join(SALT_FILE))
    }

    /// Writes the encrypted salt.
    pub fn write_salt(&self, ciphertext: &[u8]) -> Result<(), StoreError> {
        let path = self.path.join(SALT_FILE);
        std::fs::write(&path, ciphertext).map_err(|source| StoreError::Io { path, source })
    }

    fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StoreError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records invocations and answers from a script, so store behaviour can be asserted
    /// without a git binary.
    #[derive(Default)]
    struct FakeGit {
        calls: RefCell<Vec<String>>,
        ref_exists: bool,
        nothing_staged: bool,
        push_rejected: bool,
    }

    impl GitRunner for FakeGit {
        fn run(&self, _repo: &Path, args: &[&str]) -> Result<String, StoreError> {
            self.calls.borrow_mut().push(args.join(" "));
            Ok(String::new())
        }

        fn try_run(&self, _repo: &Path, args: &[&str]) -> Result<bool, StoreError> {
            self.calls.borrow_mut().push(args.join(" "));
            Ok(match args.first().copied() {
                Some("rev-parse") => self.ref_exists,
                Some("diff") => self.nothing_staged,
                Some("push") => !self.push_rejected,
                _ => true,
            })
        }
    }

    fn store(dir: &Path, git: FakeGit) -> GitStore<FakeGit> {
        GitStore {
            path: dir.to_path_buf(),
            branch: "main".into(),
            git,
        }
    }

    #[test]
    fn pull_on_an_empty_remote_does_not_reset() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(
            dir.path(),
            FakeGit {
                ref_exists: false,
                ..FakeGit::default()
            },
        );
        s.pull().unwrap();
        let calls = s.git.calls.borrow().join("|");
        assert!(calls.contains("fetch"));
        assert!(
            !calls.contains("reset"),
            "an empty remote has nothing to reset to: {calls}"
        );
    }

    #[test]
    fn pull_discards_local_state_when_the_remote_has_commits() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(
            dir.path(),
            FakeGit {
                ref_exists: true,
                ..FakeGit::default()
            },
        );
        s.pull().unwrap();
        let calls = s.git.calls.borrow().join("|");
        assert!(calls.contains("reset --hard --quiet origin/main"));
        assert!(calls.contains("clean -fdq"));
    }

    #[test]
    fn commit_reports_when_there_is_nothing_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(
            dir.path(),
            FakeGit {
                ref_exists: true,
                nothing_staged: true,
                ..FakeGit::default()
            },
        );
        assert!(!s.commit_and_push("m").unwrap());
        assert!(!s.git.calls.borrow().join("|").contains("commit"));
    }

    #[test]
    fn a_rejected_push_is_reported_rather_than_forced() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(
            dir.path(),
            FakeGit {
                push_rejected: true,
                ..FakeGit::default()
            },
        );
        let err = s.commit_and_push("m").unwrap_err();
        assert!(matches!(err, StoreError::PushContention(_)));
        assert!(
            !s.git.calls.borrow().join("|").contains("--force"),
            "a losing push must never escalate to a force push"
        );
    }

    #[test]
    fn blob_listing_ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), FakeGit::default());
        std::fs::create_dir_all(dir.path().join(BLOB_DIR)).unwrap();
        s.write_blob("aa.age", b"x").unwrap();
        std::fs::write(dir.path().join(BLOB_DIR).join("README.md"), "not a blob").unwrap();

        assert_eq!(s.blob_names().unwrap(), vec!["aa.age".to_string()]);
        assert_eq!(s.read_blob("aa.age").unwrap().unwrap(), b"x");
        assert!(s.read_blob("missing.age").unwrap().is_none());
    }
}
