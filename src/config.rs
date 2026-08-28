//! Machine-local configuration: where the store lives, and which local directory each
//! logical root maps to.
//!
//! The store never records an absolute path. A root id is the stable name shared by every
//! machine; the local path behind it is a property of this machine alone, so a directory can
//! move without touching the store.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Errors raised while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// No configuration file exists yet.
    #[error("no configuration at {0}; run `memsync init` first")]
    Missing(PathBuf),
    /// The configuration file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The configuration file was not valid TOML.
    #[error("malformed configuration at {path}: {source}")]
    Malformed {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying parse error.
        source: toml::de::Error,
    },
    /// A root pointed at something that is not a directory.
    #[error("root `{id}` points at {path}, which is not a directory")]
    RootNotADirectory {
        /// The offending root id.
        id: String,
        /// The configured path.
        path: PathBuf,
    },
    /// Two roots shared an id.
    #[error("duplicate root id `{0}`")]
    DuplicateRoot(String),
    /// The platform did not expose a home or configuration directory.
    #[error("cannot determine the {0} directory for this user")]
    NoUserDirectory(&'static str),
}

/// A directory on this machine, addressed by its logical id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    /// Stable identifier, identical on every machine.
    pub id: String,
    /// Where the directory lives on this machine.
    pub path: PathBuf,
}

/// Everything memsync needs to know about this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Git remote holding the encrypted store.
    pub store_remote: String,
    /// Local clone of the store.
    pub store_path: PathBuf,
    /// This machine's name; appears in the recipient list and in conflict file names.
    pub label: String,
    /// Directories to synchronise.
    #[serde(default)]
    pub roots: Vec<Root>,
}

impl Config {
    /// Reads the configuration for this user.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(&Self::path()?)
    }

    /// Reads a configuration from an explicit path. Used by tests to run several
    /// "machines" side by side.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let raw = match std::fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::Missing(path.to_path_buf()));
            }
            Err(source) => {
                return Err(ConfigError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let config: Self = toml::from_str(&raw).map_err(|source| ConfigError::Malformed {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Writes the configuration to `path`, creating parent directories as needed.
    ///
    /// # Panics
    ///
    /// Panics only if the configuration cannot be rendered as TOML, which its field types
    /// rule out.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        let io = |source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let rendered = toml::to_string_pretty(self).expect("configuration is serialisable");
        std::fs::write(path, rendered).map_err(io)
    }

    /// Rejects configurations that would misbehave at runtime.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = std::collections::BTreeSet::new();
        for root in &self.roots {
            if !seen.insert(root.id.as_str()) {
                return Err(ConfigError::DuplicateRoot(root.id.clone()));
            }
        }
        Ok(())
    }

    /// Looks up a root by id.
    pub fn root(&self, id: &str) -> Option<&Root> {
        self.roots.iter().find(|r| r.id == id)
    }

    /// Adds a root, or repoints an existing one at a new directory.
    ///
    /// This is how a moved directory is handled: the id — and therefore every stored object —
    /// stays the same.
    pub fn set_root(&mut self, id: &str, path: &Path) -> Result<(), ConfigError> {
        let path = expand(path)?;
        if !path.is_dir() {
            return Err(ConfigError::RootNotADirectory {
                id: id.to_string(),
                path,
            });
        }
        match self.roots.iter_mut().find(|r| r.id == id) {
            Some(root) => root.path = path,
            None => self.roots.push(Root {
                id: id.to_string(),
                path,
            }),
        }
        self.roots.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(())
    }

    /// Removes a root, reporting whether it existed.
    pub fn remove_root(&mut self, id: &str) -> bool {
        let before = self.roots.len();
        self.roots.retain(|r| r.id != id);
        before != self.roots.len()
    }

    /// Default configuration file location.
    pub fn path() -> Result<PathBuf, ConfigError> {
        Ok(config_dir()?.join("config.toml"))
    }
}

/// Directory holding the configuration and the private identity.
pub fn config_dir() -> Result<PathBuf, ConfigError> {
    Ok(dirs::config_dir()
        .ok_or(ConfigError::NoUserDirectory("configuration"))?
        .join("memsync"))
}

/// Path of the last-synchronised snapshot.
pub fn state_path() -> Result<PathBuf, ConfigError> {
    Ok(data_dir()?.join("state.json"))
}

/// Default location of the local store clone.
pub fn default_store_path() -> Result<PathBuf, ConfigError> {
    Ok(data_dir()?.join("store"))
}

fn data_dir() -> Result<PathBuf, ConfigError> {
    Ok(dirs::data_local_dir()
        .ok_or(ConfigError::NoUserDirectory("data"))?
        .join("memsync"))
}

/// Expands a leading `~/` and makes the path absolute.
pub fn expand(path: &Path) -> Result<PathBuf, ConfigError> {
    let as_string = path.to_string_lossy();
    let expanded = match as_string.strip_prefix("~/") {
        Some(rest) => dirs::home_dir()
            .ok_or(ConfigError::NoUserDirectory("home"))?
            .join(rest),
        None => path.to_path_buf(),
    };
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        let cwd = std::env::current_dir().map_err(|source| ConfigError::Io {
            path: expanded.clone(),
            source,
        })?;
        Ok(cwd.join(expanded))
    }
}

/// Finds Claude Code memory directories under `~/.claude/projects/<slug>/memory`.
///
/// The derived root id is the project slug with its leading dash removed. Slugs encode the
/// working directory, so a second machine may well produce a different one — that is what
/// `memsync root map` is for, and why the id is never assumed to match a local path.
pub fn discover_claude_roots() -> Result<Vec<Root>, ConfigError> {
    let home = dirs::home_dir().ok_or(ConfigError::NoUserDirectory("home"))?;
    discover_claude_roots_in(&home)
}

/// [`discover_claude_roots`] against an explicit home directory, for tests.
pub fn discover_claude_roots_in(home: &Path) -> Result<Vec<Root>, ConfigError> {
    let projects = home.join(".claude").join("projects");
    let mut roots = Vec::new();
    let entries = match std::fs::read_dir(&projects) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(roots),
        Err(source) => {
            return Err(ConfigError::Io {
                path: projects,
                source,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::Io {
            path: projects.clone(),
            source,
        })?;
        let memory = entry.path().join("memory");
        if !memory.is_dir() {
            continue;
        }
        let slug = entry
            .file_name()
            .to_string_lossy()
            .trim_start_matches('-')
            .to_string();
        let id = if slug.is_empty() {
            "memory".to_string()
        } else {
            slug
        };
        roots.push(Root { id, path: memory });
    }
    roots.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_roots(roots: Vec<Root>) -> Config {
        Config {
            store_remote: "git@example.com:store.git".into(),
            store_path: PathBuf::from("/tmp/store"),
            label: "test".into(),
            roots,
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = config_with_roots(vec![Root {
            id: "home-memory".into(),
            path: dir.path().to_path_buf(),
        }]);
        config.save_to(&path).unwrap();

        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded.label, "test");
        assert_eq!(loaded.roots[0].id, "home-memory");
    }

    #[test]
    fn a_missing_file_names_the_command_that_creates_it() {
        let dir = tempfile::tempdir().unwrap();
        let err = Config::load_from(&dir.path().join("nope.toml")).unwrap_err();
        assert!(err.to_string().contains("memsync init"));
    }

    #[test]
    fn duplicate_root_ids_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let root = Root {
            id: "same".into(),
            path: dir.path().to_path_buf(),
        };
        config_with_roots(vec![root.clone(), root])
            .save_to(&path)
            .unwrap();
        assert!(matches!(
            Config::load_from(&path),
            Err(ConfigError::DuplicateRoot(_))
        ));
    }

    #[test]
    fn remapping_a_root_keeps_its_id() {
        let dir = tempfile::tempdir().unwrap();
        let moved = dir.path().join("moved");
        std::fs::create_dir_all(&moved).unwrap();

        let mut config = config_with_roots(vec![]);
        config.set_root("home-memory", dir.path()).unwrap();
        config.set_root("home-memory", &moved).unwrap();

        assert_eq!(
            config.roots.len(),
            1,
            "remapping must not create a second root"
        );
        assert_eq!(config.root("home-memory").unwrap().path, moved);
    }

    #[test]
    fn a_root_must_point_at_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, "x").unwrap();
        let mut config = config_with_roots(vec![]);
        assert!(matches!(
            config.set_root("bad", &file),
            Err(ConfigError::RootNotADirectory { .. })
        ));
    }

    #[test]
    fn discovery_finds_memory_directories_and_skips_projects_without_one() {
        let home = tempfile::tempdir().unwrap();
        let projects = home.path().join(".claude").join("projects");
        std::fs::create_dir_all(projects.join("-home-ole").join("memory")).unwrap();
        std::fs::create_dir_all(projects.join("-home-ole-work")).unwrap();

        let roots = discover_claude_roots_in(home.path()).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "home-ole");
    }

    #[test]
    fn discovery_on_a_machine_without_claude_code_is_not_an_error() {
        let home = tempfile::tempdir().unwrap();
        assert!(discover_claude_roots_in(home.path()).unwrap().is_empty());
    }
}
