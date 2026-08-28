//! Wiring memsync into Claude Code's session hooks.
//!
//! The hook entries are merged into an existing `settings.json` rather than written over it:
//! that file holds the user's own configuration, and clobbering it to install a convenience
//! would be a poor trade.

use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Errors raised while installing or removing hooks.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// The settings file could not be read or written.
    #[error("cannot access {path}: {source}")]
    Io {
        /// Path being accessed.
        path: PathBuf,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// The settings file was not valid JSON.
    #[error("{path} is not valid JSON; fix or move it before installing hooks: {source}")]
    Malformed {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying parse error.
        source: serde_json::Error,
    },
    /// The settings file held something other than a JSON object where one was required.
    #[error("{path} has an unexpected shape: `{field}` is not {expected}")]
    UnexpectedShape {
        /// Path being inspected.
        path: PathBuf,
        /// The field that was wrong.
        field: String,
        /// What was expected there.
        expected: &'static str,
    },
}

/// Events memsync installs itself on.
const EVENTS: [&str; 2] = ["SessionStart", "SessionEnd"];
/// Seconds a hook may take before Claude Code gives up on it.
const TIMEOUT_SECONDS: u32 = 60;

/// Default location of Claude Code's user settings.
pub fn default_settings_path(home: &Path) -> PathBuf {
    home.join(".claude").join("settings.json")
}

/// Adds the `SessionStart` and `SessionEnd` hooks, leaving every other setting untouched.
///
/// Installing twice is a no-op: an entry whose command already invokes memsync is replaced
/// rather than duplicated.
pub fn install(settings_path: &Path, command: &str) -> Result<bool, HookError> {
    let mut settings = read_settings(settings_path)?;
    let mut changed = false;

    for event in EVENTS {
        changed |= install_event(settings_path, &mut settings, event, command)?;
    }

    if changed {
        write_settings(settings_path, &settings)?;
    }
    Ok(changed)
}

/// Removes every memsync hook entry.
pub fn uninstall(settings_path: &Path) -> Result<bool, HookError> {
    let mut settings = read_settings(settings_path)?;
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return Ok(false);
    };

    let mut changed = false;
    for event in EVENTS {
        let Some(entries) = hooks.get_mut(event).and_then(Value::as_array_mut) else {
            continue;
        };
        let before = entries.len();
        entries.retain(|entry| !is_memsync_entry(entry));
        changed |= entries.len() != before;
        if entries.is_empty() {
            hooks.remove(event);
        }
    }

    if changed {
        write_settings(settings_path, &settings)?;
    }
    Ok(changed)
}

fn install_event(
    path: &Path,
    settings: &mut Value,
    event: &str,
    command: &str,
) -> Result<bool, HookError> {
    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| HookError::UnexpectedShape {
            path: path.to_path_buf(),
            field: "<root>".to_string(),
            expected: "a JSON object",
        })?
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let hooks = hooks
        .as_object_mut()
        .ok_or_else(|| HookError::UnexpectedShape {
            path: path.to_path_buf(),
            field: "hooks".to_string(),
            expected: "a JSON object",
        })?;

    let entries = hooks.entry(event).or_insert_with(|| json!([]));
    let entries = entries
        .as_array_mut()
        .ok_or_else(|| HookError::UnexpectedShape {
            path: path.to_path_buf(),
            field: format!("hooks.{event}"),
            expected: "an array",
        })?;

    let desired = json!({
        "hooks": [{
            "type": "command",
            "command": command,
            "timeout": TIMEOUT_SECONDS,
            "statusMessage": "Synchronising memories",
        }],
    });

    if let Some(existing) = entries.iter_mut().find(|e| is_memsync_entry(e)) {
        if *existing == desired {
            return Ok(false);
        }
        *existing = desired;
        return Ok(true);
    }

    entries.push(desired);
    Ok(true)
}

/// Recognises an entry this tool installed, by the command it runs.
fn is_memsync_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|hooks| {
            hooks.iter().any(|hook| {
                hook.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains("memsync"))
            })
        })
}

fn read_settings(path: &Path) -> Result<Value, HookError> {
    match std::fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => Ok(json!({})),
        Ok(raw) => serde_json::from_str(&raw).map_err(|source| HookError::Malformed {
            path: path.to_path_buf(),
            source,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(source) => Err(HookError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_settings(path: &Path, settings: &Value) -> Result<(), HookError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| HookError::Io {
            path: path.clone(),
            source,
        }
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    let rendered = serde_json::to_string_pretty(settings).expect("settings are serialisable");
    let temp = path.with_extension("json.memsync-tmp");
    std::fs::write(&temp, format!("{rendered}\n")).map_err(io(&temp))?;
    std::fs::rename(&temp, path).map_err(io(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_at(dir: &Path) -> PathBuf {
        dir.join("settings.json")
    }

    fn read(path: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn installs_both_events_when_no_settings_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());

        assert!(install(&path, "memsync sync --quiet").unwrap());

        let settings = read(&path);
        for event in EVENTS {
            let command = settings["hooks"][event][0]["hooks"][0]["command"]
                .as_str()
                .unwrap();
            assert_eq!(command, "memsync sync --quiet");
        }
    }

    #[test]
    fn preserves_unrelated_settings_and_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());
        std::fs::write(
            &path,
            r#"{
              "model": "opus",
              "hooks": {
                "SessionStart": [
                  {"hooks": [{"type": "command", "command": "echo hello"}]}
                ]
              }
            }"#,
        )
        .unwrap();

        install(&path, "memsync sync").unwrap();

        let settings = read(&path);
        assert_eq!(settings["model"], "opus", "unrelated settings must survive");
        let entries = settings["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "the existing hook must survive alongside ours"
        );
        assert_eq!(entries[0]["hooks"][0]["command"], "echo hello");
    }

    #[test]
    fn installing_twice_does_not_duplicate_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());

        assert!(install(&path, "memsync sync").unwrap());
        assert!(
            !install(&path, "memsync sync").unwrap(),
            "second install must be a no-op"
        );

        assert_eq!(
            read(&path)["hooks"]["SessionStart"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn reinstalling_with_a_new_command_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());

        install(&path, "memsync sync").unwrap();
        assert!(install(&path, "/usr/local/bin/memsync sync --quiet").unwrap());

        let entries = read(&path)["hooks"]["SessionStart"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["hooks"][0]["command"],
            "/usr/local/bin/memsync sync --quiet"
        );
    }

    #[test]
    fn uninstall_removes_only_our_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());
        std::fs::write(
            &path,
            r#"{"hooks": {"SessionStart": [
                 {"hooks": [{"type": "command", "command": "echo hello"}]}
               ]}}"#,
        )
        .unwrap();

        install(&path, "memsync sync").unwrap();
        assert!(uninstall(&path).unwrap());

        let entries = read(&path)["hooks"]["SessionStart"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["hooks"][0]["command"], "echo hello");
    }

    #[test]
    fn uninstall_drops_the_event_key_once_it_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());

        install(&path, "memsync sync").unwrap();
        uninstall(&path).unwrap();

        assert!(read(&path)["hooks"].get("SessionStart").is_none());
    }

    #[test]
    fn refuses_to_touch_malformed_settings_rather_than_overwriting_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());
        std::fs::write(&path, "{ this is not json").unwrap();

        assert!(matches!(
            install(&path, "memsync sync"),
            Err(HookError::Malformed { .. })
        ));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ this is not json",
            "the user's file must be left exactly as it was"
        );
    }

    #[test]
    fn an_empty_settings_file_is_treated_as_an_empty_object() {
        let dir = tempfile::tempdir().unwrap();
        let path = settings_at(dir.path());
        std::fs::write(&path, "   \n").unwrap();

        assert!(install(&path, "memsync sync").unwrap());
        assert!(read(&path)["hooks"]["SessionEnd"].is_array());
    }
}
