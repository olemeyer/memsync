//! The conflict-resolution core: a pure function from three snapshots to a list of actions.
//!
//! This module performs no IO and reads no clock. Every decision that could lose data is made
//! here, which is why it is kept free of side effects and tested exhaustively.

use crate::model::{FileState, ObjectKey, Snapshot};
use std::collections::BTreeSet;

/// A single step the engine must carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write the local file's content into the store.
    UploadLocal(ObjectKey),
    /// Record a tombstone in the store for a file deleted locally.
    UploadTombstone(ObjectKey),
    /// Write the store's content to the local filesystem.
    DownloadRemote(ObjectKey),
    /// Remove the local file because the store holds a tombstone for it.
    DeleteLocal(ObjectKey),
    /// Both sides changed. `key` keeps the winning content; the losing content is preserved
    /// under `rename_to`, on disk and in the store.
    Resolve {
        /// The contested key.
        key: ObjectKey,
        /// Which side keeps the canonical path.
        winner: Side,
        /// Where the losing version is preserved.
        rename_to: ObjectKey,
    },
}

/// Which side of a conflict a version came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The version on this machine.
    Local,
    /// The version in the store.
    Remote,
}

/// Inputs to [`plan`]: the three states of the world.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    /// What is on disk now.
    pub local: &'a Snapshot,
    /// What the store holds now.
    pub remote: &'a Snapshot,
    /// What both sides agreed on at the end of the previous run.
    pub base: &'a Snapshot,
    /// This machine's label, used to name conflict copies.
    pub label: &'a str,
}

/// Decides what to do for every key present on any side.
///
/// Resolution rules, in order:
///
/// 1. A side that did not change since `base` yields to one that did.
/// 2. If both changed to the same effect, nothing is transferred.
/// 3. Content beats deletion: if one side deleted a file the other modified, the surviving
///    content is restored. Losing an edit is worse than resurrecting a file.
/// 4. Otherwise both sides hold different content: the more recently modified version keeps
///    the canonical path and the other is preserved alongside it. Ties are broken by content
///    hash so that every machine reaches the same decision without coordination.
pub fn plan(inputs: &Inputs<'_>) -> Vec<Action> {
    let keys: BTreeSet<&ObjectKey> = inputs
        .local
        .keys()
        .chain(inputs.remote.keys())
        .chain(inputs.base.keys())
        .collect();

    let mut actions = Vec::new();
    for key in keys {
        let local = state(inputs.local, key);
        let remote = state(inputs.remote, key);
        let base = state(inputs.base, key);

        let local_changed = !local.same_effect(base);
        let remote_changed = !remote.same_effect(base);

        match (local_changed, remote_changed) {
            (false, false) => {}
            (true, false) => actions.push(push_local(key, local)),
            (false, true) => actions.extend(apply_remote(key, remote)),
            (true, true) => {
                if local.same_effect(remote) {
                    // Both machines made the same edit; nothing to transfer, but the store may
                    // still need the tombstone that only one side recorded.
                    if matches!(local, FileState::Missing)
                        && matches!(remote, FileState::Missing)
                        && matches!(base, FileState::Present { .. })
                    {
                        actions.push(Action::UploadTombstone(key.clone()));
                    }
                    continue;
                }
                actions.push(resolve(key, local, remote, inputs.label));
            }
        }
    }
    actions
}

fn state<'a>(snapshot: &'a Snapshot, key: &ObjectKey) -> &'a FileState {
    snapshot.get(key).unwrap_or(&FileState::Missing)
}

fn push_local(key: &ObjectKey, local: &FileState) -> Action {
    match local {
        FileState::Present { .. } => Action::UploadLocal(key.clone()),
        FileState::Missing | FileState::Deleted { .. } => Action::UploadTombstone(key.clone()),
    }
}

fn apply_remote(key: &ObjectKey, remote: &FileState) -> Option<Action> {
    match remote {
        FileState::Present { .. } => Some(Action::DownloadRemote(key.clone())),
        FileState::Deleted { .. } => Some(Action::DeleteLocal(key.clone())),
        // The store cannot lose a key it never had; nothing to apply.
        FileState::Missing => None,
    }
}

fn resolve(key: &ObjectKey, local: &FileState, remote: &FileState, label: &str) -> Action {
    // Rule 3: content beats deletion.
    match (local.is_present(), remote.is_present()) {
        (true, false) => {
            return Action::Resolve {
                key: key.clone(),
                winner: Side::Local,
                rename_to: key.clone(),
            };
        }
        (false, true) => {
            return Action::Resolve {
                key: key.clone(),
                winner: Side::Remote,
                rename_to: key.clone(),
            };
        }
        _ => {}
    }

    // Rule 4: both present with different content.
    let local_ms = local.modified_ms().unwrap_or(i64::MIN);
    let remote_ms = remote.modified_ms().unwrap_or(i64::MIN);
    let winner = match local_ms.cmp(&remote_ms) {
        std::cmp::Ordering::Greater => Side::Local,
        std::cmp::Ordering::Less => Side::Remote,
        // Deterministic tie-break: both machines compare the same two hashes.
        std::cmp::Ordering::Equal => {
            if local.hash() > remote.hash() {
                Side::Local
            } else {
                Side::Remote
            }
        }
    };
    let loser_ms = if winner == Side::Local {
        remote_ms
    } else {
        local_ms
    };
    Action::Resolve {
        key: key.clone(),
        winner,
        rename_to: key.conflict_variant(label, loser_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ContentHash;

    fn present(content: &str, ms: i64) -> FileState {
        FileState::Present {
            hash: ContentHash::of(content.as_bytes()),
            modified_ms: ms,
        }
    }

    fn snapshot(entries: &[(&str, FileState)]) -> Snapshot {
        entries
            .iter()
            .map(|(p, s)| (ObjectKey::new("r", *p), s.clone()))
            .collect()
    }

    fn run(local: &Snapshot, remote: &Snapshot, base: &Snapshot) -> Vec<Action> {
        plan(&Inputs {
            local,
            remote,
            base,
            label: "test",
        })
    }

    fn key(path: &str) -> ObjectKey {
        ObjectKey::new("r", path)
    }

    #[test]
    fn unchanged_on_both_sides_does_nothing() {
        let s = snapshot(&[("a.md", present("x", 1))]);
        assert!(run(&s, &s, &s).is_empty());
    }

    #[test]
    fn new_local_file_is_uploaded() {
        let local = snapshot(&[("a.md", present("x", 1))]);
        let actions = run(&local, &Snapshot::new(), &Snapshot::new());
        assert_eq!(actions, vec![Action::UploadLocal(key("a.md"))]);
    }

    #[test]
    fn new_remote_file_is_downloaded() {
        let remote = snapshot(&[("a.md", present("x", 1))]);
        let actions = run(&Snapshot::new(), &remote, &Snapshot::new());
        assert_eq!(actions, vec![Action::DownloadRemote(key("a.md"))]);
    }

    #[test]
    fn local_edit_is_uploaded_when_remote_is_untouched() {
        let base = snapshot(&[("a.md", present("old", 1))]);
        let local = snapshot(&[("a.md", present("new", 2))]);
        assert_eq!(
            run(&local, &base, &base),
            vec![Action::UploadLocal(key("a.md"))]
        );
    }

    #[test]
    fn remote_edit_is_downloaded_when_local_is_untouched() {
        let base = snapshot(&[("a.md", present("old", 1))]);
        let remote = snapshot(&[("a.md", present("new", 2))]);
        assert_eq!(
            run(&base, &remote, &base),
            vec![Action::DownloadRemote(key("a.md"))]
        );
    }

    #[test]
    fn local_deletion_becomes_a_tombstone() {
        let base = snapshot(&[("a.md", present("x", 1))]);
        assert_eq!(
            run(&Snapshot::new(), &base, &base),
            vec![Action::UploadTombstone(key("a.md"))]
        );
    }

    #[test]
    fn remote_tombstone_deletes_the_local_file() {
        let base = snapshot(&[("a.md", present("x", 1))]);
        let remote = snapshot(&[("a.md", FileState::Deleted { modified_ms: 5 })]);
        assert_eq!(
            run(&base, &remote, &base),
            vec![Action::DeleteLocal(key("a.md"))]
        );
    }

    #[test]
    fn an_already_applied_tombstone_is_not_reapplied() {
        let base = snapshot(&[("a.md", FileState::Deleted { modified_ms: 5 })]);
        assert!(run(&Snapshot::new(), &base, &base).is_empty());
    }

    #[test]
    fn identical_edits_on_both_sides_converge_without_transfer() {
        let base = snapshot(&[("a.md", present("old", 1))]);
        let same = snapshot(&[("a.md", present("new", 2))]);
        assert!(run(&same, &same, &base).is_empty());
    }

    #[test]
    fn simultaneous_deletion_still_records_the_tombstone() {
        let base = snapshot(&[("a.md", present("x", 1))]);
        assert_eq!(
            run(&Snapshot::new(), &Snapshot::new(), &base),
            vec![Action::UploadTombstone(key("a.md"))]
        );
    }

    #[test]
    fn content_beats_deletion_in_both_directions() {
        let base = snapshot(&[("a.md", present("old", 1))]);

        // Deleted here, edited there: the edit survives.
        let remote = snapshot(&[("a.md", present("new", 2))]);
        assert_eq!(
            run(&Snapshot::new(), &remote, &base),
            vec![Action::Resolve {
                key: key("a.md"),
                winner: Side::Remote,
                rename_to: key("a.md"),
            }]
        );

        // Edited here, deleted there: the edit survives.
        let local = snapshot(&[("a.md", present("new", 2))]);
        let remote = snapshot(&[("a.md", FileState::Deleted { modified_ms: 3 })]);
        assert_eq!(
            run(&local, &remote, &base),
            vec![Action::Resolve {
                key: key("a.md"),
                winner: Side::Local,
                rename_to: key("a.md"),
            }]
        );
    }

    #[test]
    fn divergent_edits_keep_the_newer_version_and_preserve_the_older() {
        let base = snapshot(&[("a.md", present("old", 1))]);
        let local = snapshot(&[("a.md", present("mine", 20))]);
        let remote = snapshot(&[("a.md", present("theirs", 10))]);
        assert_eq!(
            run(&local, &remote, &base),
            vec![Action::Resolve {
                key: key("a.md"),
                winner: Side::Local,
                rename_to: key("a.conflict-test-10.md"),
            }]
        );
    }

    #[test]
    fn equal_timestamps_are_broken_deterministically_by_hash() {
        let base = snapshot(&[("a.md", present("old", 1))]);
        let mine = snapshot(&[("a.md", present("mine", 7))]);
        let theirs = snapshot(&[("a.md", present("theirs", 7))]);

        let from_here = run(&mine, &theirs, &base);
        // The other machine sees the same pair with the sides swapped and must agree on which
        // content keeps the canonical path.
        let from_other_side = run(&theirs, &mine, &base);

        let mine_won = |actions: &[Action], local_is_mine: bool| match &actions[0] {
            Action::Resolve { winner, .. } => (*winner == Side::Local) == local_is_mine,
            other => panic!("expected a conflict, got {other:?}"),
        };
        assert_eq!(
            mine_won(&from_here, true),
            mine_won(&from_other_side, false)
        );
    }

    #[test]
    fn keys_from_different_roots_do_not_interfere() {
        let mut local = Snapshot::new();
        local.insert(ObjectKey::new("one", "a.md"), present("x", 1));
        let mut remote = Snapshot::new();
        remote.insert(ObjectKey::new("two", "a.md"), present("y", 1));

        assert_eq!(
            run(&local, &remote, &Snapshot::new()),
            vec![
                Action::UploadLocal(ObjectKey::new("one", "a.md")),
                Action::DownloadRemote(ObjectKey::new("two", "a.md")),
            ]
        );
    }
}
