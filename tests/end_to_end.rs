//! Two machines synchronising through a real git repository.
//!
//! These tests exercise the production code path end to end — real age envelopes, real git,
//! real files on disk. Only the locations are redirected, so what is proven here is what
//! runs on a laptop.

use memsync::app::{self, Paths};
use memsync::crypto::AgeCipher;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One simulated machine: its own key, configuration, state, and memory directory.
struct Machine {
    label: String,
    paths: Paths,
    memory: PathBuf,
    store: PathBuf,
}

impl Machine {
    fn new(root: &Path, label: &str) -> Self {
        let home = root.join(label);
        let memory = home.join("memory");
        std::fs::create_dir_all(&memory).unwrap();
        Self {
            label: label.to_string(),
            paths: Paths {
                config: home.join("config.toml"),
                identity: home.join("identity.txt"),
                state: home.join("state.json"),
                lock: home.join("memsync.lock"),
                settings: home.join("settings.json"),
            },
            memory,
            store: home.join("store"),
        }
    }

    fn init(&self, remote: &Path) {
        app::init(
            &self.paths,
            remote.to_str().unwrap(),
            Some(self.label.clone()),
            Some(self.store.clone()),
            false, // never touch the real ~/.claude during tests
        )
        .unwrap();
    }

    fn public_key(&self) -> String {
        AgeCipher::load_or_create_identity(&self.paths.identity)
            .unwrap()
            .to_public()
            .to_string()
    }

    fn map_root(&self, id: &str, path: &Path) {
        app::root_set(&self.paths, id, path).unwrap();
    }

    fn sync(&self) {
        app::sync(&self.paths, true).unwrap();
    }

    fn write(&self, name: &str, contents: &str) {
        let path = self.memory.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.memory.join(name)).ok()
    }

    fn remove(&self, name: &str) {
        std::fs::remove_file(self.memory.join(name)).unwrap();
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = walk(&self.memory, &self.memory);
        names.sort();
        names
    }
}

fn walk(dir: &Path, base: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            out.extend(walk(&entry.path(), base));
        } else {
            out.push(
                entry
                    .path()
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    out
}

/// Creates the bare repository the machines push to, standing in for GitHub.
fn bare_remote(root: &Path) -> PathBuf {
    let path = root.join("remote.git");
    let output = Command::new("git")
        .args(["init", "--bare", "--initial-branch", "main"])
        .arg(&path)
        .output()
        .expect("git must be installed to run these tests");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

/// Sets up two authorised machines sharing one root id.
fn two_machines(root: &Path) -> (Machine, Machine) {
    let remote = bare_remote(root);

    let alpha = Machine::new(root, "alpha");
    alpha.init(&remote);
    alpha.map_root("home-memory", &alpha.memory);

    let beta = Machine::new(root, "beta");
    beta.init(&remote);
    app::key_add(&alpha.paths, &beta.public_key(), "beta").unwrap();
    beta.map_root("home-memory", &beta.memory);

    (alpha, beta)
}

#[test]
fn a_file_created_on_one_machine_appears_on_the_other() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("tailscale.md", "the key lives in 1Password");
    alpha.sync();
    beta.sync();

    assert_eq!(
        beta.read("tailscale.md").as_deref(),
        Some("the key lives in 1Password")
    );
}

#[test]
fn the_store_never_contains_readable_content_or_file_names() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, _beta) = two_machines(root.path());

    alpha.write("tailscale-api-key.md", "super secret sentence");
    alpha.sync();

    let blobs = alpha.store.join("blobs");
    let mut checked = 0;
    for entry in std::fs::read_dir(&blobs).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains("tailscale"),
            "the object name leaks the memory's file name: {name}"
        );
        let bytes = std::fs::read(entry.path()).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
        assert!(
            !text.contains("super secret"),
            "the object leaks its plaintext"
        );
        checked += 1;
    }
    assert_eq!(checked, 1, "exactly one object should have been written");
}

#[test]
fn an_edit_propagates_in_both_directions() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("notes.md", "first");
    alpha.sync();
    beta.sync();

    beta.write("notes.md", "second");
    beta.sync();
    alpha.sync();

    assert_eq!(alpha.read("notes.md").as_deref(), Some("second"));
}

#[test]
fn a_deletion_propagates_instead_of_resurrecting() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("obsolete.md", "old news");
    alpha.sync();
    beta.sync();
    assert!(beta.read("obsolete.md").is_some());

    alpha.remove("obsolete.md");
    alpha.sync();
    beta.sync();
    assert!(
        beta.read("obsolete.md").is_none(),
        "the deletion must reach the other machine"
    );

    // And it must stay deleted: a second round must not bring the file back.
    beta.sync();
    alpha.sync();
    assert!(beta.read("obsolete.md").is_none());
    assert!(alpha.read("obsolete.md").is_none());
}

#[test]
fn divergent_edits_keep_both_versions() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("shared.md", "common ancestor");
    alpha.sync();
    beta.sync();

    // Both machines edit the same file before either synchronises.
    alpha.write("shared.md", "written on alpha");
    beta.write("shared.md", "written on beta");

    alpha.sync();
    beta.sync();
    alpha.sync();

    for machine in [&alpha, &beta] {
        let files = machine.files();
        assert_eq!(
            files.len(),
            2,
            "{}: expected a conflict copy, got {files:?}",
            machine.label
        );

        let contents: Vec<String> = files.iter().filter_map(|f| machine.read(f)).collect();
        assert!(
            contents.iter().any(|c| c == "written on alpha"),
            "{}: alpha's version was lost: {contents:?}",
            machine.label
        );
        assert!(
            contents.iter().any(|c| c == "written on beta"),
            "{}: beta's version was lost: {contents:?}",
            machine.label
        );
    }
}

#[test]
fn a_moved_memory_directory_keeps_synchronising_after_remapping() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("notes.md", "before the move");
    alpha.sync();
    beta.sync();

    // Beta's memory directory moves to a completely different path.
    let moved = root.path().join("beta").join("elsewhere").join("memory");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(&beta.memory, &moved).unwrap();
    beta.map_root("home-memory", &moved);

    // Nothing was rewritten in the store, and synchronisation continues from the new path.
    alpha.write("notes.md", "after the move");
    alpha.sync();
    beta.sync();

    assert_eq!(
        std::fs::read_to_string(moved.join("notes.md")).unwrap(),
        "after the move",
        "the remapped root must receive updates"
    );
    assert!(!beta.memory.exists(), "the old path must not be recreated");
}

#[test]
fn nested_directories_and_non_ascii_names_survive_a_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("projekte/größe.md", "Umlaute bleiben erhalten");
    alpha.sync();
    beta.sync();

    assert_eq!(
        beta.read("projekte/größe.md").as_deref(),
        Some("Umlaute bleiben erhalten")
    );
}

#[test]
fn a_machine_that_was_never_authorised_cannot_read_the_store() {
    let root = tempfile::tempdir().unwrap();
    let remote = bare_remote(root.path());

    let alpha = Machine::new(root.path(), "alpha");
    alpha.init(&remote);
    alpha.map_root("home-memory", &alpha.memory);
    alpha.write("secret.md", "not for you");
    alpha.sync();

    let intruder = Machine::new(root.path(), "intruder");
    intruder.init(&remote);
    intruder.map_root("home-memory", &intruder.memory);

    let error = app::sync(&intruder.paths, true).unwrap_err().to_string();
    assert!(
        error.contains("not authorised"),
        "unexpected error: {error}"
    );
    assert!(
        intruder.read("secret.md").is_none(),
        "an unauthorised machine read the store"
    );
}

#[test]
fn revoking_a_machine_locks_it_out_of_later_updates() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("notes.md", "while beta was trusted");
    alpha.sync();
    beta.sync();

    app::key_remove(&alpha.paths, "beta").unwrap();
    alpha.write("notes.md", "after beta was revoked");
    alpha.sync();

    assert!(
        app::sync(&beta.paths, true).is_err(),
        "a revoked machine must lose access"
    );
    assert_eq!(
        beta.read("notes.md").as_deref(),
        Some("while beta was trusted"),
        "the revoked machine keeps what it already had, but receives nothing new"
    );
}

#[test]
fn synchronising_twice_with_no_changes_does_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    alpha.write("notes.md", "stable");
    alpha.sync();
    beta.sync();

    let head_before = git_head(&alpha.store);
    alpha.sync();
    beta.sync();
    assert_eq!(
        head_before,
        git_head(&alpha.store),
        "an idle run must not create commits"
    );
}

fn git_head(repo: &Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn a_root_this_machine_does_not_have_is_left_alone_rather_than_deleted() {
    // Regression: a machine that synchronises only some of the roots used to record the
    // others in its snapshot. On the next run they looked locally deleted, and it pushed
    // tombstones that destroyed the other machine's memories.
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    // Beta synchronises a second directory that alpha knows nothing about.
    let beta_only = root.path().join("beta").join("project-memory");
    std::fs::create_dir_all(&beta_only).unwrap();
    std::fs::write(beta_only.join("design.md"), "only beta has this root").unwrap();
    beta.map_root("beta-only", &beta_only);

    beta.write("shared.md", "both machines have this");
    beta.sync();

    // Alpha runs repeatedly. The first run is where the objects entered its snapshot; the
    // second is where the tombstones used to be pushed.
    alpha.sync();
    alpha.sync();
    alpha.sync();

    assert_eq!(
        alpha.read("shared.md").as_deref(),
        Some("both machines have this"),
        "alpha must still receive the root it does have"
    );
    assert!(
        alpha.files().iter().all(|f| f == "shared.md"),
        "alpha must not materialise a root it has not configured: {:?}",
        alpha.files()
    );

    beta.sync();
    assert_eq!(
        std::fs::read_to_string(beta_only.join("design.md")).unwrap(),
        "only beta has this root",
        "beta's exclusive root must survive alpha's runs"
    );
}

#[test]
fn a_poisoned_snapshot_from_an_older_version_does_not_delete_foreign_roots() {
    // Defence in depth: a snapshot written by memsync 0.1.0 already contains entries for
    // roots this machine does not have. Those entries must be ignored — if they are trusted,
    // the object looks locally deleted and the next run tombstones another machine's file.
    let root = tempfile::tempdir().unwrap();
    let (alpha, beta) = two_machines(root.path());

    let beta_only = root.path().join("beta").join("project-memory");
    std::fs::create_dir_all(&beta_only).unwrap();
    let contents = "only beta has this root";
    std::fs::write(beta_only.join("design.md"), contents).unwrap();
    beta.map_root("beta-only", &beta_only);
    beta.sync();

    // The hash must match what the store actually holds: with a stale hash the run takes the
    // conflict path instead, and the deletion this test is about never happens.
    let hash = memsync::model::ContentHash::of(contents.as_bytes()).0;
    std::fs::write(
        &alpha.paths.state,
        format!(
            r#"{{"version":1,"entries":[{{"key":{{"root":"beta-only","path":"design.md"}},
               "state":"present","hash":"{hash}","modified_ms":1}}]}}"#
        ),
    )
    .unwrap();

    alpha.sync();
    beta.sync();

    assert_eq!(
        std::fs::read_to_string(beta_only.join("design.md")).unwrap(),
        contents,
        "a stale snapshot entry must not turn into a deletion"
    );
}
