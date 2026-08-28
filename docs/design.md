# memsync — design document

**Status:** implemented (v0.1)
**Author:** Ole Meyer
**Last updated:** 2026-08-28

## Context

Claude Code keeps durable per-project memory as plain Markdown files under
`~/.claude/projects/<path-slug>/memory/`. The files are small (hundreds of bytes to a few
kilobytes), edited infrequently, and each one is self-contained. They are also the most
sensitive artefacts the assistant produces: they describe infrastructure, accounts, and
working habits.

Working across two or more machines means the memories diverge. There is no built-in
synchronisation.

## Goals

1. **Confidentiality against the transport.** The synchronisation host (GitHub) must not be
   able to read memory contents, and must not be able to learn file names, which are
   themselves descriptive (`tailscale-api-key.md`).
2. **Asymmetric keys.** Each machine holds its own private key. Authorising a new machine
   means adding a public key; no shared passphrase is copied between machines.
3. **Path independence.** The location of a memory directory is a property of a machine, not
   of the data. A machine may move its memory directory without invalidating the store.
4. **Unattended operation.** Synchronisation runs from Claude Code session hooks with no
   interactive prompt.
5. **No silent data loss.** Concurrent edits on two machines must never discard a version
   without leaving it on disk.

## Non-goals

- Real-time synchronisation. Convergence at session boundaries is sufficient.
- Merging the *contents* of two edited versions of the same file. Memory files are prose;
  a textual three-way merge would produce plausible-looking nonsense. Conflicts are
  preserved side by side and left to the user (or to Claude, which reads the directory).
- Multi-user access control. Every authorised key can read everything.
- Synchronising session transcripts or `settings.json`. Only memory files are in scope.

## Design

### Layering

```
        cli  ──────────────► thin argument parsing, human-readable output
         │
         ▼
      engine ─────────────► orchestration: read, plan, apply, commit
       │   │
       │   └──► plan ─────► PURE: (local, remote, base) -> [Action]      ← hermetically tested
       │
       ├──► store  (trait) ─► GitStore ──► GitRunner (trait) ──► SystemGit
       ├──► crypto (trait) ─► AgeCipher
       └──► state           ─► last-synchronised snapshot (local, plaintext)
```

The conflict-resolution logic — the part that is easy to get wrong and expensive to get
wrong — is a pure function over three in-memory maps. It performs no IO, so its tests are
hermetic and fast. Everything that touches the filesystem, the network, or the clock sits
behind a trait and is substituted in tests.

### Store layout

The store is an ordinary git repository whose working tree contains only ciphertext:

```
recipients.toml          plaintext: label + age public key per authorised machine
salt.age                 32 random bytes, encrypted to every recipient
blobs/<64 hex>.age       one file per synchronised memory file (ASCII-armoured age)
```

`recipients.toml` is deliberately in the clear: a machine that has not yet been authorised
must be able to see which keys exist, and the public keys are not secret.

### Object naming

A blob's name is `hex(BLAKE3::keyed(salt, root_id || 0x00 || relative_path))`.

Using a *keyed* hash rather than a plain digest matters: memory file names are drawn from a
small, guessable space. With a plain hash, anyone with read access to the repository could
confirm the presence of `tailscale-api-key.md` by hashing candidate names. The salt is
random, stored only in encrypted form, and therefore unavailable to the host.

The name is deterministic given the salt, so an update to a file rewrites the same blob and
git records a normal modification rather than an add/delete pair.

### Blob format

Plaintext inside the age envelope:

```
{"root":"home-memory","path":"notes/db.md","modified_ms":1756412345678,"deleted":false}\n
<file bytes>
```

The header carries the logical path (never an absolute one), the modification time used for
conflict ordering, and the tombstone flag. Because the header is *inside* the envelope, the
host learns neither the path nor whether a file still exists.

### Root mapping

The store addresses files as `<root-id>/<relative-path>`. A root id is a stable label; each
machine maps it to a local directory in its own configuration:

```toml
[[roots]]
id   = "home-memory"
path = "/home/ole/.claude/projects/-home-ole/memory"
```

On a machine where the directory lives elsewhere, only `path` differs. Moving a directory is
`memsync root map <id> <new-path>`; no data is rewritten. This is what makes the store
survive a change of home directory, user name, or project slug.

### Synchronisation algorithm

For every key in `local ∪ remote ∪ base`, where `base` is the snapshot recorded at the end of
the previous run:

| local vs base | remote vs base | outcome |
|---|---|---|
| unchanged | unchanged | nothing |
| changed | unchanged | push local (including deletion) |
| unchanged | changed | apply remote (including deletion) |
| changed | changed, identical result | converged, record only |
| changed | changed, different result | **conflict** |

A conflict is resolved by modification time: the newer version keeps the canonical path, the
older one is written next to it as `<stem>.conflict-<label>-<timestamp><ext>` and pushed as a
first-class file. Nothing is discarded, and both machines end up with both versions. Ties are
broken by content hash so that two machines reach the same decision independently.

Deletion requires the base snapshot: without it, a file that is absent locally and present
remotely is indistinguishable from a file that was deleted locally and must be removed
remotely. Tombstones are retained in the store; they are small and make deletion converge
without a coordinated garbage-collection step.

### Concurrency and failure

Git provides the atomicity: the run ends with `pull --rebase` followed by `push`. A push that
loses the race is retried after another rebase. A crash mid-run leaves the store unchanged
(nothing was pushed) or fully applied (the push succeeded); the local state snapshot is only
written after a successful push, so an interrupted run repeats work rather than skipping it.

A single process lock file prevents two Claude Code sessions on the same machine from running
the engine concurrently.

## Security considerations

See [threat-model.md](threat-model.md). Summary:

- The remote host learns: number of files, their approximate sizes, commit times, machine
  labels, and public keys. It learns no file name and no content.
- The private key lives in `~/.config/memsync/identity.txt` with mode `0600`, on a
  LUKS-encrypted disk, and never leaves the machine.
- Authorising a machine re-encrypts every blob to the extended recipient set. Revoking one
  removes it from future envelopes, but anything it already read remains compromised; a
  revocation is therefore accompanied by rotating the affected credentials themselves.
- The tool never writes plaintext outside the configured roots and the system temporary
  directory used for atomic file replacement.

## Alternatives considered

**git-crypt.** Transparent, mature, and the obvious first answer. Rejected because it leaks
file names, has had no release since 2022, and its GPG key management (`add-gpg-user`
re-commits the whole tree, and every machine needs a GPG keyring) is exactly the friction this
tool is meant to remove.

**SOPS + age.** Excellent for structured configuration, awkward for opaque prose files: it
encrypts values inside a document, not documents. Also leaks names.

**Syncthing.** Continuous, peer-to-peer, encrypted in transit, no host to trust — genuinely
the better fit if both machines are frequently online at the same time. Rejected because it
offers no history, requires both peers reachable, and stores plaintext at rest on every
device it reaches. It remains a reasonable alternative and is documented as such in the
README.

**rclone with a crypt backend.** Encrypts at rest and hides names, but has no notion of a
three-way merge; simultaneous edits silently resolve to last-writer-wins.

**Plain git with an `age` clean/smudge filter.** Close to this design, and the filter approach
was prototyped. Rejected because filters cannot rename files, so the file names would still be
exposed, and because error reporting from a filter is poor: a failed decryption surfaces as an
empty file rather than an error.

## Testing plan

- **Unit, hermetic:** the planner against hand-built state maps, covering every row of the
  table above plus tombstones, first-run behaviour (no base), and tie-breaking.
- **Unit:** blob encode/decode round-trip, including binary content and paths with non-ASCII
  characters; keyed naming stability.
- **Integration:** two configured "machines" in temporary directories synchronising through a
  local bare repository — the same code path as production, with git as the only stub-free
  dependency. Covers create, edit, delete, concurrent edit (conflict), and machine
  authorisation followed by re-encryption.
- **CI:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny check`.

## Rollout

`memsync init` on the first machine creates the key, the store, and the salt. It prints the
public key. On the second machine, `memsync init --remote <url>` prints its own key; running
`memsync key add <key>` on the first machine authorises it and re-encrypts. `memsync
install-hooks` then wires `memsync sync` into Claude Code's `SessionStart` and `SessionEnd`
hooks on each machine.
