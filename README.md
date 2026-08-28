# memsync

Keeps [Claude Code](https://claude.com/claude-code) memory files in step across your
machines, through a git repository that never sees a readable byte — not the contents, and
not the file names.

```console
$ memsync sync
2 uploaded, 1 downloaded
```

## Why not something simpler

| | reads your data | hides file names | history | needs both machines online |
|---|---|---|---|---|
| **memsync** | no | yes | yes | no |
| git-crypt | no | **no** | yes | no |
| Syncthing | on every device it reaches | yes | versions only | **yes** |
| plain git | **yes** | no | yes | no |

Memory file names are half the information — `tailscale-api-key.md` says plenty before it is
opened. That is the gap this tool exists to close. If your two machines are usually online
together and you are content with plaintext at rest, Syncthing is less machinery and a
perfectly good answer.

## How it works

Each machine holds its own [age](https://age-encryption.org) key pair. Files are encrypted
to every authorised public key and pushed as individual objects:

```
recipients.toml          which machines may read (public keys, in the clear)
salt.age                 32 random bytes, encrypted to every recipient
blobs/<64 hex>.age       one file per memory, ASCII-armoured
```

An object's name is a *keyed* hash of its logical path, with the salt as the key. Without the
salt — which the host never sees in plaintext — the names cannot be guessed or enumerated.
The logical path, the modification time, and whether the file still exists all live inside
the envelope.

Synchronisation is a three-way merge against the state recorded at the end of the previous
run, so deletions converge instead of resurrecting. When both machines edit the same file,
neither version is discarded: the newer keeps the name, the older is preserved beside it as
`notes.conflict-<machine>-<timestamp>.md`.

See [docs/design.md](docs/design.md) for the full design and
[docs/threat-model.md](docs/threat-model.md) for what the host can still infer.

## Paths are per machine

The store addresses files as `<root-id>/<relative-path>`. The root id is the same everywhere;
where it points is a local matter:

```toml
# machine A
[[roots]]
id   = "home-memory"
path = "/home/ole/.claude/projects/-home-ole/memory"
```

Moved a directory, changed user name, different project slug? Repoint the id and carry on —
nothing in the store is rewritten:

```console
$ memsync root map home-memory ~/work/.claude/projects/-home-ole-work/memory
root home-memory: /home/ole/.claude/projects/-home-ole/memory -> /home/ole/work/…/memory
```

## Setup

Install:

```console
$ cargo install --path .
```

On the first machine — create a **private** repository for the store first, then:

```console
$ memsync init --remote git@github.com:you/claude-memory-store.git
root home-ole -> /home/ole/.claude/projects/-home-ole/memory
store initialised and this machine authorised as `thinkpad`
public key: age1…
$ memsync sync
```

On the second machine:

```console
$ memsync init --remote git@github.com:you/claude-memory-store.git
configuration written, but this machine is not authorised yet.

Run this on a machine that already has access:
    memsync key add age1… --label workstation
```

Run that line on the first machine — it re-encrypts every object to the extended set — then
`memsync sync` on the second.

Finally, wire it into Claude Code so it runs by itself at the start and end of every session:

```console
$ memsync install-hooks
installed SessionStart and SessionEnd hooks in /home/you/.claude/settings.json
```

## Commands

| | |
|---|---|
| `memsync sync [--quiet]` | pull, merge, push |
| `memsync status` | what the store holds and whether this machine can read it |
| `memsync key show \| list \| add \| remove \| export` | manage authorised machines |
| `memsync root list \| add \| map \| remove` | manage synchronised directories |
| `memsync install-hooks` / `uninstall-hooks` | wire into Claude Code |

## Back up your key

`~/.config/memsync/identity.txt` is the only way this machine can read the store. Losing
every machine's key means losing the data — there is no recovery path by design. Put a copy
somewhere safe:

```console
$ memsync key export
```

## Development

```console
$ cargo test
$ cargo clippy --all-targets -- -D warnings
$ cargo fmt --all -- --check
```

The conflict-resolution core (`src/plan.rs`) is a pure function and is tested without touching
the filesystem. `tests/end_to_end.rs` runs two simulated machines against a real bare
repository, covering creation, editing, deletion, conflicts, revocation, and a moved
directory.

## Licence

MIT — see [LICENSE](LICENSE).
