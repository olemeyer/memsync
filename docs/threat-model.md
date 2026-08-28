# Threat model

## What is being protected

The contents and the *names* of Claude Code memory files. These describe infrastructure,
accounts, and habits; a file called `tailscale-api-key.md` is informative before it is opened.

## Who is assumed hostile

**The synchronisation host** (GitHub, or whatever git remote is configured), including anyone
who obtains a copy of the repository — a leaked backup, a compromised account, an
over-permissive organisation membership.

## What the host can see

- The number of objects, their approximate sizes, and how those change over time.
- Commit timestamps, and therefore roughly when each machine is active.
- The machine labels and public keys in `recipients.toml`.
- The commit messages, which name the machine and count changed files.

## What the host cannot see

- The content of any memory file.
- Any file name or directory structure. Object names are `BLAKE3::keyed(salt, root ‖ 0x00 ‖
  path)`; a plain hash would be reversible in practice, because memory file names come from a
  small, guessable space. The salt is random, 32 bytes, and stored only encrypted.
- Whether a given object is a live file or a tombstone.
- The local paths on any machine. The store records logical root ids only.

## Who is trusted

- **The machines themselves.** Memory files are plaintext on disk — they have to be, since
  Claude Code reads them. Full-disk encryption is the control at that layer.
- **Every authorised key.** There is no per-file access control: authorisation is read access
  to everything, past and future.

## Key handling

- The private key lives at `~/.config/memsync/identity.txt`, mode `0600`, and is never
  transmitted. `memsync key export` prints it for backup and is the only path that does.
- Authorising a machine (`key add`) re-encrypts every object to the extended recipient set.
- Revoking (`key remove`) re-encrypts without that key. This prevents it from reading *future*
  updates. It does not undo past access: assume everything that machine could read is
  compromised, and rotate those credentials.
- `key remove` refuses to remove the last machine, which would leave the store unreadable.

## Residual risks accepted

| Risk | Why it is accepted |
|---|---|
| Object sizes and counts leak activity | Padding would obscure it at a cost in complexity and repository size; the signal is weak. |
| Commit messages name the machine | Useful for debugging; the labels are already in `recipients.toml`. |
| A compromised machine reads everything | Fine-grained access control has no use case for one person's own machines. |
| No forward secrecy | age is not a ratcheting protocol; a stolen key reads every version in the repository's history. |
| Plaintext on disk | Required for Claude Code to work at all. |

## Reporting

Security issues: see [SECURITY.md](../SECURITY.md).
