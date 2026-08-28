# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Data loss:** a machine that synchronised only some of the roots recorded the others in
  its snapshot. On the next run they looked locally deleted, and it pushed tombstones that
  would have destroyed another machine's memories. Objects under a root that is not
  configured locally are now excluded from planning and from the recorded snapshot, on load
  as well as on save — so a snapshot written by 0.1.0 heals itself instead of firing.
- `sync` no longer reports objects as downloaded when they were skipped; it names them
  separately as belonging to roots that are not configured here.

## [0.1.0] — 2026-08-29

First working version.

### Added

- Per-file encryption to every authorised machine using age (X25519, ChaCha20-Poly1305),
  ASCII-armoured so the store stays a text repository.
- Object naming by keyed BLAKE3 over the logical path, so the host learns no file names.
- Logical root ids mapped to local directories per machine, so a moved directory is a
  configuration change rather than a rewrite of the store.
- Three-way synchronisation against the previous snapshot: converging deletions, tombstones,
  and conflict copies that never discard a version.
- `init`, `sync`, `status`, `key show|list|add|remove|export`, `root list|add|map|remove`,
  `install-hooks`, `uninstall-hooks`.
- Claude Code `SessionStart` and `SessionEnd` hooks, merged into an existing `settings.json`
  without disturbing it.
- Store format version 1.
