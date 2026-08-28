# Contributing

## Before you open a pull request

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets --all-features -- -D warnings
$ cargo test
```

CI runs exactly these, plus `cargo deny check` for licences and advisories.

## Where things belong

The layering is the point of the design, so keep changes on the right side of it:

- `src/plan.rs` — decides what to do when the two sides disagree. **No IO, no clock, no
  randomness.** Every change here needs a test that would fail without it.
- `src/engine.rs` — carries out a plan. Talks to the filesystem and the store.
- `src/store.rs`, `src/crypto.rs` — the outside world, behind traits.
- `src/app.rs` — command bodies. `src/cli.rs` stays declarative.

If a change makes the planner need the filesystem, that is a sign the plan is missing
information, not that the rule should be relaxed.

## Conventions

- Errors: typed with `thiserror` in the library, `anyhow` at the binary boundary. An error
  message names the file or command that failed and, where possible, what to do about it.
- Tests read as statements about behaviour: `a_deletion_propagates_instead_of_resurrecting`,
  not `test_delete_2`.
- Comments explain *why*. What the code does should be legible without them.
- Anything that changes the store layout or the blob format needs a version bump in
  `blob::FORMAT_VERSION` and a note in `CHANGELOG.md`.

## Data loss is the bug that matters

The one behaviour this tool must never exhibit is discarding a version of a file that a person
wrote. When in doubt, keep both copies and say so.
