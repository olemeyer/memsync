//! End-to-end encrypted, git-backed synchronisation of Claude Code memory files.
//!
//! The crate is layered so that the risky part — deciding what to do when two machines
//! disagree — is a pure function with no IO:
//!
//! ```text
//! cli -> app -> engine -> plan   (pure decision core)
//!                 |
//!                 +-> store  (git, behind a trait)
//!                 +-> crypto (age, behind a trait)
//!                 +-> state  (last-synchronised snapshot)
//! ```
//!
//! See `docs/design.md` for the rationale, the store layout, and the threat model.

pub mod app;
pub mod blob;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod engine;
pub mod hooks;
pub mod model;
pub mod plan;
pub mod state;
pub mod store;
