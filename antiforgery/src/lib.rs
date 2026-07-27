//! Aether-X anti-forgery core.
//!
//! The user-facing panel must NEVER trust client-reported expiry or quota.
//! This crate provides the cryptographic primitives that make that enforceable:
//!
//!   - [`token`]: PASETO v4.public subscription tokens signed with Ed25519,
//!     carrying verifiable quota + expiry. A client cannot forge remaining
//!     time/bytes.
//!   - [`audit`]: an append-only, hash-chained (Merkle-style) audit log so any
//!     unauthorized DB edit is cryptographically detectable.
//!   - [`replay`]: replay protection for token refresh via rotating HMAC tokens
//!     with nonce + timestamp + short TTL.
//!   - [`device`]: device-fingerprint registry with concurrent-connection
//!     limiting to defeat subscription-link sharing/resale.
//!
//! Design rule: every type here is deterministic and unit-testable with zero
//! network or DB dependencies. See `SECURITY.md` for the threat rationale.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::cast_possible_truncation, // u64 -> usize at size/index boundaries
    clippy::cast_possible_wrap
)]

pub mod audit;
pub mod device;
pub mod error;
pub mod merkle;
pub mod replay;
pub mod token;
pub mod zkp;

pub use error::AntiForgeryError;
