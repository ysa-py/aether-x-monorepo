//! Aether-X Iran-aware routing engine.
//!
//! Implements the spec's §10 "smart domestic/foreign routing split": given a
//! destination (domain and/or IP), decide whether traffic is **Direct**
//! (domestic — do not proxy), **Proxy** (foreign / blocked — route through the
//! tunnel), or **Block** (ads / malware). Rule sets are JSON-loadable and
//! mirror the structure of `chocolate4u/Iran-v2ray-rules` geosite/geoip lists;
//! an [`Updater`] trait models auto-update from that upstream.
//!
//! All matching is deterministic and unit/property-tested with zero network or
//! FS requirements (the [`loader::preset`] is embedded).

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown
)]

pub mod decision;
pub mod error;
pub mod loader;
pub mod matcher;
pub mod rules;

pub use decision::{Engine, Request};
pub use error::RoutingError;
pub use loader::{preset, LocalLoader, Updater};
pub use rules::{Action, Category, DomainRule, DomainType, RuleSet};
