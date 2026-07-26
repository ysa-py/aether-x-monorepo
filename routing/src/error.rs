//! Error model for the routing engine.

use thiserror::Error;

/// Every fallible routing operation returns [`Result<_, RoutingError>`].
#[derive(Debug, Error)]
pub enum RoutingError {
    /// A JSON rule set was malformed.
    #[error("malformed rule set JSON: {0}")]
    MalformedJson(#[from] serde_json::Error),

    /// A CIDR string could not be parsed.
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),

    /// A rule set was structurally valid JSON but semantically invalid.
    #[error("invalid rule set: {0}")]
    InvalidRuleSet(String),

    /// An I/O error reading a rule set file.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// An upstream update is not implemented yet (stub).
    #[error("updater not implemented: {0}")]
    NotImplemented(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, RoutingError>;
