//! Error model for the data plane.

use thiserror::Error;

/// Every fallible supervisor operation returns [`Result<_, SupervisorError>`].
#[derive(Debug, Error)]
pub enum SupervisorError {
    /// Caller referenced a core instance id that is not registered.
    #[error("core instance not found: {0}")]
    InstanceNotFound(String),

    /// Caller tried to start an instance id that already exists.
    #[error("core instance already exists: {0}")]
    InstanceExists(String),

    /// The core adapter rejected the supplied config blob.
    #[error("invalid core config for {kind:?}: {reason}")]
    InvalidConfig {
        kind: crate::protocol::CoreKind,
        reason: String,
    },

    /// A supervised core process exited unexpectedly.
    #[error("core {instance} exited: {source}")]
    CoreExited {
        instance: String,
        #[source]
        source: std::io::Error,
    },

    /// A restart-loop budget was exhausted.
    #[error("restart budget exhausted for {0}")]
    RestartBudgetExhausted(String),

    /// Hot-swap was requested on a core that cannot drain.
    #[error("core {0} is not hot-swap capable")]
    NotHotSwapCapable(String),

    /// A policy revision was older than the effective one.
    #[error("stale policy revision {provided} < effective {effective}")]
    StalePolicy { provided: u64, effective: u64 },

    /// gRPC / tonic transport error.
    #[error("transport: {0}")]
    Transport(String),

    /// A generic, human-readable failure with no wrapped source.
    #[error("{0}")]
    Generic(String),

    /// Catch-all for adapter-specific failures.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, SupervisorError>;
