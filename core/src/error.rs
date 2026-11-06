// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error type shared across core, backends and the history store.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The requested capability is not available on this platform or build.
    Unsupported(&'static str),
    /// A platform backend (ETW, WFP, netlink, eBPF, /proc, ...) failed.
    Backend(String),
    /// The history store failed.
    Store(String),
    /// Caller supplied an invalid value.
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported(what) => write!(f, "unsupported on this platform: {what}"),
            Error::Backend(msg) => write!(f, "backend error: {msg}"),
            Error::Store(msg) => write!(f, "store error: {msg}"),
            Error::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        Error::Store(err.to_string())
    }
}
