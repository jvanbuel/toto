//! `toto`: the local runner for Tokens of Gratitude.
//!
//! Module layout follows docs/design.md ("Runner architecture"). Components that need
//! external systems (queue server, Docker, Omnigent) sit behind traits so the full task
//! lifecycle runs and is tested offline.

pub mod archive;
pub mod audit;
pub mod claude_cli;
pub mod config;
pub mod context;
pub mod daemon;
pub mod doctor;
pub mod dsse;
pub mod harness;
pub mod manifest;
pub mod http_queue;
pub mod meter;
pub mod netfence;
pub mod omnigent;
pub mod policy;
pub mod proxy;
pub mod queue;
pub mod result;
pub mod runner;
pub mod sandbox;
pub mod service;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("manifest verification failed: {0}")]
    Verify(String),
    #[error("denied by policy: {0}")]
    Policy(String),
    #[error("usage limit exceeded: used {used} of {limit} tokens")]
    Meter { used: u64, limit: u64 },
    #[error("harness error: {0}")]
    Harness(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error("invalid output: {0}")]
    Schema(String),
    #[error("queue error: {0}")]
    Queue(String),
    #[error("result rejected by contributor")]
    ReviewRejected,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
