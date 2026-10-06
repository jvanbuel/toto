//! Task manifests and the manifest verifier (ADR 3: projects sign, runners verify).

use crate::{Error, Result};
use crate::dsse::Envelope;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    pub cpu_millis: u32,
    pub memory_mb: u32,
    pub timeout_secs: u64,
}

impl Default for SandboxProfile {
    /// The strictest profile: one CPU, 1 GiB, 10 minutes. Network is the project's business
    /// (its approved agent directory), never the task's.
    fn default() -> Self {
        Self { cpu_millis: 1000, memory_mb: 1024, timeout_secs: 600 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSchema {
    /// `text` or `json`.
    pub format: String,
    pub max_bytes: usize,
    /// Most bytes of changed files the task may return as artifacts; 0 means none are collected.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_artifact_bytes: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskManifest {
    pub id: String,
    pub project_id: String,
    pub kind: String,
    /// Content address (hex SHA-256) of the input bundle.
    pub inputs: String,
    /// The prompt handed to the harness. Untrusted content.
    pub prompt: String,
    pub tool_requirements: Vec<String>,
    pub sandbox_profile: SandboxProfile,
    /// Expected tokens; checked against caps before and during the run.
    pub cost_estimate: u64,
    pub output_schema: OutputSchema,
    pub redundancy: u32,
}

/// DSSE payload type of a signed task manifest.
pub const TASK_PAYLOAD_TYPE: &str = "application/vnd.toto.task+json";

impl TaskManifest {
    /// Signs the manifest as a DSSE envelope. The signed bytes are exactly the JSON payload.
    pub fn sign(&self, key: &SigningKey) -> Result<Envelope> {
        Ok(crate::dsse::sign(TASK_PAYLOAD_TYPE, &serde_json::to_vec(self)?, key))
    }
}

/// The manifest inside an envelope, **unverified** (to find the task id and project). Never act
/// on the result without `TrustedProjects::verify`.
pub fn peek_manifest(env: &Envelope) -> Result<TaskManifest> {
    Ok(serde_json::from_slice(&env.payload_bytes()?)?)
}

/// Project public keys the contributor trusts, keyed by project id.
#[derive(Debug, Clone, Default)]
pub struct TrustedProjects(BTreeMap<String, VerifyingKey>);

impl TrustedProjects {
    pub fn insert(&mut self, project_id: impl Into<String>, key: VerifyingKey) {
        self.0.insert(project_id.into(), key);
    }

    /// Verifies an envelope against the key of the project it claims to be from, and returns
    /// the manifest decoded from the *verified* bytes. Rejects unknown projects, tampered
    /// payloads and wrong payload types.
    pub fn verify(&self, env: &Envelope) -> Result<TaskManifest> {
        let claimed = peek_manifest(env)?;
        let key = self.0.get(&claimed.project_id).ok_or_else(|| Error::Verify(format!("unknown project `{}`", claimed.project_id)))?;
        let payload = env.verify(TASK_PAYLOAD_TYPE, key)?;
        Ok(serde_json::from_slice(&payload)?)
    }
}

/// Generates a fresh ed25519 key from OS randomness.
pub fn generate_key() -> SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}
