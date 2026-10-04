//! Result packager: validate against `output_schema`, hash, sign (DSSE) with the runner key.

use crate::dsse::Envelope;
use crate::manifest::OutputSchema;
use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DSSE payload type of a result.
pub const RESULT_PAYLOAD_TYPE: &str = "application/vnd.togra.result+json";

/// The signed part of a result. Artifacts travel next to it and are bound by `artifacts_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    /// Hex Ed25519 public key of the runner (self-certifying identity).
    pub runner_id: String,
    pub output: String,
    /// Hex SHA-256 of `output`.
    pub output_hash: String,
    pub tokens_used: u64,
    /// Hex SHA-256 of the artifact tar, when there are artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts_hash: Option<String>,
}

/// What a runner submits: the signed envelope plus the (optional) artifact tar, base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResult {
    pub envelope: Envelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<String>,
}

pub fn validate(output: &str, schema: &OutputSchema) -> Result<()> {
    if output.len() > schema.max_bytes {
        return Err(Error::Schema(format!("{} bytes exceeds {}", output.len(), schema.max_bytes)));
    }
    match schema.format.as_str() {
        "text" => Ok(()),
        "json" => serde_json::from_str::<serde_json::Value>(output).map(|_| ()).map_err(|e| Error::Schema(e.to_string())),
        other => Err(Error::Schema(format!("unknown format `{other}`"))),
    }
}

impl SignedResult {
    /// Validates, hashes and signs. `artifacts` is a tar (see `archive`), already size-checked
    /// by the sandbox against the task's cap.
    pub fn package(task_id: &str, output: String, tokens_used: u64, schema: &OutputSchema, key: &SigningKey, artifacts: Option<Vec<u8>>) -> Result<Self> {
        validate(&output, schema)?;
        let body = TaskResult {
            task_id: task_id.into(),
            runner_id: hex::encode(key.verifying_key().to_bytes()),
            output_hash: hex::encode(Sha256::digest(output.as_bytes())),
            output,
            tokens_used,
            artifacts_hash: artifacts.as_deref().map(crate::archive::sha256_hex),
        };
        Ok(Self { envelope: crate::dsse::sign(RESULT_PAYLOAD_TYPE, &serde_json::to_vec(&body)?, key), artifacts: artifacts.map(|a| B64.encode(a)) })
    }

    /// Verifies the signature (the runner id is its public key), the output hash and the
    /// artifact hash, and returns the signed result body.
    pub fn open(&self) -> Result<TaskResult> {
        let bad = |s: &str| Error::Verify(s.into());
        let claimed: TaskResult = serde_json::from_slice(&self.envelope.payload_bytes()?)?;
        let pk: [u8; 32] = hex::decode(&claimed.runner_id).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("bad runner id"))?;
        let key = VerifyingKey::from_bytes(&pk).map_err(|_| bad("bad runner key"))?;
        let body: TaskResult = serde_json::from_slice(&self.envelope.verify(RESULT_PAYLOAD_TYPE, &key)?)?;
        if hex::encode(Sha256::digest(body.output.as_bytes())) != body.output_hash {
            return Err(bad("output hash mismatch"));
        }
        match (&self.artifacts, &body.artifacts_hash) {
            (None, None) => {}
            (Some(a), Some(h)) => {
                let bytes = B64.decode(a).map_err(|_| bad("artifacts are not valid base64"))?;
                if &crate::archive::sha256_hex(&bytes) != h {
                    return Err(bad("artifacts hash mismatch"));
                }
            }
            _ => return Err(bad("artifacts and the signed artifacts_hash must come together")),
        }
        Ok(body)
    }

    /// Decoded artifact tar bytes, if any (call `open` first to authenticate them).
    pub fn artifact_bytes(&self) -> Result<Option<Vec<u8>>> {
        self.artifacts.as_ref().map(|a| B64.decode(a).map_err(|e| Error::Schema(e.to_string()))).transpose()
    }

    /// Decodes and validates the artifact archive, if any.
    pub fn artifact_records(&self, max_bytes: u64) -> Result<Vec<crate::archive::Record>> {
        match self.artifact_bytes()? {
            None => Ok(vec![]),
            Some(b) => crate::archive::from_bytes(&b, crate::archive::Limits::new(max_bytes)).map_err(Error::Schema),
        }
    }
}
