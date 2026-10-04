//! Result packager: validate against `output_schema`, hash, sign with the runner key.

use crate::manifest::OutputSchema;
use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub runner_id: String,
    pub output: String,
    /// Hex SHA-256 of `output` (content address).
    pub output_hash: String,
    pub tokens_used: u64,
    /// Changed files as a togra archive, base64, when the task's schema allows artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<String>,
    /// Hex SHA-256 of the decoded archive; covered by the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts_hash: Option<String>,
    pub signature: String,
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

fn payload(task_id: &str, runner_id: &str, hash: &str, tokens: u64, artifacts_hash: Option<&str>) -> Vec<u8> {
    let mut p = format!("{task_id}\n{runner_id}\n{hash}\n{tokens}");
    if let Some(a) = artifacts_hash {
        p.push_str(&format!("\n{a}"));
    }
    p.into_bytes()
}

impl TaskResult {
    pub fn package(task_id: &str, output: String, tokens_used: u64, schema: &OutputSchema, key: &SigningKey, artifacts: Option<Vec<u8>>) -> Result<Self> {
        validate(&output, schema)?;
        if let Some(a) = &artifacts {
            if a.len() as u64 > schema.max_artifact_bytes.saturating_mul(2).saturating_add(4096) {
                return Err(Error::Schema(format!("artifacts are {} bytes, limit {}", a.len(), schema.max_artifact_bytes)));
            }
        }
        let artifacts_hash = artifacts.as_deref().map(crate::archive::sha256_hex);
        let runner_id = hex::encode(key.verifying_key().to_bytes());
        let output_hash = hex::encode(Sha256::digest(output.as_bytes()));
        let sig = key.sign(&payload(task_id, &runner_id, &output_hash, tokens_used, artifacts_hash.as_deref()));
        use base64::Engine;
        let artifacts = artifacts.map(|a| base64::engine::general_purpose::STANDARD.encode(a));
        Ok(Self { task_id: task_id.into(), runner_id, output, output_hash, tokens_used, artifacts, artifacts_hash, signature: hex::encode(sig.to_bytes()) })
    }

    /// Checks the hash and the runner's signature (runner id is its public key).
    pub fn verify(&self) -> Result<()> {
        let bad = |s: &str| Error::Verify(s.into());
        if hex::encode(Sha256::digest(self.output.as_bytes())) != self.output_hash {
            return Err(bad("output hash mismatch"));
        }
        if self.artifacts.is_some() != self.artifacts_hash.is_some() {
            return Err(bad("artifacts and artifacts_hash must come together"));
        }
        if let (Some(a), Some(h)) = (&self.artifacts, &self.artifacts_hash) {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.decode(a).map_err(|_| bad("artifacts are not valid base64"))?;
            if &crate::archive::sha256_hex(&bytes) != h {
                return Err(bad("artifacts hash mismatch"));
            }
        }
        let pk: [u8; 32] = hex::decode(&self.runner_id).map_err(|_| bad("bad runner id"))?.try_into().map_err(|_| bad("bad runner id"))?;
        let sig: [u8; 64] = hex::decode(&self.signature).map_err(|_| bad("bad signature"))?.try_into().map_err(|_| bad("bad signature"))?;
        VerifyingKey::from_bytes(&pk)
            .map_err(|_| bad("bad runner key"))?
            .verify(&payload(&self.task_id, &self.runner_id, &self.output_hash, self.tokens_used, self.artifacts_hash.as_deref()), &Signature::from_bytes(&sig))
            .map_err(|_| bad("signature mismatch"))
    }
}

impl TaskResult {
    /// Decodes and validates the artifact archive, if any.
    pub fn artifact_records(&self, max_bytes: u64) -> Result<Vec<crate::archive::Record>> {
        use base64::Engine;
        let Some(a) = &self.artifacts else { return Ok(vec![]) };
        let bytes = base64::engine::general_purpose::STANDARD.decode(a).map_err(|e| Error::Schema(e.to_string()))?;
        crate::archive::from_bytes(&bytes, crate::archive::Limits::new(max_bytes)).map_err(Error::Schema)
    }
}
