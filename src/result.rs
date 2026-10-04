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

fn payload(task_id: &str, runner_id: &str, hash: &str, tokens: u64) -> Vec<u8> {
    format!("{task_id}\n{runner_id}\n{hash}\n{tokens}").into_bytes()
}

impl TaskResult {
    pub fn package(task_id: &str, output: String, tokens_used: u64, schema: &OutputSchema, key: &SigningKey) -> Result<Self> {
        validate(&output, schema)?;
        let runner_id = hex::encode(key.verifying_key().to_bytes());
        let output_hash = hex::encode(Sha256::digest(output.as_bytes()));
        let sig = key.sign(&payload(task_id, &runner_id, &output_hash, tokens_used));
        Ok(Self { task_id: task_id.into(), runner_id, output, output_hash, tokens_used, signature: hex::encode(sig.to_bytes()) })
    }

    /// Checks the hash and the runner's signature (runner id is its public key).
    pub fn verify(&self) -> Result<()> {
        let bad = |s: &str| Error::Verify(s.into());
        if hex::encode(Sha256::digest(self.output.as_bytes())) != self.output_hash {
            return Err(bad("output hash mismatch"));
        }
        let pk: [u8; 32] = hex::decode(&self.runner_id).map_err(|_| bad("bad runner id"))?.try_into().map_err(|_| bad("bad runner id"))?;
        let sig: [u8; 64] = hex::decode(&self.signature).map_err(|_| bad("bad signature"))?.try_into().map_err(|_| bad("bad signature"))?;
        VerifyingKey::from_bytes(&pk)
            .map_err(|_| bad("bad runner key"))?
            .verify(&payload(&self.task_id, &self.runner_id, &self.output_hash, self.tokens_used), &Signature::from_bytes(&sig))
            .map_err(|_| bad("signature mismatch"))
    }
}
