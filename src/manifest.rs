//! Task manifests and the manifest verifier (ADR 3: projects sign, runners verify).

use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Hosts the task may reach. Empty means default-deny egress.
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    pub cpu_millis: u32,
    pub memory_mb: u32,
    pub timeout_secs: u64,
}

impl Default for SandboxProfile {
    /// The strictest profile: no network, one CPU, 1 GiB, 10 minutes.
    fn default() -> Self {
        Self { network_allowlist: vec![], cpu_millis: 1000, memory_mb: 1024, timeout_secs: 600 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSchema {
    /// `text` or `json`.
    pub format: String,
    pub max_bytes: usize,
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
    /// Hex ed25519 signature by the project key over the manifest minus this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl TaskManifest {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        Ok(serde_json::to_vec(&unsigned)?)
    }

    pub fn sign(mut self, key: &SigningKey) -> Result<Self> {
        let sig = key.sign(&self.signing_bytes()?);
        self.signature = Some(hex::encode(sig.to_bytes()));
        Ok(self)
    }
}

/// Project public keys the contributor trusts, keyed by project id.
#[derive(Debug, Clone, Default)]
pub struct TrustedProjects(BTreeMap<String, VerifyingKey>);

impl TrustedProjects {
    pub fn insert(&mut self, project_id: impl Into<String>, key: VerifyingKey) {
        self.0.insert(project_id.into(), key);
    }

    /// Rejects unsigned, tampered or unknown-project manifests.
    pub fn verify(&self, m: &TaskManifest) -> Result<()> {
        let key = self
            .0
            .get(&m.project_id)
            .ok_or_else(|| Error::Verify(format!("unknown project `{}`", m.project_id)))?;
        let sig_hex = m.signature.as_deref().ok_or_else(|| Error::Verify("unsigned".into()))?;
        let bytes: [u8; 64] = hex::decode(sig_hex)
            .map_err(|e| Error::Verify(e.to_string()))?
            .try_into()
            .map_err(|_| Error::Verify("bad signature length".into()))?;
        key.verify(&m.signing_bytes()?, &Signature::from_bytes(&bytes))
            .map_err(|_| Error::Verify("signature mismatch".into()))
    }
}

/// Generates a fresh ed25519 key from OS randomness.
pub fn generate_key() -> SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}
