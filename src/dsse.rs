//! DSSE (Dead Simple Signing Envelope) with Ed25519.
//! Spec: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
//!
//! The signature covers `PAE(payloadType, payload)` over the exact payload bytes, so nothing
//! depends on how a struct happens to serialise. Envelopes are compatible with in-toto and
//! Sigstore tooling (key id = hex Ed25519 public key; payload types are `application/vnd.togra.*`).

use crate::{Error, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Base64 of the payload bytes.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Base64 of the 64-byte Ed25519 signature.
    pub sig: String,
}

/// Pre-Authentication Encoding: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    v.extend_from_slice(payload);
    v
}

pub fn sign(payload_type: &str, payload: &[u8], key: &SigningKey) -> Envelope {
    let sig = key.sign(&pae(payload_type, payload));
    Envelope {
        payload: B64.encode(payload),
        payload_type: payload_type.into(),
        signatures: vec![EnvelopeSignature { keyid: Some(hex::encode(key.verifying_key().to_bytes())), sig: B64.encode(sig.to_bytes()) }],
    }
}

impl Envelope {
    /// The payload bytes, **unverified**. Use only to find out whose key to verify with.
    pub fn payload_bytes(&self) -> Result<Vec<u8>> {
        B64.decode(&self.payload).map_err(|_| Error::Verify("envelope payload is not valid base64".into()))
    }

    /// Verifies that some signature is valid for `key` over this envelope's type and payload,
    /// and returns the verified payload bytes.
    pub fn verify(&self, expected_type: &str, key: &VerifyingKey) -> Result<Vec<u8>> {
        if self.payload_type != expected_type {
            return Err(Error::Verify(format!("unexpected payload type `{}`", self.payload_type)));
        }
        let payload = self.payload_bytes()?;
        let signed = pae(&self.payload_type, &payload);
        let ok = self.signatures.iter().any(|s| {
            B64.decode(&s.sig)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b).ok())
                .is_some_and(|b| key.verify(&signed, &Signature::from_bytes(&b)).is_ok())
        });
        if ok { Ok(payload) } else { Err(Error::Verify("signature mismatch".into())) }
    }
}
