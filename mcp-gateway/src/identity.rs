//! Gateway → system-backend identity forwarding. A system backend (the workspace
//! server) never re-derives who is calling: the gateway already authenticated
//! the agent token and resolved the user from the flow record, so it forwards
//! that decision in one HMAC-signed header. Loopback-only transport plus this
//! signature is what lets the backend skip its own auth without trusting the
//! agent container, which shares the network namespace it could otherwise spoof
//! a plain header from.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

pub const IDENTITY_HEADER: &str = "x-nasiko-identity";
const TTL_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIdentity {
    pub agent_id: Uuid,
    pub user_id: Uuid,
    pub flow_id: Option<String>,
    pub exp: u64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("malformed identity header")]
    Malformed,
    #[error("identity signature mismatch")]
    BadSignature,
    #[error("identity expired")]
    Expired,
}

impl SignedIdentity {
    pub fn new(agent_id: Uuid, user_id: Uuid, flow_id: Option<String>) -> Self {
        Self {
            agent_id,
            user_id,
            flow_id,
            exp: now_secs() + TTL_SECS,
        }
    }

    /// `<b64url(json)>.<hex(hmac-sha256)>`
    pub fn sign(&self, key: &[u8]) -> String {
        let payload = B64.encode(serde_json::to_vec(self).expect("identity serializes"));
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(payload.as_bytes());
        format!("{payload}.{}", hex::encode(mac.finalize().into_bytes()))
    }

    pub fn verify(header: &str, key: &[u8]) -> Result<Self, IdentityError> {
        let (payload, sig_hex) = header.split_once('.').ok_or(IdentityError::Malformed)?;
        let sig = hex::decode(sig_hex).map_err(|_| IdentityError::Malformed)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig)
            .map_err(|_| IdentityError::BadSignature)?;
        let bytes = B64.decode(payload).map_err(|_| IdentityError::Malformed)?;
        let id: Self = serde_json::from_slice(&bytes).map_err(|_| IdentityError::Malformed)?;
        if id.exp < now_secs() {
            return Err(IdentityError::Expired);
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn roundtrip_verifies() {
        let key = b"k".to_vec();
        let id = SignedIdentity {
            agent_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            flow_id: Some("abc".into()),
            exp: now_secs() + 60,
        };
        let header = id.sign(&key);
        assert_eq!(SignedIdentity::verify(&header, &key).unwrap(), id);
    }

    #[test]
    fn tampering_or_wrong_key_fails() {
        let key = b"k".to_vec();
        let id = SignedIdentity {
            agent_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            flow_id: None,
            exp: now_secs() + 60,
        };
        let header = id.sign(&key);
        assert!(SignedIdentity::verify(&header, b"other").is_err());
        let mut broken = header.clone();
        broken.replace_range(0..1, "x");
        assert!(SignedIdentity::verify(&broken, &key).is_err());
    }

    #[test]
    fn expired_fails() {
        let key = b"k".to_vec();
        let id = SignedIdentity {
            agent_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            flow_id: None,
            exp: now_secs() - 1,
        };
        assert!(SignedIdentity::verify(&id.sign(&key), &key).is_err());
    }
}
