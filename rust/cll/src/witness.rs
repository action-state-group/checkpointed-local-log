//! Witness-registration client: POST a checkpoint digest to a SCITT
//! Transparency Service's `/v1/digest` (the legacy generic-digest-anchoring
//! route -- `cll.ledger.checkpoint.register_checkpoint`'s wire contract,
//! distinct from the newer checkpoint-aware `/checkpoints` COSE route) and
//! check durable status via `GET /v1/inclusion/{capsule_id}`. Mirrors
//! `capsule-emit-mesh/plugins/capsule-producer/src/anchor.rs` byte-for-byte
//! on the wire (same endpoints, same `{"capsule_id": "<64-hex>"}` request,
//! same response shape) so this client and that one -- and the Python
//! ones -- are interchangeable against the same service.
//!
//! Deliberately a thin client only: no I/O policy, no cadence, no retry
//! loop. A caller (e.g. a checkpointer task) decides when/whether to
//! anchor and how to react to a failed call -- this module never lets a
//! network error propagate as anything other than a typed `Err`.

use serde::Deserialize;
use std::time::Duration;

pub const DEFAULT_TS_URL: &str = "https://witness.agentactioncapsule.org";

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness request failed: {0}")]
    Transport(String),
    #[error("witness service returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("witness response was not valid JSON: {0}")]
    Decode(String),
}

/// Response shape from `POST /v1/digest`.
#[derive(Debug, Clone, Deserialize)]
pub struct WitnessRecord {
    pub entry_hash: String,
    pub receipt_b64: String,
    pub leaf_index: i64,
    pub tree_size: i64,
}

/// `GET /v1/inclusion/{capsule_id}` response shape -- proves the digest was
/// actually logged, not just accepted by `/v1/digest` (registration is
/// fire-and-forget from the caller's view; inclusion is the durable-status
/// check).
#[derive(Debug, Clone, Deserialize)]
pub struct InclusionProof {
    pub capsule_id: String,
    pub entry_hash: String,
    pub leaf_index: i64,
    pub tree_size: i64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub root_hash: String,
    pub receipt_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorityPubkey {
    pub pubkey_hex: String,
    pub key_id: String,
}

pub struct WitnessClient {
    base_url: String,
    agent: ureq::Agent,
}

impl WitnessClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    /// `POST /v1/digest {"capsule_id": <64-hex>}`. Idempotent on the server
    /// side: resubmitting the same digest returns the original receipt, so
    /// callers may retry freely.
    pub fn post_digest(&self, digest_hex: &str) -> Result<WitnessRecord, WitnessError> {
        let url = format!("{}/v1/digest", self.base_url.trim_end_matches('/'));
        match self
            .agent
            .post(&url)
            .send_json(ureq::json!({ "capsule_id": digest_hex }))
        {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| WitnessError::Decode(e.to_string())),
            Err(ureq::Error::Status(status, resp)) => Err(WitnessError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(WitnessError::Transport(e.to_string())),
        }
    }

    /// `GET /v1/inclusion/{capsule_id}` -- `Ok(None)` on a 404 (not yet
    /// durable, or never submitted); never registers as a side effect,
    /// unlike `post_digest`.
    pub fn check_inclusion(
        &self,
        digest_hex: &str,
    ) -> Result<Option<InclusionProof>, WitnessError> {
        let url = format!(
            "{}/v1/inclusion/{}",
            self.base_url.trim_end_matches('/'),
            digest_hex
        );
        match self.agent.get(&url).call() {
            Ok(resp) => resp
                .into_json()
                .map(Some)
                .map_err(|e| WitnessError::Decode(e.to_string())),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(status, resp)) => Err(WitnessError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(WitnessError::Transport(e.to_string())),
        }
    }

    /// `GET /anchor/authority-pubkey` -- the raw 32-byte Ed25519 authority
    /// public key (hex) + its `key_id`, for out-of-band pinning and for
    /// verifying receipts offline via `scitt_cose.verify_receipt`.
    pub fn authority_pubkey(&self) -> Result<AuthorityPubkey, WitnessError> {
        let url = format!(
            "{}/anchor/authority-pubkey",
            self.base_url.trim_end_matches('/')
        );
        match self.agent.get(&url).call() {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| WitnessError::Decode(e.to_string())),
            Err(ureq::Error::Status(status, resp)) => Err(WitnessError::Status {
                status,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(WitnessError::Transport(e.to_string())),
        }
    }
}

impl Default for WitnessClient {
    fn default() -> Self {
        Self::new(DEFAULT_TS_URL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Minimal single-request HTTP mock: reads one full request (headers +
    /// declared body, so the client's write is fully drained before we
    /// respond -- writing early would race a still-in-progress client
    /// write and surface as a spurious client-side transport error),
    /// writes back a canned response, then stops listening. Good enough to
    /// exercise the client's request construction and response decoding
    /// without adding a mock-server dev-dependency.
    fn serve_once(response: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                        break Some(pos + 4);
                    }
                };
                if let Some(header_end) = header_end {
                    let headers = String::from_utf8_lossy(&buf[..header_end]);
                    let content_length: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .starts_with("content-length:")
                                .then(|| l["content-length:".len()..].trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while buf.len() < header_end + content_length {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn post_digest_parses_response() {
        let body = r#"{"entry_hash":"aa","receipt_b64":"YWJj","leaf_index":3,"tree_size":11}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let base = serve_once(Box::leak(response.into_boxed_str()));
        let client = WitnessClient::new(base);
        let rec = client.post_digest(&"ab".repeat(32)).unwrap();
        assert_eq!(rec.entry_hash, "aa");
        assert_eq!(rec.leaf_index, 3);
        assert_eq!(rec.tree_size, 11);
    }

    #[test]
    fn check_inclusion_404_is_none() {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let base = serve_once(response);
        let client = WitnessClient::new(base);
        let result = client.check_inclusion(&"cd".repeat(32)).unwrap();
        assert!(result.is_none());
    }
}
