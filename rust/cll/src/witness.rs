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
//! There is no default witness: a client is built with the URL its caller
//! chose (`WitnessClient::new`). A public witness is, for example,
//! `https://witness.agentactioncapsule.org`.
//!
//! Deliberately a thin client only: no I/O policy, no cadence, no retry
//! loop. A caller (e.g. a checkpointer task) decides when/whether to
//! anchor and how to react to a failed call -- this module never lets a
//! network error propagate as anything other than a typed `Err`.

use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness request failed: {0}")]
    Transport(String),
    #[error("witness service returned HTTP {status}: {body}")]
    Status { status: u16, body: String },
    #[error("witness response was not valid JSON: {0}")]
    Decode(String),
    #[error("witness response is larger than {0} bytes")]
    TooLarge(u64),
}

/// The largest response body a client reads. A receipt, an inclusion proof
/// or an authority key is a few kilobytes; anything past this is refused.
pub const MAX_RESPONSE_BYTES: u64 = 1 << 20;

/// How much of an error response's body a [`WitnessError::Status`] keeps.
const ERROR_BODY_CHARS: usize = 4096;

/// A response body, read up to [`MAX_RESPONSE_BYTES`].
fn read_capped(resp: ureq::Response) -> Result<Vec<u8>, WitnessError> {
    use std::io::Read;
    let mut body = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| WitnessError::Transport(e.to_string()))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(WitnessError::TooLarge(MAX_RESPONSE_BYTES));
    }
    Ok(body)
}

fn status_error(status: u16, resp: ureq::Response) -> WitnessError {
    let body = match read_capped(resp) {
        Ok(bytes) => String::from_utf8_lossy(&bytes)
            .chars()
            .take(ERROR_BODY_CHARS)
            .collect(),
        Err(_) => String::new(),
    };
    WitnessError::Status { status, body }
}

/// The JSON a request returned. Redirects are not followed, so a 3xx is an
/// error like any other non-2xx status; every body is read up to
/// [`MAX_RESPONSE_BYTES`].
fn json_response<T: serde::de::DeserializeOwned>(
    result: Result<ureq::Response, ureq::Error>,
) -> Result<T, WitnessError> {
    match result {
        Ok(resp) if (200..300).contains(&resp.status()) => {
            let body = read_capped(resp)?;
            serde_json::from_slice(&body).map_err(|e| WitnessError::Decode(e.to_string()))
        }
        Ok(resp) => Err(status_error(resp.status(), resp)),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp)),
        Err(e) => Err(WitnessError::Transport(e.to_string())),
    }
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
            // A redirect is never followed: a request goes to the URL the
            // caller chose and nowhere else.
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .redirects(0)
                .build(),
        }
    }

    /// `POST /v1/digest {"capsule_id": <64-hex>}`. Idempotent on the server
    /// side: resubmitting the same digest returns the original receipt, so
    /// callers may retry freely.
    pub fn post_digest(&self, digest_hex: &str) -> Result<WitnessRecord, WitnessError> {
        let url = format!("{}/v1/digest", self.base_url.trim_end_matches('/'));
        json_response(
            self.agent
                .post(&url)
                .send_json(ureq::json!({ "capsule_id": digest_hex })),
        )
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
            Err(ureq::Error::Status(404, _)) => Ok(None),
            result => json_response(result).map(Some),
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
        json_response(self.agent.get(&url).call())
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

    /// A server that answers every request with `response` (raw HTTP) and
    /// counts the requests it got.
    fn serve_counting(
        response: Vec<u8>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{BufRead, BufReader};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                counted.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let _ = stream.write_all(&response);
            }
        });
        (url, hits)
    }

    fn json_ok(body: &[u8]) -> Vec<u8> {
        let mut r = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn a_redirect_is_not_followed() {
        use std::sync::atomic::Ordering;
        let (elsewhere, elsewhere_hits) =
            serve_counting(json_ok(br#"{"pubkey_hex":"00","key_id":"k"}"#));
        let (url, hits) = serve_counting(
            format!(
                "HTTP/1.1 302 Found\r\nLocation: {elsewhere}/anchor/authority-pubkey\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .into_bytes(),
        );
        let client = WitnessClient::new(&url);
        match client.authority_pubkey() {
            Err(WitnessError::Status { status: 302, .. }) => {}
            other => panic!("expected the 302 as an error, got {other:?}"),
        }
        match client.post_digest(&"ab".repeat(32)) {
            Err(WitnessError::Status { status: 302, .. }) => {}
            other => panic!("expected the 302 as an error, got {other:?}"),
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            elsewhere_hits.load(Ordering::SeqCst),
            0,
            "the redirect target was contacted"
        );
    }

    #[test]
    fn a_response_body_is_capped() {
        let mut big = br#"{"pubkey_hex":""#.to_vec();
        big.extend(std::iter::repeat_n(b'0', MAX_RESPONSE_BYTES as usize));
        big.extend_from_slice(br#"","key_id":"k"}"#);
        let (url, _) = serve_counting(json_ok(&big));
        match WitnessClient::new(&url).authority_pubkey() {
            Err(WitnessError::TooLarge(cap)) => assert_eq!(cap, MAX_RESPONSE_BYTES),
            other => panic!("expected TooLarge, got {other:?}"),
        }
        let mut fits = br#"{"pubkey_hex":""#.to_vec();
        fits.extend(std::iter::repeat_n(b'0', 1000));
        fits.extend_from_slice(br#"","key_id":"k"}"#);
        let (url, _) = serve_counting(json_ok(&fits));
        assert_eq!(
            WitnessClient::new(&url)
                .authority_pubkey()
                .unwrap()
                .pubkey_hex
                .len(),
            1000
        );
        let mut err = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            10_000
        )
        .into_bytes();
        err.extend(std::iter::repeat_n(b'x', 10_000));
        let (url, _) = serve_counting(err);
        match WitnessClient::new(&url).authority_pubkey() {
            Err(WitnessError::Status { status: 500, body }) => {
                assert_eq!(body.len(), ERROR_BODY_CHARS)
            }
            other => panic!("expected a 500, got {other:?}"),
        }
    }
}
