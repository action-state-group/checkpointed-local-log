//! `evidencebook` -- evidence semantics over an embedded commitment history.
//!
//! This crate implements the store-level semantics of the Evidence Layer
//! Internet-Draft, `draft-mih-agent-evidence-layer-00` ("the I-D"; source:
//! <https://github.com/action-state-group/agent-action-capsule/blob/main/spec/draft-mih-agent-evidence-layer-00.md>).
//! Each public item names the I-D section it implements. The I-D is
//! implementation-independent: a store conforms by meeting its requirements,
//! not by using this crate.
//!
//! Two layers, kept distinct:
//!
//! ```text
//! evidencebook   records · epistemic types · links · retention · disclosure
//!                index classes · request answers · reconcile/close
//!   embeds
//! cll            append order · MMR · checkpoint · inclusion · consistency
//! ```
//!
//! The Checkpointed Local Log (`cll`, a sibling crate in this repository) is
//! the reference commitment substrate. It is embedded, never exposed: no
//! public item of this crate takes or returns a `cll` type
//! (`tests/public_api.rs` enforces this). Callers ask the book's substrate for
//! checkpoints and inclusion evidence in this crate's own types.
//!
//! The crate carries no deployment vocabulary. Record kinds, correlation key
//! names and content comparators belong to the calling profile and are
//! supplied by it.
//!
//! | I-D section | Module |
//! |---|---|
//! | Record header (anchor `record`); Epistemic Type; Typed Links | [`record`] |
//! | Record/Payload Separation; Retention States | [`retention`] |
//! | Disclosure Records | [`disclosure`] |
//! | Index Classes | [`index`] |
//! | The Commitment-Substrate Interface | [`substrate`] |
//! | Answering a Request; Three Kinds of "No" | [`request`] |
//! | Reconcile and Close | [`reconcile`] |
//! | Privacy Considerations: What a Checkpoint Reveals | [`padding`] |
//! | (record identity: JCS and JSON-DIGEST) | [`canonical`] |

pub mod canonical;
pub mod disclosure;
pub mod index;
pub mod padding;
pub mod reconcile;
pub mod record;
pub mod request;
pub mod retention;
pub mod substrate;
