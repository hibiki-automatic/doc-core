//! The document-update contract — the "plane of separation".
//!
//! Everything that mutates or syncs a document goes through [`DocSession`]. A
//! CRDT (currently `yrs`, see [`crate::session`]) implements it; the file
//! watcher ([`crate::file_peer`]), and later the WebSocket transport and
//! persistence, are adapters that sit *behind* this trait. Because the `.md`
//! text file remains the canonical source of truth, a `DocSession`'s state can
//! always be reconstructed from text — there is no durable CRDT-format lock-in,
//! which is what keeps the underlying library swappable.
//!
//! All positions are expressed in **UTF-16 code units**. That is the unit JS /
//! browser peers use, so fixing it here (rather than Rust-native UTF-8 bytes)
//! avoids a translation layer at the browser boundary and prevents the classic
//! "edit landed at the wrong offset on non-ASCII text" corruption.

/// A minimal text edit: remove `del` UTF-16 code units at `pos`, then insert
/// `ins`. This is the shared currency between the diff engine
/// ([`crate::diff`]) and a [`DocSession`].
///
/// Edits are deliberately *minimal* (char-level, never line-level): coarse
/// "delete-all + reinsert" edits churn CRDT tombstones and clobber concurrent
/// edits from other peers instead of merging with them.
///
/// Within a batch passed to [`DocSession::apply`], all `pos`/`del` are in the
/// coordinate space of the document *before* the batch, and edits are
/// non-overlapping. See [`DocSession::apply`] for the full batch contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextEdit {
    /// Start position, in UTF-16 code units.
    pub pos: usize,
    /// Number of UTF-16 code units to delete at `pos`.
    pub del: usize,
    /// Text to insert at `pos` after the deletion.
    pub ins: String,
}

impl TextEdit {
    /// A pure insertion at `pos`.
    pub fn insert(pos: usize, ins: impl Into<String>) -> Self {
        Self {
            pos,
            del: 0,
            ins: ins.into(),
        }
    }

    /// A pure deletion of `del` code units at `pos`.
    pub fn delete(pos: usize, del: usize) -> Self {
        Self {
            pos,
            del,
            ins: String::new(),
        }
    }
}

/// A live document that merges updates from multiple heterogeneous peers (the
/// on-disk file, browser editors, remote collaborators) without a central
/// authority.
///
/// The trait is intentionally object-safe (`Box<dyn DocSession>`) so the daemon
/// can hold a `path -> session` map of trait objects.
pub trait DocSession {
    /// The full current text of the document.
    fn text(&self) -> String;

    /// Apply a batch of [`TextEdit`]s as a single atomic change (one undo step,
    /// one update broadcast).
    ///
    /// **Batch semantics (contract):** all `edits` are expressed against the
    /// document text *as it is before this call* — positions are NOT relative
    /// to each other — and are **non-overlapping**. Implementations must apply
    /// them so that earlier edits do not shift the positions of later ones
    /// (e.g. apply the highest `pos` first, or accumulate a running length
    /// delta). [`crate::diff::diff`] produces edits in exactly this form.
    fn apply(&mut self, edits: &[TextEdit]);

    /// An opaque encoding of this peer's current version, used to request only
    /// the updates a peer is missing. (yrs: a state vector.)
    fn state_vector(&self) -> Vec<u8>;

    /// Encode the minimal update that brings a peer at `state_vector` up to this
    /// peer's current state.
    fn update_since(&self, state_vector: &[u8]) -> Vec<u8>;

    /// Merge an opaque update from another peer. Returns `true` if the document
    /// text changed as a result.
    fn merge(&mut self, update: &[u8]) -> bool;

    /// Undo the most recent local edit group. Returns `true` if anything was
    /// undone.
    fn undo(&mut self) -> bool;

    /// Redo the most recently undone edit group. Returns `true` if anything was
    /// redone.
    fn redo(&mut self) -> bool;
}
