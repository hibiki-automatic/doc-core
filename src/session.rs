//! [`YrsSession`] — the `yrs` (Yjs) implementation of [`DocSession`].
//!
//! ## UTF-16 offsets
//! The [`DocSession`] contract fixes all positions in UTF-16 code units (the
//! unit JS/browser peers use). yrs is configured with [`OffsetKind::Utf16`], so
//! the indices we hand to [`Text::insert`] / [`Text::remove_range`] are the same
//! UTF-16 offsets carried by [`TextEdit`], and the encoded updates we exchange
//! are wire-compatible with Yjs peers.
//!
//! ## Undo grouping
//! yrs groups consecutive tracked transactions into a single undo step using a
//! time window ([`yrs::undo::Options::capture_timeout_millis`], default 500ms).
//! That timing makes undo granularity non-deterministic. To honour the contract
//! ("undo the most recent local edit *group*" == one [`DocSession::apply`]
//! batch), we call [`UndoManager::reset`] after every `apply`, which closes the
//! current stack item so the next `apply` starts a fresh, independent undo step.
//!
//! The yrs `UndoManager` (by default) only tracks transactions committed with
//! *no* origin — which is exactly what `apply` uses (a plain `transact_mut`).
//! Remote `merge`s and `undo`/`redo` themselves use distinct origins and are
//! therefore not captured as new undoable local edits.

use yrs::undo::UndoManager;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Doc, GetString, OffsetKind, Options, ReadTxn, StateVector, Text, TextRef, Transact, Update,
};

use crate::doc::{DocSession, TextEdit};

/// The name of the root text type holding the document body. Must be stable
/// across peers (browser, file watcher) so they resolve the *same* shared type.
const ROOT: &str = "content";

/// A `yrs`-backed collaborative document. Holds the CRDT [`Doc`], its root text,
/// and an [`UndoManager`]; configured for UTF-16 offsets to match browser peers.
pub struct YrsSession {
    doc: Doc,
    text: TextRef,
    /// Tracks local `apply` edits so they can be undone/redone. Kept alive as a
    /// field because it owns document subscriptions that drive its stacks.
    undo: UndoManager<()>,
}

impl YrsSession {
    /// Create a session initialised with `initial` text.
    pub fn from_text(initial: &str) -> Self {
        // UTF-16 offsets so insert/remove indices line up with `TextEdit`
        // positions and with JS/browser peers.
        let options = Options {
            offset_kind: OffsetKind::Utf16,
            ..Options::default()
        };
        let doc = Doc::with_options(options);
        let text = doc.get_or_insert_text(ROOT);

        // Seed the initial content *before* the UndoManager exists, so the seed
        // is not an undoable step (you cannot undo "the document").
        if !initial.is_empty() {
            let mut txn = doc.transact_mut();
            text.insert(&mut txn, 0, initial);
        }

        let mut undo = UndoManager::new();
        undo.expand_scope(&doc, &text);

        Self { doc, text, undo }
    }
}

impl DocSession for YrsSession {
    fn text(&self) -> String {
        let txn = self.doc.transact();
        self.text.get_string(&txn)
    }

    fn apply(&mut self, edits: &[TextEdit]) {
        if edits.is_empty() {
            return;
        }

        // All edits are in pre-batch coordinates and non-overlapping. Applying
        // from the highest `pos` downward keeps earlier (lower) positions valid
        // regardless of length changes made by later (higher) ones — satisfying
        // the batch contract without tracking a running delta.
        let mut ordered: Vec<&TextEdit> = edits.iter().collect();
        ordered.sort_by_key(|e| std::cmp::Reverse(e.pos));

        // One transaction => one atomic change => one undo step / one broadcast.
        {
            let mut txn = self.doc.transact_mut();
            for edit in ordered {
                if edit.del > 0 {
                    self.text
                        .remove_range(&mut txn, edit.pos as u32, edit.del as u32);
                }
                if !edit.ins.is_empty() {
                    self.text.insert(&mut txn, edit.pos as u32, &edit.ins);
                }
            }
        } // transaction commits here, before we touch the UndoManager.

        // Close this undo step so the next `apply` is a separate, independent
        // step rather than being time-window-merged into this one.
        self.undo.reset();
    }

    fn state_vector(&self) -> Vec<u8> {
        let txn = self.doc.transact();
        txn.state_vector().encode_v1()
    }

    fn update_since(&self, state_vector: &[u8]) -> Vec<u8> {
        // Defense-in-depth on the attacker-controlled inbound SyncStep1 SV bytes
        // (audit B-security F3): in addition to the upstream size cap, decode
        // under `catch_unwind` so a panic on size-bounded malformed bytes cannot
        // unwind into the watch loop. A `StateVector` is a varint `(client_id,
        // clock)` stream with NO embedded strings, so unlike `Update::decode_v1`
        // it does not reach the `from_utf8_unchecked` UB site the `is_update_
        // bytes_safe` validator guards — this `catch_unwind` is the consistent
        // belt-and-suspenders for the SV path. A malformed/empty/panicking SV is
        // treated as "knows nothing", yielding the full document update (the
        // documented fallback, defused against bandwidth amplification by the
        // SyncStep1 size cap at the call site).
        let sv = std::panic::catch_unwind(|| StateVector::decode_v1(state_vector))
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
        let txn = self.doc.transact();
        txn.encode_diff_v1(&sv)
    }

    fn merge(&mut self, update: &[u8]) -> bool {
        let update = match Update::decode_v1(update) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // Compare text before/after — simple and unambiguous about whether the
        // merge actually changed the rendered document.
        let before = self.text();
        {
            let mut txn = self.doc.transact_mut();
            if txn.apply_update(update).is_err() {
                return false;
            }
        }
        self.text() != before
    }

    fn undo(&mut self) -> bool {
        self.undo.undo_blocking()
    }

    fn redo(&mut self) -> bool {
        self.undo.redo_blocking()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_from_text_roundtrips() {
        assert_eq!(YrsSession::from_text("").text(), "");
        assert_eq!(YrsSession::from_text("hello world").text(), "hello world");
        // Non-ASCII: combining chars, emoji (surrogate pair in UTF-16), CJK.
        let s = "café 🦀 日本語";
        assert_eq!(YrsSession::from_text(s).text(), s);
    }

    #[test]
    fn session_apply_single_insert() {
        let mut s = YrsSession::from_text("Hello world");
        s.apply(&[TextEdit::insert(5, ",")]);
        assert_eq!(s.text(), "Hello, world");
    }

    #[test]
    fn session_apply_single_delete() {
        let mut s = YrsSession::from_text("Hello, world");
        s.apply(&[TextEdit::delete(5, 1)]);
        assert_eq!(s.text(), "Hello world");
    }

    #[test]
    fn session_apply_utf16_offset() {
        // "🦀" is 2 UTF-16 code units, so offset 2 lands *right after* the crab
        // (before "a"). If yrs were using UTF-8 bytes (4) or chars (1) this
        // would land elsewhere, so this pins the UTF-16 offset configuration.
        let mut s = YrsSession::from_text("🦀ab");
        s.apply(&[TextEdit::insert(2, "X")]);
        assert_eq!(s.text(), "🦀Xab");
        // Now "🦀Xab": 🦀=[0,2), X=2, a=3, b=4. Offset 4 lands between a and b.
        s.apply(&[TextEdit::insert(4, "Y")]);
        assert_eq!(s.text(), "🦀XaYb");
    }

    #[test]
    fn session_apply_multi_edit_batch() {
        let mut s = YrsSession::from_text("abcdef");
        s.apply(&[
            TextEdit::insert(0, "["), // before 'a'
            TextEdit::delete(2, 2),   // remove 'cd'
            TextEdit::insert(6, "]"), // after 'f' (pre-batch end)
        ]);
        // "abcdef" -> "[abef]"
        assert_eq!(s.text(), "[abef]");
    }

    #[test]
    fn session_two_session_convergence() {
        let mut a = YrsSession::from_text("shared");
        let mut b = YrsSession::from_text("shared");
        // Make sure b knows a's state so they share history of the seed text.
        // (They were seeded independently, so we sync once to converge first.)
        let ua = a.update_since(&b.state_vector());
        b.merge(&ua);
        let ub = b.update_since(&a.state_vector());
        a.merge(&ub);

        // Now edit each differently.
        a.apply(&[TextEdit::insert(0, "A-")]);
        b.apply(&[TextEdit::insert(6, "-B")]);

        // Exchange the minimal missing updates both ways.
        let from_a = a.update_since(&b.state_vector());
        let from_b = b.update_since(&a.state_vector());

        let a_changed = a.merge(&from_b);
        let b_changed = b.merge(&from_a);

        assert!(a_changed, "merging b's edit should change a");
        assert!(b_changed, "merging a's edit should change b");
        assert_eq!(a.text(), b.text(), "sessions must converge");
    }

    #[test]
    fn session_merge_noop_returns_false() {
        let mut a = YrsSession::from_text("hello");
        // Merging an update derived from a's own current state changes nothing.
        let sv = a.state_vector();
        let self_update = a.update_since(&sv); // empty diff
        assert!(!a.merge(&self_update));
    }

    /// F3 regression: a malformed inbound SyncStep1 state vector must not panic
    /// or corrupt the session — `update_since` decodes it under `catch_unwind`
    /// and falls back to "knows nothing" (the full document), exactly as an empty
    /// SV does. No panic / UB escapes into the caller.
    #[test]
    fn update_since_tolerates_malformed_state_vector() {
        let s = YrsSession::from_text("hello world");
        // The full update an empty (knows-nothing) SV yields — the documented
        // fallback any unparseable SV must also produce.
        let full = s.update_since(&[]);
        assert!(
            !full.is_empty(),
            "non-empty doc yields a non-empty full update"
        );

        // A spread of adversarial / malformed SV byte strings: truncated varints,
        // an over-long varint run, random noise, and a valid prefix + garbage.
        let malformed: &[&[u8]] = &[
            &[0xFF],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x80, 0x80, 0x80, 0x80, 0x80],
            &[0x01, 0x80],
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[
                0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ],
        ];
        for bytes in malformed {
            // Must not panic; result is the safe full-doc fallback (or possibly a
            // partial diff for a coincidentally-parseable prefix — never a crash).
            let out = s.update_since(bytes);
            // A peer that "knows nothing" gets the full doc back; the key
            // invariant is no panic and a well-formed (decodable) update.
            assert!(
                Update::decode_v1(&out).is_ok(),
                "produced update must itself be a valid v1 update"
            );
        }
        // Session is untouched and still serves the same text.
        assert_eq!(s.text(), "hello world");
    }

    #[test]
    fn session_undo_redo_apply() {
        let mut s = YrsSession::from_text("base");
        s.apply(&[TextEdit::insert(4, "!")]);
        assert_eq!(s.text(), "base!");

        assert!(s.undo(), "undo should report a change");
        assert_eq!(s.text(), "base");

        assert!(s.redo(), "redo should report a change");
        assert_eq!(s.text(), "base!");

        // Nothing left to redo.
        assert!(!s.redo());
    }

    #[test]
    fn session_undo_separates_batches() {
        let mut s = YrsSession::from_text("");
        s.apply(&[TextEdit::insert(0, "one")]);
        s.apply(&[TextEdit::insert(3, "two")]);
        assert_eq!(s.text(), "onetwo");
        // Each apply is its own undo step thanks to reset().
        assert!(s.undo());
        assert_eq!(s.text(), "one");
        assert!(s.undo());
        assert_eq!(s.text(), "");
    }
}
