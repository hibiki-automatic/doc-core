//! The diff bridge: turn "the file changed to this new text" into minimal
//! [`TextEdit`]s, so an external plain-text edit (e.g. neovim saving the file)
//! merges into the CRDT as ops rather than as a whole-text replacement.
//!
//! Positions are UTF-16 code units (see [`crate::doc`]). Char-level, never
//! line-level — coarse diffs churn tombstones and clobber concurrent edits.

use crate::doc::TextEdit;
use similar::{ChangeTag, TextDiff};

/// Compute a minimal set of [`TextEdit`]s that transform `old` into `new`,
/// with positions in UTF-16 code units.
///
/// The returned edits are **non-overlapping, in `old`-text coordinates, sorted
/// ascending by `pos`** — the exact form [`crate::doc::DocSession::apply`]
/// expects. Identical strings yield an empty vec.
///
/// The algorithm walks `similar`'s char-level change stream while tracking a
/// running UTF-16 offset into `old`:
///
/// * `Equal`  — advances the old-offset; flushes any in-progress edit.
/// * `Delete` — adds the char's UTF-16 width to the current run's `del` and
///   advances the old-offset.
/// * `Insert` — appends the char to the current run's `ins`; the old-offset is
///   *not* advanced (insertions occupy no space in `old`).
///
/// Consecutive `Delete`/`Insert` changes form a single "run" anchored at the
/// old-offset where the run started, so a contiguous replacement (delete +
/// insert at the same spot) coalesces into one `TextEdit` with both `del > 0`
/// and a non-empty `ins`.
pub fn diff(old: &str, new: &str) -> Vec<TextEdit> {
    let diff = TextDiff::from_chars(old, new);

    let mut edits: Vec<TextEdit> = Vec::new();
    // UTF-16 offset into `old` of the next not-yet-consumed change.
    let mut old_off: usize = 0;
    // The edit currently being accumulated, if a run is in progress. Its `pos`
    // is the old-offset at which the run started.
    let mut current: Option<TextEdit> = None;

    for change in diff.iter_all_changes() {
        let ch = change.value();
        let width: usize = ch.chars().map(char::len_utf16).sum();

        match change.tag() {
            ChangeTag::Equal => {
                // End of any run: flush it and step over the equal text.
                if let Some(edit) = current.take() {
                    edits.push(edit);
                }
                old_off += width;
            }
            ChangeTag::Delete => {
                let edit = current.get_or_insert_with(|| TextEdit {
                    pos: old_off,
                    del: 0,
                    ins: String::new(),
                });
                edit.del += width;
                old_off += width;
            }
            ChangeTag::Insert => {
                let edit = current.get_or_insert_with(|| TextEdit {
                    pos: old_off,
                    del: 0,
                    ins: String::new(),
                });
                edit.ins.push_str(ch);
            }
        }
    }

    // Flush a trailing run (changes at the very end of the document).
    if let Some(edit) = current.take() {
        edits.push(edit);
    }

    edits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apply a batch of [`TextEdit`]s to `s` via UTF-16 splicing, honoring the
    /// documented batch semantics: positions are all in the pre-batch
    /// coordinate space, so we apply highest `pos` first to avoid shifting
    /// later (here: earlier) positions.
    fn apply(s: &str, edits: &[TextEdit]) -> String {
        // Work in a UTF-16 unit buffer so pos/del map directly to indices.
        let mut units: Vec<u16> = s.encode_utf16().collect();
        let mut sorted = edits.to_vec();
        sorted.sort_by_key(|e| e.pos);
        // Apply from the back so unmodified prefixes keep their indices.
        for edit in sorted.iter().rev() {
            let ins: Vec<u16> = edit.ins.encode_utf16().collect();
            units.splice(edit.pos..edit.pos + edit.del, ins);
        }
        String::from_utf16(&units).expect("valid UTF-16")
    }

    /// Edits must be sorted ascending by `pos` and non-overlapping.
    fn assert_well_formed(edits: &[TextEdit]) {
        let mut cursor = 0usize;
        for e in edits {
            assert!(
                e.pos >= cursor,
                "edits must be sorted ascending and non-overlapping: {edits:?}"
            );
            // A run with del==0 && ins=="" would be a no-op; the engine should
            // never emit one.
            assert!(
                e.del > 0 || !e.ins.is_empty(),
                "no-op edit emitted: {e:?}"
            );
            cursor = e.pos + e.del;
        }
    }

    /// Convenience: diff, sanity-check shape, and assert it round-trips.
    fn check(old: &str, new: &str) -> Vec<TextEdit> {
        let edits = diff(old, new);
        assert_well_formed(&edits);
        assert_eq!(apply(old, &edits), new, "round-trip failed for {old:?} -> {new:?}");
        edits
    }

    #[test]
    fn no_change_is_empty() {
        assert_eq!(diff("hello", "hello"), vec![]);
        assert_eq!(diff("", ""), vec![]);
    }

    #[test]
    fn insert_at_start() {
        let edits = check("world", "hello world");
        assert_eq!(edits, vec![TextEdit::insert(0, "hello ")]);
    }

    #[test]
    fn insert_in_middle() {
        let edits = check("ac", "abc");
        assert_eq!(edits, vec![TextEdit::insert(1, "b")]);
    }

    #[test]
    fn insert_at_end() {
        let edits = check("hello", "hello!");
        assert_eq!(edits, vec![TextEdit::insert(5, "!")]);
    }

    #[test]
    fn insert_into_empty() {
        let edits = check("", "hi");
        assert_eq!(edits, vec![TextEdit::insert(0, "hi")]);
    }

    #[test]
    fn pure_delete() {
        let edits = check("hello world", "hello");
        assert_eq!(edits, vec![TextEdit::delete(5, 6)]);
    }

    #[test]
    fn delete_to_empty() {
        let edits = check("gone", "");
        assert_eq!(edits, vec![TextEdit::delete(0, 4)]);
    }

    #[test]
    fn replace_coalesces() {
        // A contiguous delete+insert at the same anchor is ONE edit.
        let edits = check("cat", "dog");
        assert_eq!(edits.len(), 1, "should be a single coalesced edit: {edits:?}");
        let e = &edits[0];
        assert!(e.del > 0 && !e.ins.is_empty(), "edit should both delete and insert: {e:?}");
        assert_eq!(*e, TextEdit { pos: 0, del: 3, ins: "dog".into() });
    }

    #[test]
    fn replace_in_middle() {
        let edits = check("the quick fox", "the slow fox");
        // Exactly the changed region in the middle, both del and ins present.
        assert_eq!(edits.len(), 1);
        assert!(edits[0].del > 0 && !edits[0].ins.is_empty());
    }

    #[test]
    fn multiple_separate_regions() {
        // Two independent changes: insert near the front, delete near the back.
        let edits = check("abcXYZdef", "abQcXYZde");
        assert!(edits.len() >= 2, "expected multiple edit regions: {edits:?}");
        assert_well_formed(&edits); // ascending + non-overlapping
    }

    #[test]
    fn three_regions_ascending() {
        let edits = check("11aa22bb33cc", "11AA22bb33CC");
        assert_well_formed(&edits);
        // Positions strictly increase across regions.
        let positions: Vec<usize> = edits.iter().map(|e| e.pos).collect();
        let mut sorted = positions.clone();
        sorted.sort();
        assert_eq!(positions, sorted);
    }

    #[test]
    fn astral_emoji_counts_utf16_units() {
        // "😀" is 1 char, 4 UTF-8 bytes, but 2 UTF-16 code units.
        let edits = check("ab", "a😀b");
        assert_eq!(edits, vec![TextEdit::insert(1, "😀")]);

        // Deleting an emoji that sits after a BMP char: pos counts UTF-16 units.
        // "x" = 1 unit, so the emoji starts at UTF-16 offset 1 and spans 2 units.
        let edits = check("x😀y", "xy");
        assert_eq!(edits, vec![TextEdit::delete(1, 2)]);
    }

    #[test]
    fn non_ascii_bmp_positions() {
        // Cyrillic chars are multi-byte in UTF-8 but a single UTF-16 unit each.
        let edits = check("привет", "приветик");
        // 6 BMP chars => offset 6 in UTF-16 units.
        assert_eq!(edits, vec![TextEdit::insert(6, "ик")]);
    }

    #[test]
    fn emoji_between_emoji_offsets() {
        // Each "😀" is 2 UTF-16 units; insert between them lands at offset 2.
        let edits = check("😀😀", "😀X😀");
        assert_eq!(edits, vec![TextEdit::insert(2, "X")]);
    }

    #[test]
    fn round_trip_property_assorted() {
        let cases = [
            ("", ""),
            ("a", "b"),
            ("hello world", "hello cruel world"),
            ("the quick brown fox", "the lazy brown dog"),
            ("😀 emoji 🎉 test", "😀 emoji test 🎉🎉"),
            ("line one\nline two\nline three", "line one\nline 2\nline three\nline four"),
            ("αβγδ", "αXβδZ"),
            ("aaaaa", ""),
            ("", "bbbbb"),
        ];
        for (old, new) in cases {
            check(old, new);
        }
    }
}
