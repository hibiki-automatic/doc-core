//! Pre-decode validator for untrusted `yrs` v1 update bytes — the **UB / remote-DoS
//! guard** on the `/collab` path.
//!
//! ## The bug this closes
//! `yrs`'s `Update::decode_v1` (and the lib0 `Decoder::read_string` it relies on)
//! reads every embedded string with `std::str::from_utf8_unchecked`. Bytes that are
//! well-formed *per the v1 update grammar* but carry an embedded string field whose
//! bytes are NOT valid UTF-8 therefore construct a `&str` over invalid UTF-8 — UB.
//! In practice this surfaces as a **non-unwinding abort** (the whole process is
//! killed), so it cannot be contained by `catch_unwind`. On `/collab` the update is
//! attacker-controlled, making this a remote-DoS / UB vector.
//!
//! ## The fix
//! Before any update reaches `decode_v1`, walk the exact same v1 grammar using
//! `yrs`'s OWN bounds-checked read cursor ([`yrs::encoding::read::Cursor`] + the
//! [`Read`] trait). Every read goes through that cursor, so it can never index past
//! the buffer; and at every site where the decoder would call the *unchecked*
//! `read_string`, we instead read the raw length-prefixed buffer with the
//! bounds-checked `read_buf` and validate it with **checked** [`std::str::from_utf8`].
//! Any malformed byte sequence, over-long length, truncation, invalid UTF-8 string,
//! or unexpected tag makes the walk return `false` (reject) — never a panic, never an
//! abort. An accepted update is byte-structurally safe for `decode_v1` to consume.
//!
//! Soundness rationale (matches `audit/02-security.md`): we do not re-implement a
//! varint reader (which could drift from the decoder); we drive `yrs`'s own cursor
//! through the same call sequence as `Update::decode` → `decode_block` →
//! `ItemContent::decode` → `IdSet::decode`, substituting checked UTF-8 decoding for
//! the one unsound step. Because validation only ever *reads* through the cursor and
//! returns a bool, a divergence from the grammar can only cause a (safe) rejection,
//! never UB.
//!
//! ## Residual assumption (revisit on change)
//! This mirrors the grammar of **default `yrs` features** (the crate is built with
//! `sync`; NOT `small-client` and NOT `weak`) on the **v1 decode path**. Specifically:
//!   * client IDs are `u64` varints (the `small-client` flag would make them `u32`);
//!   * `TYPE_REFS_WEAK` (7) is treated as an unknown/rejected type-ref (the `weak`
//!     flag would add a `LinkSource` sub-grammar);
//!   * only the v1 (`DecoderV1` / lib0 v1) wire format is walked — the v2 RLE format
//!     has its own `from_utf8_unchecked` site (`StringDecoder`) and is out of scope.
//!
//! If any of those feature flags are enabled, or a v2 decode path is introduced on
//! `/collab`, this validator MUST be revisited.

// --- F3: loud guard against silently invalidating the UB-guard's assumptions ---
//
// This validator's grammar is pinned to **default `yrs` features** (`sync`, but
// NOT `small-client`, NOT `weak`) on the **v1** wire format (see the module
// residual note). Enabling `small-client` (client IDs become `u32`), `weak`
// (adds the `LinkSource` sub-grammar under `TYPE_REFS_WEAK`), or routing v2
// updates through `/collab` would make a structurally-different update pass this
// walk and reach `decode_v1`'s `from_utf8_unchecked` — a SILENT bypass.
//
// Our crate does not currently expose a passthrough feature that flips any of
// those `yrs` flags (we depend on `yrs = { features = ["sync"] }`; verified via
// `cargo tree -e features -i yrs`). To make a *future* silent bypass impossible
// rather than merely unlikely, this `compile_error!` fires if anyone ever adds a
// crate feature that forwards one of the assumption-breaking knobs. If you add
// such a feature, you MUST first revisit this validator's grammar — do not just
// delete the guard. The locked `decode_path_assumptions_hold` test below is the
// runtime counterpart for the case where the flip arrives via transitive feature
// unification (which a cfg on our own features cannot observe).
#[cfg(any(
    feature = "yrs-small-client",
    feature = "yrs-weak",
    feature = "yrs-v2-collab",
))]
compile_error!(
    "validate.rs UB guard assumes DEFAULT yrs features (sync; not small-client, not weak) \
     on the v1 wire format. A feature forwarding small-client/weak or enabling a v2 /collab \
     decode path would silently bypass the guard — revisit the grammar walk before enabling it."
);

use std::str;
use yrs::encoding::read::{Cursor, Error as ReadError, Read};

/// Maximum nesting depth for the `Any` value grammar (CBOR-like maps/arrays) and the
/// content walk. `Any` is the only self-recursive shape in the grammar; this bounds
/// validator stack usage so a deeply-nested-but-small update can't overflow the
/// stack. The legitimate document model never nests `Any` this deep.
const MAX_ANY_DEPTH: u32 = 256;

// --- v1 block "info" bit flags (mirrors `yrs::block`) ---------------------------
const HAS_RIGHT_ORIGIN: u8 = 0b0100_0000;
const HAS_ORIGIN: u8 = 0b1000_0000;
const HAS_PARENT_SUB: u8 = 0b0010_0000;

// --- block ref numbers (low nibble of `info`) -----------------------------------
const BLOCK_ITEM_DELETED: u8 = 1;
const BLOCK_ITEM_JSON: u8 = 2;
const BLOCK_ITEM_BINARY: u8 = 3;
const BLOCK_ITEM_STRING: u8 = 4;
const BLOCK_ITEM_EMBED: u8 = 5;
const BLOCK_ITEM_FORMAT: u8 = 6;
const BLOCK_ITEM_TYPE: u8 = 7;
const BLOCK_ITEM_ANY: u8 = 8;
const BLOCK_ITEM_DOC: u8 = 9;
const BLOCK_SKIP_REF: u8 = 10;
const BLOCK_GC_REF: u8 = 0;

// --- shared type ref tags (mirrors `yrs::types`) --------------------------------
const TYPE_REFS_ARRAY: u8 = 0;
const TYPE_REFS_MAP: u8 = 1;
const TYPE_REFS_TEXT: u8 = 2;
const TYPE_REFS_XML_ELEMENT: u8 = 3;
const TYPE_REFS_XML_FRAGMENT: u8 = 4;
const TYPE_REFS_XML_HOOK: u8 = 5;
const TYPE_REFS_XML_TEXT: u8 = 6;
const TYPE_REFS_DOC: u8 = 9;
const TYPE_REFS_UNDEFINED: u8 = 15;
// NOTE: TYPE_REFS_WEAK (7) is intentionally absent — see the module residual note.

/// Validate raw `yrs` **v1 update bytes** (NOT a y-sync frame — the caller has
/// already unwrapped the SyncStep2/Update payload; this is exactly what
/// `collab::sync_update_payload` / `collab::Inbound::Update` yields and what
/// `collab::apply_client_update` receives as `update: &[u8]`).
///
/// Returns `true` only if the bytes can be walked end-to-end as a well-formed v1
/// update in which **every** embedded string field is valid UTF-8 — i.e. it is safe
/// to hand to `Update::decode_v1`. Returns `false` on ANY malformed, truncated,
/// over-long, over-nested, or invalid-UTF-8 content. Never panics, never aborts.
///
/// This is the integrator's entry point: call it on the untrusted update bytes and
/// drop the update (do not merge it) when it returns `false`.
pub fn is_update_bytes_safe(update: &[u8]) -> bool {
    walk_update(update).is_ok()
}

/// Convenience entry point for a base64-encoded update (daemon builds only).
///
/// Some transports deliver the update as a base64 string rather than raw bytes; this
/// decodes (standard and URL-safe alphabets, padded or not) and then validates the
/// bytes. Returns `false` if the input is not valid base64 or the decoded bytes are
/// unsafe.
///
/// Gated on the optional `base64` feature: the `base64` dependency is not part of
/// the minimal kernel (the crate builds with `--no-default-features` and no extra
/// deps); the raw-bytes [`is_update_bytes_safe`] is always available. md-preview's
/// `daemon` feature turns this on so it is present identically in daemon builds.
#[cfg(feature = "base64")]
pub fn is_update_b64_safe(update_b64: &str) -> bool {
    use base64::Engine as _;
    let trimmed = update_b64.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed));
    match decoded {
        Ok(bytes) => is_update_bytes_safe(&bytes),
        Err(_) => false,
    }
}

/// The single error type for the walk. Every failure mode collapses to "reject"; we
/// keep variants only to make the walk self-documenting. (Not surfaced publicly — the
/// public API is a bool, since the only safe action on any failure is to drop the
/// update.)
#[derive(Debug)]
enum Reject {
    /// Underlying bounds-checked cursor hit end-of-buffer / bad varint, etc.
    Cursor,
    /// A length-prefixed string field was not valid UTF-8 (the core bug).
    InvalidUtf8,
    /// An unexpected tag / ref number for the position in the grammar.
    BadTag,
    /// Nesting exceeded [`MAX_ANY_DEPTH`].
    TooDeep,
    /// Trailing bytes remained after a complete update was walked.
    Trailing,
}

impl From<ReadError> for Reject {
    fn from(_: ReadError) -> Self {
        Reject::Cursor
    }
}

type WalkResult = Result<(), Reject>;

/// Walk a complete v1 update. Mirrors `yrs::update::Update::decode`.
fn walk_update(buf: &[u8]) -> WalkResult {
    let mut cur = Cursor::new(buf);

    // read blocks: varint client count, then per-client (block count, client id,
    // start clock, then that many blocks).
    let clients_len: u32 = cur.read_var()?;
    for _ in 0..clients_len {
        let blocks_len: u32 = cur.read_var()?;
        let _client = read_client(&mut cur)?;
        let _clock: u32 = cur.read_var()?;
        for _ in 0..blocks_len {
            walk_block(&mut cur)?;
        }
    }

    // read delete set: varint client count, then per-client (client id, id-range).
    walk_id_set(&mut cur)?;

    // A well-formed update consumes the whole buffer; trailing bytes are suspicious
    // and rejected (defence in depth — `decode_v1` would ignore them).
    if cur.has_content() {
        return Err(Reject::Trailing);
    }
    Ok(())
}

/// Read a client id. Default features ⇒ `u64` varint (see residual note).
#[inline]
fn read_client(cur: &mut Cursor<'_>) -> Result<u64, Reject> {
    let client: u64 = cur.read_var()?;
    Ok(client)
}

/// Read an `ID` (left/right origin / parent id): client + clock varints.
#[inline]
fn read_id(cur: &mut Cursor<'_>) -> WalkResult {
    let _client: u64 = cur.read_var()?;
    let _clock: u32 = cur.read_var()?;
    Ok(())
}

/// Read one length-prefixed buffer and validate it as UTF-8 (the checked substitute
/// for the decoder's unchecked `read_string`). This is the load-bearing line.
#[inline]
fn read_string(cur: &mut Cursor<'_>) -> WalkResult {
    let bytes = cur.read_buf()?;
    match str::from_utf8(bytes) {
        Ok(_) => Ok(()),
        Err(_) => Err(Reject::InvalidUtf8),
    }
}

/// Walk one block. Mirrors `yrs::update::Update::decode_block`.
fn walk_block(cur: &mut Cursor<'_>) -> WalkResult {
    let info = cur.read_u8()?;
    match info {
        BLOCK_SKIP_REF => {
            // Skip: a single length varint, no embedded data.
            let _len: u32 = cur.read_var()?;
            Ok(())
        }
        BLOCK_GC_REF => {
            // GC: a single length varint.
            let _len: u32 = cur.read_var()?;
            Ok(())
        }
        info => {
            let cant_copy_parent_info = info & (HAS_ORIGIN | HAS_RIGHT_ORIGIN) == 0;
            if info & HAS_ORIGIN != 0 {
                read_id(cur)?;
            }
            if info & HAS_RIGHT_ORIGIN != 0 {
                read_id(cur)?;
            }
            if cant_copy_parent_info {
                // read_parent_info: a varint == 1 means "named parent" (a string),
                // otherwise a left id.
                let parent_info: u32 = cur.read_var()?;
                if parent_info == 1 {
                    read_string(cur)?; // TypePtr::Named(<string>)
                } else {
                    read_id(cur)?; // TypePtr::ID(<id>)
                }
                if info & HAS_PARENT_SUB != 0 {
                    read_string(cur)?; // parent_sub key
                }
            }
            walk_content(cur, info)
        }
    }
}

/// Walk an item's content. Mirrors `yrs::block::ItemContent::decode`.
fn walk_content(cur: &mut Cursor<'_>, info: u8) -> WalkResult {
    match info & 0b1111 {
        BLOCK_ITEM_DELETED => {
            let _len: u32 = cur.read_var()?;
            Ok(())
        }
        BLOCK_ITEM_JSON => {
            // read_len, then (len + 1) JSON strings (the decoder loops while
            // `remaining >= 0`, starting from `remaining = len`).
            let len: u32 = cur.read_var()?;
            for _ in 0..=len {
                read_string(cur)?;
            }
            Ok(())
        }
        BLOCK_ITEM_BINARY => {
            // Arbitrary bytes — bounds-checked, no UTF-8 requirement.
            let _bytes = cur.read_buf()?;
            Ok(())
        }
        BLOCK_ITEM_STRING => read_string(cur),
        BLOCK_ITEM_EMBED => {
            // read_json ⇒ read_string (then JSON-parsed by yrs, pure-Rust, no UB).
            // For safety all we must guarantee is the string bytes are valid UTF-8.
            read_string(cur)
        }
        BLOCK_ITEM_FORMAT => {
            read_string(cur)?; // read_key (a string)
            read_string(cur) // read_json (a string)
        }
        BLOCK_ITEM_TYPE => walk_type_ref(cur),
        BLOCK_ITEM_ANY => {
            let len: u32 = cur.read_var()?;
            for _ in 0..len {
                walk_any(cur, 0)?;
            }
            Ok(())
        }
        BLOCK_ITEM_DOC => walk_doc_options(cur),
        _ => Err(Reject::BadTag),
    }
}

/// Walk a `TypeRef`. Mirrors `yrs::types::TypeRef::decode` (default features:
/// `weak` is NOT enabled, so `TYPE_REFS_WEAK` is rejected as an unknown tag).
fn walk_type_ref(cur: &mut Cursor<'_>) -> WalkResult {
    let type_ref = cur.read_u8()?; // read_type_ref: a single byte in v1
    match type_ref {
        TYPE_REFS_ARRAY
        | TYPE_REFS_MAP
        | TYPE_REFS_TEXT
        | TYPE_REFS_XML_FRAGMENT
        | TYPE_REFS_XML_HOOK
        | TYPE_REFS_XML_TEXT
        | TYPE_REFS_DOC
        | TYPE_REFS_UNDEFINED => Ok(()),
        TYPE_REFS_XML_ELEMENT => read_string(cur), // read_key (a string)
        _ => Err(Reject::BadTag),
    }
}

/// Walk `Doc` content options. Mirrors `yrs::doc::Options::decode`: a guid string
/// then an `Any` value (expected to be a map, but any `Any` is walked safely).
fn walk_doc_options(cur: &mut Cursor<'_>) -> WalkResult {
    read_string(cur)?; // guid
    walk_any(cur, 0) // options blob (an Any value)
}

/// Walk an `Any` (lib0 CBOR-like) value. Mirrors `yrs::any::Any::decode`. Recursion
/// is depth-bounded by [`MAX_ANY_DEPTH`].
fn walk_any(cur: &mut Cursor<'_>, depth: u32) -> WalkResult {
    if depth > MAX_ANY_DEPTH {
        return Err(Reject::TooDeep);
    }
    match cur.read_u8()? {
        127 | 126 => Ok(()), // undefined | null
        125 => cur.read_var::<i64>().map(|_| ()).map_err(Reject::from), // integer (varint)
        124 => cur.read_f32().map(|_| ()).map_err(Reject::from), // float32
        123 => cur.read_f64().map(|_| ()).map_err(Reject::from), // float64
        122 => cur.read_i64().map(|_| ()).map_err(Reject::from), // bigint
        121 | 120 => Ok(()), // boolean false | true
        119 => read_string(cur), // string
        118 => {
            // Map<string, Any>: len, then len * (string key, Any value).
            let len: u32 = cur.read_var()?;
            for _ in 0..len {
                read_string(cur)?;
                walk_any(cur, depth + 1)?;
            }
            Ok(())
        }
        117 => {
            // Array<Any>: len, then len * Any.
            let len: u32 = cur.read_var()?;
            for _ in 0..len {
                walk_any(cur, depth + 1)?;
            }
            Ok(())
        }
        116 => {
            let _bytes = cur.read_buf()?; // buffer (arbitrary bytes)
            Ok(())
        }
        _ => Err(Reject::BadTag),
    }
}

/// Walk the delete set (`IdSet`). Mirrors `yrs::id_set::IdSet::decode` followed by
/// `IdRange::decode`. Contains only varints — no embedded strings — but it must be
/// walked so the trailing-bytes check is accurate and so a malformed delete set is
/// rejected before `decode_v1` sees it.
fn walk_id_set(cur: &mut Cursor<'_>) -> WalkResult {
    let client_len: u32 = cur.read_var()?;
    for _ in 0..client_len {
        let _client: u64 = cur.read_var()?;
        walk_id_range(cur)?;
    }
    Ok(())
}

/// Walk one client's `IdRange`: a length varint, then that many (clock, len) varint
/// pairs. Mirrors `yrs::id_set::IdRange::decode` for the v1 format.
fn walk_id_range(cur: &mut Cursor<'_>) -> WalkResult {
    let len: u32 = cur.read_var()?;
    for _ in 0..len {
        let _clock: u32 = cur.read_var()?; // read_ds_clock (a varint in v1)
        let _range_len: u32 = cur.read_var()?; // read_ds_len (a varint in v1)
    }
    Ok(())
}

#[cfg(test)]
// These tests construct yrs v1 wire-format buffers byte-by-byte; each `push` carries
// an inline comment documenting the field it encodes, so a `vec![]` literal would lose
// that documentation. Keep the explicit pushes.
#[allow(clippy::vec_init_then_push)]
mod tests {
    use super::*;
    use yrs::updates::decoder::Decode;
    use yrs::{Doc, GetString, ReadTxn, Text, Transact};

    /// Build a real, well-formed v1 update by editing a yrs document and encoding the
    /// state as an update. This exercises the String / block / delete-set grammar.
    fn make_valid_update(text: &str) -> Vec<u8> {
        let doc = Doc::new();
        let txt = doc.get_or_insert_text("content");
        {
            let mut txn = doc.transact_mut();
            txt.insert(&mut txn, 0, text);
        }
        let txn = doc.transact();
        txn.encode_state_as_update_v1(&yrs::StateVector::default())
    }

    #[test]
    fn valid_update_is_accepted() {
        let update = make_valid_update("hello world");
        assert!(is_update_bytes_safe(&update), "a real yrs update must pass");
    }

    #[test]
    fn valid_update_with_multibyte_utf8_is_accepted() {
        // Multi-byte string content (é, emoji, CJK) must still validate — the checked
        // from_utf8 accepts well-formed multi-byte sequences.
        let update = make_valid_update("café 🦀 日本語");
        assert!(is_update_bytes_safe(&update));
    }

    #[test]
    fn accepted_update_actually_decodes() {
        // Cross-check: anything we accept must really be decodable by yrs (no false
        // accept that decode_v1 would then choke on).
        let update = make_valid_update("round trip");
        assert!(is_update_bytes_safe(&update));
        let decoded = yrs::Update::decode_v1(&update);
        assert!(decoded.is_ok());
        // And applying it reproduces the text.
        let doc = Doc::new();
        let _txt = doc.get_or_insert_text("content");
        {
            let mut txn = doc.transact_mut();
            txn.apply_update(decoded.expect("decoded above"))
                .expect("apply");
        }
        let txt = doc.get_or_insert_text("content");
        let txn = doc.transact();
        assert_eq!(txt.get_string(&txn), "round trip");
    }

    #[test]
    fn empty_input_is_rejected_without_panic() {
        // Zero bytes: read_var for clients_len fails ⇒ reject (never panic).
        assert!(!is_update_bytes_safe(&[]));
    }

    #[test]
    fn garbage_is_rejected_without_panic() {
        // Random/garbage bytes must reject cleanly.
        assert!(!is_update_bytes_safe(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));
        assert!(!is_update_bytes_safe(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80]));
        assert!(!is_update_bytes_safe(&[0x42]));
    }

    #[test]
    fn truncated_update_is_rejected() {
        // Take a valid update and lop off the tail: the walk runs out of buffer and
        // the bounds-checked cursor returns an error ⇒ reject (no over-read).
        let update = make_valid_update("some content here");
        assert!(update.len() > 4);
        for cut in 1..update.len() {
            let truncated = &update[..cut];
            assert!(
                !is_update_bytes_safe(truncated),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        // A valid update with extra bytes appended: the trailing-bytes guard rejects.
        let mut update = make_valid_update("trailing test");
        update.extend_from_slice(&[0x00, 0x01, 0x02]);
        assert!(!is_update_bytes_safe(&update));
    }

    #[test]
    fn over_long_string_length_is_rejected() {
        // A hand-built update whose String content claims a huge length: the cursor's
        // read_exact sees length > remaining buffer ⇒ EndOfBuffer ⇒ reject. No alloc,
        // no over-read, no panic.
        // clients_len=1, blocks_len=1, client=0, clock=0,
        // info=BLOCK_ITEM_STRING (no origin/parent bits, cant_copy_parent_info=true)
        //   ⇒ parent_info varint=0 ⇒ TypePtr::ID ⇒ read_id (client+clock).
        // Then content STRING: a string with an absurd length prefix.
        let mut update: Vec<u8> = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(BLOCK_ITEM_STRING); // info (low nibble 4, no high bits)
        update.push(0); // parent_info varint = 0 ⇒ TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        // String content length: 0xFFFFFFFF as a u32 varint.
        update.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x0F]);
        update.push(0x41); // a single byte of "content" — far short of the claim.
        assert!(!is_update_bytes_safe(&update));
    }

    /// CORE REGRESSION TEST. Craft an update that is structurally well-formed per the
    /// v1 grammar but whose String content field carries INVALID UTF-8. This is the
    /// exact input that would make `decode_v1`'s `from_utf8_unchecked` construct a
    /// `&str` over invalid bytes (UB / process abort). The validator MUST reject it.
    ///
    /// Per the prior de-flake lesson, the invalid sequence is a TWO-byte sequence
    /// `[0xC3, 0x28]` (a lead byte 0xC3 followed by 0x28, which is not a valid UTF-8
    /// continuation byte) placed inside an explicitly-built string — NOT a single
    /// stray byte that could collide with random client-id bytes.
    #[test]
    fn string_field_with_invalid_utf8_is_rejected() {
        // Hand-build: clients_len=1, blocks_len=1, client=0, clock=0,
        // info=BLOCK_ITEM_STRING, parent_info=0 (TypePtr::ID), parent id (0,0),
        // then String content = len-prefixed bytes that are invalid UTF-8.
        let invalid_utf8: &[u8] = &[0xC3, 0x28]; // classic invalid 2-byte sequence
        let mut update: Vec<u8> = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // start clock
        update.push(BLOCK_ITEM_STRING); // info
        update.push(0); // parent_info = 0 ⇒ TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        update.push(invalid_utf8.len() as u8); // string length varint (= 2)
        update.extend_from_slice(invalid_utf8); // the invalid bytes
        // A (possibly empty) delete set so the structure can complete; even if it
        // can't, the invalid-UTF-8 reject fires first.
        update.push(0); // delete set client_len = 0

        // The validator rejects on InvalidUtf8 — the whole point.
        assert!(
            !is_update_bytes_safe(&update),
            "an embedded invalid-UTF-8 string MUST be rejected (the core UB guard)"
        );
    }

    /// A second invalid-UTF-8 placement, this time inside the JSON content array,
    /// using `[0xE9, 0x80]` (incomplete 3-byte sequence). Confirms the check fires on
    /// every read_string site, not just the simple String content.
    #[test]
    fn json_field_with_invalid_utf8_is_rejected() {
        let invalid_utf8: &[u8] = &[0xE9, 0x80]; // truncated 3-byte lead
        let mut update: Vec<u8> = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(BLOCK_ITEM_JSON); // info (low nibble 2)
        update.push(0); // parent_info = 0 ⇒ TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        update.push(0); // JSON read_len = 0 ⇒ loop runs 0..=0 i.e. one string
        update.push(invalid_utf8.len() as u8); // string length = 2
        update.extend_from_slice(invalid_utf8);
        update.push(0); // delete set client_len = 0
        assert!(!is_update_bytes_safe(&update));
    }

    /// Sanity: the SAME hand-built frame but with VALID UTF-8 in the string is
    /// accepted — proving the rejection above is due to the UTF-8 content and not the
    /// hand-built framing itself.
    #[test]
    fn hand_built_frame_with_valid_utf8_string_is_accepted() {
        let valid_utf8: &[u8] = b"ok"; // valid UTF-8
        let mut update: Vec<u8> = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(BLOCK_ITEM_STRING); // info
        update.push(0); // parent_info = 0 ⇒ TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        update.push(valid_utf8.len() as u8); // string length = 2
        update.extend_from_slice(valid_utf8);
        update.push(0); // delete set client_len = 0
        assert!(
            is_update_bytes_safe(&update),
            "the same frame with valid UTF-8 must be accepted (isolates the UTF-8 check)"
        );
    }

    #[test]
    fn deeply_nested_any_is_rejected_without_stack_overflow() {
        // Build a DOC-content block whose options Any is an array nested far beyond
        // MAX_ANY_DEPTH. The depth guard rejects before recursion blows the stack.
        let mut update: Vec<u8> = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(BLOCK_ITEM_DOC); // info (low nibble 9)
        update.push(0); // parent_info = 0 ⇒ TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        // Doc options: guid string (empty), then a deeply nested Any array.
        update.push(0); // guid length = 0 (empty string, valid UTF-8)
        for _ in 0..(MAX_ANY_DEPTH + 50) {
            update.push(117); // Any::Array tag
            update.push(1); // array len = 1 (one nested element)
        }
        update.push(126); // innermost Any::Null
        assert!(!is_update_bytes_safe(&update));
    }

    #[test]
    fn empty_document_update_agrees_with_decode() {
        // An update from an untouched doc is still a (near-empty) update. Whatever its
        // bytes are, validating must not panic and must agree with decode_v1.
        let doc = Doc::new();
        let _txt = doc.get_or_insert_text("content");
        let txn = doc.transact();
        let update = txn.encode_state_as_update_v1(&yrs::StateVector::default());
        let safe = is_update_bytes_safe(&update);
        let decodes = yrs::Update::decode_v1(&update).is_ok();
        assert_eq!(
            safe, decodes,
            "validator must agree with decode_v1 on empty doc"
        );
    }

    /// F3 LOCKED ASSUMPTION TEST. The validator's grammar is pinned to the v1
    /// wire format under default yrs features. A transitive feature flip
    /// (`small-client`/`weak`) or a v2 decode path on `/collab` cannot be seen by
    /// a `cfg` on our own crate features, so this runtime test is the backstop:
    /// it locks in that a real, default-feature yrs document still encodes to a
    /// **v1** update that this validator accepts AND that `decode_v1` consumes.
    /// If yrs's wire format or default features ever change underneath us so that
    /// this no longer holds, this test fails loudly — pointing at the residual
    /// note — rather than the guard being silently bypassed at runtime.
    #[test]
    fn decode_path_assumptions_hold() {
        // A document touching String, Map and nested content exercises the
        // string/block grammar this walk mirrors.
        let doc = Doc::new();
        let txt = doc.get_or_insert_text("content");
        let map = doc.get_or_insert_map("meta");
        {
            use yrs::Map;
            let mut txn = doc.transact_mut();
            txt.insert(&mut txn, 0, "locked v1 assumption");
            map.insert(&mut txn, "k", "v");
        }
        let txn = doc.transact();
        let update = txn.encode_state_as_update_v1(&yrs::StateVector::default());

        // 1. The validator accepts the v1 update produced by default-feature yrs.
        assert!(
            is_update_bytes_safe(&update),
            "default-feature yrs v1 update must still validate; if this fails the \
             wire format/features changed — revisit the validate.rs grammar walk"
        );

        // 2. And `decode_v1` actually consumes exactly what we accept (no drift
        //    between the validator's v1 walk and yrs's v1 decoder).
        let decoded = yrs::Update::decode_v1(&update);
        assert!(
            decoded.is_ok(),
            "the v1 update we accepted must decode via decode_v1 (v1 path locked)"
        );

        // 3. The same bytes must NOT decode as v2 — proof we are genuinely on the
        //    v1 path the grammar assumes, not a v2 format that has its own
        //    (out-of-scope) unchecked-UTF-8 site. If a future yrs makes v1==v2
        //    here, the assumption note must be revisited.
        assert!(
            yrs::Update::decode_v2(&update).is_err(),
            "a v1-encoded update must not also decode as v2 — confirms v1 wire format"
        );
    }

    #[cfg(feature = "base64")]
    #[test]
    fn base64_entry_point_round_trips_and_rejects_garbage() {
        use base64::Engine as _;
        let update = make_valid_update("b64 path");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&update);
        assert!(
            is_update_b64_safe(&b64),
            "valid update, base64-encoded, accepted"
        );
        assert!(
            !is_update_b64_safe("not valid base64!!!"),
            "bad base64 rejected"
        );
        assert!(!is_update_b64_safe(""), "empty string rejected");
    }

    // --- additional adversarial cases -----------------------------------------

    /// Helper: build the common prefix for a single-block frame with no origin
    /// bits (cant_copy_parent_info=true) and a TypePtr::ID parent (parent_info=0).
    /// Returns a Vec<u8> covering: clients_len=1, blocks_len=1, client=0,
    /// clock=0, info byte, parent_info=0, parent id client=0, parent id clock=0.
    fn single_block_prefix(info: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // clients_len
        v.push(1); // blocks_len
        v.push(0); // client (u64 varint)
        v.push(0); // start clock (u32 varint)
        v.push(info); // info byte
        v.push(0); // parent_info = 0 → TypePtr::ID
        v.push(0); // parent id client
        v.push(0); // parent id clock
        v
    }

    /// Append a length-prefixed byte string to a buffer.
    fn push_string(v: &mut Vec<u8>, bytes: &[u8]) {
        // Length as a varint (u32); for test sizes (<128) a single byte suffices.
        assert!(bytes.len() < 128, "test helper only handles short strings");
        v.push(bytes.len() as u8);
        v.extend_from_slice(bytes);
    }

    #[test]
    fn format_block_invalid_utf8_in_key() {
        // FORMAT block (info & 0xf == 6 = BLOCK_ITEM_FORMAT): two strings — key
        // then value. The key carries invalid UTF-8; must reject.
        let invalid_key: &[u8] = &[0xFE, 0x80]; // invalid UTF-8
        let valid_val: &[u8] = b"true";
        let mut update = single_block_prefix(BLOCK_ITEM_FORMAT);
        push_string(&mut update, invalid_key);
        push_string(&mut update, valid_val);
        update.push(0); // delete set client_len=0
        assert!(
            !is_update_bytes_safe(&update),
            "FORMAT block with invalid UTF-8 key must be rejected"
        );
    }

    #[test]
    fn format_block_invalid_utf8_in_value() {
        // FORMAT block: valid UTF-8 key, invalid UTF-8 value. Both read_string
        // sites must be checked; this confirms the second one fires.
        let valid_key: &[u8] = b"bold";
        let invalid_val: &[u8] = &[0xFE, 0x80];
        let mut update = single_block_prefix(BLOCK_ITEM_FORMAT);
        push_string(&mut update, valid_key);
        push_string(&mut update, invalid_val);
        update.push(0); // delete set client_len=0
        assert!(
            !is_update_bytes_safe(&update),
            "FORMAT block with invalid UTF-8 value must be rejected"
        );
    }

    #[test]
    fn embed_block_invalid_utf8() {
        // EMBED block (info & 0xf == 5 = BLOCK_ITEM_EMBED): a single string field
        // (the JSON embed). Invalid UTF-8 must be rejected.
        let invalid: &[u8] = &[0xC0, 0x80]; // overlong NUL — invalid UTF-8
        let mut update = single_block_prefix(BLOCK_ITEM_EMBED);
        push_string(&mut update, invalid);
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "EMBED block with invalid UTF-8 must be rejected"
        );
    }

    #[test]
    fn type_ref_xml_element_invalid_utf8() {
        // TYPE block (BLOCK_ITEM_TYPE = 7) with type_ref = TYPE_REFS_XML_ELEMENT
        // (3): that branch calls read_string for the element tag name.
        // Surrogate-half bytes are invalid UTF-8.
        let invalid_tag: &[u8] = &[0xED, 0xA0, 0x80]; // lone surrogate half
        let mut update = single_block_prefix(BLOCK_ITEM_TYPE);
        update.push(TYPE_REFS_XML_ELEMENT); // type_ref byte
        push_string(&mut update, invalid_tag);
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "TYPE block XmlElement with invalid UTF-8 tag must be rejected"
        );
    }

    #[test]
    fn type_ref_unknown_tag_rejected() {
        // TYPE block with a type_ref not in {0,1,2,3,4,5,6,9,15} — maps to
        // BadTag and must be rejected.
        let mut update = single_block_prefix(BLOCK_ITEM_TYPE);
        update.push(8); // 8 is not a valid type_ref (TYPE_REFS_WEAK forbidden)
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "TYPE block with unknown type_ref must be rejected"
        );
    }

    #[test]
    fn doc_block_invalid_utf8_guid() {
        // DOC block (BLOCK_ITEM_DOC = 9): first field is the guid string, then an
        // Any value. Invalid UTF-8 in the guid must be rejected.
        let invalid_guid: &[u8] = &[0xC3, 0x28];
        let mut update = single_block_prefix(BLOCK_ITEM_DOC);
        push_string(&mut update, invalid_guid);
        // Any value would follow but the reject fires before we get there.
        update.push(0); // delete set (update is already malformed before this)
        assert!(
            !is_update_bytes_safe(&update),
            "DOC block with invalid UTF-8 guid must be rejected"
        );
    }

    #[test]
    fn named_parent_invalid_utf8() {
        // Block with cant_copy_parent_info=true (no HAS_ORIGIN or HAS_RIGHT_ORIGIN
        // bits) and parent_info=1 (→ TypePtr::Named → a string). The named-parent
        // string carries invalid UTF-8; must reject.
        //
        // info = BLOCK_ITEM_DELETED (1, no high bits) so content is just one varint.
        let invalid_name: &[u8] = &[0xC3, 0x28];
        let mut update = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(BLOCK_ITEM_DELETED); // info (1, no origin bits)
        update.push(1); // parent_info = 1 → TypePtr::Named → read_string
        push_string(&mut update, invalid_name);
        // If we got past the named-parent string, content would follow; but reject
        // fires first. Push a delete set anyway so the frame looks structurally
        // complete if the string were valid.
        update.push(1); // content len (DELETED content)
        update.push(0); // delete set client_len=0
        assert!(
            !is_update_bytes_safe(&update),
            "named parent string with invalid UTF-8 must be rejected"
        );
    }

    #[test]
    fn parent_sub_invalid_utf8() {
        // Block with HAS_PARENT_SUB set and no origin bits (cant_copy_parent_info=
        // true). After the TypePtr::ID parent, the parent_sub key string is read.
        // Invalid UTF-8 there must be rejected.
        //
        // info = BLOCK_ITEM_DELETED | HAS_PARENT_SUB = 0x01 | 0x20 = 0x21.
        let invalid_sub: &[u8] = &[0xC3, 0x28];
        let mut update = Vec::new();
        update.push(1); // clients_len
        update.push(1); // blocks_len
        update.push(0); // client
        update.push(0); // clock
        update.push(0x21); // info: DELETED | HAS_PARENT_SUB, no origin bits
        update.push(0); // parent_info = 0 → TypePtr::ID
        update.push(0); // parent id client
        update.push(0); // parent id clock
        push_string(&mut update, invalid_sub); // parent_sub (HAS_PARENT_SUB)
        update.push(1); // DELETED content len
        update.push(0); // delete set client_len=0
        assert!(
            !is_update_bytes_safe(&update),
            "parent_sub with invalid UTF-8 must be rejected"
        );
    }

    #[test]
    fn any_map_key_invalid_utf8() {
        // ANY block (BLOCK_ITEM_ANY = 8): one Map Any (tag=118) with one entry
        // whose key carries invalid UTF-8. Must reject.
        let invalid_key: &[u8] = &[0xC3, 0x28];
        let mut update = single_block_prefix(BLOCK_ITEM_ANY);
        update.push(1); // ANY len = 1 element
        update.push(118); // Any tag: Map
        update.push(1); // map len = 1 entry
        push_string(&mut update, invalid_key); // map key
        // map value would follow if key were valid; reject fires first.
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "Any map key with invalid UTF-8 must be rejected"
        );
    }

    #[test]
    fn any_string_invalid_utf8() {
        // ANY block with a string Any (tag=119): the string carries invalid UTF-8.
        let invalid: &[u8] = &[0xC3, 0x28];
        let mut update = single_block_prefix(BLOCK_ITEM_ANY);
        update.push(1); // ANY len = 1
        update.push(119); // Any tag: string
        push_string(&mut update, invalid);
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "Any string with invalid UTF-8 must be rejected"
        );
    }

    #[test]
    fn binary_block_accepts_non_utf8_bytes() {
        // BINARY block (BLOCK_ITEM_BINARY = 3): arbitrary bytes with no UTF-8
        // requirement. An update whose binary payload contains all-0xFF bytes
        // must be ACCEPTED — the validator must not over-reject non-UTF-8 content
        // in fields that have no UTF-8 invariant.
        let arbitrary_bytes: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        let mut update = single_block_prefix(BLOCK_ITEM_BINARY);
        push_string(&mut update, arbitrary_bytes); // read_buf: length-prefixed, no UTF-8 check
        update.push(0);
        assert!(
            is_update_bytes_safe(&update),
            "BINARY block with non-UTF-8 bytes must be accepted (no UTF-8 requirement)"
        );
    }

    #[test]
    fn multiple_blocks_second_has_invalid_utf8() {
        // Two blocks: first STRING block is well-formed, second STRING block
        // carries invalid UTF-8. The rejection must propagate from the second block.
        let valid: &[u8] = b"ok";
        let invalid: &[u8] = &[0xC3, 0x28];
        let mut update = Vec::new();
        update.push(1); // clients_len = 1
        update.push(2); // blocks_len = 2
        update.push(0); // client
        update.push(0); // clock
        // Block 1: STRING, parent_info=0→ID
        update.push(BLOCK_ITEM_STRING);
        update.push(0); // parent_info
        update.push(0); // parent id client
        update.push(0); // parent id clock
        push_string(&mut update, valid);
        // Block 2: STRING, parent_info=0→ID, invalid UTF-8
        update.push(BLOCK_ITEM_STRING);
        update.push(0);
        update.push(0);
        update.push(0);
        push_string(&mut update, invalid);
        update.push(0); // delete set client_len=0
        assert!(
            !is_update_bytes_safe(&update),
            "second block with invalid UTF-8 must cause overall rejection"
        );
    }

    #[test]
    fn delete_set_truncation_rejected() {
        // A frame with zero blocks (clients_len=0 for the block section) followed
        // by a delete set that claims 10 id-ranges but provides only 1 byte.
        // The cursor's read_var hits end-of-buffer → reject (no over-read).
        let mut update = Vec::new();
        update.push(0); // clients_len = 0 (no blocks)
        // Delete set:
        update.push(1); // client_len = 1
        update.push(42); // client id (varint u64 = 42)
        update.push(10); // range_len = 10 (claims 10 (clock, range_len) pairs)
        update.push(7); // only one byte of data — far short of 10 pairs
        assert!(
            !is_update_bytes_safe(&update),
            "truncated delete set must be rejected"
        );
    }

    #[test]
    fn unknown_any_tag_rejected() {
        // ANY block containing an Any value whose tag byte (100) is not in the
        // defined set (116-127). Must reject with BadTag.
        let mut update = single_block_prefix(BLOCK_ITEM_ANY);
        update.push(1); // ANY len = 1
        update.push(100); // unknown Any tag
        update.push(0);
        assert!(
            !is_update_bytes_safe(&update),
            "unknown Any tag must be rejected"
        );
    }
}
