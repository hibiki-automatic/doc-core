//! `doc-core`: the **web-free** document / CRDT kernel (ADR-0008 Phase 1).
//!
//! Everything here touches only `yrs`, `similar`, and (behind the `watch`
//! feature) `notify` — there is **zero** warp/tokio/hyper/web dependency, by
//! design and verified by CI (`cargo tree -p doc-core -e normal` must show no web
//! crates). Two downstream reuse goals depend on that purity:
//!   * the LAN/WAN collaboration relay (D2) reuses the [`collab`] wire codec
//!     without the daemon's websocket pump;
//!   * research-thin-server (D1) reuses [`file_peer::FilePeer`] for granular
//!     file-backed CRDT editing without the web stack.
//!
//! ## Modules
//! - [`doc`] — the [`doc::DocSession`] contract (the "plane of separation").
//! - [`session`] — [`session::YrsSession`], the `yrs` implementation. **`!Send`**:
//!   the doc must stay on a single thread; this invariant propagates to
//!   [`file_peer::FilePeer`] and any relay wrapper (a cross-crate kernel
//!   constraint, ADR-0008 Phase 1).
//! - [`diff`] — the char-level file→session diff bridge.
//! - [`validate`] — the pre-decode yrs UB / remote-DoS guard for `/collab`.
//! - [`collab`] — the transport-agnostic y-websocket wire codec + apply funnel.
//! - [`file_peer`] — the on-disk file ↔ session bridge (`watch` feature for the
//!   `notify` filewatcher). The confinement-aware write-back (`write_within`)
//!   deliberately stays in the daemon: doc-core has NO dependency on the
//!   confinement funnel (`fs-confine`), keeping the kernels free of inter-kernel
//!   edges (ADR-0008 acyclic DAG). The daemon does the confinement and drives the
//!   peer through doc-core's public API.

pub mod collab;
pub mod diff;
pub mod doc;
pub mod file_peer;
pub mod session;
pub mod validate;
