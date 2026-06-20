# doc-core

[![CI](https://github.com/hibiki-automatic/doc-core/actions/workflows/ci.yml/badge.svg)](https://github.com/hibiki-automatic/doc-core/actions/workflows/ci.yml)

`doc-core` is the **web-free document / CRDT kernel** extracted from the mycelium editor stack. It holds the CRDT document model (`DocSession` / `YrsSession`), the file-session diff bridge, the y-protocols wire codec, the yrs UB pre-decode validator, and the `FilePeer` file bridge — all deliberately free of any web or async dependency (no warp, tokio, hyper, ureq, sha2). The clean dependency boundary lets downstream consumers (`research-thin-server`, the D2 relay) pull in exactly the CRDT / file-sync logic they need without touching the web stack. Verify this invariant with `cargo tree -p doc-core -e normal`.

## Build

```bash
cargo build                        # default features (includes notify filewatcher)
cargo build --no-default-features  # minimal: no filewatcher (web-free invariant check)
cargo test
cargo clippy --all-targets -- -D warnings
```

Requires stable Rust (edition 2024). No system dependencies beyond the Rust toolchain.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `watch` | yes | `notify`-backed filewatcher for `FilePeer::watch`/`run` |
| `base64` | no | `is_update_b64_safe` entry point for the UB validator |
| `yrs-small-client` | no | Compile-error interlock — do not enable |
| `yrs-weak` | no | Compile-error interlock — do not enable |
| `yrs-v2-collab` | no | Compile-error interlock — do not enable |

The `yrs-*` interlock features exist to make a silent yrs grammar bypass impossible: enabling any of them is a `compile_error!` in `validate.rs` until the UB guard grammar is revisited.

## Modules

- `doc` — the `DocSession` contract (the plane of separation)
- `session` — `YrsSession`, the `yrs` implementation (`!Send`)
- `diff` — char-level file-to-session diff bridge
- `validate` — pre-decode yrs UB / remote-DoS guard
- `collab` — transport-agnostic y-websocket wire codec + apply funnel
- `file_peer` — on-disk file / session bridge (`watch` feature for the notify filewatcher)

## Part of the [mycelium](https://github.com/hibiki-automatic) ecosystem

| Repo | Description |
|------|-------------|
| [md-render](https://github.com/hibiki-automatic/md-render) | Markdown → HTML renderer (Rust crate) |
| [doc-core](https://github.com/hibiki-automatic/doc-core) | Web-free CRDT / document kernel (this repo) |
| [fs-confine](https://github.com/hibiki-automatic/fs-confine) | Web-free filesystem confinement kernel |
| [md-preview](https://github.com/hibiki-automatic/md-preview) | Collaborative Markdown preview daemon |
| [mycelium-editor](https://github.com/hibiki-automatic/mycelium-editor) | CodeMirror 6 editor component (npm) |
| [nvim-md-preview](https://github.com/hibiki-automatic/nvim-md-preview) | Neovim live-preview plugin |
| [md-hub](https://github.com/hibiki-automatic/research-thin-server) | Research document hub (Axum server) |
