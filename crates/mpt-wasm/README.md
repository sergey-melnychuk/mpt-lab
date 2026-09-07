# mpt-wasm

`wasm-bindgen` glue around [`mpt-core`](../mpt-core), exposing a
JSON-friendly API to two browser demo pages under `www/`. Kept as a separate
crate so `mpt-core` itself stays `no_std` + `alloc`, with no serialization or
wasm dependencies of its own.

## Pages

- **[`www/index.html`](www/index.html) — MPT Explorer.** Fetches a real
  account (and, optionally, storage slots) from a live Ethereum JSON-RPC
  endpoint via `eth_getProof`, reconstructs the account/storage tries from
  that proof witness, and independently re-derives both roots to verify the
  response wasn't tampered with or incomplete. Supports patching storage
  values in place, and shows exactly which node a public RPC can't supply
  when a patch needs one it didn't send.
- **[`www/build.html`](www/build.html) — MPT Builder.** Builds a trie from
  scratch out of a table of hex key/value pairs you type in yourself, with a
  toggle for whether keys get keccak256-hashed first (Ethereum's "secure
  trie" transform) or inserted as raw bytes — a way to build intuition for
  `Fork`/`Skip`/`Leaf` shape without needing real chain data.

Both pages render the trie as an interactive canvas diagram, via the shared
renderer in [`www/tree-view.js`](www/tree-view.js).

## Build & run

```bash
rm -rf www/pkg
wasm-pack build --release --target web --no-typescript --out-dir www/pkg
python3 -m http.server -d www
```

Then open `http://localhost:8000/index.html` or `.../build.html`. Must be
served over HTTP(S), not `file://` — browsers refuse to fetch a wasm module
from a `file:` URL.

## Notes

- `[package.metadata.wasm-pack.profile.release] wasm-opt = false` in
  `Cargo.toml` is required, not optional: the bundled `wasm-opt` mistransforms
  this `wasm-bindgen` version's externref table, and the resulting release
  build fails to instantiate (`WebAssembly.Table.grow(): failed to grow table
  by 4`). Rustc's own release optimizations still apply — only the extra
  `wasm-opt` post-processing pass is skipped.
- `www/index.html`'s default RPC endpoint matters: several public providers
  (publicnode's default endpoint included) reject `eth_getProof` outright on
  their free tier, for every block, with an "Archive requests require a
  personal token" error — separately from the usual pruned-node/old-block
  limitation. The pre-filled default is one that doesn't.

## License

MIT — see [`LICENSE`](../../LICENSE) in the repository root.
