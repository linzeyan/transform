# Transform (Rust WASM Playground)

A lightweight Rust/WebAssembly rewrite of the original `transform-go` toolbox. It provides a browser UI (`www/`) backed entirely by the `wasm_core` crate compiled to WebAssembly. Current features include:

- UUID & ULID generation (v1-v8, GUID uppercase)
- User-Agent catalog with quick filtering
- Base encoders/decoders + hash digests
- URL & JWT encode/decode helpers
- Number-base converter, IPv4 calculator
- JSON ⇄ YAML/TOML/XML/JSON Schema/Go Struct conversions
- Markdown ⇄ HTML pair tool driven by the wasm module

## Project layout

```
transform/
├── Makefile             # convenience tasks (fmt, lint, build)
├── wasm_core/           # Rust crate compiled to WebAssembly
└── www/                 # static frontend (vanilla JS + CSS)
```

## Prerequisites

- Rust toolchain (1.78+ recommended) with `wasm32-unknown-unknown` target
- `wasm-pack` in `PATH` for `make build`
- Node/npm (only if you plan to serve `www/` via your own dev server)

Install requirements:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack # if not already installed
```

## Common tasks

```bash
make fmt          # cargo fmt on wasm_core
make lint         # cargo clippy -D warnings (passes after this change)
make build        # wasm-pack build --target web --out-dir www/pkg
make serve        # simple static dev server for www/ (see Makefile)
```

You can also run tests directly:

```bash
cd wasm_core
cargo test
```

## Running locally

1. Build the wasm bundle:
   ```bash
   make build
   ```
2. Serve the `www/` directory (use `make serve` or your own static server).
3. Visit `http://localhost:3000` (default from the Makefile server) to use the tools.

## Continuous integration

GitHub Actions (`.github/workflows/ci.yml`) ensures formatting, linting, and tests stay green on every push/PR.
