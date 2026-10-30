# Build and run

Prerequisites, building, the gates CI enforces, and running the server. The prebuilt-binary install stays in the README.

## Prerequisites (building from source)
- **Rust 1.95+** (2021 edition). Set by `yara-x` and `wasmtime`, which both
  declare `rust-version = "1.95.0"`; the workspace itself uses nothing newer.
- Node.js 20.19+ or 22.12+ (for the Web UI build; vite 8, plugin-react 6,
  oxlint and jsdom require it)
- System libraries for the default feature set:

  | Library | Feature | Needed for |
  |---|---|---|
  | `libewf` | `e01` | E01/EWF images |
  | `libheif` **≥ 1.19** | `heic` | HEIC/HEIF thumbnails |
  | `libssl` | — | report signing (`openssl-sys`) |
  | `clang` + `libclang` | — | `bindgen`, which generates the libewf FFI |

  ```bash
  # Debian/Ubuntu
  sudo apt install pkg-config clang libclang-dev libewf-dev libheif-dev libssl-dev
  # macOS
  brew install libewf libheif pkg-config
  ```

  `libesedb` (ESE/SRUM) needs no system package: `libesedb-sys` vendors its C
  source. On Debian, note that `libheif` must be **trixie or newer** — bookworm
  ships 1.15.1, which is below what the `heic` feature binds against.

## Building
```bash
git clone https://github.com/conorarmstrong/seance.git
cd seance

# Release build of the seance binary, all default features
cargo build --release -p seance_cli

# Build with no system C libraries at all. Drops four features:
#   e01          E01/EWF images
#   esedb        ESE / SRUM artifacts
#   heic         HEIC/HEIF thumbnails
#   video-thumbs video keyframe thumbnails
cargo build --release -p seance_cli --no-default-features

# Run tests
cargo test --workspace --all-features

# The gates CI enforces. `cargo test` alone passes while these fail.
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo deny check          # licences, advisories, sources
```

Some tests compare Séance against real evidence with published ground truth and
skip when it is absent — see [TESTING.md](TESTING.md) for the
corpus gate, which is built so that a skipped comparison cannot report as a
pass.

`cargo build --workspace` builds `seance_container_e01` as a member in its own
right, so it needs libewf whatever the feature flags say. Add
`--exclude seance_container_e01` to build the workspace without it.

## Running

```bash
# Build the Web UI once (served by the server from frontend/dist)
npm --prefix frontend install
npm --prefix frontend run build

# Start the server with the Web UI (default: http://127.0.0.1:8080)
cargo run --bin seance

# API only, no Web UI
cargo run --bin seance -- --headless

# Start with the REPL interface
cargo run --bin seance -- --interactive

# Scan a single file (batch mode)
cargo run --bin seance -- scan --path /path/to/evidence.E01

# Set log verbosity (1=WARN, 2=INFO, 3=DEBUG, 4=TRACE)
cargo run --bin seance -- -l 3
```
