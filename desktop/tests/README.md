# Desktop regressions without Tauri

Use Rust 1.99.0 and Node 24. The harnesses compile production source fragments
or the complete private-file module, without building a Desktop application or
requiring platform UI libraries/signing credentials. Commit their Cargo.lock
files and run with `--locked` so dependency checksums/versions are reproduced.

```bash
cargo run --locked --manifest-path desktop/tests/probe-regression/Cargo.toml
cargo run --locked --manifest-path desktop/tests/native-bridge-regression/Cargo.toml -- /tmp/insellers-bridge-fixture.js
node desktop/tests/native-bridge-regression/bridge-test.cjs /tmp/insellers-bridge-fixture.js
cargo test --locked --manifest-path desktop/tests/private-file-regression/Cargo.toml --lib
```

In the managed workspace used for this audit, Rust was installed outside the
checkout. Set these selectors for the commands above:

```bash
export RUSTUP_HOME=/workspace/.tools/insellers-rustup
export CARGO_HOME=/workspace/.tools/insellers-cargo
export CARGO_TARGET_DIR=/workspace/.cache/insellers-rust-target
export PATH="$CARGO_HOME/bin:$PATH"
```

The probe harness uses local fixture sockets; no live user connections are
changed. The bridge fixture contains synthetic credentials. Private-file tests
write only temporary files. Linux tests do not replace Windows/macOS builds,
WebView/device tests, signed release checks or validation of Windows ACLs.

With Playwright and Chromium installed, use the actual Rust-generated bridge
fixture above for browser-frame checks:

```bash
CHROME_BIN=/usr/bin/chromium node tests/test_native_frame_bootstrap.cjs desktop /tmp/insellers-bridge-fixture.js
```

The Desktop workflow pins Playwright 1.62.1. The generated bridge runs only in a
trusted top document, including when injection targets an opaque same-location
iframe. Same-origin children still have access to their parent: preventing direct
injection is a prerequisite, not full advertisement isolation. All responses and
credentials in this check are synthetic; no production/vendor request is sent.
