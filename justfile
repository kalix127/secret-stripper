default:
    @just --list

# Full pre-PR chain: format check, lint, tests
ci: fmt-check lint test

build:
    cargo build

build-release:
    cargo build --release

test:
    cargo test --all-targets

# Filesystem seam integration tests (what CI runs on macOS/Windows)
test-fs:
    cargo test --test config_fs

# Clippy with warnings as errors
lint:
    cargo clippy --all-targets --all-features -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Build release binary then run the hidden preset-latency benchmark
bench: build-release
    ./target/release/secret-stripper bench

release:
    bash scripts/release.sh

# Regenerate DETECTION_COVERAGE.md from the live catalog
patterns-doc:
    cargo run --quiet --features patterns-doc --bin patterns_doc > DETECTION_COVERAGE.md

clean:
    cargo clean
