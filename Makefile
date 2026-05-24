CARGO ?= cargo

.PHONY: build build-release test test-fs lint fmt fmt-check ci bench release patterns-doc clean help

help:
	@echo "Targets:"
	@echo "  build          cargo build"
	@echo "  build-release  cargo build --release"
	@echo "  test           cargo test --all-targets"
	@echo "  test-fs        cargo test --test config_fs (filesystem seam integration)"
	@echo "  lint           cargo clippy --all-targets --all-features -- -D warnings"
	@echo "  fmt            cargo fmt --all"
	@echo "  fmt-check      cargo fmt --all -- --check"
	@echo "  ci             fmt-check + lint + test (run before opening a PR)"
	@echo "  bench          release-build + run the hidden preset-latency benchmark"
	@echo "  release        interactive version bump + CHANGELOG + commit + tag"
	@echo "  patterns-doc   regenerate DETECTION_COVERAGE.md from the live catalog"
	@echo "  clean          cargo clean"

build:
	$(CARGO) build

build-release:
	$(CARGO) build --release

test:
	$(CARGO) test --all-targets

test-fs:
	$(CARGO) test --test config_fs

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

ci: fmt-check lint test

bench:
	$(CARGO) build --release
	./target/release/secret-stripper bench

release:
	@bash scripts/release.sh

patterns-doc:
	$(CARGO) run --quiet --features patterns-doc --bin patterns_doc > DETECTION_COVERAGE.md

clean:
	$(CARGO) clean
