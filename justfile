set positional-arguments

NIGHTLY_VERSION := trim(read(justfile_directory() / "nightly-version"))

_default:
  @just --list

[group('ci')]
check:
    @fmt
    cargo +{{NIGHTLY_VERSION}} clippy --quiet --all-targets --all-features -- --deny warnings

# Quick lint.
@lint:
  cargo +{{NIGHTLY_VERSION}} clippy --quiet --all-targets --all-features -- --deny warnings
  cargo +{{NIGHTLY_VERSION}} fmt -- --check
  ./contrib/check-whitespace.sh

# Format workspace.
@fmt:
  cargo +{{NIGHTLY_VERSION}} fmt --all

# Check formatting (matches pre-commit hook behavior, without --all).
@fmt-check:
  cargo +{{NIGHTLY_VERSION}} fmt -- --check

# Check for unused dependencies.
@udeps:
  cargo +{{NIGHTLY_VERSION}} udeps --all-targets

# Check for broken links.
@link-check:
  @bash -c 'if command -v lychee >/dev/null 2>&1; then lychee .; else echo "Warning: lychee not found. Skipping link check."; echo "Install with: cargo install lychee"; fi'

# Run tests.
test:
  cargo test

# Run security audit.
@audit:
  cargo audit

# Quick sanity check.
[group('ci')]
@sane: lint
  cargo test --quiet --all-targets --no-default-features
  cargo test --quiet --all-targets --all-features

# Generate documentation (accepts cargo doc args, e.g. --open).
@docsrs *flags:
  RUSTDOCFLAGS="--cfg docsrs -D warnings -D rustdoc::broken-intra-doc-links" cargo +{{NIGHTLY_VERSION}} doc --all-features --no-deps {{flags}}

# Check for public API changes.
@api-check:
  ./contrib/check-for-api-changes.sh

# Query the public API (types, types_no_err, traits).
api cmd:
  ./contrib/api.sh {{cmd}}

# Copy git hooks from githooks/ directory.
@hooks:
  ./contrib/copy-githooks.sh

# Setup development environment (install tools, create directories).
@setup:
  ./contrib/setup.sh

# Run pre-commit checks (formatting, linting, link checking).
@pre-commit:
  @fmt
  @lint
  @link-check
