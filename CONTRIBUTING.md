# Contributing

We welcome contributions to URT Executor.

## Getting Started

```bash
# Clone and build
git clone https://github.com/Unified-Projects/unified-runtimes.git
cd unified-runtimes
cargo build

# Run tests
cargo test

# Format and lint
cargo fmt
cargo clippy
```

## Refreshing the runtime table

`crates/urt-executor/src/config.rs` holds `OFFICIAL_RUNTIMES`, the static list
of OpenRuntimes families and their published `v5` tags. It is verified by hand
against Docker Hub; the date is in the comment above the constant.

```bash
python scripts/refresh-runtime-table.py          # prints the Rust constant
python scripts/refresh-runtime-table.py --json   # prints the raw tag data
```

Paste the output over the existing constant, then cross-check the version lists
against `ci/runtimes.toml` in `open-runtimes/open-runtimes`:

```bash
gh api repos/open-runtimes/open-runtimes/contents/ci/runtimes.toml \
  --jq .content | base64 -d
```

Docker Hub keeps tags for versions that upstream has since dropped, so the two
lists do not have to agree exactly; the table records what is pullable. Run
`cargo test -p urt-executor` afterwards: the table integrity test catches
malformed or misordered versions.

## Pull Requests

1. Fork the repository and create a branch from `dev`
2. Make your changes
3. Ensure tests pass and code is formatted
4. Submit a pull request against `dev`

## Reporting Issues

- Check existing issues before creating a new one
- Include steps to reproduce, expected vs actual behavior, and environment details

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
