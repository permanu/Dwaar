test:
    cargo test --workspace

test-crate crate='dwaar-config':
    cargo test -p {{crate}}

lint:
    cargo fmt && cargo clippy --workspace -- -D warnings

build-release:
    cargo build --workspace --release

ci: lint test build-release

quick crate='dwaar-config':
    cargo test -p {{crate}} && cargo fmt -p {{crate}} && cargo clippy -p {{crate}} -- -D warnings
