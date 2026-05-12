default:
    @just --list

ci:
    cargo xtask ci

fmt:
    cargo xtask fmt

lint:
    cargo xtask lint

test:
    cargo xtask test

bench:
    cargo xtask bench

doc:
    cargo xtask doc

# Run the CLI on the unhealthy Rust fixture (smoke test).
demo:
    cargo run -p zuit-cli -- analyze fixtures/rust/unhealthy --format terminal
