# Building Debian packages for rage

## Requirements

```
cargo install cargo-deb
```

## Process

```
cargo run --example generate-completions
cargo run --example generate-docs
cargo deb --package rage
```
