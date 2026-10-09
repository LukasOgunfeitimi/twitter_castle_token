# x-web-wreq-client

Standalone Rust client for the local X web login flow. It generates transaction
and protection tokens natively and does not launch a browser or JavaScript
runtime.

## Build

```powershell
cargo build --release
```

## Run

```powershell
$env:X_USERNAME = "your_username"
$env:X_PASSWORD = "your_password"
cargo run --release
```

Credentials can also be passed as the first two arguments. Optional trailing
arguments are `web_url jf_url api_url`. Only localhost targets are accepted.

## Check

```powershell
cargo fmt -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```
