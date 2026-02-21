# pleme-auth-sessions

pleme-auth-sessions library

## Installation

```toml
[dependencies]
pleme-auth-sessions = "0.1"
```

## Usage

```rust
use pleme_auth_sessions::{SessionManager, SessionConfig};

let sessions = SessionManager::new(redis_conn, SessionConfig::default());
let session = sessions.create(user_id, device_fingerprint).await?;
let valid = sessions.validate(&session.token).await?;
```

## Development

This project uses [Nix](https://nixos.org/) for reproducible builds:

```bash
nix develop            # Dev shell with Rust toolchain
nix run .#check-all    # cargo fmt + clippy + test
nix run .#publish      # Publish to crates.io (--dry-run supported)
nix run .#regenerate   # Regenerate Cargo.nix
```

## License

MIT - see [LICENSE](LICENSE) for details.
