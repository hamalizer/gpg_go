# gpg-go

GPG that doesn't suck. A complete OpenPGP implementation rewritten from scratch in Go.

Full CLI + full GUI + cross-platform + modern crypto. No C, no legacy baggage, no bullshit.

## Features

- **Full OpenPGP** - Encrypt, decrypt, sign, verify, key management (RFC 4880 / RFC 9580)
- **Modern Algorithms** - Ed25519/X25519 (default), RSA-2048/3072/4096, AES-256, SHA-256
- **CLI** - Drop-in replacement workflow for GPG with a clean cobra-based interface
- **GUI** - Full Fyne-based graphical suite (keys, encrypt/decrypt, sign/verify, keyserver, settings)
- **Keyserver Support** - HKP protocol (search, send, receive keys)
- **Cross-Platform** - Linux, macOS, Windows, FreeBSD, OpenBSD - one codebase
- **Man Pages** - Proper `man gpg-go` and `man gpg-go-gui` documentation

## Install

```bash
# Build from source
make build

# Install system-wide (includes man pages)
sudo make install

# Or just build what you need
make cli    # CLI only (no CGO needed)
make gui    # GUI (needs OpenGL dev libs)
```

### Build Dependencies

- Go 1.22+
- GUI only: `libgl-dev`, `xorg-dev` (Linux), Xcode (macOS)

## Quick Start

```bash
# Generate a key (Ed25519 by default - fast, modern, secure)
gpg-go generate --quick --name "Your Name" --email "you@example.com"

# Or RSA-4096 if you need legacy compatibility
gpg-go generate --quick --name "Your Name" --email "you@example.com" --algo rsa4096

# List your keys
gpg-go list-keys

# Encrypt for someone
gpg-go encrypt -a -r recipient@example.com -o message.asc plaintext.txt

# Decrypt
gpg-go decrypt message.asc

# Sign a file (detached, armored)
gpg-go sign -a -b document.pdf -o document.pdf.sig

# Verify a signature
gpg-go verify document.pdf.sig document.pdf

# Search a keyserver
gpg-go search-keys someone@example.com

# Fetch a key from keyserver
gpg-go recv-keys ABCD1234

# Export your public key
gpg-go export you@example.com

# Launch the GUI
gpg-go-gui
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `generate` | Generate a new key pair (Ed25519, RSA) |
| `list-keys` | List public keys |
| `list-secret-keys` | List secret keys |
| `encrypt` | Encrypt file/stdin (public-key or symmetric) |
| `decrypt` | Decrypt file/stdin |
| `sign` | Sign (detached, clear-text, or inline) |
| `verify` | Verify signatures |
| `import` | Import keys from file |
| `export` | Export keys (public or secret) |
| `delete` | Delete keys |
| `fingerprint` | Show key fingerprints |
| `search-keys` | Search HKP keyservers |
| `recv-keys` | Download keys from keyserver |
| `send-keys` | Upload keys to keyserver |

## GUI

The GUI (`gpg-go-gui`) provides a tabbed interface:

- **Keys** - Full key management (generate, import, export, delete, details)
- **Encrypt / Decrypt** - Public-key and symmetric encryption/decryption
- **Sign / Verify** - Create and verify digital signatures
- **Keyserver** - Search, send, receive, and refresh keys
- **Settings** - Configure keyserver, theme (light/dark), view paths

## Architecture

```
cmd/gpg-go/          CLI entrypoint
cmd/gpg-go-gui/      GUI entrypoint
internal/config/     Configuration & paths
internal/keyring/    Key storage & management
internal/crypto/     OpenPGP operations (keygen, encrypt, decrypt, sign, verify)
internal/keyserver/  HKP keyserver client
cli/                 Cobra command definitions
gui/                 Fyne GUI implementation
man/                 Man pages (troff)
```

### Tech Stack

| Component | Library |
|-----------|---------|
| Crypto | [ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto) (maintained x/crypto fork, RFC 9580) |
| CLI | [spf13/cobra](https://github.com/spf13/cobra) |
| GUI | [Fyne](https://fyne.io/) (OpenGL, cross-platform) |
| Build | Makefile + [GoReleaser](https://goreleaser.com/) |
| CI | GitHub Actions (Linux, macOS, Windows) |

## Cross-Platform Builds

```bash
make build-all        # Build for all platforms
make build-linux      # Linux amd64 + arm64
make build-darwin     # macOS amd64 + arm64 (Apple Silicon)
make build-windows    # Windows amd64
```

Automated releases via GoReleaser on git tags:
```bash
git tag v0.1.0
git push --tags
```

## Compatibility

gpg-go implements OpenPGP (RFC 4880 / RFC 9580) and is interoperable with:
- GnuPG
- Sequoia-PGP
- OpenPGP.js
- Any RFC-compliant implementation

## License

MIT
