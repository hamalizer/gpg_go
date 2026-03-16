# Changelog

All notable changes to gpg-go will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Release CI workflow now uses Go 1.24 (was 1.23, mismatched go.mod)

## [0.2.0-canary] - 2026-03-05

### Added
- 122-test integration suite covering crypto, keyring, subkeys, and UIDs
- Integration test script (`release/test.sh`) with filtering and color output
- Subkey rotation: add encryption/signing subkeys with optional expiry
- Multiple UIDs per key: add, deduplicate, with comment support
- Agent functionality for GPG agent protocol
- Git integration and `--json` output for machine-readable output
- Man pages for CLI and GUI (`man/gpg-go.1`, `man/gpg-go-gui.1`)

### Fixed
- All 31 security audit findings from R1 and R2 addressed
- Critical: key expiration logic — keys without `--expire` no longer show as expired
- High: decrypt timing oracle eliminated (single-pass decryption)
- High: binary key import implemented (was armored-only)
- High: upgraded go-crypto v1.1.6 → v1.4.0 (x25519 low-order point rejection)
- Medium: sign command now warns when using default key selection
- Medium: key files use full fingerprint instead of short key ID (collision risk)
- Medium: clearsign verification implemented (was sign-only, broken round-trip)
- Medium: decompression bomb protection via `MaxMessageSize`
- Medium: GUI passphrase handling for sign operations
- Medium: secret key export requires confirmation
- Low: improved UID matching specificity in key lookup

### Changed
- Crypto test suite expanded from 0 to 122 tests
- Polished GUI across all tabs

## [0.1.0] - 2026-03-01

### Added
- Complete OpenPGP implementation in Go wrapping ProtonMail/go-crypto
- CLI with 14 cobra commands: generate, list-keys, list-secret-keys, encrypt, decrypt, sign, verify, import, export, delete, fingerprint, search-keys, recv-keys, send-keys
- Full Fyne-based GUI with 5 tabs: Keys, Encrypt/Decrypt, Sign/Verify, Keyserver, Settings
- Ed25519/X25519 (default) and RSA-2048/3072/4096 key generation
- Public-key and symmetric encryption/decryption
- Detached, inline, and clearsign signature creation
- HKP keyserver protocol (search, send, receive)
- Trust database with trust level management
- Cross-platform build system (Linux, macOS, Windows, FreeBSD, OpenBSD)
- Makefile with build, install, test, lint, and cross-compilation targets
- GoReleaser configuration for automated releases
- GitHub Actions CI (Linux, macOS, Windows matrix)
- Hardcoded SHA-256 and AES-256 — no weak algorithm fallbacks
- File permissions enforced at 0600 for key material
- Thread-safe keyring with sync.RWMutex
