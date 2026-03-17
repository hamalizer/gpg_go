# Changelog

All notable changes to gpg-go will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Release CI workflow now uses Go 1.24 (was 1.23, mismatched go.mod)

### Changed
- README: Go version requirement corrected from 1.22+ to 1.24+

## [0.2.0-canary] - 2026-03-05

### Added
- 122-test integration suite covering crypto, keyring, subkeys, and UIDs
- Integration test script (`release/test.sh`) with filtering and color output
- Subkey rotation: add encryption/signing subkeys with optional expiry
- Multiple UIDs per key: add, deduplicate, with comment support
- Agent functionality for GPG agent protocol
- Git integration and `--json` output for machine-readable output
- Man pages for CLI and GUI (`man/gpg-go.1`, `man/gpg-go-gui.1`)
- Binary key import fallback (armored-only → armored + binary)
- Decompression bomb protection via `MaxMessageSize` (256 MB limit on ReadAll)

### Fixed
- **Critical (R0-C1):** Private keys now S2K-encrypted at rest — `SerializePrivate` passes `s2kSerializeConfig()` instead of `nil`
- **Critical (R1-C01):** Key expiration logic — keys without `--expire` no longer show as expired (deduplicated into shared function)
- **High (R0-H3):** Decrypt config now sets `DefaultHash: SHA256, DefaultCipher: AES256` (was empty `packet.Config{}`)
- **High (R0-H4):** golang.org/x/crypto upgraded to v0.48.0 (fixes CVE-2024-45337, CVE-2025-22869, CVE-2025-58181)
- **High (R1-H02):** Decrypt timing oracle eliminated — checks `IsEntityKeyEncrypted` upfront, single decryption pass
- **High (R1-H03):** Binary key import implemented (was armored-only, fallback was a no-op comment)
- **High (R2-H01):** go-crypto upgraded v1.1.6 → v1.4.0 (x25519 low-order point rejection, hash enforcement, decompression limits)
- **Medium (R1-M01):** Sign command now warns when using default key selection
- **Medium (R1-M03):** Key files use full fingerprint instead of short key ID (collision risk eliminated)
- **Medium (R2-M02):** Clearsign verification implemented (was sign-only, broken round-trip)
- **Medium (R2-M03):** GUI passphrase handling for sign operations
- **Medium (R2-M04):** Secret key export requires confirmation
- **Low (R1-L01):** File permission validation — warns on permissive key file/directory permissions
- **Low (R1-L05):** Armor detection window expanded from 100 bytes to 1024 bytes
- **Low (R2-L01):** Key lookup now uses exact email → exact name → substring (was substring-only, overly permissive)
- **Info (R0-H2):** GUI key selection uses 64-bit `KeyIdString()` (was 32-bit `KeyIdShortString()`)
- **Info (R1-I03):** `cmd/` entrypoints created (were missing, CI couldn't build)
- **Info (R1-I04):** CI Go version matrix fixed to 1.24 (was testing 1.22/1.23)

### Known Issues (still open)
- H5/R0: Decrypted plaintext not zeroed after use
- M1/R0: Silent errors on corrupt key files, no file size limit on key loading
- M2/R0: No self-signature verification on key import
- M3/R0: Keyserver fetch adds keys without fingerprint validation
- M4/R0: Non-atomic key file writes (crash = truncated key)
- R2-L-03: Trust model cosmetic — not enforced in crypto operations
- See TODO.md for full list

### Changed
- Crypto test suite expanded from 0 to 122 tests
- Polished GUI across all tabs
- `findKey()` rewritten with 4-pass lookup: fingerprint → exact email → exact name → unique substring

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
