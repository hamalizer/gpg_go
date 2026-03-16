# Roadmap

## v0.3.0 — Hardening

- [ ] Zero decrypted plaintext after use (H5/R0 — heap/swap exposure)
- [ ] Atomic file writes for key storage (write-to-temp + fsync + rename)
- [ ] File size cap on key loading to prevent OOM on malicious `.asc` files
- [ ] Log warnings on corrupt/unreadable key files instead of silent skip
- [ ] Enforce trust model in cryptographic operations (encrypt/verify respect trust levels)
- [ ] Rate-limit keyserver refresh (backoff, concurrency cap, per-key progress)
- [ ] GUI state refresh after key operations (encrypt/sign dropdowns stay in sync)
- [ ] Warn or refuse `hkp://` (plaintext HTTP) keyserver connections without `--allow-insecure`
- [ ] File permission validation on key load (warn on world-readable secret keys)
- [ ] Sanitize internal paths from error messages in non-verbose mode
- [ ] TrustDB integrity protection (MAC or signature over trust entries)
- [ ] Pin S2K parameters explicitly in symmetric encryption config
- [ ] Warn on empty/weak passphrases for symmetric encryption
- [ ] Set algorithm preference lists on generated keys (PreferredHash, PreferredCipher, PreferredCompression)
- [ ] Deprecation warning when generating RSA-2048 keys
- [ ] File-level locking for concurrent `~/.gpg-go` access

## v0.4.0 — Key Lifecycle

- [ ] Revocation certificate generation at key creation time
- [ ] Revocation certificate import and application
- [ ] Subkey revocation (individual subkey without revoking primary)
- [ ] Key expiry extension (update expiry on existing keys)
- [ ] Certify other users' keys (key signing)
- [ ] Self-signature verification on key import
- [ ] Keyserver fetch validation (fingerprint confirmation prompt)

## v0.5.0 — Interoperability

- [ ] WKD (Web Key Directory) support
- [ ] Autocrypt header generation/parsing
- [ ] Key signature verification chain display
- [ ] GnuPG keyring import (convert `~/.gnupg` to `~/.gpg-go`)
- [ ] SSH key export (`gpg-go export --ssh`)

## v1.0.0 — Stable

- [ ] GPG-signed commits and tags (see TODO.md)
- [ ] Comprehensive fuzz testing on all parsers
- [ ] Third-party security audit (human)
- [ ] Stable API guarantees for `internal/` packages (promote to `pkg/`)
- [ ] Published documentation site
- [ ] Reproducible builds
- [ ] Package manager distribution (Homebrew, AUR, Nix, Debian)

## Future

- [ ] Hardware token support (YubiKey, Nitrokey via PKCS#11 or PC/SC)
- [ ] Secret sharing (Shamir's) for key backup
- [ ] Plugin system for custom keyserver backends
- [ ] LDAP keyserver support
- [ ] Threshold signatures
