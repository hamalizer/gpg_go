# CLAUDE.md

## Project

gpg-go — OpenPGP implementation in Go. CLI + GUI. Wraps ProtonMail/go-crypto.

**Version:** 0.2.0-canary (pre-release)
**Go:** 1.24+ required (go.mod, CI, and README must stay in sync)

## Build & Test

```bash
make cli          # build CLI only (no CGO)
make gui          # build GUI (needs libgl-dev, xorg-dev on Linux)
make build        # both
make test         # go test -v -race ./...
make lint         # go vet ./...
```

GUI build requires OpenGL dev libraries. CLI builds with `CGO_ENABLED=0`.

## Architecture

```
cmd/gpg-go/          CLI entrypoint
cmd/gpg-go-gui/      GUI entrypoint
internal/crypto/     keygen, encrypt, decrypt, sign, verify
internal/keyring/    key storage, import/export, key lookup
internal/keyserver/  HKP protocol client
internal/config/     paths, version constant
internal/trustdb/    trust level database
internal/agent/      GPG agent protocol
cli/                 cobra command definitions (17 commands)
gui/                 fyne GUI (5 tabs)
man/                 troff man pages
```

## Key Conventions

- **Commits:** conventional commits (`feat:`, `fix:`, `test:`, `chore:`, `docs:`)
- **Changelog:** update `CHANGELOG.md` under `[Unreleased]` with every user-facing change
- **Version:** defined in TWO places, keep in sync:
  - `Makefile` line 1: `VERSION := x.y.z`
  - `internal/config/config.go` line 13: `AppVersion = "x.y.z"`
- **Audit IDs:** reference finding IDs (e.g., `R2-M-01`, `H5/R0`) in commit messages when fixing security issues

## Crypto Rules

- SHA-256 and AES-256 only. No weak algorithm fallbacks.
- Key files: 0600 permissions. Key directories: 0700.
- Always pass `s2kSerializeConfig()` to `SerializePrivate` — never `nil`.
- Always set `DefaultHash` and `DefaultCipher` in `packet.Config` — don't rely on library defaults.
- Zero passphrases after use with `defer zeroBytes()`.
- Never use `KeyIdShortString()` (32-bit). Use `KeyIdString()` (64-bit) or full fingerprint.
- `MaxMessageSize` (256 MB) limits all `io.ReadAll` on message bodies.

## Testing

- Unit tests: `internal/crypto/crypto_test.go` (122 tests, 47 test functions)
- Integration tests: `release/test.sh` (shell-based, 122 tests)
- RSA-4096 tests are slow — they skip under `go test -short`
- Every bugfix or feature needs a test. No exceptions for crypto code.

## Known Open Issues

See `TODO.md` for the full list. Key items:
- Verify accepts signatures from expired keys
- Trust model not enforced in verify/decrypt (only warns in encrypt)
- Decrypted plaintext not zeroed after use
- Non-atomic key file writes
- No self-signature verification on import
- No keyserver fetch validation

See `SECURITY-AUDIT-R1.md` and `SECURITY-AUDIT-R2.md` for audit details.
See `best_practices.md` for cross-reference notes from all three audit passes.

## Files Not to Touch Without Care

- `internal/crypto/` — security-critical, changes need tests
- `internal/keyring/store.go` — key serialization, S2K config
- `.github/workflows/` — CI config, Go version must match go.mod
- `go.mod` — dependency changes need security review for `go-crypto`

## Release Process

1. Update `CHANGELOG.md` — move `[Unreleased]` to `[vX.Y.Z]`
2. Bump version in `Makefile` and `internal/config/config.go`
3. `git tag vX.Y.Z && git push --tags`
4. GoReleaser handles the rest via `.github/workflows/release.yml`
