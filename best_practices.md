# Best Practices

Standards and habits for gpg-go development. Treat as a living document.

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `test:`, `chore:`, `docs:`, `refactor:`
- One logical change per commit. Don't bundle unrelated fixes.
- Sign commits with GPG once a stable gpg-go client is available (see TODO.md).

## Changelog

- Update `CHANGELOG.md` with every user-facing change under `[Unreleased]`.
- Move `[Unreleased]` entries to a versioned section at release time.
- Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## Versioning

- Follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- Pre-release tags: `-canary` (dev), `-alpha`, `-beta`, `-rc.N`.
- Version is defined in two places — keep them in sync:
  - `Makefile` line 1: `VERSION := x.y.z`
  - `internal/config/config.go`: `AppVersion = "x.y.z"`

## Issues & Tracking

- Use `TODO.md` for local issue tracking during solo development.
- Use GitHub Issues for anything that needs external visibility or collaboration.
- Security findings go in `SECURITY-AUDIT-R*.md` with structured format (ID, severity, file, impact, fix).
- Reference audit finding IDs (e.g., `R2-M-01`) in commit messages when fixing them.

## Testing

- Every new feature or bugfix gets a test. No exceptions for crypto code.
- Unit tests: `internal/crypto/crypto_test.go` (and future per-package `_test.go` files).
- Integration tests: `release/test.sh` for end-to-end CLI testing.
- Run `make test` before pushing. CI runs `-race` detection.
- RSA-4096 tests are slow — gate them behind `testing.Short()`.

## Dependencies

- Pin direct dependencies to exact versions in `go.mod`.
- Audit dependency updates before upgrading — especially `go-crypto` (security-critical).
- Keep `go.mod` Go version, CI workflow Go version, and README Go version in sync.

## Security

- No weak algorithm fallbacks. SHA-256 and AES-256 only.
- Key material files: 0600 permissions, always.
- Zero passphrases after use via `defer zeroBytes()`.
- Never log or expose key material in error messages.
- Run security audits before any stable release.

## Releases

- Tag with `git tag vX.Y.Z` — GoReleaser handles the rest.
- Don't hand-roll release tarballs — let CI build them for reproducibility.
- Update CHANGELOG.md, bump version in Makefile + config.go, then tag.
