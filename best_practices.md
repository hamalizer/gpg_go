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

---

## Audit Cross-Reference Notes (2026-03-16)

Raw notes from cross-referencing the R0 (initial crypto audit), R1, and R2 audit
reports against the current codebase. Kept here as a reference for what was
checked, what's fixed, and what patterns to watch for going forward.

### Three audit sources
- R0: "Comprehensive Cryptographic & Security Audit" — the earliest, deepest pass.
  Found C1-C3, H1-H5, M1-M6, L1-L5. Predates all fix commits.
- R1: "Security Audit Report — Round 1" (2026-03-03). 18 findings. Overlaps R0
  significantly but uses different numbering (C-01, H-01...).
- R2: "Security Audit Report — Round 2" (2026-03-03). 13 new findings. Focused on
  deps, protocol compliance, GUI edge cases.

### What was fixed (verified in code)
- C1/R0 (keys unencrypted at rest): FIXED. `s2kSerializeConfig()` now passed to
  `SerializePrivate` everywhere (store.go:73, keyring.go:271,279). Config sets
  SHA256 + AES256 for S2K derivation.
- C2/R0 = R2-L-03 (trust model): NOT FIXED. trustdb.go exists, SetTrust/GetTrust
  work, but encrypt.go and verify.go never consult it. AllKeys() returns everything.
  Tracked in roadmap v0.3.0.
- C3/R0 = R1-C01 (key expiry): FIXED. Expiry logic checks `*KeyLifetimeSecs > 0`.
  Tests exist (TestExpiredKeyRejection_*). Deduplicated check.
- H1/R0 (findKey 64-bit ID): PARTIALLY FIXED. findKey rewritten with 4-pass:
  fingerprint → exact email → exact name → unique substring. First pass still
  matches on KeyIdString (64-bit) alongside full fingerprint. 64-bit is better
  than 32-bit but still birthday-attackable at ~2^32 work. Full fingerprint match
  is tried first though, so this is acceptable.
- H2/R0 (GUI 32-bit short IDs): FIXED. `KeyIdShortString` no longer used anywhere.
  GUI uses `KeyIdString()` (64-bit). extractKeyID parses `[KEYID]` from dropdown
  and passes to findKey which matches against 64-bit IDs and fingerprints.
- H3/R0 (empty decrypt config): FIXED. decrypt.go:59-62 now sets DefaultHash=SHA256,
  DefaultCipher=AES256.
- H4/R0 (x/crypto CVEs): FIXED. go.mod shows golang.org/x/crypto v0.48.0 (all
  CVEs fixed by v0.45.0). SSH packages not imported anywhere in the codebase.
- H5/R0 (plaintext not zeroed): NOT FIXED. DecryptResult.Plaintext is returned to
  caller and never zeroed. Go GC makes this hard (can't guarantee all copies are
  zeroed) but we should zero what we can. Track in TODO high priority.
- M1/R0 (silent key load errors): NOT FIXED. store.go:176 still `continue`s silently.
  os.ReadFile has no size cap. Need to add io.LimitReader + log.Warn.
- M2/R0 (no self-sig verification): NOT FIXED. go-crypto's ReadArmoredKeyRing does
  basic parsing but gpg-go never calls any explicit validation. Accept for now,
  track for v0.4.0 (key lifecycle).
- M3/R0 (keyserver no validation): NOT FIXED. hkp.go adds keys directly. Should
  prompt for fingerprint confirmation at minimum.
- M4/R0 (non-atomic writes): NOT FIXED. store.go still uses os.WriteFile directly.
  Standard fix: write to .tmp, fsync, rename. Track for v0.3.0.
- M5/R0 (S2K weakness): NOT FIXABLE within OpenPGP protocol. S2K is what OpenPGP
  specifies. Argon2 would break interoperability. Maximize iteration count.
- M6/R0 = R1-H02 (decrypt double-attempt): FIXED. cli/decrypt.go now checks
  IsEntityKeyEncrypted upfront and prompts once. Single decryption pass.
- L1/R0 (PromptFunc in-place decrypt): NOT FIXED. Lower risk now that keys are
  encrypted at rest. Still, decrypted key material stays in memory.
- L2/R0 (RSA-2048): NOT FIXED. Still offered in CLI and GUI. Ed25519 is default.
  Add deprecation warning, don't remove (legacy compat).
- L3/R0 (no algorithm prefs): NOT FIXED. PreferredHash/PreferredCipher/
  PreferredCompression arrays not set on generated keys. Other impls may pick
  suboptimal algos when encrypting to our keys.
- L4/R0 = R1-M04 (hkp:// accepted): NOT FIXED. isValidServerURL still accepts
  hkp:// and http://. Track for v0.3.0.
- L5/R0 (no file locking): NOT FIXED. sync.RWMutex is process-local only.
  Two gpg-go instances = disk race. flock() needed.

### Patterns to watch
- SerializePrivate: always pass s2kSerializeConfig(), never nil. Grep for nil
  second arg periodically.
- Key selection: any new code using KeyIdString() should also check fingerprint.
  Never use KeyIdShortString().
- Config structs: always set DefaultHash + DefaultCipher explicitly. Don't rely
  on library defaults.
- File writes for key material: should always be atomic (temp+rename) once M4
  is fixed. Enforce in code review.
- Plaintext handling: zero bytes when done. Even if GC copies exist, zero what
  you can. Add `defer zeroBytes(result.Plaintext)` pattern to callers.
- Trust model: until v0.3.0, trust is cosmetic. Don't claim trust enforcement
  in docs or UI until it's real.

### Version string confusion
- Code says 0.2.0-canary (Makefile + config.go). Only tag is v0.2.0-canary.
- release/gpg-go-v0.9.0-beta-linux-amd64.tar.gz is a hand-rolled artifact with
  an aspirational filename. Not from CI, not from goreleaser, not referenced
  anywhere. Should be deleted.
- GoReleaser uses `{{.Version}}` from git tags. Will be correct on real releases.
