# TODO

Active work items for gpg-go. Check items off and move to CHANGELOG.md when done.

## Blockers for v1.0.0

### GPG-Signed Commits
- [ ] Ship a stable gpg-go release that can act as a git signing backend
- [ ] Configure `git config gpg.program gpg-go` and verify it works end-to-end
- [ ] Sign all commits and tags from that point forward
- [ ] Add signing verification to CI (reject unsigned commits on main)

### Cleanup
- [ ] Remove stale `release/gpg-go-v0.9.0-beta-linux-amd64.tar.gz` — hand-rolled artifact with wrong version string (actual version is 0.2.0-canary, tarball says 0.9.0-beta)
- [ ] Remove `release/gpg-go` binary from repo (build artifacts belong in CI, not git)
- [ ] Decide if `release/test.sh` should live in `release/` or `test/` or project root

## Testing

### Unit Tests (`make test`)
- [x] Key generation (Ed25519, RSA-4096, expiry, passphrase, error cases) — 8 tests
- [x] Encrypt/decrypt round-trips (armored, binary, symmetric, signed, passphrase-protected) — 8 tests
- [x] Sign/verify round-trips (detached, inline, clearsign, wrong key, tampered) — 9 tests
- [x] Expired key rejection (encrypt, sign, sign+encrypt) — 3 tests
- [x] Armor detection edge cases — 14 subtests
- [x] Decompression bomb constant validation — 1 test
- [x] Clearsign detection — 4 subtests
- [x] Subkey management (add, expiry, passphrase, round-trip) — 10 tests
- [x] Multiple UID management (add, comment, duplicate, encrypted, multiple) — 6 tests
- [x] RSA-4096 round-trips (encrypt+decrypt, sign+verify) — 2 tests
- [ ] Keyring operations (import, export, delete, list, find by UID/fingerprint)
- [ ] Keyserver HKP client (search, fetch, send — mock server)
- [ ] Trust database (set, get, persistence, concurrent access)
- [ ] Agent protocol handling
- [ ] Config and path resolution
- [ ] CLI command parsing and flag validation
- [ ] GUI state management (dropdown refresh after key ops)

### Integration Tests (`release/test.sh`)
- [x] 122-test shell-based integration suite
- [ ] Add to CI as a post-build step
- [ ] Test cross-platform (currently Linux-only)

### Fuzz Tests
- [ ] `isArmored()` — binary vs armor boundary detection
- [ ] `parseMachineReadableIndex()` — keyserver response parsing
- [ ] `ImportKey()` — malformed key data
- [ ] `Decrypt()` — malformed ciphertext
- [ ] `VerifyDetached()` — malformed signatures

## Remaining Audit Findings

Cross-referenced from three audit passes: R0 (initial crypto audit), R1, and R2.

### High Priority (still open)
- [ ] H5/R0: Decrypted plaintext never zeroed — `DecryptResult.Plaintext` stays in heap indefinitely, can be paged to swap. Zero after use or use `mlock()`.

### Medium Priority (still open)
- [ ] M1/R0: Silent errors on key loading — `store.go:176` silently `continue`s on corrupt `.asc` files. No file size limit on `os.ReadFile` (OOM on multi-GB file). Add size cap + log warning.
- [ ] M2/R0: No self-signature verification on key import — `ImportKey` relies on go-crypto's parsing but never explicitly validates self-signatures. Forged UIDs could be imported.
- [ ] M3/R0: Keyserver fetch has no key validation — keys added directly from HKP response with no fingerprint confirmation or prompt.
- [ ] M4/R0: Non-atomic file writes — `store.go` uses `os.WriteFile` directly. Crash during write = truncated key file. Use write-to-temp + fsync + rename.
- [ ] M5/R0: S2K weakness for symmetric encryption — OpenPGP iterated+salted S2K with SHA-256 is weaker than Argon2/scrypt against GPU brute-force. Protocol limitation, but iteration count should be maximized.

### Low Priority (still open)
- [ ] L-02/R1: Error messages leak internal filesystem paths
- [ ] L-03/R1: TrustDB has no integrity protection (no MAC/signature)
- [ ] L-04/R1: `readPassphrase()` falls back to insecure line-reading on non-TTY
- [ ] L1/R0: `PromptFunc` decrypts private key in-place — key stays decrypted in memory for process lifetime. Lower risk now that keys are S2K-encrypted at rest.
- [ ] L2/R0: RSA-2048 still offered as keygen option — only 112-bit security. Ed25519 is default but RSA-2048 should show a deprecation warning.
- [ ] L3/R0: No algorithm preference lists in generated keys — `PreferredHash`, `PreferredCipher`, `PreferredCompression` not set. Other OpenPGP implementations may choose suboptimal algorithms.
- [ ] L5/R0: No file-level locking for concurrent access — `sync.RWMutex` protects in-memory state but two gpg-go processes on same `~/.gpg-go` can race on disk.
- [ ] R2-L-02: Keyserver refresh has no rate limiting or backoff
- [ ] R2-L-03: Trust model is cosmetic — not enforced in crypto operations
- [ ] R2-L-04: GUI dropdowns stale after key operations

### Informational (feature gaps)
- [ ] R2-I-02: No revocation certificate generation
- [ ] R2-I-04: EncryptSymmetric doesn't pin S2K parameters explicitly

## Documentation
- [ ] Add `CONTRIBUTING.md` when accepting external contributions
- [ ] Write security policy (`SECURITY.md`) for vulnerability reporting
- [ ] Publish godoc for exported APIs (if any packages are promoted from `internal/`)
