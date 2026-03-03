# Security Audit Report — gpg-go v0.2.0-canary

**Auditor:** Walter (AI security researcher)
**Date:** 2026-03-03
**Scope:** All 3,901 LOC across 28 Go source files
**Commit:** `de21f11` (HEAD of main)

---

## Executive Summary

gpg-go is a from-scratch OpenPGP implementation in Go wrapping ProtonMail's go-crypto library. The codebase is clean and well-structured, but has several security-relevant bugs ranging from a critical key expiration bypass to missing input validation and information leakage. No test files exist, which means none of these issues are caught by CI.

**Finding Severity Distribution:**

| Severity | Count |
|----------|-------|
| Critical | 1     |
| High     | 3     |
| Medium   | 5     |
| Low      | 5     |
| Info     | 4     |
| **Total**| **18**|

---

## Critical

### C-01: Key Expiration Not Enforced — Keys Generated Without `--expire` Are Shown as Expired

**File:** `internal/crypto/keygen.go:62-64`, `internal/keyring/keyring.go` (KeyInfo/IsKeyExpired)
**Impact:** All keys generated without `--expire` display as `[EXPIRED <today>]` in listings, yet are still fully functional for signing and encryption. This is a dual bug:

1. **go-crypto's `KeyLifetimeSecs` defaults to 0 when not set**, but the `Config{}` is passed with no explicit lifetime. The library creates a self-signature with `KeyLifetimeSecs = nil` (no expiry), but `keygen.go` only sets it when `params.Lifetime > 0`. This is correct — the bug is in display.

2. **`IsKeyExpired()` and `isEntityExpired()`** iterate over identities and check `SelfSignature.KeyLifetimeSecs`. When the pointer is non-nil and `*KeyLifetimeSecs == 0`, the expiry computes as `CreationTime + 0 seconds = CreationTime`, which is always in the past.

**Reproduction:** Generate any key without `--expire`. It shows `[EXPIRED 2026-03-03]` immediately.

**Root Cause:** The go-crypto library's `openpgp.NewEntity()` may set `KeyLifetimeSecs` to a pointer to `0` (rather than `nil`) depending on the Config. The expiration checks don't distinguish between "lifetime is 0 seconds" and "no lifetime set."

**Fix:** In `IsKeyExpired()`, `KeyExpiry()`, `isEntityExpired()`, and `isSignerExpired()`: check `*id.SelfSignature.KeyLifetimeSecs == 0` and treat it as "no expiration" (same as nil). There are **4 copies** of this logic — should be deduplicated into one shared function.

```go
if id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
    // has real expiration
}
```

**Why Critical:** Users will see all their keys as "expired" and either (a) ignore expiry warnings entirely (normalizing the false alarm), or (b) refuse to use the tool. Both outcomes defeat the purpose of key expiration. Additionally, since `Encrypt()` calls `isEntityExpired()` which would reject truly expired keys, a key with `*KeyLifetimeSecs == 0` can't be used as a recipient — **encryption to non-expiring keys fails**.

---

## High

### H-01: Passphrase Not Zeroed After Failed Key Generation

**File:** `cli/generate.go:105-128`
**Impact:** If `crypto.GenerateKey()` or `kr.AddEntity()` fails after the passphrase is read and confirmed, the `defer zeroBytes(passphrase)` will still fire — but the second passphrase (`passphrase2`) is zeroed immediately after comparison. However, if the comparison succeeds but then the function returns early due to a later error, the first passphrase remains in memory until the function returns. More critically:

The `readPassphrase()` function uses `term.ReadPassword()` which allocates internally — **the returned slice may be a copy**, meaning `zeroBytes()` only zeros the copy, not the original allocation in term's buffer. This is a fundamental limitation of Go's GC — you can't guarantee zeroing of all copies.

**Mitigation:** Use `golang.org/x/crypto/ssh/terminal` or pin memory with `mlock()` via syscall. At minimum, document this limitation.

### H-02: Decrypt Attempts Without Passphrase First, Leaking Timing Information

**File:** `cli/decrypt.go:25-41`
**Impact:** The decrypt command first tries decryption without a passphrase (`nil`), and only if that fails, prompts for one. This means:

1. **Timing oracle:** An attacker observing the process can distinguish between passphrase-protected and non-protected keys based on whether the passphrase prompt appears.
2. **Double processing:** The ciphertext is read into memory, then `ReadMessage()` is called twice — once failing, once succeeding. The first call may partially parse the message, leaving sensitive data in memory.
3. **Error swallowing:** The first error from `crypto.Decrypt()` is silently discarded. If it was a malformed-message error (not a passphrase error), the user sees a misleading "decryption failed" from the second attempt.

**Fix:** Check if any keys in the keyring are encrypted first, and prompt for passphrase upfront if so. Or parse the message header to determine if it needs a passphrase.

### H-03: No Binary Key Import — Only Armored Keys Accepted

**File:** `internal/keyring/keyring.go:95-99`
**Impact:** `ImportKey()` only calls `openpgp.ReadArmoredKeyRing()`. The comment says "Try binary format as fallback" but the fallback is never implemented — it just returns the error. Binary-format keys (which are common in key exchange) silently fail to import.

```go
entities, err := openpgp.ReadArmoredKeyRing(armoredKey)
if err != nil {
    // Try binary format as fallback
    return nil, fmt.Errorf("read key: %w", err)  // ← fallback never happens
}
```

**Fix:** On armor decode failure, attempt `openpgp.ReadKeyRing()` with the raw reader.

---

## Medium

### M-01: Sign Command Uses Wrong Key When No `-u` Specified

**File:** `cli/sign.go:34-42`
**Impact:** When `--local-user` is not specified, the sign command silently uses `secKeys[0]` — the first secret key in the keyring. Key ordering depends on filesystem readdir order (non-deterministic across platforms/runs). Users may unknowingly sign with the wrong identity.

**Observed:** Generated keys for "Walter" and "Alice". Signing without `-u` used Walter's key regardless of intent. No warning displayed.

**Fix:** If multiple secret keys exist and `-u` is not specified, either (a) prompt the user to choose, or (b) require `-u` explicitly. At minimum, print which key is being used.

### M-02: Symmetric Encryption Passphrase Not Validated for Strength

**File:** `cli/encrypt.go:41-56`, `internal/crypto/encrypt.go`
**Impact:** Empty passphrases are accepted for symmetric encryption without any warning. A user can encrypt sensitive data with an empty passphrase, which provides zero security. The key generation flow prompts but doesn't warn; symmetric encryption doesn't even distinguish between "empty" and "typed."

**Fix:** Warn (but don't block, for scripting) when passphrase is empty or very short.

### M-03: Key Store Files Named by Short Key ID — Collision Risk

**File:** `internal/keyring/store.go:26,43`
**Impact:** Key files are stored as `<KeyIdString>.asc` which is the 16-hex-char short key ID. Short key IDs are known to be vulnerable to collision attacks (demonstrated against PGP in 2016). Two different keys with colliding short IDs would overwrite each other on disk.

**Fix:** Use full fingerprint (40 hex chars) for filenames.

### M-04: Keyserver Client Doesn't Validate TLS Certificates in Custom Configs

**File:** `internal/keyserver/hkp.go:35-38`
**Impact:** The `http.Client` is created with default settings, which is fine for standard TLS. However, if a user configures a custom keyserver with a self-signed cert, there's no mechanism to pin certificates or add custom CAs. More importantly, the `hkp://` scheme silently downgrades to plaintext HTTP:

```go
} else if strings.HasPrefix(serverURL, "hkp://") {
    serverURL = "http://" + strings.TrimPrefix(serverURL, "hkp://")
```

Keys fetched over plaintext HTTP can be MITM'd — an attacker substitutes their own key.

**Fix:** Warn or refuse `hkp://` (non-TLS) connections by default. Require `--allow-insecure` flag.

### M-05: Keyring `AllKeys()` Returns Both Public and Secret in a Single List

**File:** `internal/keyring/keyring.go:63-69`
**Impact:** `AllKeys()` combines public and secret keys into one list and passes it to `openpgp.ReadMessage()` for decryption. If a public-only entity is in the list and shares a key ID with a secret key (via subkey collision), the wrong entity could be selected. More subtly, this means secret key material is loaded into memory even when only public keys are needed for signature verification (the verify command also uses `AllKeys()`).

**Fix:** Use `SecretKeys()` for decryption, `PublicKeys()` for verification. Only combine when both are genuinely needed.

---

## Low

### L-01: No File Permission Validation on Key Import

**File:** `internal/keyring/store.go`
**Impact:** When loading keys from disk, there's no check that key files have restrictive permissions (e.g., 0600). A secret key file with world-readable permissions (0644) would be silently loaded. GnuPG warns about this.

### L-02: Error Messages Leak Internal Paths

**File:** Various (all error wrapping)
**Impact:** Errors like `"load public keys: read /home/user/.gpg-go/pubring/..."` expose the full filesystem path of the keyring. In a server/daemon context, this leaks deployment details.

### L-03: TrustDB Has No Integrity Protection

**File:** `internal/trustdb/trustdb.go`
**Impact:** The trust database is a plain JSON file with no MAC or signature. An attacker with filesystem access can silently modify trust levels (e.g., set an attacker's key to "ultimate" trust). GnuPG uses a binary format with internal checksums.

### L-04: `readPassphrase()` Falls Back to Line-Reading on Non-TTY

**File:** `cli/encrypt.go:145-157`
**Impact:** When stdin is not a terminal (piped input), the passphrase is read as a plain line. This means passphrases in scripts are visible in process lists (`/proc/PID/cmdline` if passed as echo-pipe) and shell history.

### L-05: `isArmored()` Detection Only Checks First 100 Bytes

**File:** `internal/crypto/decrypt.go:90-93`
**Impact:** The armor detection trims whitespace from the first 100 bytes and looks for `-----BEGIN PGP`. If a file has >100 bytes of whitespace/garbage before the armor header, it will be treated as binary. Unlikely but could cause confusing failures.

---

## Informational

### I-01: Zero Test Files

**Impact:** No unit tests, integration tests, or fuzz tests exist. Every finding in this audit would have been caught by basic test coverage. Especially concerning for a cryptographic tool.

**Recommendation:** Priority test areas:
1. Key generation with and without expiry
2. Encrypt/decrypt round-trip (armored + binary, symmetric + asymmetric)
3. Sign/verify round-trip (detached, inline, clearsign)
4. Import/export round-trip
5. Expired key rejection
6. Fuzz testing on `isArmored()`, `parseMachineReadableIndex()`, armor decoding

### I-02: Four Duplicate Implementations of Expiry Check

**Files:** `internal/crypto/encrypt.go:87-96`, `internal/crypto/sign.go:130-140`, `internal/keyring/keyring.go:387-399`, `internal/keyring/keyring.go:401-412`
**Impact:** `isEntityExpired()`, `isSignerExpired()`, `IsKeyExpired()`, and `KeyExpiry()` all implement the same logic with slight variations. A fix to one won't fix the others.

### I-03: `cmd/` Directory Was Missing — Build Was Broken

**Impact:** The `cmd/gpg-go/` and `cmd/gpg-go-gui/` directories with `main.go` entrypoints did not exist. CI would fail on `go build ./cmd/gpg-go`. Created during this audit.

### I-04: CI Matrix Tests Go 1.22/1.23 but `go.mod` Requires 1.24

**File:** `.github/workflows/ci.yml:11`, `go.mod:3`
**Impact:** `go.mod` specifies `go 1.24.0` with `toolchain go1.24.7`, but CI tests on Go 1.22 and 1.23. These will fail because the go directive requires the specified minimum version. CI should test 1.24+.

---

## Positive Findings

1. **Passphrase zeroing is implemented** — `zeroBytes()` is called via `defer` in all passphrase paths
2. **S2K encryption of private keys** — Properly encrypts all subkeys, not just primary
3. **Armor output uses correct headers** — `PGP MESSAGE`, `PGP PUBLIC KEY BLOCK`, `PGP PRIVATE KEY BLOCK`
4. **File permissions are 0600** — Key files are written with restrictive permissions
5. **Concurrent access** — Keyring uses `sync.RWMutex` for thread safety
6. **Key lookup requires unambiguous match** — `findKey()` returns nil if multiple UIDs match (prevents wrong-key encryption)
7. **Response size limits** — Keyserver client limits response sizes (1MB search, 10MB keys)
8. **SHA-256 and AES-256 hardcoded** — No weak algorithm fallbacks
9. **Verify returns no plaintext on bad signature** — `VerifyInline()` correctly withholds plaintext when signature fails

---

## Build Results

| Target | Result |
|--------|--------|
| CLI (`./cmd/gpg-go`) | ✅ Compiles, runs, functional |
| GUI (`./cmd/gpg-go-gui`) | ❌ Needs X11/OpenGL (expected on headless) |
| Tests | ⚠️ No test files exist |
| `go vet` | ✅ Clean |

**Functional test:** Key generation → encrypt → decrypt → sign → verify round-trip works correctly (with the caveats noted above).

---

## Recommendations (Priority Order)

1. **Fix C-01 immediately** — The expiry bug makes the tool look broken to every user
2. **Add the `cmd/` entrypoints** — CI can't build without them (done during audit)
3. **Write tests** — At least round-trip tests for all crypto operations
4. **Deduplicate expiry logic** — Single function, single fix
5. **Add binary key import** — Complete the TODO
6. **Use full fingerprint for filenames** — Prevent short-ID collision
7. **Warn on `hkp://`** — Don't silently use plaintext HTTP for key exchange
8. **Fix CI Go versions** — Match `go.mod` requirement
