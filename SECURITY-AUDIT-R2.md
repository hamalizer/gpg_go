# Security Audit Report — gpg-go v0.2.0-canary — Round 2

**Auditor:** Walter (AI security researcher)
**Date:** 2026-03-03
**Scope:** Full second pass of all 3,901 LOC across 28 Go source files + dependency analysis
**Focus:** Cryptographic correctness, protocol compliance, supply chain, edge cases, attack surface the first audit missed

---

## Executive Summary

Round 1 found 18 issues focused on obvious bugs (expiry, import, key selection). Round 2 goes deeper: cryptographic protocol compliance, dependency supply chain, state management edge cases, and adversarial input handling. The most significant new finding is that go-crypto v1.1.6 is missing a security fix for low-order x25519 curve points (patched in v1.4.0) — meaning Ed25519 key exchange can be attacked.

**New findings this round: 13** (1 High, 4 Medium, 4 Low, 4 Info)
**Combined total across both audits: 31**

---

## High

### R2-H-01: Dependency 3 Versions Behind — Missing x25519 Low-Order Point Rejection

**File:** `go.mod` — `github.com/ProtonMail/go-crypto v1.1.6`
**Upstream fix:** v1.4.0 (Feb 27, 2026), PR #299: "ECDHv4: Error on low-order x25519 public key curve points"
**Impact:** gpg-go uses Ed25519 as its default and recommended algorithm. The underlying ECDH key exchange for Ed25519 encryption subkeys uses x25519. go-crypto v1.1.6 does NOT reject low-order curve points, meaning an attacker can craft a malicious public key where the shared secret is predictable (all zeros or a small set of values). If a user encrypts to such a key, the ciphertext is trivially decryptable.

**Attack scenario:**
1. Attacker generates a key with a low-order x25519 public point
2. Uploads it to a keyserver
3. Victim fetches and encrypts to it
4. Shared ECDH secret is deterministic → attacker decrypts without the private key

**Also missing from v1.3.0:**
- Enforced acceptable hash functions in clearsign (PR #281, #286) — gpg-go's `cleartextSignMsg()` could accept weak hashes from crafted input
- Decompressed message size limit (PR #285) — no protection against zip bomb in encrypted messages

**Also missing from v1.4.0:**
- Cleartext hash header validation per RFC 9580 (PR #298)

**Fix:** `go get github.com/ProtonMail/go-crypto@v1.4.0` — this is a single command.

---

## Medium

### R2-M-01: No Decompression Bomb Protection

**File:** `internal/crypto/decrypt.go:68` — `io.ReadAll(md.UnverifiedBody)`
**Impact:** OpenPGP messages can contain compressed data. A malicious message can have a small ciphertext that decompresses to gigabytes (zip bomb). `io.ReadAll()` will allocate until OOM. go-crypto v1.3.0 added `Config.MaxDecompressedMessageSize` but gpg-go doesn't set it (and can't, since it's on v1.1.6).

**Fix:** Upgrade go-crypto, then set `MaxDecompressedMessageSize` in the packet.Config (e.g., 256MB). Alternatively, use `io.LimitReader(md.UnverifiedBody, maxSize)` as an immediate mitigation.

### R2-M-02: Clearsign Verification Not Implemented — Only Detached and Inline

**File:** `cli/verify.go`, `internal/crypto/verify.go`
**Impact:** gpg-go can CREATE clearsign signatures (`--clear-sign` flag works in `sign.go` using `clearsign.Encode`), but the verify command has NO clearsign verification path. If a user creates a cleartext signature and tries to verify it, it goes through `VerifyInline()` which calls `openpgp.ReadMessage()` — this will fail because cleartext-signed messages are not standard OpenPGP messages. The `clearsign.Decode()` function exists in the library but is never called anywhere in gpg-go.

**Result:** Users can sign but can't verify their own clearsign output. Broken round-trip.

**Fix:** In the verify command, detect cleartext signatures (they start with `-----BEGIN PGP SIGNED MESSAGE-----`) and use `clearsign.Decode()` + `openpgp.CheckDetachedSignature()` on the decoded body.

### R2-M-03: GUI Signing Doesn't Decrypt Passphrase-Protected Keys

**File:** `gui/sign.go:55-72`
**Impact:** The GUI sign tab calls `crypto.Sign()` directly without checking if the signer's private key is encrypted. The CLI correctly checks `keyring.IsEntityKeyEncrypted(signer)` and prompts for a passphrase (cli/sign.go:47-57), but the GUI skips this entirely. If a user has a passphrase-protected key and tries to sign via the GUI, it will fail with a cryptic error about the key being locked.

The GUI encrypt tab has the same issue — when `signWith` is set, it prompts in CLI (cli/encrypt.go:79-89) but the GUI encrypt tab never signs at all (no signer option exposed in the GUI encrypt flow).

**Fix:** Add passphrase dialog before signing in the GUI. Use `dialog.NewEntryDialog` with password masking.

### R2-M-04: Secret Key Export Doesn't Require Authentication

**File:** `cli/import_cmd.go:39-51` (newExportCmd), `gui/keys.go` (showExportDialog)
**Impact:** The `export --secret` CLI command and the GUI export dialog will dump the full private key (including encrypted private key material) without requesting the user's passphrase or any confirmation. While the key material is S2K-encrypted, exporting it to stdout or a GUI text widget makes it trivially copyable. GnuPG requires passphrase entry before exporting secret keys.

This combines with H-01 from the first audit (passphrase not truly zeroed) — the exported armored private key block is the only thing between an attacker and the user's identity.

**Fix:** Require passphrase confirmation before secret key export. Add "Are you sure?" confirmation dialog.

---

## Low

### R2-L-01: findKey() UID Matching Is Case-Insensitive Substring — Overly Permissive

**File:** `internal/keyring/keyring.go:232-246`
**Impact:** Key lookup by UID does case-insensitive substring matching: `strings.Contains(strings.ToLower(id.Name), lowerID)`. This means searching for "a" matches every key with "a" anywhere in any UID. While the function returns nil for >1 match (good), a search for a common substring like "gmail" would match many keys and return nil (confusing "not found" error when the key clearly exists).

More subtly: searching for "joe" would match both "Joe Smith <joe@x.com>" and "Joey Johnson <joey@x.com>", returning nil even when the user clearly meant one specific key.

**Fix:** Prefer exact email match, then exact name match, then substring as last resort.

### R2-L-02: Keyring Refresh Fetches Every Key Sequentially — No Rate Limiting

**File:** `gui/keyserver_tab.go:119-134`
**Impact:** The "Refresh Keys from Server" button iterates ALL public keys and fetches each from the keyserver sequentially. For a large keyring (50+ keys), this is both slow and could trigger keyserver rate limiting or IP blocking. No backoff, no concurrency limit, no progress reporting per-key.

### R2-L-03: Trust Model Doesn't Affect Cryptographic Operations

**File:** `internal/trustdb/trustdb.go`, `internal/crypto/encrypt.go`
**Impact:** The trust database exists and can be modified, but it's never consulted during encryption or verification. A key marked as `TrustNever` can still be used as an encryption recipient or its signatures will be reported as "Good signature." The trust model is purely cosmetic.

GnuPG uses trust levels to determine whether to accept signatures and show appropriate warnings. Without this, the trust UI gives false confidence.

### R2-L-04: GUI State Not Refreshed After Operations

**File:** `gui/keys.go`, `gui/encrypt.go`
**Impact:** The encrypt tab's recipient checkbox list and sign tab's signer dropdown are populated once at GUI startup via `getKeyOptions()` / `getSecretKeyOptions()`. After generating, importing, or deleting keys in the Keys tab, these dropdowns are stale — the new/removed keys won't appear/disappear until the app is restarted. The Keys tab list itself refreshes (via `keyList.Refresh()`), but the other tabs don't.

---

## Informational

### R2-I-01: No Subkey Rotation or Management

**Impact:** gpg-go generates a primary key + one encryption subkey (via go-crypto's `NewEntity`). There's no way to add new subkeys, rotate encryption subkeys, set per-subkey expiration, or revoke individual subkeys. When a key "expires," the only option is to generate an entirely new identity.

### R2-I-02: No Revocation Certificate Generation

**Impact:** If a private key is compromised, there's no way to generate or import a revocation certificate. GnuPG generates a revocation cert at key creation time as a safety measure. Without this, a compromised key can't be formally revoked on keyservers.

### R2-I-03: No Support for Multiple UIDs Per Key

**Impact:** Keys are generated with exactly one UID. There's no way to add additional UIDs to an existing key. Users with multiple email addresses need multiple keys instead of one key with multiple UIDs.

### R2-I-04: EncryptSymmetric Doesn't Set S2K Parameters Explicitly

**File:** `internal/crypto/encrypt.go:105-113`
**Impact:** The `packet.Config` passed to `SymmetricallyEncrypt` doesn't explicitly set S2K iteration count or mode. go-crypto defaults are reasonable, but future library versions could change defaults. Pinning S2K parameters prevents surprise downgrades.

---

## Dependency Summary

| Dependency | Version | Latest | Gap | Risk |
|-----------|---------|--------|-----|------|
| ProtonMail/go-crypto | v1.1.6 | v1.4.0 | **3 major** | **HIGH** — missing x25519 low-order rejection, hash enforcement, decompression limits |
| golang.org/x/crypto | v0.48.0 | current | OK | Low |
| fyne.io/fyne/v2 | v2.5.4 | current | OK | Low |
| spf13/cobra | v1.8.1 | current | OK | Low |
| cloudflare/circl | v1.3.7 | v1.6.0+ | 3 minor | Low — circl is used by go-crypto for curve operations |

---

## Combined Findings Matrix (Round 1 + Round 2)

| ID | Severity | Summary | Round |
|----|----------|---------|-------|
| C-01 | Critical | Key expiration broken — all keys show EXPIRED | R1 |
| H-01 | High | Passphrase not truly zeroed (GC copies) | R1 |
| H-02 | High | Decrypt timing oracle (double-attempt) | R1 |
| H-03 | High | Binary key import TODO never implemented | R1 |
| **R2-H-01** | **High** | **go-crypto 3 versions behind — x25519 low-order points** | **R2** |
| M-01 | Medium | Sign uses wrong key silently | R1 |
| M-02 | Medium | No symmetric passphrase strength warning | R1 |
| M-03 | Medium | Short key ID filenames — collision risk | R1 |
| M-04 | Medium | hkp:// silently downgrades to HTTP | R1 |
| M-05 | Medium | AllKeys() mixes secret+public unnecessarily | R1 |
| **R2-M-01** | **Medium** | **No decompression bomb protection** | **R2** |
| **R2-M-02** | **Medium** | **Clearsign verify not implemented (broken round-trip)** | **R2** |
| **R2-M-03** | **Medium** | **GUI sign doesn't handle passphrase-protected keys** | **R2** |
| **R2-M-04** | **Medium** | **Secret key export requires no authentication** | **R2** |
| L-01 | Low | No file permission validation on key load | R1 |
| L-02 | Low | Error messages leak internal paths | R1 |
| L-03 | Low | TrustDB has no integrity protection | R1 |
| L-04 | Low | readPassphrase falls back to line-reading | R1 |
| L-05 | Low | isArmored only checks first 100 bytes | R1 |
| **R2-L-01** | **Low** | **findKey() substring matching too permissive** | **R2** |
| **R2-L-02** | **Low** | **Keyring refresh — no rate limiting** | **R2** |
| **R2-L-03** | **Low** | **Trust model is cosmetic — not enforced** | **R2** |
| **R2-L-04** | **Low** | **GUI state stale after key operations** | **R2** |
| I-01 | Info | Zero test files | R1 |
| I-02 | Info | Four duplicate expiry check implementations | R1 |
| I-03 | Info | cmd/ directory was missing | R1 |
| I-04 | Info | CI Go version matrix wrong | R1 |
| **R2-I-01** | **Info** | **No subkey rotation/management** | **R2** |
| **R2-I-02** | **Info** | **No revocation certificate generation** | **R2** |
| **R2-I-03** | **Info** | **No multiple UIDs per key** | **R2** |
| **R2-I-04** | **Info** | **EncryptSymmetric doesn't pin S2K params** | **R2** |

**Total: 31 findings** (1C, 4H, 9M, 9L, 8I)

---

## Priority Fix Order

1. **go-crypto upgrade** (R2-H-01) — single `go get` command, fixes R2-H-01 + enables R2-M-01 fix
2. **C-01 expiry bug** — deduplicate 4 functions, add `> 0` check
3. **R2-M-02 clearsign verify** — broken round-trip is embarrassing for a GPG tool
4. **H-03 binary import** — complete the TODO
5. **R2-M-03 GUI passphrase** — GUI is unusable for passphrase-protected keys
6. **R2-M-04 secret export auth** — low-hanging fruit, big security win
7. **M-01 key selection** — stop silently picking wrong key
8. **Write tests** — before fixing anything else, lock down the expected behavior
