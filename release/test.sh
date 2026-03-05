#!/usr/bin/env bash
set -euo pipefail

# gpg-go v0.9.0-beta integration test suite
# Run: chmod +x test.sh && ./test.sh

BIN="./gpg-go"
HOMEDIR=$(mktemp -d)
FAIL=0
PASS_COUNT=0
TOTAL=0

cleanup() { rm -rf "$HOMEDIR"; }
trap cleanup EXIT

# Helper: generate a key without interactive prompts
gen_key() {
    echo "" | $BIN generate --homedir "$HOMEDIR" --quick --name "$1" --email "$2" --algo "${3:-ed25519}" >/dev/null 2>&1
}

# Helper: extract fingerprint (remove spaces from formatted output)
get_fp() {
    $BIN fingerprint --homedir "$HOMEDIR" "$1" 2>/dev/null | grep "Fingerprint:" | sed 's/.*Fingerprint: //;s/ //g'
}

run() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  \033[32mPASS\033[0m  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        printf "  \033[31mFAIL\033[0m  %s\n" "$desc"
    fi
}

run_expect_fail() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"; shift
    if ! "$@" >/dev/null 2>&1; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  \033[32mPASS\033[0m  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        printf "  \033[31mFAIL\033[0m  %s (expected failure)\n" "$desc"
    fi
}

run_output() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"; local pattern="$2"; shift 2
    local out
    out=$("$@" 2>&1) || true
    if echo "$out" | grep -qi "$pattern"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        printf "  \033[32mPASS\033[0m  %s\n" "$desc"
    else
        FAIL=$((FAIL + 1))
        printf "  \033[31mFAIL\033[0m  %s (pattern '%s' not found)\n" "$desc" "$pattern"
        echo "    output: $(echo "$out" | head -3)"
    fi
}

FLAGS="--homedir $HOMEDIR"

echo ""
echo "========================================="
echo "  gpg-go v0.9.0-beta Integration Tests"
echo "========================================="
echo ""
echo "Home directory: $HOMEDIR"
echo ""

# -----------------------------------------------
echo "--- Key Generation ---"
# -----------------------------------------------

TOTAL=$((TOTAL + 1))
if gen_key "Alice Test" "alice@test.local"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  \033[32mPASS\033[0m  generate Ed25519 key (Alice)\n"
else
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m  generate Ed25519 key (Alice)\n"
fi

TOTAL=$((TOTAL + 1))
if gen_key "Bob Test" "bob@test.local"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  \033[32mPASS\033[0m  generate Ed25519 key (Bob)\n"
else
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m  generate Ed25519 key (Bob)\n"
fi

run_output "list-keys shows Alice" "Alice Test" \
    $BIN list-keys $FLAGS

run_output "list-keys shows Bob" "Bob Test" \
    $BIN list-keys $FLAGS

run_output "list-secret-keys shows both" "alice@test.local" \
    $BIN list-secret-keys $FLAGS

# -----------------------------------------------
echo ""
echo "--- Key Info & Fingerprint ---"
# -----------------------------------------------

ALICE_FP=$(get_fp "Alice Test")
BOB_FP=$(get_fp "Bob Test")

TOTAL=$((TOTAL + 1))
if [ -n "$ALICE_FP" ] && [ ${#ALICE_FP} -eq 40 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  \033[32mPASS\033[0m  fingerprint extracted: %s\n" "$ALICE_FP"
else
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m  fingerprint extraction failed: '%s'\n" "$ALICE_FP"
fi

run_output "list-keys shows subkey info" "sub:" \
    $BIN list-keys $FLAGS

# -----------------------------------------------
echo ""
echo "--- Encrypt / Decrypt ---"
# -----------------------------------------------

echo "Hello from gpg-go!" > "$HOMEDIR/plain.txt"

run "encrypt file (armored)" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/enc.asc" -r "Alice Test" "$HOMEDIR/plain.txt"

run_output "encrypted file is armored" "BEGIN PGP MESSAGE" \
    cat "$HOMEDIR/enc.asc"

run "decrypt file" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec.txt" "$HOMEDIR/enc.asc"

run_output "decrypted content matches" "Hello from gpg-go!" \
    cat "$HOMEDIR/dec.txt"

# Encrypt to multiple recipients
run "encrypt to multiple recipients" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/multi.asc" -r "Alice Test" -r "Bob Test" "$HOMEDIR/plain.txt"

run "Bob can decrypt multi-recipient message" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/multi_dec.txt" "$HOMEDIR/multi.asc"

# Binary encrypt/decrypt
run "encrypt file (binary)" \
    $BIN encrypt $FLAGS -o "$HOMEDIR/enc.gpg" -r "Alice Test" "$HOMEDIR/plain.txt"

run "decrypt binary file" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec2.txt" "$HOMEDIR/enc.gpg"

run_output "binary decrypt matches" "Hello from gpg-go!" \
    cat "$HOMEDIR/dec2.txt"

# -----------------------------------------------
echo ""
echo "--- Sign / Verify ---"
# -----------------------------------------------

# Detached signature (armored)
run "create detached signature (armored)" \
    $BIN sign $FLAGS -a --detach-sign -o "$HOMEDIR/plain.sig" -u "Alice Test" "$HOMEDIR/plain.txt"

run "verify detached signature" \
    $BIN verify $FLAGS "$HOMEDIR/plain.sig" "$HOMEDIR/plain.txt"

# Detached signature (binary)
run "create detached signature (binary)" \
    $BIN sign $FLAGS --detach-sign -o "$HOMEDIR/plain.bsig" -u "Alice Test" "$HOMEDIR/plain.txt"

run "verify binary detached signature" \
    $BIN verify $FLAGS "$HOMEDIR/plain.bsig" "$HOMEDIR/plain.txt"

# Inline signature
run "create inline signature" \
    $BIN sign $FLAGS -a -o "$HOMEDIR/inline.asc" -u "Alice Test" "$HOMEDIR/plain.txt"

run "verify inline signature" \
    $BIN verify $FLAGS "$HOMEDIR/inline.asc"

# Clearsign
run "create clearsign signature" \
    $BIN sign $FLAGS --clear-sign -o "$HOMEDIR/clear.asc" -u "Alice Test" "$HOMEDIR/plain.txt"

run_output "clearsign output contains header" "BEGIN PGP SIGNED MESSAGE" \
    cat "$HOMEDIR/clear.asc"

run "verify clearsign signature" \
    $BIN verify $FLAGS "$HOMEDIR/clear.asc"

# Tampered message should fail verification
cp "$HOMEDIR/plain.txt" "$HOMEDIR/tampered.txt"
echo "TAMPERED" >> "$HOMEDIR/tampered.txt"
run_expect_fail "verify detects tampered message" \
    $BIN verify $FLAGS "$HOMEDIR/plain.sig" "$HOMEDIR/tampered.txt"

# -----------------------------------------------
echo ""
echo "--- Export / Import ---"
# -----------------------------------------------

run "export public key (armored)" \
    $BIN export $FLAGS -a -o "$HOMEDIR/alice.pub" "Alice Test"

run_output "exported key is armored" "BEGIN PGP PUBLIC KEY" \
    cat "$HOMEDIR/alice.pub"

# Delete and reimport (need --secret to fully remove)
run "delete Alice's key (public + secret)" \
    $BIN delete $FLAGS --secret "$ALICE_FP"

run_expect_fail "Alice gone after delete" \
    $BIN fingerprint $FLAGS "Alice Test"

run "reimport Alice's public key" \
    $BIN import $FLAGS "$HOMEDIR/alice.pub"

run_output "Alice is back after import" "Alice Test" \
    $BIN list-keys $FLAGS

# -----------------------------------------------
echo ""
echo "--- Add Subkey (R2-I-01) ---"
# -----------------------------------------------

# Generate a fresh key for subkey tests
TOTAL=$((TOTAL + 1))
if gen_key "SubkeyUser" "subkey@test.local"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  \033[32mPASS\033[0m  generate key for subkey test\n"
else
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m  generate key for subkey test\n"
fi

SUBKEY_FP=$(get_fp "SubkeyUser")

# Count initial subkeys
INITIAL_SUBS=$($BIN list-keys $FLAGS 2>/dev/null | grep -c "sub:" || true)

run "add encryption subkey" \
    $BIN add-subkey $FLAGS "$SUBKEY_FP" --type encrypt

NEW_SUBS=$($BIN list-keys $FLAGS 2>/dev/null | grep -c "sub:" || true)
TOTAL=$((TOTAL + 1))
if [ "$NEW_SUBS" -gt "$INITIAL_SUBS" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "  \033[32mPASS\033[0m  subkey count increased (%d -> %d)\n" "$INITIAL_SUBS" "$NEW_SUBS"
else
    FAIL=$((FAIL + 1))
    printf "  \033[31mFAIL\033[0m  subkey count did not increase (%d -> %d)\n" "$INITIAL_SUBS" "$NEW_SUBS"
fi

run "add signing subkey" \
    $BIN add-subkey $FLAGS "$SUBKEY_FP" --type sign

run_output "list shows [sign] subkey" "sign" \
    $BIN list-keys $FLAGS

# Encrypt/decrypt still works after subkey rotation
echo "post-rotation message" > "$HOMEDIR/rotate.txt"
run "encrypt after subkey rotation" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/rotate.asc" -r "SubkeyUser" "$HOMEDIR/rotate.txt"

run "decrypt after subkey rotation" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/rotate_dec.txt" "$HOMEDIR/rotate.asc"

run_output "decrypted rotation message matches" "post-rotation message" \
    cat "$HOMEDIR/rotate_dec.txt"

# -----------------------------------------------
echo ""
echo "--- Add UID (R2-I-03) ---"
# -----------------------------------------------

run "add UID to SubkeyUser" \
    $BIN add-uid $FLAGS "$SUBKEY_FP" --name "SubkeyUser Alt" --email "alt@test.local"

run_output "new UID appears in list" "alt@test.local" \
    $BIN list-keys $FLAGS

run "add second UID" \
    $BIN add-uid $FLAGS "$SUBKEY_FP" --name "SubkeyUser Work" --email "work@test.local" --comment "office"

run_output "second UID appears in list" "work@test.local" \
    $BIN list-keys $FLAGS

# -----------------------------------------------
echo ""
echo "--- Trust Database ---"
# -----------------------------------------------

run "set trust level" \
    $BIN edit-trust $FLAGS "$SUBKEY_FP" full

run_output "list-trust shows trust entry" "SubkeyUser" \
    $BIN list-trust $FLAGS

# -----------------------------------------------
echo ""
echo "--- Revocation Certificate ---"
# -----------------------------------------------

run "generate revocation certificate" \
    $BIN gen-revoke $FLAGS -o "$HOMEDIR/revoke.asc" "$SUBKEY_FP"

run_output "revocation cert is armored" "BEGIN PGP PUBLIC KEY" \
    cat "$HOMEDIR/revoke.asc"

# -----------------------------------------------
echo ""
echo "--- JSON Output ---"
# -----------------------------------------------

run_output "list-keys --json produces JSON" '"key_id"' \
    $BIN list-keys $FLAGS --json

run_output "list-secret-keys --json produces JSON" '"key_id"' \
    $BIN list-secret-keys $FLAGS --json

# -----------------------------------------------
echo ""
echo "--- Self-Audit ---"
# -----------------------------------------------

run_output "audit command runs" "audit" \
    $BIN audit $FLAGS

# -----------------------------------------------
echo ""
echo "--- Edge Cases ---"
# -----------------------------------------------

run_expect_fail "encrypt to nonexistent recipient fails" \
    $BIN encrypt $FLAGS -r "nobody@nowhere" "$HOMEDIR/plain.txt"

run_expect_fail "decrypt garbage fails" \
    bash -c "echo 'not encrypted' | $BIN decrypt $FLAGS"

run_expect_fail "verify garbage fails" \
    bash -c "echo 'not signed' | $BIN verify $FLAGS"

run_expect_fail "delete nonexistent key fails" \
    $BIN delete $FLAGS "0000000000000000"

run_expect_fail "add-subkey to nonexistent key fails" \
    $BIN add-subkey $FLAGS "0000000000000000" --type encrypt

run_expect_fail "add-uid to nonexistent key fails" \
    $BIN add-uid $FLAGS "0000000000000000" --name "X" --email "x@x"

# -----------------------------------------------
echo ""
echo "========================================="
printf "  Results: \033[32m%d passed\033[0m" "$PASS_COUNT"
if [ "$FAIL" -gt 0 ]; then
    printf ", \033[31m%d failed\033[0m" "$FAIL"
fi
printf " / %d total\n" "$TOTAL"
echo "========================================="
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
